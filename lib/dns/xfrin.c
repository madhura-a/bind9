/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: xfrin.c,v 1.99 2000/10/06 18:58:21 bwelling Exp $ */

#include <config.h>

#include <isc/mem.h>
#include <isc/print.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/events.h>
#include <dns/journal.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/result.h>
#include <dns/tcpmsg.h>
#include <dns/tsig.h>
#include <dns/view.h>
#include <dns/xfrin.h>
#include <dns/zone.h>

#include <dst/dst.h>

/*
 * Incoming AXFR and IXFR.
 */

/*
 * It would be non-sensical (or at least obtuse) to use FAIL() with an
 * ISC_R_SUCCESS code, but the test is there to keep the Solaris compiler
 * from complaining about "end-of-loop code not reached".
 */
#define FAIL(code) \
	do { result = (code);					\
		if (result != ISC_R_SUCCESS) goto failure;	\
	} while (0)

#define CHECK(op) \
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) goto failure;	\
	} while (0)

/*
 * The states of the *XFR state machine.  We handle both IXFR and AXFR
 * with a single integrated state machine because they cannot be distinguished
 * immediately - an AXFR response to an IXFR request can only be detected
 * when the first two (2) response RRs have already been received.
 */
typedef enum {
	XFRST_SOAQUERY,
	XFRST_GOTSOA,
	XFRST_INITIALSOA,
	XFRST_FIRSTDATA,
	XFRST_IXFR_DELSOA,
	XFRST_IXFR_DEL,
	XFRST_IXFR_ADDSOA,
	XFRST_IXFR_ADD,
	XFRST_AXFR,
	XFRST_END
} xfrin_state_t;

/*
 * Incoming zone transfer context.
 */

struct dns_xfrin_ctx {
	unsigned int		magic;
	isc_mem_t		*mctx;
	dns_zone_t		*zone;

	int			refcount;

	isc_task_t 		*task;
	isc_timer_t		*timer;
	isc_socketmgr_t 	*socketmgr;

	int			connects; 	/* Connect in progress */
	int			sends;		/* Send in progress */
	int			recvs;	  	/* Receive in progress */
	isc_boolean_t		shuttingdown;

	dns_name_t 		name; 		/* Name of zone to transfer */
	dns_rdataclass_t 	rdclass;

	/*
	 * Requested transfer type (dns_rdatatype_axfr or
	 * dns_rdatatype_ixfr).  The actual transfer type
	 * may differ due to IXFR->AXFR fallback.
	 */
	dns_rdatatype_t 	reqtype;

	isc_sockaddr_t 		masteraddr;
	isc_sockaddr_t		sourceaddr;
	isc_socket_t 		*socket;

	/* Buffer for IXFR/AXFR request message */
	isc_buffer_t 		qbuffer;
	unsigned char 		qbuffer_data[512];

	/* Incoming reply TCP message */
	dns_tcpmsg_t		tcpmsg;
	isc_boolean_t		tcpmsg_valid;

	dns_db_t 		*db;
	dns_dbversion_t 	*ver;
	dns_diff_t 		diff;		/* Pending database changes */
	int 			difflen;	/* Number of pending tuples */

	xfrin_state_t 		state;
	isc_uint32_t 		end_serial;
	isc_boolean_t 		is_ixfr;

	unsigned int		nmsg;		/* Number of messages recvd */

	dns_tsigkey_t		*tsigkey;	/* Key used to create TSIG */
	isc_buffer_t		*lasttsig;	/* The last TSIG */
	dst_context_t		*tsigctx;	/* TSIG verification context */
	unsigned int		sincetsig;	/* recvd since the last TSIG */
	dns_xfrindone_t		done;

	/*
	 * AXFR- and IXFR-specific data.  Only one is used at a time
	 * according to the is_ixfr flag, so this could be a union,
	 * but keeping them separate makes it a bit simpler to clean
	 * things up when destroying the context.
	 */
	struct {
		dns_addrdatasetfunc_t add_func;
		dns_dbload_t	      *add_private;
	} axfr;

	struct {
		isc_uint32_t 	request_serial;
		isc_uint32_t 	end_serial;
		dns_journal_t	*journal;

	} ixfr;
};

#define XFRIN_MAGIC		  0x58667269U		/* XfrI. */
#define VALID_XFRIN(x)		  ISC_MAGIC_VALID(x, XFRIN_MAGIC)

/**************************************************************************/
/*
 * Forward declarations.
 */

static isc_result_t
xfrin_create(isc_mem_t *mctx,
	     dns_zone_t *zone,
	     dns_db_t *db,
	     isc_task_t *task,
	     isc_timermgr_t *timermgr,
	     isc_socketmgr_t *socketmgr,
	     dns_name_t *zonename,
	     dns_rdataclass_t rdclass,
	     dns_rdatatype_t reqtype,
	     isc_sockaddr_t *masteraddr,
	     dns_tsigkey_t *tsigkey,
	     dns_xfrin_ctx_t **xfrp);

static isc_result_t axfr_init(dns_xfrin_ctx_t *xfr);
static isc_result_t axfr_makedb(dns_xfrin_ctx_t *xfr, dns_db_t **dbp);
static isc_result_t axfr_putdata(dns_xfrin_ctx_t *xfr, dns_diffop_t op,
				   dns_name_t *name, dns_ttl_t ttl,
				   dns_rdata_t *rdata);
static isc_result_t axfr_apply(dns_xfrin_ctx_t *xfr);
static isc_result_t axfr_commit(dns_xfrin_ctx_t *xfr);

static isc_result_t ixfr_init(dns_xfrin_ctx_t *xfr);
static isc_result_t ixfr_apply(dns_xfrin_ctx_t *xfr);
static isc_result_t ixfr_putdata(dns_xfrin_ctx_t *xfr, dns_diffop_t op,
				 dns_name_t *name, dns_ttl_t ttl,
				 dns_rdata_t *rdata);
static isc_result_t ixfr_commit(dns_xfrin_ctx_t *xfr);

static isc_result_t xfr_rr(dns_xfrin_ctx_t *xfr, dns_name_t *name,
			   isc_uint32_t ttl, dns_rdata_t *rdata);

static isc_result_t xfrin_start(dns_xfrin_ctx_t *xfr);

static void xfrin_connect_done(isc_task_t *task, isc_event_t *event);
static isc_result_t xfrin_send_request(dns_xfrin_ctx_t *xfr);
static void xfrin_send_done(isc_task_t *task, isc_event_t *event);
static void xfrin_sendlen_done(isc_task_t *task, isc_event_t *event);
static void xfrin_recv_done(isc_task_t *task, isc_event_t *event);
static void xfrin_timeout(isc_task_t *task, isc_event_t *event);

static void maybe_free(dns_xfrin_ctx_t *xfr);

static void
xfrin_fail(dns_xfrin_ctx_t *xfr, isc_result_t result, const char *msg);
static isc_result_t
render(dns_message_t *msg, isc_buffer_t *buf);

static void
xfrin_logv(int level, dns_name_t *zonename, isc_sockaddr_t *masteraddr,
	   const char *fmt, va_list ap);
static void
xfrin_log1(int level, dns_name_t *zonename, isc_sockaddr_t *masteraddr,
	   const char *fmt, ...);
static void
xfrin_log(dns_xfrin_ctx_t *xfr, unsigned int level, const char *fmt, ...);


/**************************************************************************/
/*
 * AXFR handling
 */

static isc_result_t
axfr_init(dns_xfrin_ctx_t *xfr) {
	isc_result_t result;

 	xfr->is_ixfr = ISC_FALSE;

	if (xfr->db != NULL)
		dns_db_detach(&xfr->db);

	CHECK(axfr_makedb(xfr, &xfr->db));
	CHECK(dns_db_beginload(xfr->db, &xfr->axfr.add_func,
			       &xfr->axfr.add_private));
	result = ISC_R_SUCCESS;
 failure:
	return (result);
}

static isc_result_t
axfr_makedb(dns_xfrin_ctx_t *xfr, dns_db_t **dbp) {
	return (dns_db_create(xfr->mctx, /* XXX */
			      "rbt", /* XXX guess */
			      &xfr->name,
			      dns_dbtype_zone,
			      xfr->rdclass,
			      0, NULL, /* XXX guess */
			      dbp));
}

static isc_result_t
axfr_putdata(dns_xfrin_ctx_t *xfr, dns_diffop_t op,
	     dns_name_t *name, dns_ttl_t ttl, dns_rdata_t *rdata)
{
	isc_result_t result;

	dns_difftuple_t *tuple = NULL;
	CHECK(dns_difftuple_create(xfr->diff.mctx, op,
				   name, ttl, rdata, &tuple));
	dns_diff_append(&xfr->diff, &tuple);
	if (++xfr->difflen > 100)
		CHECK(axfr_apply(xfr));
	result = ISC_R_SUCCESS;
 failure:
	return (result);
}

/*
 * Store a set of AXFR RRs in the database.
 */
static isc_result_t
axfr_apply(dns_xfrin_ctx_t *xfr) {
	isc_result_t result;

        CHECK(dns_diff_load(&xfr->diff,
			    xfr->axfr.add_func, xfr->axfr.add_private));
	xfr->difflen = 0;
	dns_diff_clear(&xfr->diff);
	result = ISC_R_SUCCESS;
 failure:
	return (result);
}

static isc_result_t
axfr_commit(dns_xfrin_ctx_t *xfr) {
	isc_result_t result;

	CHECK(axfr_apply(xfr));
	CHECK(dns_db_endload(xfr->db, &xfr->axfr.add_private));
	CHECK(dns_zone_replacedb(xfr->zone, xfr->db, ISC_TRUE));

	result = ISC_R_SUCCESS;
 failure:
	return (result);
}

/**************************************************************************/
/*
 * IXFR handling
 */

static isc_result_t
ixfr_init(dns_xfrin_ctx_t *xfr) {
	isc_result_t result;
	char *journalfile;

	if (xfr->reqtype != dns_rdatatype_ixfr) {
		xfrin_log(xfr, ISC_LOG_ERROR,
			  "got incremental response to AXFR request");
		return (DNS_R_FORMERR);
	}

	xfr->is_ixfr = ISC_TRUE;
	INSIST(xfr->db != NULL);
	xfr->difflen = 0;

	journalfile = dns_zone_getjournal(xfr->zone);
	if (journalfile != NULL)
		CHECK(dns_journal_open(xfr->mctx, journalfile,
				       ISC_TRUE, &xfr->ixfr.journal));

	result = ISC_R_SUCCESS;
 failure:
	return (result);
}

static isc_result_t
ixfr_putdata(dns_xfrin_ctx_t *xfr, dns_diffop_t op,
	     dns_name_t *name, dns_ttl_t ttl, dns_rdata_t *rdata)
{
	isc_result_t result;

	dns_difftuple_t *tuple = NULL;
	CHECK(dns_difftuple_create(xfr->diff.mctx, op,
				   name, ttl, rdata, &tuple));
	dns_diff_append(&xfr->diff, &tuple);
	if (++xfr->difflen > 100)
		CHECK(ixfr_apply(xfr));
	result = ISC_R_SUCCESS;
 failure:
	return (result);
}

/*
 * Apply a set of IXFR changes to the database.
 */
static isc_result_t
ixfr_apply(dns_xfrin_ctx_t *xfr) {
	isc_result_t result;

	if (xfr->ver == NULL) {
		CHECK(dns_db_newversion(xfr->db, &xfr->ver));
		if (xfr->ixfr.journal != NULL)
			CHECK(dns_journal_begin_transaction(xfr->ixfr.journal));
	}
        CHECK(dns_diff_apply(&xfr->diff, xfr->db, xfr->ver));
	if (xfr->ixfr.journal != NULL)
		dns_journal_writediff(xfr->ixfr.journal, &xfr->diff);
	dns_diff_clear(&xfr->diff);
	xfr->difflen = 0;
	result = ISC_R_SUCCESS;
 failure:
	return (result);
}

static isc_result_t
ixfr_commit(dns_xfrin_ctx_t *xfr) {
	isc_result_t result;

	ixfr_apply(xfr);
	if (xfr->ver != NULL) {
		/* XXX enter ready-to-commit state here */
		if (xfr->ixfr.journal != NULL)
			CHECK(dns_journal_commit(xfr->ixfr.journal));
		dns_db_closeversion(xfr->db, &xfr->ver, ISC_TRUE);
		dns_zone_markdirty(xfr->zone);
	}
	result = ISC_R_SUCCESS;
 failure:
	return (result);
}

/**************************************************************************/
/*
 * Common AXFR/IXFR protocol code
 */

/*
 * Handle a single incoming resource record according to the current
 * state.
 */
static isc_result_t
xfr_rr(dns_xfrin_ctx_t *xfr, dns_name_t *name, isc_uint32_t ttl,
       dns_rdata_t *rdata)
{
	isc_result_t result;

 redo:
	switch (xfr->state) {
	case XFRST_SOAQUERY:
		xfr->end_serial = dns_soa_getserial(rdata);
		if (!DNS_SERIAL_GT(xfr->end_serial,
				   xfr->ixfr.request_serial)) {
			xfrin_log(xfr, ISC_LOG_DEBUG(3),
				  "requested serial %u, "
				  "master has %u, not updating",
				  xfr->ixfr.request_serial, xfr->end_serial);
			FAIL(DNS_R_UPTODATE);
		}
		xfr->state = XFRST_GOTSOA;
		break;

	case XFRST_GOTSOA:
		/*
		 * Skip other records in the answer section.
		 */
		break;

	case XFRST_INITIALSOA:
		if (rdata->type != dns_rdatatype_soa) {
			xfrin_log(xfr, ISC_LOG_ERROR,
				  "first RR in zone transfer must be SOA");
			FAIL(DNS_R_FORMERR);
		}
		/*
		 * Remember the serial number in the intial SOA.
		 * We need it to recognize the end of an IXFR.
		 */
		xfr->end_serial = dns_soa_getserial(rdata);
		if (xfr->reqtype == dns_rdatatype_ixfr &&
		    ! DNS_SERIAL_GT(xfr->end_serial, xfr->ixfr.request_serial))
		{
			/*
			 * This must be the single SOA record that is
			 * sent when the current version on the master
			 * is not newer than the version in the request.
			 */
			xfrin_log(xfr, ISC_LOG_DEBUG(3),
				  "requested serial %u, "
				  "master has %u, not updating",
				  xfr->ixfr.request_serial, xfr->end_serial);
			FAIL(DNS_R_UPTODATE);
		}
		xfr->state = XFRST_FIRSTDATA;
		break;

	case XFRST_FIRSTDATA:
		/*
		 * If the transfer begins with one SOA record, it is an AXFR,
		 * if it begins with two SOAs, it is an IXFR.
		 */
		if (xfr->reqtype == dns_rdatatype_ixfr &&
		    rdata->type == dns_rdatatype_soa &&
		    xfr->ixfr.request_serial == dns_soa_getserial(rdata)) {
			xfrin_log(xfr, ISC_LOG_DEBUG(3),
				  "got incremental response");
			CHECK(ixfr_init(xfr));
			xfr->state = XFRST_IXFR_DELSOA;
		} else {
			xfrin_log(xfr, ISC_LOG_DEBUG(3),
				  "got nonincremental response");
			CHECK(axfr_init(xfr));
			xfr->state = XFRST_AXFR;
		}
		goto redo;

	case XFRST_IXFR_DELSOA:
		INSIST(rdata->type == dns_rdatatype_soa);
		CHECK(ixfr_putdata(xfr, DNS_DIFFOP_DEL, name, ttl, rdata));
		xfr->state = XFRST_IXFR_DEL;
		break;

	case XFRST_IXFR_DEL:
		if (rdata->type == dns_rdatatype_soa) {
			isc_uint32_t soa_serial = dns_soa_getserial(rdata);
			xfr->state = XFRST_IXFR_ADDSOA;
			xfr->ixfr.end_serial = soa_serial;
			goto redo;
		}
		CHECK(ixfr_putdata(xfr, DNS_DIFFOP_DEL, name, ttl, rdata));
		break;

	case XFRST_IXFR_ADDSOA:
		INSIST(rdata->type == dns_rdatatype_soa);
		CHECK(ixfr_putdata(xfr, DNS_DIFFOP_ADD, name, ttl, rdata));
		xfr->state = XFRST_IXFR_ADD;
		break;

	case XFRST_IXFR_ADD:
		if (rdata->type == dns_rdatatype_soa) {
			isc_uint32_t soa_serial = dns_soa_getserial(rdata);
			CHECK(ixfr_commit(xfr));
			if (soa_serial == xfr->end_serial) {
				xfr->state = XFRST_END;
				break;
			} else {
				xfr->state = XFRST_IXFR_DELSOA;
				goto redo;
			}
		}
		CHECK(ixfr_putdata(xfr, DNS_DIFFOP_ADD, name, ttl, rdata));
		break;

	case XFRST_AXFR:
		CHECK(axfr_putdata(xfr, DNS_DIFFOP_ADD, name, ttl, rdata));
		if (rdata->type == dns_rdatatype_soa) {
			CHECK(axfr_commit(xfr));
			xfr->state = XFRST_END;
			break;
		}
		break;
	case XFRST_END:
		FAIL(DNS_R_EXTRADATA);
	default:
		INSIST(0);
		break;
	}
	result = ISC_R_SUCCESS;
 failure:
	return (result);
}

isc_result_t
dns_xfrin_create(dns_zone_t *zone, dns_rdatatype_t xfrtype,
		 isc_sockaddr_t *masteraddr, dns_tsigkey_t *tsigkey,
		 isc_mem_t *mctx, isc_timermgr_t *timermgr,
		 isc_socketmgr_t *socketmgr, isc_task_t *task,
		 dns_xfrindone_t done, dns_xfrin_ctx_t **xfrp)
{
	dns_name_t *zonename = dns_zone_getorigin(zone);
	dns_xfrin_ctx_t *xfr;
	isc_result_t result;
	dns_db_t *db = NULL;

	REQUIRE(xfrp != NULL && *xfrp == NULL);

	(void)dns_zone_getdb(zone, &db);

	CHECK(xfrin_create(mctx, zone, db, task, timermgr, socketmgr, zonename,
			   dns_zone_getclass(zone), xfrtype, masteraddr,
			   tsigkey, &xfr));

	CHECK(xfrin_start(xfr));

	xfr->done = done;
	xfr->refcount++;
	*xfrp = xfr;

 failure:
	if (db != NULL)
		dns_db_detach(&db);
	if (result != ISC_R_SUCCESS)
		xfrin_log1(ISC_LOG_ERROR, zonename, masteraddr,
			   "zone transfer setup failed");
	return (result);
}

void
dns_xfrin_shutdown(dns_xfrin_ctx_t *xfr) {
	if (! xfr->shuttingdown)
		xfrin_fail(xfr, ISC_R_CANCELED, "shut down");
}

void
dns_xfrin_detach(dns_xfrin_ctx_t **xfrp) {
	dns_xfrin_ctx_t *xfr = *xfrp;
	INSIST(xfr->refcount > 0);
	xfr->refcount--;
	maybe_free(xfr);
	*xfrp = NULL;
}

static void
xfrin_fail(dns_xfrin_ctx_t *xfr, isc_result_t result, const char *msg) {
	if (result != DNS_R_UPTODATE) {
		xfrin_log(xfr, ISC_LOG_ERROR, "%s: %s",
			  msg, isc_result_totext(result));
	}
	if (xfr->connects > 0) {
		isc_socket_cancel(xfr->socket, xfr->task,
				  ISC_SOCKCANCEL_CONNECT);
	} else if (xfr->recvs > 0) {
		dns_tcpmsg_cancelread(&xfr->tcpmsg);
	} else if (xfr->sends > 0) {
		isc_socket_cancel(xfr->socket, xfr->task,
				  ISC_SOCKCANCEL_SEND);
	}
	if (xfr->done != NULL) {
		(xfr->done)(xfr->zone, result);
		xfr->done = NULL;
	}
	xfr->shuttingdown = ISC_TRUE;
	maybe_free(xfr);
}

static isc_result_t
xfrin_create(isc_mem_t *mctx,
	     dns_zone_t *zone,
	     dns_db_t *db,
	     isc_task_t *task,
	     isc_timermgr_t *timermgr,
	     isc_socketmgr_t *socketmgr,
	     dns_name_t *zonename,
	     dns_rdataclass_t rdclass,
	     dns_rdatatype_t reqtype,
	     isc_sockaddr_t *masteraddr,
	     dns_tsigkey_t *tsigkey,
	     dns_xfrin_ctx_t **xfrp)
{
	dns_xfrin_ctx_t *xfr = NULL;
	isc_result_t result;
	isc_interval_t maxinterval, idleinterval;
	isc_time_t expires;

	xfr = isc_mem_get(mctx, sizeof(*xfr));
	if (xfr == NULL)
		return (ISC_R_NOMEMORY);
	xfr->mctx = mctx;
	xfr->refcount = 0;
	xfr->zone = NULL;
	dns_zone_iattach(zone, &xfr->zone);
	xfr->task = NULL;
	isc_task_attach(task, &xfr->task);
	xfr->timer = NULL;
	xfr->socketmgr = socketmgr;
	xfr->done = NULL;

	xfr->connects = 0;
	xfr->sends = 0;
	xfr->recvs = 0;
	xfr->shuttingdown = ISC_FALSE;

	dns_name_init(&xfr->name, NULL);
	xfr->rdclass = rdclass;
	xfr->reqtype = reqtype;

	/* sockaddr */
	xfr->socket = NULL;
	/* qbuffer */
	/* qbuffer_data */
	/* tcpmsg */
	xfr->tcpmsg_valid = ISC_FALSE;

	xfr->db = NULL;
	if (db != NULL)
		dns_db_attach(db, &xfr->db);
	xfr->ver = NULL;
	dns_diff_init(xfr->mctx, &xfr->diff);
	xfr->difflen = 0;

	xfr->state = XFRST_INITIALSOA;
	/* end_serial */

	xfr->nmsg = 0;

	xfr->tsigkey = NULL;
	if (tsigkey != NULL)
		dns_tsigkey_attach(tsigkey, &xfr->tsigkey);
	xfr->lasttsig = NULL;
	xfr->tsigctx = NULL;
	xfr->sincetsig = 0;

	/* is_ixfr */

	/* ixfr.request_serial */
	/* ixfr.end_serial */
	xfr->ixfr.journal = NULL;

	xfr->axfr.add_func = NULL;
	xfr->axfr.add_private = NULL;

	CHECK(dns_name_dup(zonename, mctx, &xfr->name));

	isc_interval_set(&maxinterval, dns_zone_getmaxxfrin(xfr->zone), 0);
	CHECK(isc_time_nowplusinterval(&expires, &maxinterval));
	isc_interval_set(&idleinterval, dns_zone_getidlein(xfr->zone), 0);

	CHECK(isc_timer_create(timermgr, isc_timertype_once,
			       &expires, &idleinterval, task,
			       xfrin_timeout, xfr, &xfr->timer));

	xfr->masteraddr = *masteraddr;

	switch (isc_sockaddr_pf(masteraddr)) {
	case PF_INET:
		xfr->sourceaddr = *dns_zone_getxfrsource4(zone);
		break;
	case PF_INET6:
		xfr->sourceaddr = *dns_zone_getxfrsource6(zone);
		break;
	default:
		INSIST(0);
	}

	isc_buffer_init(&xfr->qbuffer, xfr->qbuffer_data,
			sizeof(xfr->qbuffer_data));

	xfr->magic = XFRIN_MAGIC;
	*xfrp = xfr;
	return (ISC_R_SUCCESS);

 failure:
	xfrin_fail(xfr, result, "creating transfer context");
	return (result);
}

static isc_result_t
xfrin_start(dns_xfrin_ctx_t *xfr) {
	isc_result_t result;
	CHECK(isc_socket_create(xfr->socketmgr,
				isc_sockaddr_pf(&xfr->sourceaddr),
				isc_sockettype_tcp,
				&xfr->socket));
	CHECK(isc_socket_bind(xfr->socket, &xfr->sourceaddr));
	CHECK(isc_socket_connect(xfr->socket, &xfr->masteraddr, xfr->task,
				 xfrin_connect_done, xfr));
	xfr->connects++;
	return (ISC_R_SUCCESS);
 failure:
	xfrin_fail(xfr, result, "setting up socket");
	return (result);
}

/* XXX the resolver could use this, too */

static isc_result_t
render(dns_message_t *msg, isc_buffer_t *buf) {
	isc_result_t result;

	CHECK(dns_message_renderbegin(msg, buf));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_QUESTION, 0));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_ANSWER, 0));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_AUTHORITY, 0));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_ADDITIONAL, 0));
	CHECK(dns_message_renderend(msg));
	result = ISC_R_SUCCESS;
 failure:
	return (result);
}

/*
 * A connection has been established.
 */
static void
xfrin_connect_done(isc_task_t *task, isc_event_t *event) {
	isc_socket_connev_t *cev = (isc_socket_connev_t *) event;
	dns_xfrin_ctx_t *xfr = (dns_xfrin_ctx_t *) event->ev_arg;
	isc_result_t evresult = cev->result;
	isc_result_t result;

	REQUIRE(VALID_XFRIN(xfr));

	UNUSED(task);

	INSIST(event->ev_type == ISC_SOCKEVENT_CONNECT);
	isc_event_free(&event);

	xfr->connects--;
	if (xfr->shuttingdown) {
		maybe_free(xfr);
		return;
	}

	CHECK(evresult);
	xfrin_log(xfr, ISC_LOG_DEBUG(3), "connected");

	dns_tcpmsg_init(xfr->mctx, xfr->socket, &xfr->tcpmsg);
	xfr->tcpmsg_valid = ISC_TRUE;

	CHECK(xfrin_send_request(xfr));
 failure:
	if (result != ISC_R_SUCCESS)
		xfrin_fail(xfr, result, "connect");
}

/*
 * Convert a tuple into a dns_name_t suitable for inserting
 * into the given dns_message_t.
 */
static isc_result_t
tuple2msgname(dns_difftuple_t *tuple, dns_message_t *msg, dns_name_t **target)
{
	isc_result_t result;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdl = NULL;
	dns_rdataset_t *rds = NULL;
	dns_name_t *name = NULL;

	REQUIRE(target != NULL && *target == NULL);

	CHECK(dns_message_gettemprdata(msg, &rdata));
	dns_rdata_init(rdata);
	*rdata = tuple->rdata; /* Struct assignment. */

	CHECK(dns_message_gettemprdatalist(msg, &rdl));
	dns_rdatalist_init(rdl);
	rdl->type = tuple->rdata.type;
	rdl->rdclass = tuple->rdata.rdclass;
	rdl->ttl = tuple->ttl;
	ISC_LIST_APPEND(rdl->rdata, rdata, link);

	CHECK(dns_message_gettemprdataset(msg, &rds));
	dns_rdataset_init(rds);
	CHECK(dns_rdatalist_tordataset(rdl, rds));

	CHECK(dns_message_gettempname(msg, &name));
	dns_name_init(name, NULL);
	dns_name_clone(&tuple->name, name);
	ISC_LIST_APPEND(name->list, rds, link);

	*target = name;
 failure:
	return (result);
}


/*
 * Build an *XFR request and send its length prefix.
 */
static isc_result_t
xfrin_send_request(dns_xfrin_ctx_t *xfr) {
	isc_result_t result;
	isc_region_t region;
	isc_region_t lregion;
	dns_rdataset_t *qrdataset = NULL;
	dns_message_t *msg = NULL;
	unsigned char length[2];
	dns_difftuple_t *soatuple = NULL;
	dns_name_t *qname = NULL;
	dns_dbversion_t *ver = NULL;
	dns_name_t *msgsoaname = NULL;

	/* Create the request message */
	CHECK(dns_message_create(xfr->mctx, DNS_MESSAGE_INTENTRENDER, &msg));
	dns_message_settsigkey(msg, xfr->tsigkey);

	/* Create a name for the question section. */
	dns_message_gettempname(msg, &qname);
	dns_name_init(qname, NULL);
	dns_name_clone(&xfr->name, qname);

	/* Formulate the question and attach it to the question name. */
	dns_message_gettemprdataset(msg, &qrdataset);
	dns_rdataset_init(qrdataset);
	dns_rdataset_makequestion(qrdataset, xfr->rdclass, xfr->reqtype);
	ISC_LIST_APPEND(qname->list, qrdataset, link);

	dns_message_addname(msg, qname, DNS_SECTION_QUESTION);

	if (xfr->reqtype == dns_rdatatype_ixfr) {
		/* Get the SOA and add it to the authority section. */
		/* XXX is using the current version the right thing? */
		dns_db_currentversion(xfr->db, &ver);
		CHECK(dns_db_createsoatuple(xfr->db, ver, xfr->mctx,
					    DNS_DIFFOP_EXISTS, &soatuple));
		xfr->ixfr.request_serial = dns_soa_getserial(&soatuple->rdata);
		xfrin_log(xfr, ISC_LOG_DEBUG(3),
			  "requesting IXFR for serial %u",
			  xfr->ixfr.request_serial);

		CHECK(tuple2msgname(soatuple, msg, &msgsoaname));
		dns_message_addname(msg, msgsoaname, DNS_SECTION_AUTHORITY);
	}

	msg->id = ('b' << 8) | '9'; /* Arbitrary */

	CHECK(render(msg, &xfr->qbuffer));

	/*
	 * Free the last tsig, if there is one.
	 */
	if (xfr->lasttsig != NULL)
		isc_buffer_free(&xfr->lasttsig);

	/*
	 * Save the query TSIG and don't let message_destroy free it.
	 */
	CHECK(dns_message_getquerytsig(msg, xfr->mctx, &xfr->lasttsig));

	isc_buffer_usedregion(&xfr->qbuffer, &region);
	INSIST(region.length <= 65535);

	length[0] = region.length >> 8;
	length[1] = region.length & 0xFF;
	lregion.base = length;
	lregion.length = 2;
	CHECK(isc_socket_send(xfr->socket, &lregion, xfr->task,
			      xfrin_sendlen_done, xfr));
	xfr->sends++;

 failure:
	if (msg != NULL)
		dns_message_destroy(&msg);
	if (soatuple != NULL)
		dns_difftuple_free(&soatuple);
	if (ver != NULL)
		dns_db_closeversion(xfr->db, &ver, ISC_FALSE);
	return (result);
}

/* XXX there should be library support for sending DNS TCP messages */

static void
xfrin_sendlen_done(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sev = (isc_socketevent_t *) event;
	dns_xfrin_ctx_t *xfr = (dns_xfrin_ctx_t *) event->ev_arg;
	isc_result_t evresult = sev->result;
	isc_result_t result;
	isc_region_t region;

	REQUIRE(VALID_XFRIN(xfr));

	UNUSED(task);

	INSIST(event->ev_type == ISC_SOCKEVENT_SENDDONE);
	isc_event_free(&event);

	xfr->sends--;
	if (xfr->shuttingdown) {
		maybe_free(xfr);
		return;
	}

	xfrin_log(xfr, ISC_LOG_DEBUG(3), "sent request length prefix");
	CHECK(evresult);

	isc_buffer_usedregion(&xfr->qbuffer, &region);
	CHECK(isc_socket_send(xfr->socket, &region, xfr->task,
			      xfrin_send_done, xfr));
	xfr->sends++;
 failure:
	if (result != ISC_R_SUCCESS)
		xfrin_fail(xfr, result, "sending request length prefix");
}


static void
xfrin_send_done(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sev = (isc_socketevent_t *) event;
	dns_xfrin_ctx_t *xfr = (dns_xfrin_ctx_t *) event->ev_arg;
	isc_result_t result;

	REQUIRE(VALID_XFRIN(xfr));

	UNUSED(task);

	INSIST(event->ev_type == ISC_SOCKEVENT_SENDDONE);

	xfr->sends--;
	xfrin_log(xfr, ISC_LOG_DEBUG(3), "sent request data");
	CHECK(sev->result);

	CHECK(dns_tcpmsg_readmessage(&xfr->tcpmsg, xfr->task,
				     xfrin_recv_done, xfr));
	xfr->recvs++;
 failure:
	isc_event_free(&event);
	if (result != ISC_R_SUCCESS)
		xfrin_fail(xfr, result, "sending request data");
}


static void
xfrin_recv_done(isc_task_t *task, isc_event_t *ev) {
	dns_xfrin_ctx_t *xfr = (dns_xfrin_ctx_t *) ev->ev_arg;
	isc_result_t result;
	dns_message_t *msg = NULL;
	dns_name_t *name;
	dns_tcpmsg_t *tcpmsg;
	dns_name_t *tsigowner = NULL;

	REQUIRE(VALID_XFRIN(xfr));

	UNUSED(task);

	INSIST(ev->ev_type == DNS_EVENT_TCPMSG);
	tcpmsg = ev->ev_sender;
	isc_event_free(&ev);

	xfr->recvs--;
	if (xfr->shuttingdown) {
		maybe_free(xfr);
		return;
	}

	CHECK(tcpmsg->result);

	xfrin_log(xfr, ISC_LOG_DEBUG(7), "received %u bytes",
		  tcpmsg->buffer.used);

	CHECK(isc_timer_touch(xfr->timer));

	CHECK(dns_message_create(xfr->mctx, DNS_MESSAGE_INTENTPARSE, &msg));

	dns_message_settsigkey(msg, xfr->tsigkey);
	dns_message_setquerytsig(msg, xfr->lasttsig);
	msg->tsigctx = xfr->tsigctx;
	if (xfr->nmsg > 0)
		msg->tcp_continuation = 1;

	result = dns_message_parse(msg, &tcpmsg->buffer,
				   DNS_MESSAGEPARSE_PRESERVEORDER);

	if (result != ISC_R_SUCCESS || msg->rcode != dns_rcode_noerror) {
		if (result == ISC_R_SUCCESS)
			result = ISC_RESULTCLASS_DNSRCODE + msg->rcode; /*XXX*/
		if (xfr->reqtype == dns_rdatatype_axfr ||
		    xfr->reqtype == dns_rdatatype_soa)
			FAIL(result);
		xfrin_log(xfr, ISC_LOG_DEBUG(3), "got %s, retrying with AXFR",
		       isc_result_totext(result));
		dns_message_destroy(&msg);
		xfr->reqtype = dns_rdatatype_soa;
		xfr->state = XFRST_SOAQUERY;
		CHECK(xfrin_send_request(xfr));
		return;
	}

	result = dns_message_checksig(msg, dns_zone_getview(xfr->zone));
	if (result != ISC_R_SUCCESS) {
		xfrin_log(xfr, ISC_LOG_DEBUG(3), "TSIG check failed: %s",
		       isc_result_totext(result));
		return;
	}

	for (result = dns_message_firstname(msg, DNS_SECTION_ANSWER);
	     result == ISC_R_SUCCESS;
	     result = dns_message_nextname(msg, DNS_SECTION_ANSWER))
	{
		dns_rdataset_t *rds;

		name = NULL;
		dns_message_currentname(msg, DNS_SECTION_ANSWER, &name);
		if (!dns_name_issubdomain(name, &xfr->name)) {
			xfrin_log(xfr, ISC_LOG_WARNING,
				  "ignoring out-of-zone data");
			continue;
		}
		for (rds = ISC_LIST_HEAD(name->list);
		     rds != NULL;
		     rds = ISC_LIST_NEXT(rds, link))
		{
			for (result = dns_rdataset_first(rds);
			     result == ISC_R_SUCCESS;
			     result = dns_rdataset_next(rds))
			{
				dns_rdata_t rdata;
				dns_rdataset_current(rds, &rdata);
				CHECK(xfr_rr(xfr, name, rds->ttl, &rdata));
			}
		}
	}
	if (result != ISC_R_NOMORE)
		goto failure;

	if (dns_message_gettsig(msg, &tsigowner) != NULL) {
		/*
		 * Reset the counter.
		 */
		xfr->sincetsig = 0;

		/*
		 * Free the last tsig, if there is one.
		 */
		if (xfr->lasttsig != NULL)
			isc_buffer_free(&xfr->lasttsig);

		/*
		 * Update the last tsig pointer.
		 */
		CHECK(dns_message_getquerytsig(msg, xfr->mctx,
					       &xfr->lasttsig));

	} else if (dns_message_gettsigkey(msg) != NULL) {
		xfr->sincetsig++;
		if (xfr->sincetsig > 100 ||
		    xfr->nmsg == 0 || xfr->state == XFRST_END)
		{
			result = DNS_R_EXPECTEDTSIG;
			goto failure;
		}
	}

#ifndef NOMINUM_PUBLIC
	/*
	 * Check the database size.  Note that xfr->db can still
	 * be NULL at this point, e.g. when doing an initial AXFR
	 * and the first response message contains only the SOA.
	 */
	if (xfr->db != NULL) {
		unsigned int count = dns_db_nodecount(xfr->db);
		unsigned int maxnames = dns_zone_getmaxnames(xfr->zone);
		
		if (maxnames != 0 && count > maxnames) {
			result = DNS_R_ZONETOOLARGE;
			goto failure;
		}
	}
#endif /* NOMINUM_PUBLIC */
	
	/*
	 * Update the number of messages received.
	 */
	xfr->nmsg++;

	/*
	 * Copy the context back.
	 */
	xfr->tsigctx = msg->tsigctx;

	dns_message_destroy(&msg);

	if (xfr->state == XFRST_GOTSOA) {
		xfr->reqtype = dns_rdatatype_axfr;
		xfr->state = XFRST_INITIALSOA;
		CHECK(xfrin_send_request(xfr));
	} else if (xfr->state == XFRST_END) {
		/*
		 * Inform the caller we succeeded.
		 */
		if (xfr->done != NULL) {
			(xfr->done)(xfr->zone, ISC_R_SUCCESS);
			xfr->done = NULL;
		}
		/*
		 * We should have no outstanding events at this
		 * point, thus maybe_free() should succeed.
		 */
		xfr->shuttingdown = ISC_TRUE;
		maybe_free(xfr);
	} else {
		/*
		 * Read the next message.
		 */
		CHECK(dns_tcpmsg_readmessage(&xfr->tcpmsg, xfr->task,
					     xfrin_recv_done, xfr));
		xfr->recvs++;
	}
	return;

 failure:
	if (msg != NULL)
		dns_message_destroy(&msg);
	if (result != ISC_R_SUCCESS)
		xfrin_fail(xfr, result, "receiving responses");
}

static void
xfrin_timeout(isc_task_t *task, isc_event_t *event) {
	dns_xfrin_ctx_t *xfr = (dns_xfrin_ctx_t *) event->ev_arg;

	REQUIRE(VALID_XFRIN(xfr));

	UNUSED(task);

	isc_event_free(&event);
	/*
	 * This will log "giving up: timeout".
	 */
	xfrin_fail(xfr, ISC_R_TIMEDOUT, "giving up");
}

static void
maybe_free(dns_xfrin_ctx_t *xfr) {
	REQUIRE(VALID_XFRIN(xfr));

	if (! xfr->shuttingdown || xfr->refcount != 0 ||
	    xfr->connects != 0 || xfr->sends != 0 ||
	    xfr->recvs != 0)
		return;

	xfrin_log(xfr, ISC_LOG_INFO, "end of transfer");

	if (xfr->socket != NULL)
		isc_socket_detach(&xfr->socket);

	if (xfr->timer != NULL)
		isc_timer_detach(&xfr->timer);

	if (xfr->task != NULL)
		isc_task_detach(&xfr->task);

	if (xfr->tsigkey != NULL)
		dns_tsigkey_detach(&xfr->tsigkey);

	if (xfr->lasttsig != NULL)
		isc_buffer_free(&xfr->lasttsig);

	dns_diff_clear(&xfr->diff);

	if (xfr->ixfr.journal != NULL)
		dns_journal_destroy(&xfr->ixfr.journal);

	if (xfr->axfr.add_private != NULL)
		(void)dns_db_endload(xfr->db, &xfr->axfr.add_private);

	if (xfr->tcpmsg_valid)
		dns_tcpmsg_invalidate(&xfr->tcpmsg);

	if ((xfr->name.attributes & DNS_NAMEATTR_DYNAMIC) != 0)
		dns_name_free(&xfr->name, xfr->mctx);

	if (xfr->ver != NULL)
		dns_db_closeversion(xfr->db, &xfr->ver, ISC_FALSE);

	if (xfr->db != NULL)
		dns_db_detach(&xfr->db);

	if (xfr->zone != NULL)
		dns_zone_idetach(&xfr->zone);

	isc_mem_put(xfr->mctx, xfr, sizeof(*xfr));
}

/*
 * Log incoming zone transfer messages in a format like
 * transfer of <zone> from <address>: <message>
 */
static void
xfrin_logv(int level, dns_name_t *zonename, isc_sockaddr_t *masteraddr,
	   const char *fmt, va_list ap)
{
	char zntext[DNS_NAME_FORMATSIZE];
	char mastertext[ISC_SOCKADDR_FORMATSIZE];
	char msgtext[2048];

	dns_name_format(zonename, zntext, sizeof(zntext));
	isc_sockaddr_format(masteraddr, mastertext, sizeof(mastertext));
	vsnprintf(msgtext, sizeof(msgtext), fmt, ap);

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_XFER_IN,
		      DNS_LOGMODULE_XFER_IN, level,
		      "transfer of '%s' from %s: %s",
		      zntext, mastertext, msgtext);
}

/*
 * Logging function for use when a xfrin_ctx_t has not yet been created.
 */

static void
xfrin_log1(int level, dns_name_t *zonename, isc_sockaddr_t *masteraddr,
	   const char *fmt, ...)
{
        va_list ap;

	if (isc_log_wouldlog(dns_lctx, level) == ISC_FALSE)
		return;

	va_start(ap, fmt);
	xfrin_logv(level, zonename, masteraddr, fmt, ap);
	va_end(ap);
}

/*
 * Logging function for use when there is a xfrin_ctx_t.
 */

static void
xfrin_log(dns_xfrin_ctx_t *xfr, unsigned int level, const char *fmt, ...)
{
        va_list ap;

	if (isc_log_wouldlog(dns_lctx, level) == ISC_FALSE)
		return;

	va_start(ap, fmt);
	xfrin_logv(level, &xfr->name, &xfr->masteraddr, fmt, ap);
	va_end(ap);
}
