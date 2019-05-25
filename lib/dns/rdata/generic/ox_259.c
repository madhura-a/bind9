/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef RDATA_GENERIC_OX_259_C
#define RDATA_GENERIC_OX_259_C

#define RRTYPE_OX_ATTRIBUTES (0)

static inline isc_result_t
fromtext_ox(ARGS_FROMTEXT) {
	isc_token_t token;

	REQUIRE(type == dns_rdatatype_ox);

	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(callbacks);

	/*
	 * OX-ENTERPRISE
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	/*
	 * OX-TYPE
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	/*
	 * OX-LOCATION
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffU) {
		RETTOK(ISC_R_RANGE);
	}
	RETERR(uint8_tobuffer(token.value.as_ulong, target));

	/*
	 * OX-MEDIA-TYPE
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_qstring,
				      false));
	RETTOK(txt_fromtext(&token.value.as_textregion, target));

	/*
	 * OX-DATA
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));
	if (strcmp(DNS_AS_STR(token), "-") == 0) {
		return (ISC_R_SUCCESS);
	} else {
		isc_lex_ungettoken(lexer, &token);
		return (isc_base64_tobuffer(lexer, target, -1));
	}
}

static inline isc_result_t
totext_ox(ARGS_TOTEXT) {
	char buf[sizeof("4294967295 ")];
	isc_region_t region;
	uint32_t n;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_ox);
	REQUIRE(rdata->length != 0);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &region);

	/*
	 * OX-ENTERPRISE
	 */
	n = uint32_fromregion(&region);
	isc_region_consume(&region, 4);
	snprintf(buf, sizeof(buf), "%u ", n);
	RETERR(str_totext(buf, target));

	/*
	 * OX-TYPE
	 */
	n = uint32_fromregion(&region);
	isc_region_consume(&region, 4);
	snprintf(buf, sizeof(buf), "%u ", n);
	RETERR(str_totext(buf, target));

	/*
	 * OX-LOCATION
	 */
	n = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	snprintf(buf, sizeof(buf), "%u ", n);
	RETERR(str_totext(buf, target));

	/*
	 * OX-MEDIA-TYPE
	 */
	RETERR(txt_totext(&region, true, target));
	RETERR(str_totext(" ", target));

	/*
	 * OX-DATA
	 */
	if (region.length == 0) {
		return (str_totext("-", target));
	} else {
		return (isc_base64_totext(&region, 60, "", target));
	}
}

static inline isc_result_t
fromwire_ox(ARGS_FROMWIRE) {
	isc_region_t region;

	UNUSED(rdclass);
	UNUSED(dctx);
	UNUSED(options);

	REQUIRE(type == dns_rdatatype_ox);

	isc_buffer_activeregion(source, &region);
	/*
	 * OX-MEDIA-TYPE may be an empty <character-string> (i.e.,
	 * comprising of just the length octet) and OX-DATA can have
	 * zero length.
	 */
	if (region.length < 4 + 4 + 1 + 1) {
		return (ISC_R_UNEXPECTEDEND);
	}

	/*
	 * Check whether OX-MEDIA-TYPE length is not malformed.
	 */
	if (region.base[9] > region.length - 10) {
		return (ISC_R_UNEXPECTEDEND);
	}

	isc_buffer_forward(source, region.length);
	return (mem_tobuffer(target, region.base, region.length));
}

static inline isc_result_t
towire_ox(ARGS_TOWIRE) {
	isc_region_t region;

	UNUSED(cctx);

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_ox);
	REQUIRE(rdata->length != 0);

	dns_rdata_toregion(rdata, &region);
	return (mem_tobuffer(target, region.base, region.length));
}

static inline int
compare_ox(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1 != NULL);
	REQUIRE(rdata2 != NULL);
	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->type == dns_rdatatype_ox);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (isc_region_compare(&r1, &r2));
}

static inline isc_result_t
fromstruct_ox(ARGS_FROMSTRUCT) {
	dns_rdata_ox_t *ox = source;

	REQUIRE(type == dns_rdatatype_ox);
	REQUIRE(source != NULL);
	REQUIRE(ox->common.rdtype == dns_rdatatype_ox);
	REQUIRE(ox->common.rdclass == rdclass);

	RETERR(uint32_tobuffer(ox->enterprise, target));
	RETERR(uint32_tobuffer(ox->type, target));
	RETERR(uint8_tobuffer(ox->location, target));
	RETERR(uint8_tobuffer(ox->mediatype_len, target));
	RETERR(mem_tobuffer(target, ox->mediatype, ox->mediatype_len));
	return (mem_tobuffer(target, ox->data, ox->data_len));
}

static inline isc_result_t
tostruct_ox(ARGS_TOSTRUCT) {
	dns_rdata_ox_t *ox = target;
	isc_region_t region;

	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_ox);
	REQUIRE(rdata->length != 0);

	ox->common.rdclass = rdata->rdclass;
	ox->common.rdtype = rdata->type;
	ISC_LINK_INIT(&ox->common, link);

	dns_rdata_toregion(rdata, &region);

	/*
	 * OX-ENTERPRISE
	 */
	if (region.length < 4) {
		return (ISC_R_UNEXPECTEDEND);
	}
	ox->enterprise = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	/*
	 * OX-TYPE
	 */
	if (region.length < 4) {
		return (ISC_R_UNEXPECTEDEND);
	}
	ox->type = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	/*
	 * OX-LOCATION
	 */
	if (region.length < 1) {
		return (ISC_R_UNEXPECTEDEND);
	}
	ox->location = uint8_fromregion(&region);
	isc_region_consume(&region, 1);

	/*
	 * OX-MEDIA-TYPE
	 */
	if (region.length < 1) {
		return (ISC_R_UNEXPECTEDEND);
	}
	ox->mediatype_len = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	INSIST(ox->mediatype_len <= region.length);
	ox->mediatype = mem_maybedup(mctx, region.base, ox->mediatype_len);
	if (ox->mediatype == NULL) {
		goto cleanup;
	}
	isc_region_consume(&region, ox->mediatype_len);

	/*
	 * OX-DATA
	 */
	ox->data_len = region.length;
	ox->data = NULL;
	if (ox->data_len > 0) {
		ox->data = mem_maybedup(mctx, region.base, ox->data_len);
		if (ox->data == NULL) {
			goto cleanup;
		}
		isc_region_consume(&region, ox->data_len);
	}

	ox->mctx = mctx;

	return (ISC_R_SUCCESS);

cleanup:
	if (mctx != NULL && ox->mediatype != NULL) {
		isc_mem_free(mctx, ox->mediatype);
	}
	return (ISC_R_NOMEMORY);
}

static inline void
freestruct_ox(ARGS_FREESTRUCT) {
	dns_rdata_ox_t *ox = source;

	REQUIRE(source != NULL);
	REQUIRE(ox->common.rdtype == dns_rdatatype_ox);

	if (ox->mctx == NULL) {
		return;
	}

	if (ox->mediatype != NULL) {
		isc_mem_free(ox->mctx, ox->mediatype);
	}
	if (ox->data != NULL) {
		isc_mem_free(ox->mctx, ox->data);
	}

	ox->mctx = NULL;
}

static inline isc_result_t
additionaldata_ox(ARGS_ADDLDATA) {
	UNUSED(rdata);
	UNUSED(add);
	UNUSED(arg);

	REQUIRE(rdata->type == dns_rdatatype_ox);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
digest_ox(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_ox);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

static inline bool
checkowner_ox(ARGS_CHECKOWNER) {
	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	REQUIRE(type == dns_rdatatype_ox);

	return (true);
}

static inline bool
checknames_ox(ARGS_CHECKNAMES) {
	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	REQUIRE(rdata->type == dns_rdatatype_ox);

	return (true);
}

static inline int
casecompare_ox(ARGS_COMPARE) {
	return (compare_ox(rdata1, rdata2));
}

#endif	/* RDATA_GENERIC_DOA_259_C */
