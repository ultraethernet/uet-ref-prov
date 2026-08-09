/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Transport Security Sublayer (TSS) crypto core: per-packet security header
 * build/refresh and AES-GCM encrypt/decrypt. The secure-domain database
 * (SDKDB), key material, statistics, and the AN key-rotation (SDME stand-in)
 * lives in uet_sec_sd.c.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "uet_pkt_hdr.h"
#include "uet_log.h"
#include "uet_sec.h"
#include "kdf_ctr_cmac_aes.h"
#include "gcm.h"

#define UET_SEC_IV_SIZE 12

#define DEF_AOFF_V4     -12 /* AAD src/dest IPv4 (8) + entropy (4) */
#define DEF_AOFF_V6     -36 /* AAD src/dest IPv6 (32) + entropy (4) */
#define UET_SEC_AOFF(is_ipv6) ((is_ipv6) ? DEF_AOFF_V6 : DEF_AOFF_V4)

int uet_sec_build_hdr(uint32_t sdi,
		      uint32_t ssi,
		      uint8_t *pkt_buf,
		      int pkt_buf_len,
		      uint8_t *pkt,
		      int pkt_len,
		      uint8_t **new_pkt,
		      int *new_pkt_len,
		      bool is_ipv6)
{
	struct uet_sec_sd *sd;
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	uint64_t tsc;
	uint32_t tfs;
	uint8_t tx_an;
	int copy_len;
	char *client_ssi;

	if ((pkt == NULL) || (pkt_len <= 0) ||
	    (new_pkt == NULL) || (new_pkt_len == NULL)) {
		UET_TSS_ERR("invalid args to build security header\n");
		return -EINVAL;
	}

	sd = uet_sec_sd_get(sdi);
	if (sd == NULL) {
		uet_sec_port_stats.out_errored_pkts++;
		UET_TSS_ERR("invalid SDI %u\n", sdi);
		return -EINVAL;
	}

	if (!sd->enabled) {
		uet_sec_port_stats.out_errored_pkts++;
		UET_TSS_ERR("SDI %u is not enabled\n", sdi);
		return -EINVAL;
	}

	/* active AN + association-change bookkeeping */
	tx_an = uet_sec_sd_tx_an(sd);
	uet_sec_sd_tx_rotate(sd);

	copy_len = (sizeof(struct ethhdr) +
		    (is_ipv6 ? sizeof(struct ipv6hdr) :
			       sizeof(struct iphdr)) +
		    sizeof(struct uet_entropy));

	/* move the Ethernet and IP headers down */
	if (sd->use_ssi) {
		if ((pkt - sizeof(struct uet_sec_ssi)) < pkt_buf) {
			UET_TSS_ERR("no headroom for uet_sec_ssi header\n");
			return -EINVAL;
		}

		*new_pkt     = (pkt - sizeof(struct uet_sec_ssi));
		*new_pkt_len = (pkt_len + sizeof(struct uet_sec_ssi));
		memmove(*new_pkt, pkt, copy_len);
	} else {
		if ((pkt - sizeof(struct uet_sec)) < pkt_buf) {
			UET_TSS_ERR("no headroom for uet_sec header\n");
			return -EINVAL;
		}

		*new_pkt     = (pkt - sizeof(struct uet_sec));
		*new_pkt_len = (pkt_len + sizeof(struct uet_sec));
		memmove(*new_pkt, pkt, copy_len);
	}

	sec = (struct uet_sec *)(*new_pkt + copy_len);
	sec_ssi = (struct uet_sec_ssi *)sec;

	/* fill in the security header */

	tfs = (uint32_t)((UET_PDS_TYPE_SECURITY << UET_SEC_TYPE_SHIFT) |
			 ((tx_an << UET_SEC_AN_SHIFT) & UET_SEC_AN_MASK) |
			 ((sd->sdi << UET_SEC_SDI_SHIFT) & UET_SEC_SDI_MASK));
	if (sd->use_ssi)
		tfs |= (uint32_t)(UET_SEC_SP << UET_SEC_SP_SHIFT);

	sec->type_flags_sdi = htonl(tfs);

	/* Invoke (TSC counter) fatal limit. Once the per-SD counter reaches
	 * the threshold it MUST NOT be reused (IV/nonce uniqueness). Drop the
	 * packet and count it.
	 */
	if (sd->tx_counter >= sd->invoke_fatal_threshold) {
		sd->stats.out_invoke_fail++;
		UET_TSS_ERR("SDI %u invoke fatal: TSC counter exhausted\n",
			    sd->sdi);
		return -EINVAL;
	}

	tsc = sd->tx_counter++;

	if (sd->use_ssi) {
		if ((sd->mode == UET_SEC_MODE_SERVER) &&
		    getenv(UET_SEC_SERVER)) {
			client_ssi = getenv(UET_SEC_CLIENT_SSI);
			sec_ssi->ssi = htonl(strtoul(client_ssi, NULL, 10));
		} else {
			sec_ssi->ssi = htonl(ssi);
		}

		sec_ssi->epoch_tsc =
			(uint64_t)(((uint64_t)sd->epoch <<
				    UET_SEC_EPOCH_SHIFT) |
				   (tsc & UET_SEC_TSC_MASK));
		sec_ssi->epoch_tsc = htonll(sec_ssi->epoch_tsc);
	} else {
		sec->epoch_tsc =
			(uint64_t)(((uint64_t)sd->epoch <<
				    UET_SEC_EPOCH_SHIFT) |
				   (tsc & UET_SEC_TSC_MASK));
		sec->epoch_tsc = htonll(sec->epoch_tsc);
	}

	return 0;
}

int uet_sec_update_hdr_tsc(uint8_t *pkt, bool is_ipv6)
{
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	struct uet_sec_sd *sd;
	uint32_t sdi;
	uint64_t tsc;
	uint32_t tfs;

	sec = (struct uet_sec *)(pkt +
				 sizeof(struct ethhdr) +
				 (is_ipv6 ? sizeof(struct ipv6hdr) :
					    sizeof(struct iphdr)) +
				 sizeof(struct uet_entropy));
	sec_ssi = (struct uet_sec_ssi *)sec;

	tfs = ntohl(sec->type_flags_sdi);
	if (((tfs & UET_SEC_TYPE_MASK) >> UET_SEC_TYPE_SHIFT) !=
	     UET_PDS_TYPE_SECURITY) {
		UET_TSS_ERR("no security header present\n");
		return -EINVAL;
	}

	/* get the sdi */
	sdi = ((tfs & UET_SEC_SDI_MASK) >> UET_SEC_SDI_SHIFT);

	/* get the SD to pull the latest epoch */
	sd = uet_sec_sd_get(sdi);
	if (sd == NULL) {
		UET_TSS_ERR("invalid SDI %u\n", sdi);
		return -EINVAL;
	}

	if (!sd->enabled) {
		UET_TSS_ERR("SDI %u is not enabled\n", sdi);
		return -EINVAL;
	}

	/* A retransmit is a fresh frame on the wire. With AN key rotation,
	 * the active AN may have advanced since the original send, so
	 * re-stamp the current AN into the header.
	 */
	if (sd->rotation_enabled) {
		tfs &= ~UET_SEC_AN_MASK;
		tfs |= (((uint32_t)uet_sec_sd_tx_an(sd) << UET_SEC_AN_SHIFT) &
			UET_SEC_AN_MASK);
		sec->type_flags_sdi = htonl(tfs);
	}

	/* association-change bookkeeping */
	uet_sec_sd_tx_rotate(sd);

	if (sd->tx_counter >= sd->invoke_fatal_threshold) {
		sd->stats.out_invoke_fail++;
		UET_TSS_ERR("SDI %u invoke fatal: TSC counter exhausted\n",
			    sd->sdi);
		return -EINVAL;
	}

	/* a retransmit is a new frame on the wire = new counter value */
	tsc = sd->tx_counter++;

	if (tfs & UET_SEC_SP_MASK) {
		sec_ssi->epoch_tsc =
			(uint64_t)(((uint64_t)sd->epoch <<
				    UET_SEC_EPOCH_SHIFT) |
				   (tsc & UET_SEC_TSC_MASK));
		sec_ssi->epoch_tsc = htonll(sec_ssi->epoch_tsc);
	} else {
		sec->epoch_tsc =
			(uint64_t)(((uint64_t)sd->epoch <<
				    UET_SEC_EPOCH_SHIFT) |
				   (tsc & UET_SEC_TSC_MASK));
		sec->epoch_tsc = htonll(sec->epoch_tsc);
	}

	return 0;
}

int uet_sec_enc_pkt(struct uet_instance *uet,
		    uint8_t *pkt_buf,
		    int pkt_buf_len,
		    uint8_t *pkt,
		    int pkt_len,
		    uint8_t **enc_pkt,
		    int *enc_pkt_len,
		    bool is_ipv6)
{
	uint8_t derived_key[UET_SEC_KDF_GEN_SIZE];
	uint8_t small_context[UET_SEC_SMALL_CTX_SIZE];
	uint8_t large_context[UET_SEC_LARGE_CTX_SIZE];
	uint8_t iv[UET_SEC_IV_SIZE];
	uint8_t tag[UET_SEC_TAG_LEN];
	struct gcm_context gcm;
	struct uet_sec_sd *sd;
	struct iphdr *ipv4 = NULL;
	struct ipv6hdr *ipv6 = NULL;
	uint8_t *sec_hdr, *aad;
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	uint8_t *enc_out;
	uint8_t an;
	uint32_t sdi;
	uint32_t ssi;
	uint16_t epoch;
	uint64_t tsc;
	uint64_t counter; // 48b
	uint32_t tfs;
	uint32_t rekey;
	uint32_t tmp_val;
	uint64_t tmp_lval;
	int i, rc, clrtxt_len;
	int fam = UET_SEC_FAM(is_ipv6);

	if (is_ipv6)
		ipv6 = (struct ipv6hdr *)(pkt + sizeof(struct ethhdr));
	else
		ipv4 = (struct iphdr *)(pkt + sizeof(struct ethhdr));

	sec_hdr = (pkt +
		   sizeof(struct ethhdr) +
		   (is_ipv6 ? sizeof(struct ipv6hdr) :
			      sizeof(struct iphdr)) +
		   sizeof(struct uet_entropy));
	sec = (struct uet_sec *)sec_hdr;
	sec_ssi = (struct uet_sec_ssi *)sec_hdr;

	tfs = ntohl(sec->type_flags_sdi);
	if (((tfs & UET_SEC_TYPE_MASK) >> UET_SEC_TYPE_SHIFT) !=
	     UET_PDS_TYPE_SECURITY) {
		UET_TSS_ERR("no security header present\n");
		return -EINVAL;
	}

	/* get the sdi/an */
	sdi = ((tfs & UET_SEC_SDI_MASK) >> UET_SEC_SDI_SHIFT);
	an  = !!(tfs & UET_SEC_AN_MASK);

	sd = uet_sec_sd_get(sdi);
	if (sd == NULL) {
		UET_TSS_ERR("invalid SDI %u\n", sdi);
		return -EINVAL;
	}

	if (!sd->enabled) {
		UET_TSS_ERR("SDI %u is not enabled\n", sdi);
		return -EINVAL;
	}

	/* if the SSI is being used, verify it's there in the header */
	if (sd->use_ssi && !(tfs & UET_SEC_SP_MASK)) {
		UET_TSS_ERR("security header is missing the SSI\n");
		return -EINVAL;
	}

	/* get the epoch/tsc */
	tsc = (sd->use_ssi) ? ntohll(sec_ssi->epoch_tsc)
		            : ntohll(sec->epoch_tsc);
	epoch = htons((uint16_t)((tsc & UET_SEC_EPOCH_MASK) >> UET_SEC_EPOCH_SHIFT));
	counter = ((tsc & UET_SEC_TSC_MASK) >> UET_SEC_TSC_SHIFT);

	/* crypto output is going in the upper half of the pkt_buf */
	enc_out = (pkt_buf + (pkt_buf_len / 2));

	/* make sure we're not going to overrun the cleartext or pkt_buf */
	if ((enc_out < (pkt + pkt_len)) ||
	    ((enc_out + pkt_len) > (pkt_buf + pkt_buf_len))) {
		UET_TSS_ERR("pkt buffer not large enough for crypto out\n");
		return -EINVAL;
	}

	/* generate the key needed for encrypting the packet */

	memset(derived_key, 0, sizeof(derived_key));

	rekey = 0;
	if (sd->rekey) {
		rekey = (uint32_t)((counter & sd->rekey_mask) >> sd->rekey_shift);
		rekey = htonl(rekey);
	}

	switch (sd->mode) {
	case UET_SEC_MODE_DIRECT:
		memcpy(derived_key, uet_sec_sd_key(sd, fam, an),
		       UET_SEC_KEY_SIZE);
		break;

	case UET_SEC_MODE_CLUSTER:
		if (is_ipv6) {
			memset(large_context, 0, sizeof(large_context));
			memcpy((large_context + 4), (uint8_t *)&epoch, 2);
			memcpy((large_context + 6), (uint8_t *)&rekey, 4);
			memcpy((large_context + 10), &ipv6->saddr, 16);

			kdf_ctr_cmac_aes(uet_sec_sd_key(sd, fam, an),
					 (UET_SEC_KEY_SIZE * 8),
					 UET_SEC_CTR_SIZE,
					 (uint8_t *)uet_sec_label1,
					 strlen(uet_sec_label1),
					 large_context,
					 UET_SEC_LARGE_CTX_SIZE,
					 derived_key,
					 (UET_SEC_KDF_GEN_SIZE * 8));
		} else {
			memset(small_context, 0, sizeof(small_context));
			memcpy(small_context, (uint8_t *)&epoch, 2);
			memcpy((small_context + 2), (uint8_t *)&rekey, 4);
			tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ipv4->saddr;
			memcpy((small_context + 6), (uint8_t *)&tmp_val, 4);

			kdf_ctr_cmac_aes(uet_sec_sd_key(sd, fam, an),
					 (UET_SEC_KEY_SIZE * 8),
					 UET_SEC_CTR_SIZE,
					 (uint8_t *)uet_sec_label1,
					 strlen(uet_sec_label1),
					 small_context,
					 UET_SEC_SMALL_CTX_SIZE,
					 derived_key,
					 (UET_SEC_KDF_GEN_SIZE * 8));
		}

		break;

	case UET_SEC_MODE_SERVER:
		/* in client/server mode the client operates in direct mode */
		if (!getenv(UET_SEC_SERVER)) {
			memcpy(derived_key, uet_sec_sd_key(sd, fam, an),
			       UET_SEC_KDF_GEN_SIZE);
			break;
		}

		if (is_ipv6) {
			memset(large_context, 0, sizeof(large_context));
			memcpy((large_context + 4), (uint8_t *)&epoch, 2);
			memcpy((large_context + 10), &ipv6->daddr, 16);

			kdf_ctr_cmac_aes(uet_sec_sd_key(sd, fam, an),
					 (UET_SEC_KEY_SIZE * 8),
					 UET_SEC_CTR_SIZE,
					 (uint8_t *)uet_sec_label2,
					 strlen(uet_sec_label2),
					 large_context,
					 UET_SEC_LARGE_CTX_SIZE,
					 derived_key,
					 (UET_SEC_KDF_GEN_SIZE * 8));
		} else {
			memset(small_context, 0, sizeof(small_context));
			memcpy(small_context, (uint8_t *)&epoch, 2);
			tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ipv4->daddr;
			memcpy((small_context + 6), (uint8_t *)&tmp_val, 4);

			kdf_ctr_cmac_aes(uet_sec_sd_key(sd, fam, an),
					 (UET_SEC_KEY_SIZE * 8),
					 UET_SEC_CTR_SIZE,
					 (uint8_t *)uet_sec_label2,
					 strlen(uet_sec_label2),
					 small_context,
					 UET_SEC_SMALL_CTX_SIZE,
					 derived_key,
					 (UET_SEC_KDF_GEN_SIZE * 8));
		}

		break;

	default:
		UET_TSS_ERR("unknown mode\n");
		return -EINVAL;
		break;
	}

	/* encrypt the packet */

	aad = (sec_hdr + UET_SEC_AOFF(is_ipv6)); /* likely negative, moves back */

	tmp_val = (sd->use_ssi) ? sec_ssi->ssi :
				  (is_ipv6) ? htonl(sdi) : ipv4->saddr;
	memcpy(iv, (uint8_t *)&tmp_val, 4);
	tmp_lval = htonll(tsc);
	memcpy((iv + 4), (uint8_t *)&tmp_lval, 8);

	/* XOR in the IVMASK */
	if (sd->mode != UET_SEC_MODE_DIRECT) {
		for (i = 0; i < UET_SEC_IV_SIZE; i++)
			iv[i] ^= derived_key[UET_SEC_KEY_SIZE + i];
	}

	clrtxt_len = ((sec_hdr + sd->coff) - pkt);
	memcpy(enc_out, pkt, clrtxt_len);

	gcm_init(&gcm);
	gcm_setkey(&gcm, derived_key, (UET_SEC_KEY_SIZE * 8));
	rc = gcm_crypt_and_tag(&gcm,
			       GCM_ENCRYPT,
			       (pkt_len - clrtxt_len - UET_SEC_TAG_LEN),
			       iv,
			       UET_SEC_IV_SIZE,
			       aad,
			       ((sec_hdr + sd->coff) - aad),
			       (pkt + clrtxt_len),
			       (enc_out + clrtxt_len),
			       UET_SEC_TAG_LEN,
			       tag);
	if (rc != 0) {
		UET_TSS_ERR("failed to encrypt packet\n");
		return -EINVAL;
	}

	memcpy((enc_out + pkt_len - UET_SEC_TAG_LEN), tag, UET_SEC_TAG_LEN);

	*enc_pkt = enc_out;
	*enc_pkt_len = pkt_len;

	sd->stats.out_auth_pkts++;

	return 0;
}

int uet_sec_dec_pkt(struct uet_instance *uet,
		    uint8_t *pkt,
		    int pkt_len,
		    int *tag_len)
{
	uint8_t derived_key[UET_SEC_KDF_GEN_SIZE];
	uint8_t small_context[UET_SEC_SMALL_CTX_SIZE];
	uint8_t large_context[UET_SEC_LARGE_CTX_SIZE];
	uint8_t iv[UET_SEC_IV_SIZE];
	struct gcm_context gcm;
	struct uet_sec_sd *sd;
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	struct ethhdr *eth;
	struct iphdr *ipv4 = NULL;
	struct ipv6hdr *ipv6 = NULL;
	uint8_t *sec_hdr, *aad;
	uint32_t rekey;
	uint32_t tmp_val;
	uint64_t tmp_lval;
	uint16_t epoch;
	uint16_t cur_epoch;
	uint64_t tsc;
	uint64_t counter; /* 48b */
	uint16_t pkt_epoch;
	uint16_t age;
	uint8_t an;
	uint32_t sdi;
	uint32_t tfs;
	int i, rc, clrtxt_len;
	int fam;
	bool is_ipv6;

	eth = (struct ethhdr *)pkt;

	if (eth->h_proto == htons(ETH_P_IPV6)) {
		is_ipv6 = true;
	} else if (eth->h_proto == htons(ETH_P_IP)) {
		is_ipv6 = false;
	} else {
		*tag_len = 0;
		return 0;
	}

	fam = UET_SEC_FAM(is_ipv6);

	/* do some preliminary sanity checks */
	if (is_ipv6) {
		ipv6 = (struct ipv6hdr *)(pkt + sizeof(struct ethhdr));
		if ((eth->h_proto != htons(ETH_P_IPV6)) ||
		    (ipv6->nexthdr != uet->uet_ipproto)) {
			*tag_len = 0;
			return 0;
		}
	} else {
		ipv4 = (struct iphdr *)(pkt + sizeof(struct ethhdr));
		if ((eth->h_proto != htons(ETH_P_IP)) ||
		    (ipv4->version != IPVERSION) ||
		    (ipv4->ihl != UET_IPV4_IHL_NO_OPTIONS) ||
		    (ipv4->protocol != uet->uet_ipproto)) {
			*tag_len = 0;
			return 0;
		}
	}

	sec_hdr = (pkt +
		   sizeof(struct ethhdr) +
		   (is_ipv6 ? sizeof(struct ipv6hdr) :
			      sizeof(struct iphdr)) +
		   sizeof(struct uet_entropy));
	sec = (struct uet_sec *)sec_hdr;
	sec_ssi = (struct uet_sec_ssi *)sec_hdr;

	tfs = ntohl(sec->type_flags_sdi);
	if (((tfs & UET_SEC_TYPE_MASK) >> UET_SEC_TYPE_SHIFT) !=
	     UET_PDS_TYPE_SECURITY) {
		uet_sec_port_stats.in_rx_encryption_bypass_pkts++;
		*tag_len = 0;
		return 0;
	}

	/* get the sdi/an */
	sdi = ((tfs & UET_SEC_SDI_MASK) >> UET_SEC_SDI_SHIFT);
	an  = !!(tfs & UET_SEC_AN_MASK);

	sd = uet_sec_sd_get(sdi);
	if (sd == NULL) {
		uet_sec_port_stats.in_errored_pkts++;
		UET_TSS_ERR("invalid SDI %u\n", sdi);
		return -EINVAL;
	}

	if (!sd->enabled) {
		sd->stats.in_invalid_sa++;
		UET_TSS_ERR("SDI %u is not enabled\n", sdi);
		return -EINVAL;
	}

	/* auth-fail latch once tripped, ALL packets on this SD are dropped */
	if (sd->domain_dropping) {
		sd->stats.in_invalid++;
		return -EINVAL;
	}

	/* if the SSI is being used, verify it's there in the header */
	if (sd->use_ssi && !(tfs & UET_SEC_SP_MASK)) {
		sd->stats.in_invalid++;
		UET_TSS_ERR("security header is missing the SSI\n");
		return -EINVAL;
	}

	/* get the epoch/tsc */
	tsc = (sd->use_ssi) ? ntohll(sec_ssi->epoch_tsc)
		            : ntohll(sec->epoch_tsc);
	epoch = htons((uint16_t)((tsc & UET_SEC_EPOCH_MASK) >> UET_SEC_EPOCH_SHIFT));
	counter = ((tsc & UET_SEC_TSC_MASK) >> UET_SEC_TSC_SHIFT);

	/* Epoch-based packet rejection drops packets whose epoch is older
	 * than the current epoch by more than rx_max_epoch_lifetime. The
	 * epoch is only advanced by an SDME on a FEP leave/rejoin (and reset
	 * to 0 on key rotation), so with no SDME here it is static (0). This
	 * path is kept for spec completeness but never rejects (epoch is
	 * always 0).
	 */
	if (sd->epoch_based_rejection) {
		cur_epoch = sd->epoch;

		pkt_epoch = (uint16_t)((tsc & UET_SEC_EPOCH_MASK) >>
				       UET_SEC_EPOCH_SHIFT);
		age = (uint16_t)(cur_epoch - pkt_epoch);

		/* age < 0x8000 => pkt epoch is older (RFC-1982); reject only
		 * if older by more than the lifetime. Same-or-newer value is
		 * accepted.
		 */
		if ((age < 0x8000) && (age > sd->rx_max_epoch_lifetime)) {
			sd->stats.in_late_pkts++;
			UET_TSS_WARN("SDI %u late pkt: epoch %u vs current %u",
				     sd->sdi, pkt_epoch, cur_epoch);
			return -EINVAL;
		}
	}

	/* generate the key needed for decrypting the packet */

	memset(derived_key, 0, sizeof(derived_key));

	rekey = 0;
	if (sd->rekey) {
		rekey = (uint32_t)((counter & sd->rekey_mask) >> sd->rekey_shift);
		rekey = htonl(rekey);
	}

	switch (sd->mode) {
	case UET_SEC_MODE_DIRECT:
		memcpy(derived_key, uet_sec_sd_key(sd, fam, an),
		       UET_SEC_KEY_SIZE);
		break;

	case UET_SEC_MODE_CLUSTER:
		if (is_ipv6) {
			memset(large_context, 0, sizeof(large_context));
			memcpy((large_context + 4), (uint8_t *)&epoch, 2);
			memcpy((large_context + 6), (uint8_t *)&rekey, 4);
			memcpy((large_context + 10), &ipv6->saddr, 16);

			kdf_ctr_cmac_aes(uet_sec_sd_key(sd, fam, an),
					 (UET_SEC_KEY_SIZE * 8),
					 UET_SEC_CTR_SIZE,
					 (uint8_t *)uet_sec_label1,
					 strlen(uet_sec_label1),
					 large_context,
					 UET_SEC_LARGE_CTX_SIZE,
					 derived_key,
					 (UET_SEC_KDF_GEN_SIZE * 8));
		} else {
			memset(small_context, 0, sizeof(small_context));
			memcpy(small_context, (uint8_t *)&epoch, 2);
			memcpy((small_context + 2), (uint8_t *)&rekey, 4);
			tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ipv4->saddr;
			memcpy((small_context + 6), (uint8_t *)&tmp_val, 4);

			kdf_ctr_cmac_aes(uet_sec_sd_key(sd, fam, an),
					 (UET_SEC_KEY_SIZE * 8),
					 UET_SEC_CTR_SIZE,
					 (uint8_t *)uet_sec_label1,
					 strlen(uet_sec_label1),
					 small_context,
					 UET_SEC_SMALL_CTX_SIZE,
					 derived_key,
					 (UET_SEC_KDF_GEN_SIZE * 8));
		}

		break;

	case UET_SEC_MODE_SERVER:
		/* in client/server mode the client operates in direct mode */
		if (!getenv(UET_SEC_SERVER)) {
			memcpy(derived_key, uet_sec_sd_key(sd, fam, an),
			       UET_SEC_KDF_GEN_SIZE);
			break;
		}

		if (is_ipv6) {
			memset(large_context, 0, sizeof(large_context));
			memcpy((large_context + 4), (uint8_t *)&epoch, 2);
			memcpy((large_context + 10), &ipv6->saddr, 16);

			kdf_ctr_cmac_aes(uet_sec_sd_key(sd, fam, an),
					 (UET_SEC_KEY_SIZE * 8),
					 UET_SEC_CTR_SIZE,
					 (uint8_t *)uet_sec_label2,
					 strlen(uet_sec_label2),
					 large_context,
					 UET_SEC_LARGE_CTX_SIZE,
					 derived_key,
					 (UET_SEC_KDF_GEN_SIZE * 8));
		} else {
			memset(small_context, 0, sizeof(small_context));
			memcpy(small_context, (uint8_t *)&epoch, 2);
			tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ipv4->saddr;
			memcpy((small_context + 6), (uint8_t *)&tmp_val, 4);

			kdf_ctr_cmac_aes(uet_sec_sd_key(sd, fam, an),
					 (UET_SEC_KEY_SIZE * 8),
					 UET_SEC_CTR_SIZE,
					 (uint8_t *)uet_sec_label2,
					 strlen(uet_sec_label2),
					 small_context,
					 UET_SEC_SMALL_CTX_SIZE,
					 derived_key,
					 (UET_SEC_KDF_GEN_SIZE * 8));
		}

		break;

	default:
		UET_TSS_ERR("unknown mode\n");
		return -EINVAL;
		break;
	}

	/* decrypt the packet */

	aad = (sec_hdr + UET_SEC_AOFF(is_ipv6)); /* likely negative, moves back */

	tmp_val = (sd->use_ssi) ? sec_ssi->ssi :
				  (is_ipv6) ? htonl(sdi) : ipv4->saddr;
	memcpy(iv, (uint8_t *)&tmp_val, 4);
	tmp_lval = htonll(tsc);
	memcpy((iv + 4), (uint8_t *)&tmp_lval, 8);

	/* XOR in the IVMASK */
	if (sd->mode != UET_SEC_MODE_DIRECT) {
		for (i = 0; i < UET_SEC_IV_SIZE; i++)
			iv[i] ^= derived_key[UET_SEC_KEY_SIZE + i];
	}

	clrtxt_len = ((sec_hdr + sd->coff) - pkt);

	gcm_init(&gcm);
	gcm_setkey(&gcm, derived_key, (UET_SEC_KEY_SIZE * 8));
	rc = gcm_auth_decrypt(&gcm,
			      (pkt_len - clrtxt_len - UET_SEC_TAG_LEN),
			      iv,
			      UET_SEC_IV_SIZE,
			      aad,
			      ((sec_hdr + sd->coff) - aad),
			      (pkt + pkt_len - UET_SEC_TAG_LEN),
			      UET_SEC_TAG_LEN,
			      (pkt + clrtxt_len),
			      (pkt + clrtxt_len));
	if (rc != 0) {
		sd->stats.in_auth_fail_pkts++;
		UET_TSS_ERR("failed to decrypt packet\n");
		/* Auth-fail threshold once exceeded, latch the domain into
		 * dropping ALL packets for this SD!
		 */
		if (sd->stats.in_auth_fail_pkts > sd->auth_fail_threshold) {
			sd->domain_dropping = true;
			UET_TSS_ERR("SDI %u authFail: threshold exceeded, "
				    "dropping all domain packets\n", sd->sdi);
		}
		return -EINVAL;
	}

	sd->stats.in_auth_pkts++;

	*tag_len = UET_SEC_TAG_LEN;

	return 0;
}
