/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <linux/stddef.h>

//#include "uet_api_private.h"
#include "uet_pkt_hdr.h"
#include "uet_log.h"
#include "uet_sec.h"
#include "kdf_ctr_cmac_aes.h"
#include "gcm.h"

#define UET_SEC_MAX_SD         8
#define UET_SEC_KEY_SIZE       32
#define UET_SEC_CTR_SIZE       8
#define UET_SEC_SMALL_CTX_SIZE 7
#define UET_SEC_LARGE_CTX_SIZE 23
#define UET_SEC_IV_SIZE        12

typedef enum {
	UET_SEC_ALG_NONE        = 0,
	UET_SEC_ALG_AES_GCM_256 = 1,
} uet_sec_alg_t;

typedef enum {
	UET_SEC_MODE_NONE    = 0,
	UET_SEC_MODE_DIRECT  = 1,
	UET_SEC_MODE_CLUSTER = 2,
	UET_SEC_MODE_SERVER  = 3,
	UET_SEC_MODE_DOMAIN  = 4,
} uet_sec_mode_t;

struct uet_sec_sd {
	bool           enabled;
	uint32_t       sdi;
	uet_sec_mode_t mode;
	bool           use_ssi;
	bool           rekey;
	uint64_t       rekey_mask;
	uint8_t        rekey_shift;
	int16_t        aoff;
	uint16_t       coff;
	uet_sec_alg_t  alg;
	uint8_t        an;
	uint8_t        key[2][32];
};

static struct uet_sec_sd sdkdb[UET_SEC_MAX_SD];

static char *uet_sec_label1 = "UE1";
static char *uet_sec_label2 = "UE2";

void (*uet_gcm_init)(struct gcm_context *ctx);

int (*uet_gcm_auth_decrypt)(struct gcm_context *ctx,
		     size_t length,
		     const uint8_t *iv,
		     size_t iv_len,
		     const uint8_t *aad,
		     size_t aad_len,
		     const uint8_t *tag,
		     size_t tag_len,
		     const uint8_t *input,
		     uint8_t *output);

int (*uet_gcm_crypt_and_tag)(struct gcm_context *ctx,
		      int mode,
		      size_t length,
		      const uint8_t *iv,
		      size_t iv_len,
		      const uint8_t *aad,
		      size_t aad_len,
		      const uint8_t *input,
		      uint8_t *output,
		      size_t tag_len,
		      uint8_t *tag);

int (*uet_gcm_setkey)(struct gcm_context *ctx,
	       const uint8_t *key,
	       uint32_t keybits);

void (*uet_kdf_ctr_cmac_aes)(uint8_t *key,
		      uint32_t keybits,
		      uint32_t ctr_len,
		      uint8_t *label,
		      uint32_t label_len,
		      uint8_t *context,
		      uint32_t context_len,
		      uint8_t *key_out,
		      uint32_t keybits_out);

EXPORT_SYMBOL(uet_gcm_init);
EXPORT_SYMBOL(uet_gcm_auth_decrypt);
EXPORT_SYMBOL(uet_gcm_crypt_and_tag);
EXPORT_SYMBOL(uet_gcm_setkey);

/**************************************************************************/
/* FIXME: Default fields used for the fixed SD... not yet configurable!   */

/* key generation: `dd if=/dev/urandom ibs=32 count=1 | xxd -i -c 8` */

static uint8_t def_key[2][UET_SEC_KEY_SIZE] = {
	{
		0x07, 0xe9, 0x72, 0x49, 0x58, 0xd9, 0xe1, 0xf7,
		0x10, 0xf5, 0x94, 0xe1, 0x8e, 0x11, 0xfd, 0x8d,
		0x4a, 0x35, 0x82, 0xc2, 0x56, 0xcc, 0xfe, 0xcf,
		0xc5, 0xeb, 0x19, 0x02, 0xe5, 0x56, 0xbe, 0xd4,
	},
	{
		0xd4, 0xc3, 0xa2, 0xcf, 0xb3, 0xc1, 0x06, 0x7f,
		0xdd, 0xcf, 0x9f, 0xe2, 0xe1, 0x42, 0x8a, 0x29,
		0xc8, 0xd3, 0x1b, 0xfb, 0x2a, 0x97, 0x02, 0x64,
		0x90, 0x0f, 0x16, 0xdf, 0x7c, 0x36, 0xdb, 0x6f
	},
};

#define DEF_SDI         1
#define DEF_REKEY_MASK  0x00000000FF000000UL
#define DEF_REKEY_SHIFT 24
#define DEF_AOFF        -8 /* AAD includes source IPv4 address */
#define DEF_COFF        16 /* sizeof security header, +4 if using SSI */

static int fep_an = 0;
static uint8_t fep_key[2][UET_SEC_KEY_SIZE] = {
	{
		0xa1, 0xbf, 0x74, 0xac, 0x7f, 0xf2, 0x35, 0x63,
		0xec, 0x59, 0x51, 0xaf, 0x99, 0x62, 0x68, 0xf0,
		0x02, 0xdb, 0x87, 0x82, 0x1c, 0xda, 0xab, 0x47,
		0x1e, 0x99, 0x1b, 0xd9, 0x96, 0xc4, 0xd7, 0xf1
	},
	{
		0x52, 0xf4, 0x95, 0x91, 0x76, 0xcd, 0xa4, 0x57,
		0x20, 0x65, 0xc3, 0x0f, 0xaa, 0x48, 0xeb, 0x01,
		0x5e, 0x62, 0x6e, 0xc8, 0x0b, 0x20, 0x0d, 0xe8,
		0xdb, 0x1f, 0x2f, 0xfb, 0x9d, 0x4a, 0xdc, 0x27
	},
};

/**************************************************************************/

int uet_sec_build_hdr(uint32_t sdi,
		      uint32_t ssi,
		      uint8_t *pkt_buf,
		      int pkt_buf_len,
		      uint8_t *pkt,
		      int pkt_len,
		      uint8_t **new_pkt,
		      int *new_pkt_len)
{
	struct uet_sec_sd *sd;
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	uint64_t tsc;
	uint16_t tnf;
	int copy_len;
	char *client_ssi;

	if ((pkt == NULL) || (pkt_len <= 0) ||
	    (new_pkt == NULL) || (new_pkt_len == NULL)) {
		UET_USP_ERR("invalid args to build security header\n");
		return -EINVAL;
	}

	if (sdi >= UET_SEC_MAX_SD) {
		UET_USP_ERR("invalid SDI %u\n", sdi);
		return -EINVAL;
	}

	sd = &sdkdb[sdi];
	if (!sd->enabled) {
		UET_USP_ERR("SDI %u is not enabled\n", sdi);
		return -EINVAL;
	}

	/* TODO: IPv6 support */
	copy_len = (sizeof(struct ethhdr) + sizeof(struct iphdr));

	/* move the Ethernet and IP headers down */
	if (sd->use_ssi) {
		if ((pkt - sizeof(struct uet_sec_ssi)) < pkt_buf) {
			UET_USP_ERR("no headroom for uet_sec_ssi header\n");
			return -EINVAL;
		}

		*new_pkt     = (pkt - sizeof(struct uet_sec_ssi));
		*new_pkt_len = (pkt_len + sizeof(struct uet_sec_ssi));
		memcpy(*new_pkt, pkt, copy_len);
	} else {
		if ((pkt - sizeof(struct uet_sec)) < pkt_buf) {
			UET_USP_ERR("no headroom for uet_sec header\n");
			return -EINVAL;
		}

		*new_pkt     = (pkt - sizeof(struct uet_sec));
		*new_pkt_len = (pkt_len + sizeof(struct uet_sec));
		memcpy(*new_pkt, pkt, copy_len);
	}

	sec = (struct uet_sec *)(*new_pkt + copy_len);
	sec_ssi = (struct uet_sec_ssi *)sec;

	/* fill in the security header */

	tnf = (uint16_t)((UET_PDS_TYPE_SECURITY << UET_SEC_TYPE_SHIFT) |
			 (UET_HDR_PDS << UET_SEC_NEXT_HDR_SHIFT)       |
			 (UET_SEC_VER_1 << UET_SEC_VER_SHIFT)          |
			 (UET_SEC_ENC_TYPE_AES_GCM_256 <<
			  UET_SEC_ENC_TYPE_SHIFT));
	if (sd->use_ssi)
		tnf |= (uint16_t)(UET_SEC_SP << UET_SEC_SP_SHIFT);

	sec->type_next_flags = htons(tnf);

	if (sd->mode == UET_SEC_MODE_DOMAIN)
		sec->an_sdi = htonl((fep_an << UET_SEC_AN_SHIFT) | sd->sdi);
	else
		sec->an_sdi = htonl((sd->an << UET_SEC_AN_SHIFT) | sd->sdi);

	uet_gettime((uint64_t *)&tsc);

	if (sd->use_ssi) {
		sec_ssi->entropy = *((uint16_t *)(sec_ssi + 1));
		if (sd->mode == UET_SEC_MODE_SERVER) {
			/* for server mode the client SSI is always used */
			if (NULL /* FIXME: getenv(UET_SEC_SERVER) */) {
				client_ssi = NULL /* FIXME: getenv(UET_SEC_CLIENT_SSI) */;
				sec_ssi->ssi = htonl(kstrtoul(client_ssi,
							     10, NULL));
			} else {
				sec_ssi->ssi = htonl(ssi);
			}
		} else {
			sec_ssi->ssi = htonl(ssi);
		}
		sec_ssi->tsc = htonll(tsc);
	} else {
		sec->entropy = *((uint16_t *)(sec + 1));
		sec->tsc = htonll(tsc);
	}

	return 0;
}

int uet_sec_update_hdr_tsc(uint8_t *pkt)
{
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	uint64_t tsc;
	uint16_t tnf;

	/* TODO: IPv6 support */
	sec = (struct uet_sec *)(pkt +
				 sizeof(struct ethhdr) +
				 sizeof(struct iphdr));
	sec_ssi = (struct uet_sec_ssi *)sec;

	tnf = ntohs(sec->type_next_flags);
	if (((tnf & UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT) !=
	     UET_PDS_TYPE_SECURITY) {
		UET_USP_ERR("no security header present\n");
		return -EINVAL;
	}

	uet_gettime((uint64_t *)&tsc);

	if (ntohs(sec->type_next_flags) & UET_SEC_SP_MASK)
		sec_ssi->tsc = htonll(tsc);
	else
		sec->tsc = htonll(tsc);

	return 0;
}

int uet_sec_enc_pkt(uint8_t *pkt_buf,
		    int pkt_buf_len,
		    uint8_t *pkt,
		    int pkt_len,
		    uint8_t **enc_pkt,
		    int *enc_pkt_len)
{
	uint8_t derived_key[UET_SEC_KEY_SIZE];
	uint8_t small_context[UET_SEC_SMALL_CTX_SIZE];
	//uint8_t large_context[UET_SEC_LARGE_CTX_SIZE];
	uint8_t iv[UET_SEC_IV_SIZE];
	uint8_t tag[UET_SEC_TAG_LEN];
	struct gcm_context gcm;
	struct uet_sec_sd *sd;
	struct iphdr *ip;
	uint8_t *sec_hdr, *aad;
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	uint8_t *enc_out;
	uint8_t an;
	uint32_t sdi;
	uint32_t ssi;
	uint64_t tsc;
	uint16_t tnf;
	uint16_t rekey;
	uint32_t tmp_val;
	uint64_t tmp_lval;
	int rc, clrtxt_len;

	/* TODO: IPv6 support */
	ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
	sec_hdr = (pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
	sec = (struct uet_sec *)sec_hdr;
	sec_ssi = (struct uet_sec_ssi *)sec_hdr;

	tnf = ntohs(sec->type_next_flags);
	if (((tnf & UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT) !=
	     UET_PDS_TYPE_SECURITY) {
		UET_USP_ERR("no security header present\n");
		return -EINVAL;
	}

	/* get the sdi/an */
	sdi = ntohl(sec->an_sdi);
	an  = !!(sdi & UET_SEC_AN_MASK);
	sdi = (sdi & UET_SEC_SDI_MASK);

	if (sdi >= UET_SEC_MAX_SD) {
		UET_USP_ERR("invalid SDI %u\n", sdi);
		return -EINVAL;
	}

	sd = &sdkdb[sdi];
	if (!sd->enabled) {
		UET_USP_ERR("SDI %u is not enabled\n", sdi);
		return -EINVAL;
	}

	/* if the SSI is being used, verify it's there in the header */
	if (sd->use_ssi && !(tnf & UET_SEC_SP_MASK)) {
		UET_USP_ERR("security header is missing the SSI\n");
		return -EINVAL;
	}

	/* get the tsc */
	tsc = (sd->use_ssi) ? ntohll(sec_ssi->tsc) : ntohll(sec->tsc);

	/* crypto output is going in the upper half of the pkt_buf */
	enc_out = (pkt_buf + (pkt_buf_len / 2));

	/* make sure we're not going to overrun the cleartext or pkt_buf */
	if ((enc_out < (pkt + pkt_len)) ||
	    ((enc_out + pkt_len + UET_SEC_TAG_LEN) >
	     (pkt_buf + pkt_buf_len))) {
		UET_USP_ERR("pkt buffer not large enough for crypto out\n");
		return -EINVAL;
	}

	/* generate the key needed for encrypting the packet */

	memset(derived_key, 0, sizeof(derived_key));

	rekey = 0;
	if (sd->rekey) {
		rekey = (uint16_t)((tsc & sd->rekey_mask) >> sd->rekey_shift);
		rekey = htons(rekey);
	}

	switch (sd->mode) {
	case UET_SEC_MODE_DIRECT:
		memcpy(derived_key, sd->key[an], UET_SEC_KEY_SIZE);
		break;

	case UET_SEC_MODE_CLUSTER:
		memset(small_context, 0, sizeof(small_context));
		memcpy((small_context + 1), (uint8_t *)&rekey, 2);
		tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ip->saddr;
		memcpy((small_context + 3), (uint8_t *)&tmp_val, 4);

		uet_kdf_ctr_cmac_aes(sd->key[an],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label1,
				 strlen(uet_sec_label1), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KEY_SIZE * 8));
		break;

	case UET_SEC_MODE_SERVER:
		if (!NULL /* FIXME: getenv(UET_SEC_SERVER) */) {
			memcpy(derived_key, sd->key[an], UET_SEC_KEY_SIZE);
			break;
		}

		memset(small_context, 0, sizeof(small_context));
		tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ip->saddr;
		memcpy((small_context + 3), (uint8_t *)&tmp_val, 4);

		uet_kdf_ctr_cmac_aes(sd->key[sd->an],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label1,
				 strlen(uet_sec_label1), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KEY_SIZE * 8));
		break;

	case UET_SEC_MODE_DOMAIN:
		memset(small_context, 0, sizeof(small_context));
		memcpy((small_context + 1), (uint8_t *)&rekey, 2);
		tmp_val = htonl(sdi);
		memcpy((small_context + 3), (uint8_t *)&tmp_val, 4);

		uet_kdf_ctr_cmac_aes(fep_key[an],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label2,
				 strlen(uet_sec_label2), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KEY_SIZE * 8));
		break;

	default:
		UET_USP_ERR("unknown mode\n");
		return -EINVAL;
		break;
	}

	/* encrypt the packet */

	aad = (sec_hdr + sd->aoff); /* likely negative and moves backwards */

	tmp_val = (sd->use_ssi) ? sec_ssi->ssi : htonl(sdi);
	memcpy(iv, (uint8_t *)&tmp_val, 4);
	tmp_lval = htonll(tsc);
	memcpy((iv + 4), (uint8_t *)&tmp_lval, 8);

	clrtxt_len = ((sec_hdr + sd->coff) - pkt);
	memcpy(enc_out, pkt, clrtxt_len);

	uet_gcm_init(&gcm);
	uet_gcm_setkey(&gcm, derived_key, (UET_SEC_KEY_SIZE * 8));
	rc = uet_gcm_crypt_and_tag(&gcm,
			       GCM_ENCRYPT,
			       (pkt_len - clrtxt_len),
			       iv,
			       UET_SEC_IV_SIZE,
			       aad,
			       ((sec_hdr + sd->coff) - aad),
			       (pkt + clrtxt_len),
			       (enc_out + clrtxt_len),
			       UET_SEC_TAG_LEN,
			       tag);
	if (rc != 0) {
		UET_USP_ERR("failed to encrypt packet\n");
		return -EINVAL;
	}

	memcpy((enc_out + pkt_len), tag, UET_SEC_TAG_LEN);

	*enc_pkt = enc_out;
	*enc_pkt_len = (pkt_len + UET_SEC_TAG_LEN);

	return 0;
}

int uet_sec_dec_pkt(uint8_t *pkt,
		    int pkt_len,
		    int *tag_len)
{
	uint8_t derived_key[UET_SEC_KEY_SIZE];
	uint8_t small_context[UET_SEC_SMALL_CTX_SIZE];
	//uint8_t large_context[UET_SEC_LARGE_CTX_SIZE];
	uint8_t iv[UET_SEC_IV_SIZE];
	struct gcm_context gcm;
	struct uet_sec_sd *sd;
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	struct iphdr *ip;
	uint8_t *sec_hdr, *aad;
	uint16_t rekey;
	uint32_t tmp_val;
	uint64_t tmp_lval;
	uint64_t tsc;
	uint8_t an;
	uint32_t sdi;
	uint16_t tnf;
	int rc, clrtxt_len;

	/* TODO: IPv6 support */
	ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
	sec_hdr = (pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
	sec = (struct uet_sec *)sec_hdr;
	sec_ssi = (struct uet_sec_ssi *)sec_hdr;

	tnf = ntohs(sec->type_next_flags);
	if (((tnf & UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT) !=
	     UET_PDS_TYPE_SECURITY) {
		*tag_len = 0;
		return 0;
	}

	BUG_ON(1);

	/* get the sdi/an */
	sdi = ntohl(sec->an_sdi);
	an  = !!(sdi & UET_SEC_AN_MASK);
	sdi = (sdi & UET_SEC_SDI_MASK);

	if (sdi >= UET_SEC_MAX_SD) {
		UET_USP_ERR("invalid SDI %u\n", sdi);
		return -EINVAL;
	}

	sd = &sdkdb[sdi];
	if (!sd->enabled) {
		UET_USP_ERR("SDI %u is not enabled\n", sdi);
		return -EINVAL;
	}

	/* if the SSI is being used, verify it's there in the header */
	if (sd->use_ssi && !(tnf & UET_SEC_SP_MASK)) {
		UET_USP_ERR("security header is missing the SSI\n");
		return -EINVAL;
	}

	/* get the tsc */
	tsc = (sd->use_ssi) ? ntohll(sec_ssi->tsc) : ntohll(sec->tsc);

	/* generate the key needed for encrypting the packet */

	memset(derived_key, 0, sizeof(derived_key));

	rekey = 0;
	if (sd->rekey) {
		rekey = (uint16_t)((tsc & sd->rekey_mask) >> sd->rekey_shift);
		rekey = htons(rekey);
	}

	switch (sd->mode) {
	case UET_SEC_MODE_DIRECT:
		memcpy(derived_key, sd->key[an], UET_SEC_KEY_SIZE);
		break;

	case UET_SEC_MODE_CLUSTER:
		memset(small_context, 0, sizeof(small_context));
		memcpy((small_context + 1), (uint8_t *)&rekey, 2);
		tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ip->saddr;
		memcpy((small_context + 3), (uint8_t *)&tmp_val, 4);

		uet_kdf_ctr_cmac_aes(sd->key[an],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label1,
				 strlen(uet_sec_label1), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KEY_SIZE * 8));
		break;

	case UET_SEC_MODE_SERVER:
		if (!NULL /* FIXME: getenv(UET_SEC_SERVER) */) {
			memcpy(derived_key, sd->key[an], UET_SEC_KEY_SIZE);
			break;
		}

		memset(small_context, 0, sizeof(small_context));
		tmp_val = (sd->use_ssi) ? sec_ssi->ssi : ip->saddr;
		memcpy((small_context + 3), (uint8_t *)&tmp_val, 4);

		uet_kdf_ctr_cmac_aes(sd->key[sd->an],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label1,
				 strlen(uet_sec_label1), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KEY_SIZE * 8));
		break;

	case UET_SEC_MODE_DOMAIN:
		memset(small_context, 0, sizeof(small_context));
		memcpy((small_context + 1), (uint8_t *)&rekey, 2);
		tmp_val = htonl(sdi);
		memcpy((small_context + 3), (uint8_t *)&tmp_val, 4);

		uet_kdf_ctr_cmac_aes(fep_key[an],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label2,
				 strlen(uet_sec_label2), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KEY_SIZE * 8));
		break;

	default:
		UET_USP_ERR("unknown mode\n");
		return -EINVAL;
		break;
	}

	/* decrypt the packet */

	aad = (sec_hdr + sd->aoff); /* likely negative and moves backwards */

	tmp_val = (sd->use_ssi) ? sec_ssi->ssi : htonl(sdi);
	memcpy(iv, (uint8_t *)&tmp_val, 4);
	tmp_lval = htonll(tsc);
	memcpy((iv + 4), (uint8_t *)&tmp_lval, 8);

	clrtxt_len = ((sec_hdr + sd->coff) - pkt);

	uet_gcm_init(&gcm);
	uet_gcm_setkey(&gcm, derived_key, (UET_SEC_KEY_SIZE * 8));
	rc = uet_gcm_auth_decrypt(&gcm,
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
		UET_USP_ERR("failed to decrypt packet\n");
		return -EINVAL;
	}

	*tag_len = UET_SEC_TAG_LEN;

	return 0;
}
EXPORT_SYMBOL(uet_sec_dec_pkt);

static int uet_sec_init_sd(uint32_t sdi,
			   uet_sec_mode_t mode,
			   bool use_ssi,
			   bool rekey)
{
	uint8_t derived_key[UET_SEC_KEY_SIZE];
	uint8_t small_context[UET_SEC_SMALL_CTX_SIZE];
	//uint8_t large_context[UET_SEC_LARGE_CTX_SIZE];
	struct uet_sec_sd *sd;
	char *client_ssi;
	uint32_t tmp_val;

	if (sdi >= UET_SEC_MAX_SD) {
		UET_USP_ERR("invalid SDI %u\n", sdi);
		return -EINVAL;
	}

	sd = &sdkdb[sdi];
	memset(sd, 0, sizeof(*sd));

	sd->enabled     = true;
	sd->sdi         = sdi;
	sd->mode        = mode;
	sd->use_ssi     = use_ssi;
	sd->rekey       = rekey;
	sd->rekey_mask  = DEF_REKEY_MASK;
	sd->rekey_shift = DEF_REKEY_SHIFT;
	sd->aoff        = DEF_AOFF;
	sd->coff        = (use_ssi) ? (DEF_COFF + 4) : DEF_COFF;
	sd->alg         = UET_SEC_ALG_AES_GCM_256;
	sd->an          = 0;
	memcpy(sd->key, def_key, sizeof(def_key));

	/* for client side of server mode, do KDFs now */
	if ((mode == UET_SEC_MODE_SERVER) && !NULL /* FIXME: getenv(UET_SEC_SERVER) */) {
		/* FIXME: support both SSI and source IP for server mode */
		if (!NULL /* FIXME: getenv(UET_SEC_SSI) */) {
			UET_USP_ERR("server mode requires SSI\n");
			memset(sd, 0, sizeof(*sd));
			return -EINVAL;
		}

		memset(small_context, 0, sizeof(small_context));
		client_ssi = NULL /* FIXME: getenv(UET_SEC_SSI) */;
		tmp_val = htonl(kstrtoul(client_ssi, 10, NULL));
		memcpy((small_context + 3), (uint8_t *)&tmp_val, 4);

		uet_kdf_ctr_cmac_aes(sd->key[0],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label1,
				 strlen(uet_sec_label1), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KEY_SIZE * 8));

		memcpy(sd->key[0], derived_key, UET_SEC_KEY_SIZE);

		uet_kdf_ctr_cmac_aes(sd->key[1],
				 (UET_SEC_KEY_SIZE * 8),
				 UET_SEC_CTR_SIZE,
				 (uint8_t *)uet_sec_label1,
				 strlen(uet_sec_label1), /* ignore delimiter */
				 small_context,
				 UET_SEC_SMALL_CTX_SIZE,
				 derived_key,
				 (UET_SEC_KEY_SIZE * 8));

		memcpy(sd->key[1], derived_key, UET_SEC_KEY_SIZE);
	}

	return 0;
}

int uet_sec_init(void)
{
	char *sec, *sec_mode, *sec_ssi;
	int i, rc;

	memset(sdkdb, 0, sizeof(sdkdb));

	for (i = 0; i < UET_SEC_MAX_SD; i++)
		sdkdb[i].enabled = false;

	sec_mode = NULL /* FIXME: getenv(UET_SEC_MODE) */;
	sec_ssi  = NULL /* FIXME: getenv(UET_SEC_SSI) */;

	if (sec_mode == NULL)
		return 0;

	/* FIXME: Only using SDI=0x1 AN=0x0 for now... */

	if ((sec_mode == NULL) || (strcmp(sec_mode, "direct") == 0)) {

		rc = uet_sec_init_sd(DEF_SDI, UET_SEC_MODE_DIRECT,
				     (sec_ssi != NULL), false);

	} else if (strcmp(sec_mode, "cluster") == 0) {

		rc = uet_sec_init_sd(DEF_SDI, UET_SEC_MODE_CLUSTER,
				     (sec_ssi != NULL), true);

	} else if (strcmp(sec_mode, "server") == 0) {

		if (sec_ssi == NULL) {
			UET_USP_ERR("UET_SEC_SSI required for server mode");
			return -EINVAL;
		}

		if (NULL /* FIXME: getenv(UET_SEC_SERVER) */ && !NULL /* FIXME: getenv(UET_SEC_CLIENT_SSI) */) {
			UET_USP_ERR("UET_SEC_CLIENT_SSI required on server "
				    "for server mode");
			return -EINVAL;
		}

		rc = uet_sec_init_sd(DEF_SDI, UET_SEC_MODE_SERVER,
				     true, false);

	} else if (strcmp(sec_mode, "domain") == 0) {

		rc = uet_sec_init_sd(DEF_SDI, UET_SEC_MODE_DOMAIN,
				     (sec_ssi != NULL), true);

	} else {

		UET_USP_ERR("invalid UET_SEC_MODE environment variable");
		return -EINVAL;

	}

	return rc;
}

