// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rdma/fi_errno.h>
#include <rdma/fabric.h>

#include "uet_api.h"

static int expect_rc(const char *operation, int rc, int expected)
{
	if (rc == expected)
		return 0;

	fprintf(stderr, "%s returned %d, expected %d\n",
		operation, rc, expected);
	return -1;
}

static int test_failed_initialize(const char *ifname)
{
	uet_handle_t uet = NULL;
	int rc;

	if (setenv("UET_IFNAME", "uetbad0", 1)) {
		perror("setenv");
		return -1;
	}

	rc = uet_initialize(&uet);
	if (rc == FI_SUCCESS) {
		fprintf(stderr,
			"initialization accepted a missing interface\n");
		uet_finalize(uet);
		return -1;
	}

	if (setenv("UET_IFNAME", ifname, 1)) {
		perror("setenv");
		return -1;
	}
	return 0;
}

static int test_domain_lifecycle(void)
{
	struct fid_fabric fabric = { 0 };
	struct fid_domain fid_domain[2] = { 0 };
	struct fid_ep fid_ep[2] = { 0 };
	uet_domain_handle_t domain[2] = { NULL, NULL };
	uet_ep_handle_t ep = NULL;
	uet_handle_t uet = NULL;
	struct fi_info *info = NULL;
	int rc;

	rc = uet_initialize(&uet);
	if (expect_rc("uet_initialize", rc, FI_SUCCESS))
		return -1;

	rc = uet_getinfo(uet, NULL, NULL, &info);
	if (expect_rc("uet_getinfo", rc, FI_SUCCESS))
		return -1;

	for (size_t i = 0; i < 2; i++) {
		rc = uet_domain(uet, &fabric, info, &fid_domain[i], NULL,
				NULL, NULL, &domain[i]);
		if (expect_rc("uet_domain", rc, FI_SUCCESS))
			return -1;
	}

	rc = uet_endpoint(domain[0], info, &fid_ep[0], NULL, &ep);
	if (expect_rc("uet_endpoint(first domain)", rc, FI_SUCCESS))
		return -1;

	rc = uet_domain_close(domain[0]);
	if (expect_rc("uet_domain_close(busy)", rc, -FI_EBUSY))
		return -1;

	/* A rejected domain close must not tear down the shared PDS state. */
	rc = uet_ep_close(ep);
	if (expect_rc("uet_ep_close(first domain)", rc, FI_SUCCESS))
		return -1;
	ep = NULL;

	rc = uet_domain_close(domain[0]);
	if (expect_rc("uet_domain_close(first domain)", rc, FI_SUCCESS))
		return -1;
	domain[0] = NULL;

	/* Closing one domain must leave the instance usable by another domain. */
	rc = uet_endpoint(domain[1], info, &fid_ep[1], NULL, &ep);
	if (expect_rc("uet_endpoint(second domain)", rc, FI_SUCCESS))
		return -1;

	rc = uet_ep_close(ep);
	if (expect_rc("uet_ep_close(second domain)", rc, FI_SUCCESS))
		return -1;
	ep = NULL;

	rc = uet_domain_close(domain[1]);
	if (expect_rc("uet_domain_close(second domain)", rc, FI_SUCCESS))
		return -1;
	domain[1] = NULL;

	rc = uet_finalize(uet);
	if (expect_rc("uet_finalize", rc, FI_SUCCESS))
		return -1;
	uet = NULL;

	fi_freeinfo(info);
	return 0;
}

int main(int argc, char **argv)
{
	const char *pds;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <interface>\n", argv[0]);
		return EXIT_FAILURE;
	}

	pds = getenv("UET_PDS");
	if (!pds || (strcmp(pds, "pds") && strcmp(pds, "sng"))) {
		fprintf(stderr, "UET_PDS must be pds or sng\n");
		return EXIT_FAILURE;
	}

	if (test_failed_initialize(argv[1]) || test_domain_lifecycle())
		return EXIT_FAILURE;

	printf("PDS instance lifecycle test passed (%s)\n", pds);
	return EXIT_SUCCESS;
}
