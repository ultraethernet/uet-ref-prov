/*
 * Copyright (c) 2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * UET reference device model - the L2 rings
 *
 * Opened at bring-up and processed by the progress thread. The transmit ring
 * is drained straight from its doorbell. Simple and effective for basic L2
 * packets.
 */

#ifndef _UET_DEV_L2_H_
#define _UET_DEV_L2_H_

#include "uet_dev_priv.h"

int uet_dev_l2_open(struct uet_dev *dev);
void uet_dev_l2_close(struct uet_dev *dev);
void uet_dev_l2_poll(struct uet_dev *dev);
void uet_dev_tx_drain_locked(struct uet_dev *dev);

#endif /* _UET_DEV_L2_H_ */

