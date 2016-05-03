/*
 * Copyright (c) 2016 MediaTek Inc.
 * Author: PC Chen <pc.chen@mediatek.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _VDEC_VPU_IF_H_
#define _VDEC_VPU_IF_H_

#include "mtk_vpu.h"

/**
 * struct vdec_vpu_inst - VPU instance for video codec
 * @dev	        : platform device of VPU
 * @inst_addr	: VPU decoder instance addr
 * @signaled    : 1 - Host has received ack message from VPU, 0 - not recevie
 * @failure     : VPU execution result status
 * @wq          : Wait queue to wait VPU message ack
 */
struct vdec_vpu_inst {
	enum ipi_id id;
	void *vsi;
	int failure;
	unsigned int inst_addr;
	unsigned int signaled;
	struct mtk_vcodec_ctx *ctx;
	struct platform_device *dev;
	wait_queue_head_t wq;
	ipi_handler_t handler;
};

/*
 * Note these functions are not thread-safe for the same decoder instance.
 * the reason is |signaled|. In vdec_vpu_wait_ack,
 * wait_event_interruptible_timeout waits |signaled| to be 1.
 * Suppose wait_event_interruptible_timeout returns and the execution has not
 * reached line 127. If another thread calls vpu_dec_end,
 * |signaled| will be 1 and wait_event_interruptible_timeout will return
 *  immediately. We enusure thread-safe to add mtk_vdec_lock()/unlock() in
 * vdec_drv_if.c
 *
 */

int vpu_dec_init(struct vdec_vpu_inst *vpu);
int vpu_dec_start(struct vdec_vpu_inst *vpu, unsigned int *data,
		  unsigned int length);
int vpu_dec_end(struct vdec_vpu_inst *vpu);
int vpu_dec_deinit(struct vdec_vpu_inst *vpu);
int vpu_dec_reset(struct vdec_vpu_inst *vpu);
void vpu_dec_ipi_handler(void *data, unsigned int len, void *priv);

#endif
