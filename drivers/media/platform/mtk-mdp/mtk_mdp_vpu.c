/*
 * Copyright (c) 2015 MediaTek Inc.
 * Author: Houlong Wei <houlong.wei@mediatek.com>
 *         Ming Hsiu Tsai <minghsiu.tsai@mediatek.com>
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


#include "mtk_mdp_core.h"
#include "mtk_mdp_vpu.h"
#include "mtk_vpu.h"


static inline struct mtk_mdp_ctx *vpu_to_ctx(struct mtk_mdp_vpu *vpu)
{
	return container_of(vpu, struct mtk_mdp_ctx, vpu);
}

static void mtk_mdp_vpu_ipi_handler(void *data, unsigned int len, void *priv)
{
	unsigned int msg_id = *(unsigned int *)data;
	struct mdp_ipi_comm_ack *msg = (struct mdp_ipi_comm_ack *)data;
	struct mtk_mdp_vpu *vpu = (struct mtk_mdp_vpu *)msg->mdp_priv;

	vpu->failure = msg->status;
	if (msg->status == MDP_IPI_MSG_STATUS_OK) {
		u32 vpu_addr;
		struct mdp_ipi_init_ack *init_msg;
		struct mtk_mdp_ctx *ctx;

		switch (msg_id) {
		case VPU_MDP_INIT_ACK:
			/* mapping VPU address to kernel virtual address */
			init_msg = (struct mdp_ipi_init_ack *)msg;
			vpu_addr = init_msg->shmem_addr;
			vpu->shmem_va = vpu_mapping_dm_addr(vpu->pdev,
							    vpu_addr);
			vpu->param = (struct mdp_process_param *)vpu->shmem_va;
			vpu->param->h_drv = init_msg->h_drv;
			break;
		case VPU_MDP_DEINIT_ACK:
		case VPU_MDP_PROCESS_ACK:
			break;

		default:
			ctx = vpu_to_ctx(vpu);
			dev_err(&ctx->mdp_dev->pdev->dev,
				"handle unknown ipi msg %x\n",
				msg_id);
			break;
		}
	}
}

static int mtk_mdp_vpu_send_msg(void *msg, int len, struct mtk_mdp_vpu *vpu,
				int id)
{
	struct mtk_mdp_ctx *ctx = vpu_to_ctx(vpu);
	int err;

	mutex_lock(&ctx->mdp_dev->vpulock);
	err = vpu_ipi_send(vpu->pdev, (enum ipi_id)id, msg, len);
	if (err != 0) {
		mutex_unlock(&ctx->mdp_dev->vpulock);
		dev_err(&ctx->mdp_dev->pdev->dev,
			"vpu_ipi_send fail status %d\n", err);
		return -EBUSY;
	}

	mutex_unlock(&ctx->mdp_dev->vpulock);

	return MDP_IPI_MSG_STATUS_OK;
}

int mtk_mdp_vpu_register(struct platform_device *pdev)
{
	struct mtk_mdp_dev *mdp = platform_get_drvdata(pdev);
	int err;

	err = vpu_ipi_register(mdp->vpu_dev, IPI_MDP,
			       mtk_mdp_vpu_ipi_handler, "mdp_vpu", NULL);
	if (err != 0) {
		dev_err(&mdp->pdev->dev,
			"vpu_ipi_registration fail status=%d\n",
			err);
		return -EBUSY;
	}

	return 0;
}

int mtk_mdp_vpu_init(struct mtk_mdp_vpu *vpu)
{
	int err;
	struct mdp_ipi_init msg;
	struct mtk_mdp_ctx *ctx = vpu_to_ctx(vpu);

	memset(vpu, 0, sizeof(*vpu));
	vpu->pdev = ctx->mdp_dev->vpu_dev;

	msg.msg_id = AP_MDP_INIT;
	msg.ipi_id = IPI_MDP;
	msg.mdp_priv = (uint64_t)vpu;
	err = mtk_mdp_vpu_send_msg((void *)&msg, sizeof(msg), vpu, msg.ipi_id);
	if (!err && vpu->failure != MDP_IPI_MSG_STATUS_OK)
		err = vpu->failure;

	return err;
}

int mtk_mdp_vpu_deinit(struct mtk_mdp_vpu *vpu)
{
	int err;
	struct mdp_ipi_deinit msg;

	msg.msg_id = AP_MDP_DEINIT;
	msg.ipi_id = IPI_MDP;
	msg.h_drv = vpu->param->h_drv;
	msg.mdp_priv = (uint64_t)vpu;
	err = mtk_mdp_vpu_send_msg((void *)&msg, sizeof(msg), vpu, msg.ipi_id);
	if (!err && vpu->failure != MDP_IPI_MSG_STATUS_OK)
		err = vpu->failure;

	return err;
}

int mtk_mdp_vpu_process(struct mtk_mdp_vpu *vpu)
{
	int err;
	struct mdp_ipi_process msg;

	msg.msg_id = AP_MDP_PROCESS;
	msg.ipi_id = IPI_MDP;
	msg.h_drv = vpu->param->h_drv;
	msg.mdp_priv = (uint64_t)vpu;
	err = mtk_mdp_vpu_send_msg((void *)&msg, sizeof(msg), vpu, msg.ipi_id);
	if (!err && vpu->failure != MDP_IPI_MSG_STATUS_OK)
		err = vpu->failure;

	return err;
}

