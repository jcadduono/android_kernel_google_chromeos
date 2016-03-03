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


#ifndef __MTK_MDP_IPI_H__
#define __MTK_MDP_IPI_H__

#define MTK_MDP_MAX_CTX		14

enum mdp_ipi_msgid {
	AP_MDP_INIT		= 0xD000,
	AP_MDP_DEINIT		= 0xD001,
	AP_MDP_PROCESS		= 0xD002,

	VPU_MDP_INIT_ACK	= 0xE000,
	VPU_MDP_DEINIT_ACK	= 0xE001,
	VPU_MDP_PROCESS_ACK	= 0xE002
};

enum mdp_ipi_msg_status {
	MDP_IPI_MSG_STATUS_OK	= 0,
	MDP_IPI_MSG_STATUS_FAIL	= -1,
	MDP_IPI_MSG_TIMEOUT	= -2
};

#pragma pack(push, 4)

struct mdp_ipi_init {
	uint32_t msg_id;
	uint32_t ipi_id;
	uint64_t mdp_priv;
};

struct mdp_ipi_deinit {
	uint32_t msg_id;
	uint32_t ipi_id;
	uint32_t h_drv;
	uint64_t mdp_priv;
};

struct mdp_ipi_config {
	uint32_t msg_id;
	uint32_t ipi_id;
	uint32_t h_drv;
	uint64_t mdp_priv;
};

struct mdp_src_config {
	int32_t x;
	int32_t y;
	int32_t w;
	int32_t h;
	int32_t w_stride;
	int32_t h_stride;
	int32_t crop_x;
	int32_t crop_y;
	int32_t crop_w;
	int32_t crop_h;
	int32_t format;
};

struct mdp_src_buffer {
	uint64_t addr_mva[3];
	int32_t plane_size[3];
	int32_t plane_num;
};

struct mdp_dst_config {
	int32_t x;
	int32_t y;
	int32_t w;
	int32_t h;
	int32_t w_stride;
	int32_t h_stride;
	int32_t crop_x;
	int32_t crop_y;
	int32_t crop_w;
	int32_t crop_h;
	int32_t format;
};

struct mdp_dst_buffer {
	uint64_t addr_mva[3];
	int32_t plane_size[3];
	int32_t plane_num;
};

struct mdp_config_misc {
	int32_t orientation; /* 0, 90, 180, 270 */
	int32_t hflip;
	int32_t vflip;
	int32_t alpha; /* global alpha */
};

struct mdp_process_param {
	struct mdp_src_config src_config;
	struct mdp_src_buffer src_buffer;
	struct mdp_dst_config dst_config;
	struct mdp_dst_buffer dst_buffer;
	struct mdp_config_misc misc;
	uint32_t h_drv;
	uint64_t mdp_priv;
};

struct mdp_ipi_process {
	uint32_t msg_id;
	uint32_t ipi_id;
	uint32_t h_drv;
	uint64_t mdp_priv;
};

struct mdp_ipi_init_ack {
	uint32_t msg_id;
	uint32_t ipi_id;
	int32_t status;
	int32_t reserved;
	uint64_t mdp_priv;
	uint32_t shmem_addr;
	uint32_t h_drv;
};

struct mdp_ipi_comm_ack {
	uint32_t msg_id;
	uint32_t ipi_id;
	int32_t status;
	int32_t reserved;
	uint64_t mdp_priv;
};

#pragma pack(pop)

#endif /* __MTK_MDP_IPI_H__ */
