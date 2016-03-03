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
#include "mtk_mdp_type.h"


int mtk_mdp_map_color_format(int v4l2_format)
{
	switch (v4l2_format) {
	case V4L2_PIX_FMT_NV12M:
	case V4L2_PIX_FMT_NV12:
		return DP_COLOR_NV12;
	case V4L2_PIX_FMT_MT21:
		return DP_COLOR_420_MT21;
	case V4L2_PIX_FMT_YUV420M:
	case V4L2_PIX_FMT_YUV420:
		return DP_COLOR_I420;
	}

	return DP_COLOR_UNKNOWN;
}

void mtk_mdp_hw_set_input_addr(struct mtk_mdp_ctx *ctx,
			       struct mtk_mdp_addr *addr)
{
	struct mdp_src_buffer *src_buf = &ctx->vpu.param->src_buffer;

	src_buf->addr_mva[0] = (uint64_t)addr->y;
	src_buf->addr_mva[1] = (uint64_t)addr->cb;
	src_buf->addr_mva[2] = (uint64_t)addr->cr;
}

void mtk_mdp_hw_set_output_addr(struct mtk_mdp_ctx *ctx,
				struct mtk_mdp_addr *addr)
{
	struct mdp_dst_buffer *dst_buf = &ctx->vpu.param->dst_buffer;

	dst_buf->addr_mva[0] = (uint64_t)addr->y;
	dst_buf->addr_mva[1] = (uint64_t)addr->cb;
	dst_buf->addr_mva[2] = (uint64_t)addr->cr;
}

void mtk_mdp_hw_set_in_size(struct mtk_mdp_ctx *ctx)
{
	struct mtk_mdp_frame *frame = &ctx->s_frame;
	struct mdp_src_config *config = &ctx->vpu.param->src_config;

	/* Set input pixel offset */
	config->crop_x = frame->crop.left;
	config->crop_y = frame->crop.top;

	/* Set input cropped size */
	config->crop_w = frame->crop.width;
	config->crop_h = frame->crop.height;

	/* Set input original size */
	config->x = 0;
	config->y = 0;
	config->w = frame->f_width;
	config->h = frame->f_height;
}

void mtk_mdp_hw_set_in_image_format(struct mtk_mdp_ctx *ctx)
{
	unsigned int i;
	struct mtk_mdp_frame *frame = &ctx->s_frame;
	struct mdp_src_config *config = &ctx->vpu.param->src_config;
	struct mdp_src_buffer *src_buf = &ctx->vpu.param->src_buffer;

	src_buf->plane_num = frame->fmt->num_planes;
	config->format = mtk_mdp_map_color_format(frame->fmt->pixelformat);
	config->w_stride = 0; /* MDP will calculate it by color format. */
	config->h_stride = 0; /* MDP will calculate it by color format. */

	for (i = 0; i < src_buf->plane_num; i++)
		src_buf->plane_size[i] = frame->payload[i];
}

void mtk_mdp_hw_set_out_size(struct mtk_mdp_ctx *ctx)
{
	struct mtk_mdp_frame *frame = &ctx->d_frame;
	struct mdp_dst_config *config = &ctx->vpu.param->dst_config;

	config->crop_x = frame->crop.left;
	config->crop_y = frame->crop.top;
	config->crop_w = frame->crop.width;
	config->crop_h = frame->crop.height;
	config->x = 0;
	config->y = 0;
	config->w = frame->f_width;
	config->h = frame->f_height;
}

void mtk_mdp_hw_set_out_image_format(struct mtk_mdp_ctx *ctx)
{
	unsigned int i;
	struct mtk_mdp_frame *frame = &ctx->d_frame;
	struct mdp_dst_config *config = &ctx->vpu.param->dst_config;
	struct mdp_dst_buffer *dst_buf = &ctx->vpu.param->dst_buffer;

	dst_buf->plane_num = frame->fmt->num_planes;
	config->format = mtk_mdp_map_color_format(frame->fmt->pixelformat);
	config->w_stride = 0; /* MDP will calculate it by color format. */
	config->h_stride = 0; /* MDP will calculate it by color format. */
	for (i = 0; i < dst_buf->plane_num; i++)
		dst_buf->plane_size[i] = frame->payload[i];
}

void mtk_mdp_hw_set_rotation(struct mtk_mdp_ctx *ctx)
{
	struct mdp_config_misc *misc = &ctx->vpu.param->misc;

	misc->orientation = ctx->ctrls.rotate->val;
	misc->hflip = ctx->ctrls.hflip->val;
	misc->vflip = ctx->ctrls.vflip->val;
}

void mtk_mdp_hw_set_global_alpha(struct mtk_mdp_ctx *ctx)
{
	struct mdp_config_misc *misc = &ctx->vpu.param->misc;

	misc->alpha = ctx->ctrls.global_alpha->val;
}

int mtk_mdp_hw_set_sfr_update(struct mtk_mdp_ctx *ctx)
{
	return mtk_mdp_vpu_process(&ctx->vpu);
}

