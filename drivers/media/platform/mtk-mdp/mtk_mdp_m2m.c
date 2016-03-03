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


#include <linux/bug.h>
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <media/v4l2-ioctl.h>

#include "mtk_mdp_core.h"
#include "mtk_vpu.h"


static inline struct mtk_mdp_ctx *fh_to_ctx(struct v4l2_fh *fh)
{
	return container_of(fh, struct mtk_mdp_ctx, fh);
}

static void mtk_mdp_ctx_state_lock_set(u32 state, struct mtk_mdp_ctx *ctx)
{
	mutex_lock(&ctx->slock);
	ctx->state |= state;
	mutex_unlock(&ctx->slock);
}

static void mtk_mdp_ctx_state_lock_clear(u32 state, struct mtk_mdp_ctx *ctx)
{
	mutex_lock(&ctx->slock);
	ctx->state &= ~state;
	mutex_unlock(&ctx->slock);
}

static void mtk_mdp_ctx_lock(struct vb2_queue *vq)
{
	struct mtk_mdp_ctx *ctx = vb2_get_drv_priv(vq);

	mutex_lock(&ctx->qlock);
}

static void mtk_mdp_ctx_unlock(struct vb2_queue *vq)
{
	struct mtk_mdp_ctx *ctx = vb2_get_drv_priv(vq);

	mutex_unlock(&ctx->qlock);
}

static bool mtk_mdp_ctx_state_is_set(u32 mask, struct mtk_mdp_ctx *ctx)
{
	bool ret;

	mutex_lock(&ctx->slock);
	ret = (ctx->state & mask) == mask;
	mutex_unlock(&ctx->slock);
	return ret;
}

static int mtk_mdp_ctx_stop_req(struct mtk_mdp_ctx *ctx)
{
	struct mtk_mdp_ctx *curr_ctx;
	struct mtk_mdp_dev *mdp = ctx->mdp_dev;
	int ret;

	curr_ctx = v4l2_m2m_get_curr_priv(mdp->m2m_dev);
	if (!test_bit(MTK_MDP_M2M_PEND, &mdp->state) || (curr_ctx != ctx))
		return 0;

	mtk_mdp_ctx_state_lock_set(MTK_MDP_CTX_STOP_REQ, ctx);
	ret = wait_event_timeout(mdp->irq_queue,
			!mtk_mdp_ctx_state_is_set(MTK_MDP_CTX_STOP_REQ, ctx),
			MTK_MDP_SHUTDOWN_TIMEOUT);

	return ret == 0 ? -ETIMEDOUT : ret;
}

struct mtk_mdp_frame *mtk_mdp_ctx_get_frame(struct mtk_mdp_ctx *ctx,
					    enum v4l2_buf_type type)
{
	struct mtk_mdp_frame *frame;

	if (V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE == type) {
		frame = &ctx->s_frame;
	} else if (V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE == type) {
		frame = &ctx->d_frame;
	} else {
		dev_err(&ctx->mdp_dev->pdev->dev,
			"Wrong buffer/video queue type %d",
			type);
		return ERR_PTR(-EINVAL);
	}

	return frame;
}

static void mtk_mdp_ctx_abort(struct mtk_mdp_ctx *ctx)
{
	int ret;

	ret = mtk_mdp_ctx_stop_req(ctx);
	if ((ret == -ETIMEDOUT) || (ctx->state & MTK_MDP_CTX_ABORT)) {
		mtk_mdp_ctx_state_lock_clear(MTK_MDP_CTX_STOP_REQ |
					     MTK_MDP_CTX_ABORT, ctx);
		mtk_mdp_m2m_job_finish(ctx, VB2_BUF_STATE_ERROR);
	}
}

void mtk_mdp_ctx_error(struct mtk_mdp_ctx *ctx)
{
	mtk_mdp_ctx_state_lock_set(MTK_MDP_CTX_ERROR, ctx);
}

static int mtk_mdp_m2m_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct mtk_mdp_ctx *ctx = q->drv_priv;
	int ret;

	ret = pm_runtime_get_sync(&ctx->mdp_dev->pdev->dev);
	return ret > 0 ? 0 : ret;
}

static void *mtk_mdp_m2m_buf_remove(struct mtk_mdp_ctx *ctx,
				    enum v4l2_buf_type type)
{
	if (V4L2_TYPE_IS_OUTPUT(type))
		return v4l2_m2m_src_buf_remove(ctx->m2m_ctx);
	else
		return v4l2_m2m_dst_buf_remove(ctx->m2m_ctx);
}

static void mtk_mdp_m2m_stop_streaming(struct vb2_queue *q)
{
	struct mtk_mdp_ctx *ctx = q->drv_priv;
	struct vb2_buffer *vb;

	mtk_mdp_ctx_abort(ctx);
	vb = mtk_mdp_m2m_buf_remove(ctx, q->type);
	while (vb != NULL) {
		v4l2_m2m_buf_done(vb, VB2_BUF_STATE_ERROR);
		vb = mtk_mdp_m2m_buf_remove(ctx, q->type);
	}

	pm_runtime_put(&ctx->mdp_dev->pdev->dev);
}

void mtk_mdp_m2m_job_finish(struct mtk_mdp_ctx *ctx, int vb_state)
{
	struct vb2_buffer *src_vb, *dst_vb;

	if (!ctx || !ctx->m2m_ctx)
		return;

	src_vb = v4l2_m2m_src_buf_remove(ctx->m2m_ctx);
	dst_vb = v4l2_m2m_dst_buf_remove(ctx->m2m_ctx);

	if (src_vb && dst_vb) {
		dst_vb->v4l2_buf.timestamp = src_vb->v4l2_buf.timestamp;
		dst_vb->v4l2_buf.timecode = src_vb->v4l2_buf.timecode;
		dst_vb->v4l2_buf.flags &= ~V4L2_BUF_FLAG_TSTAMP_SRC_MASK;
		dst_vb->v4l2_buf.flags |= src_vb->v4l2_buf.flags &
					  V4L2_BUF_FLAG_TSTAMP_SRC_MASK;

		v4l2_m2m_buf_done(src_vb, vb_state);
		v4l2_m2m_buf_done(dst_vb, vb_state);

		v4l2_m2m_job_finish(ctx->mdp_dev->m2m_dev,
				    ctx->m2m_ctx);
	}
}

static void mtk_mdp_m2m_job_abort(void *priv)
{
	mtk_mdp_ctx_abort((struct mtk_mdp_ctx *)priv);
}

static int mtk_mdp_m2m_get_bufs(struct mtk_mdp_ctx *ctx)
{
	struct mtk_mdp_frame *s_frame, *d_frame;
	struct vb2_buffer *src_vb, *dst_vb;
	int ret;

	s_frame = &ctx->s_frame;
	d_frame = &ctx->d_frame;

	src_vb = v4l2_m2m_next_src_buf(ctx->m2m_ctx);
	ret = mtk_mdp_prepare_addr(ctx, src_vb, s_frame, &s_frame->addr);
	if (ret)
		return ret;

	dst_vb = v4l2_m2m_next_dst_buf(ctx->m2m_ctx);
	ret = mtk_mdp_prepare_addr(ctx, dst_vb, d_frame, &d_frame->addr);
	if (ret)
		return ret;

	dst_vb->v4l2_buf.timestamp = src_vb->v4l2_buf.timestamp;

	return 0;
}

static void mtk_mdp_m2m_worker(struct work_struct *work)
{
	struct mtk_mdp_ctx *ctx =
				container_of(work, struct mtk_mdp_ctx, work);
	struct mtk_mdp_dev *mdp;
	enum vb2_buffer_state buf_state = VB2_BUF_STATE_ERROR;
	int ret;

	mdp = ctx->mdp_dev;
	set_bit(MTK_MDP_M2M_PEND, &mdp->state);

	if (ctx->state & MTK_MDP_CTX_ERROR) {
		dev_err(&mdp->pdev->dev, "ctx is in error state");
		goto worker_end;
	}

	if (ctx->state & MTK_MDP_CTX_STOP_REQ) {
		ctx->state &= ~MTK_MDP_CTX_STOP_REQ;
		ctx->state |= MTK_MDP_CTX_ABORT;
		wake_up(&mdp->irq_queue);
		goto worker_end;
	}

	ret = mtk_mdp_m2m_get_bufs(ctx);
	if (ret) {
		dev_err(&mdp->pdev->dev, "Wrong buffer address");
		goto worker_end;
	}

	mtk_mdp_hw_set_input_addr(ctx, &ctx->s_frame.addr);
	mtk_mdp_hw_set_output_addr(ctx, &ctx->d_frame.addr);

	mtk_mdp_hw_set_in_size(ctx);
	mtk_mdp_hw_set_in_image_format(ctx);

	mtk_mdp_hw_set_out_size(ctx);
	mtk_mdp_hw_set_out_image_format(ctx);

	mtk_mdp_hw_set_rotation(ctx);
	mtk_mdp_hw_set_global_alpha(ctx);

	ret = mtk_mdp_hw_set_sfr_update(ctx);
	if (ret) {
		dev_err(&mdp->pdev->dev, "process failed");
		goto worker_end;
	}

	buf_state = VB2_BUF_STATE_DONE;

worker_end:
	ctx->state &= ~MTK_MDP_PARAMS;
	mtk_mdp_process_done(mdp, buf_state);
}

static void mtk_mdp_m2m_device_run(void *priv)
{
	struct mtk_mdp_ctx *ctx = priv;

	queue_work(ctx->mdp_dev->workqueue, &ctx->work);
}

static int mtk_mdp_m2m_queue_setup(struct vb2_queue *vq,
			const struct v4l2_format *fmt,
			unsigned int *num_buffers, unsigned int *num_planes,
			unsigned int sizes[], void *allocators[])
{
	struct mtk_mdp_ctx *ctx = vb2_get_drv_priv(vq);
	struct mtk_mdp_frame *frame;
	int i;

	frame = mtk_mdp_ctx_get_frame(ctx, vq->type);
	if (IS_ERR(frame))
		return PTR_ERR(frame);

	if (!frame->fmt)
		return -EINVAL;

	*num_planes = frame->fmt->num_planes;
	for (i = 0; i < frame->fmt->num_planes; i++) {
		sizes[i] = frame->payload[i];
		allocators[i] = ctx->mdp_dev->alloc_ctx;
	}
	return 0;
}

static int mtk_mdp_m2m_buf_prepare(struct vb2_buffer *vb)
{
	struct mtk_mdp_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);
	struct mtk_mdp_frame *frame;
	int i;

	frame = mtk_mdp_ctx_get_frame(ctx, vb->vb2_queue->type);
	if (IS_ERR(frame))
		return PTR_ERR(frame);

	if (!V4L2_TYPE_IS_OUTPUT(vb->vb2_queue->type)) {
		for (i = 0; i < frame->fmt->num_planes; i++)
			vb2_set_plane_payload(vb, i, frame->payload[i]);
	}

	return 0;
}

static void mtk_mdp_m2m_buf_queue(struct vb2_buffer *vb)
{
	struct mtk_mdp_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);

	if (ctx->m2m_ctx)
		v4l2_m2m_buf_queue(ctx->m2m_ctx, vb);
}

static struct vb2_ops mtk_mdp_m2m_qops = {
	.queue_setup	 = mtk_mdp_m2m_queue_setup,
	.buf_prepare	 = mtk_mdp_m2m_buf_prepare,
	.buf_queue	 = mtk_mdp_m2m_buf_queue,
	.wait_prepare	 = mtk_mdp_ctx_unlock,
	.wait_finish	 = mtk_mdp_ctx_lock,
	.stop_streaming	 = mtk_mdp_m2m_stop_streaming,
	.start_streaming = mtk_mdp_m2m_start_streaming,
};

static int mtk_mdp_m2m_querycap(struct file *file, void *fh,
				struct v4l2_capability *cap)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);
	struct mtk_mdp_dev *mdp = ctx->mdp_dev;

	strlcpy(cap->driver, mdp->pdev->name, sizeof(cap->driver));
	strlcpy(cap->card, mdp->pdev->name, sizeof(cap->card));
	strlcpy(cap->bus_info, "platform", sizeof(cap->bus_info));
	cap->device_caps = V4L2_CAP_STREAMING |
			   V4L2_CAP_VIDEO_M2M_MPLANE |
			   V4L2_CAP_VIDEO_CAPTURE_MPLANE |
			   V4L2_CAP_VIDEO_OUTPUT_MPLANE;

	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;
	return 0;
}

static int mtk_mdp_m2m_enum_fmt_mplane(struct file *file, void *priv,
				       struct v4l2_fmtdesc *f)
{
	return mtk_mdp_enum_fmt_mplane(f);
}

static int mtk_mdp_m2m_g_fmt_mplane(struct file *file, void *fh,
				    struct v4l2_format *f)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);

	return mtk_mdp_g_fmt_mplane(ctx, f);
}

static int mtk_mdp_m2m_try_fmt_mplane(struct file *file, void *fh,
				      struct v4l2_format *f)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);

	return mtk_mdp_try_fmt_mplane(ctx, f);
}

static int mtk_mdp_m2m_s_fmt_mplane(struct file *file, void *fh,
				    struct v4l2_format *f)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);
	struct vb2_queue *vq;
	struct mtk_mdp_frame *frame;
	struct v4l2_pix_format_mplane *pix;
	int i, ret = 0;

	ret = mtk_mdp_m2m_try_fmt_mplane(file, fh, f);
	if (ret)
		return ret;

	vq = v4l2_m2m_get_vq(ctx->m2m_ctx, f->type);

	if (vb2_is_streaming(vq)) {
		dev_err(&ctx->mdp_dev->pdev->dev, "queue%d busy", f->type);
		return -EBUSY;
	}

	if (V4L2_TYPE_IS_OUTPUT(f->type))
		frame = &ctx->s_frame;
	else
		frame = &ctx->d_frame;

	pix = &f->fmt.pix_mp;
	frame->fmt = mtk_mdp_find_fmt(&pix->pixelformat, 0);
	frame->colorspace = pix->colorspace;
	if (!frame->fmt)
		return -EINVAL;

	for (i = 0; i < frame->fmt->num_planes; i++) {
		frame->payload[i] = pix->plane_fmt[i].sizeimage;
		frame->pitch[i] = pix->plane_fmt[i].bytesperline;
	}

	mtk_mdp_set_frame_size(frame, pix->width, pix->height);

	if (f->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)
		mtk_mdp_ctx_state_lock_set(MTK_MDP_PARAMS | MTK_MDP_DST_FMT,
					   ctx);
	else
		mtk_mdp_ctx_state_lock_set(MTK_MDP_PARAMS | MTK_MDP_SRC_FMT,
					   ctx);

	return 0;
}

static int mtk_mdp_m2m_reqbufs(struct file *file, void *fh,
			       struct v4l2_requestbuffers *reqbufs)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);
	struct mtk_mdp_dev *mdp = ctx->mdp_dev;
	u32 max_cnt;

	max_cnt = (reqbufs->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) ?
		mdp->variant->in_buf_cnt : mdp->variant->out_buf_cnt;
	if (reqbufs->count > max_cnt) {
		return -EINVAL;
	} else if (reqbufs->count == 0) {
		if (reqbufs->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE)
			mtk_mdp_ctx_state_lock_clear(MTK_MDP_SRC_FMT, ctx);
		else
			mtk_mdp_ctx_state_lock_clear(MTK_MDP_DST_FMT, ctx);
	}

	return v4l2_m2m_reqbufs(file, ctx->m2m_ctx, reqbufs);
}

static int mtk_mdp_m2m_expbuf(struct file *file, void *fh,
			      struct v4l2_exportbuffer *eb)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);

	return v4l2_m2m_expbuf(file, ctx->m2m_ctx, eb);
}

static int mtk_mdp_m2m_querybuf(struct file *file, void *fh,
				struct v4l2_buffer *buf)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);

	return v4l2_m2m_querybuf(file, ctx->m2m_ctx, buf);
}

static int mtk_mdp_m2m_qbuf(struct file *file, void *fh,
			    struct v4l2_buffer *buf)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);

	return v4l2_m2m_qbuf(file, ctx->m2m_ctx, buf);
}

static int mtk_mdp_m2m_dqbuf(struct file *file, void *fh,
			     struct v4l2_buffer *buf)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);

	return v4l2_m2m_dqbuf(file, ctx->m2m_ctx, buf);
}

static int mtk_mdp_m2m_streamon(struct file *file, void *fh,
				enum v4l2_buf_type type)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);

	/* The source and target color format need to be set */
	if (V4L2_TYPE_IS_OUTPUT(type)) {
		if (!mtk_mdp_ctx_state_is_set(MTK_MDP_SRC_FMT, ctx))
			return -EINVAL;
	} else if (!mtk_mdp_ctx_state_is_set(MTK_MDP_DST_FMT, ctx)) {
		return -EINVAL;
	}

	return v4l2_m2m_streamon(file, ctx->m2m_ctx, type);
}

static int mtk_mdp_m2m_streamoff(struct file *file, void *fh,
			    enum v4l2_buf_type type)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);

	return v4l2_m2m_streamoff(file, ctx->m2m_ctx, type);
}

/* Return 1 if rectangle a is enclosed in rectangle b, or 0 otherwise. */
static int mtk_mdp_m2m_is_rectangle_enclosed(struct v4l2_rect *a,
					     struct v4l2_rect *b)
{
	if (a->left < b->left || a->top < b->top)
		return 0;

	if (a->left + a->width > b->left + b->width)
		return 0;

	if (a->top + a->height > b->top + b->height)
		return 0;

	return 1;
}

static int mtk_mdp_m2m_g_selection(struct file *file, void *fh,
				   struct v4l2_selection *s)
{
	struct mtk_mdp_frame *frame;
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);

	if ((s->type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) &&
	    (s->type != V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE))
		return -EINVAL;

	frame = mtk_mdp_ctx_get_frame(ctx, s->type);
	if (IS_ERR(frame))
		return PTR_ERR(frame);

	switch (s->target) {
	case V4L2_SEL_TGT_COMPOSE_DEFAULT:
	case V4L2_SEL_TGT_COMPOSE_BOUNDS:
	case V4L2_SEL_TGT_CROP_BOUNDS:
	case V4L2_SEL_TGT_CROP_DEFAULT:
		s->r.left = 0;
		s->r.top = 0;
		s->r.width = frame->f_width;
		s->r.height = frame->f_height;
		return 0;

	case V4L2_SEL_TGT_COMPOSE:
	case V4L2_SEL_TGT_CROP:
		s->r.left = frame->crop.left;
		s->r.top = frame->crop.top;
		s->r.width = frame->crop.width;
		s->r.height = frame->crop.height;
		return 0;
	}

	return -EINVAL;
}

static int mtk_mdp_m2m_s_selection(struct file *file, void *fh,
				   struct v4l2_selection *s)
{
	struct mtk_mdp_frame *frame;
	struct mtk_mdp_ctx *ctx = fh_to_ctx(fh);
	struct v4l2_crop cr;
	struct mtk_mdp_variant *variant = ctx->mdp_dev->variant;
	int ret;

	cr.type = s->type;
	cr.c = s->r;

	if ((s->type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) &&
	    (s->type != V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE))
		return -EINVAL;

	ret = mtk_mdp_try_crop(ctx, &cr);
	if (ret)
		return ret;

	if (s->flags & V4L2_SEL_FLAG_LE &&
	    !mtk_mdp_m2m_is_rectangle_enclosed(&cr.c, &s->r))
		return -ERANGE;

	if (s->flags & V4L2_SEL_FLAG_GE &&
	    !mtk_mdp_m2m_is_rectangle_enclosed(&s->r, &cr.c))
		return -ERANGE;

	s->r = cr.c;

	switch (s->target) {
	case V4L2_SEL_TGT_COMPOSE_BOUNDS:
	case V4L2_SEL_TGT_COMPOSE_DEFAULT:
	case V4L2_SEL_TGT_COMPOSE:
		frame = &ctx->s_frame;
		break;

	case V4L2_SEL_TGT_CROP_BOUNDS:
	case V4L2_SEL_TGT_CROP:
	case V4L2_SEL_TGT_CROP_DEFAULT:
		frame = &ctx->d_frame;
		break;

	default:
		return -EINVAL;
	}

	/* Check to see if scaling ratio is within supported range */
	if (mtk_mdp_ctx_state_is_set(MTK_MDP_DST_FMT | MTK_MDP_SRC_FMT, ctx)) {
		if (s->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
			ret = mtk_mdp_check_scaler_ratio(variant, cr.c.width,
				cr.c.height, ctx->d_frame.crop.width,
				ctx->d_frame.crop.height,
				ctx->ctrls.rotate->val);
		} else {
			ret = mtk_mdp_check_scaler_ratio(variant,
				ctx->s_frame.crop.width,
				ctx->s_frame.crop.height, cr.c.width,
				cr.c.height, ctx->ctrls.rotate->val);
		}

		if (ret) {
			dev_err(&ctx->mdp_dev->pdev->dev,
				"Out of scaler range");
			return -EINVAL;
		}
	}

	frame->crop = cr.c;

	mtk_mdp_ctx_state_lock_set(MTK_MDP_PARAMS, ctx);
	return 0;
}

static const struct v4l2_ioctl_ops mtk_mdp_m2m_ioctl_ops = {
	.vidioc_querycap		= mtk_mdp_m2m_querycap,
	.vidioc_enum_fmt_vid_cap_mplane	= mtk_mdp_m2m_enum_fmt_mplane,
	.vidioc_enum_fmt_vid_out_mplane	= mtk_mdp_m2m_enum_fmt_mplane,
	.vidioc_g_fmt_vid_cap_mplane	= mtk_mdp_m2m_g_fmt_mplane,
	.vidioc_g_fmt_vid_out_mplane	= mtk_mdp_m2m_g_fmt_mplane,
	.vidioc_try_fmt_vid_cap_mplane	= mtk_mdp_m2m_try_fmt_mplane,
	.vidioc_try_fmt_vid_out_mplane	= mtk_mdp_m2m_try_fmt_mplane,
	.vidioc_s_fmt_vid_cap_mplane	= mtk_mdp_m2m_s_fmt_mplane,
	.vidioc_s_fmt_vid_out_mplane	= mtk_mdp_m2m_s_fmt_mplane,
	.vidioc_reqbufs			= mtk_mdp_m2m_reqbufs,
	.vidioc_expbuf                  = mtk_mdp_m2m_expbuf,
	.vidioc_querybuf		= mtk_mdp_m2m_querybuf,
	.vidioc_qbuf			= mtk_mdp_m2m_qbuf,
	.vidioc_dqbuf			= mtk_mdp_m2m_dqbuf,
	.vidioc_streamon		= mtk_mdp_m2m_streamon,
	.vidioc_streamoff		= mtk_mdp_m2m_streamoff,
	.vidioc_g_selection		= mtk_mdp_m2m_g_selection,
	.vidioc_s_selection		= mtk_mdp_m2m_s_selection
};

static int mtk_mdp_m2m_queue_init(void *priv, struct vb2_queue *src_vq,
				  struct vb2_queue *dst_vq)
{
	struct mtk_mdp_ctx *ctx = priv;
	int ret;

	memset(src_vq, 0, sizeof(*src_vq));
	src_vq->type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	src_vq->io_modes = VB2_MMAP | VB2_USERPTR | VB2_DMABUF;
	src_vq->drv_priv = ctx;
	src_vq->ops = &mtk_mdp_m2m_qops;
	src_vq->mem_ops = &vb2_dma_contig_memops;
	src_vq->buf_struct_size = sizeof(struct v4l2_m2m_buffer);
	src_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;

	ret = vb2_queue_init(src_vq);
	if (ret)
		return ret;

	memset(dst_vq, 0, sizeof(*dst_vq));
	dst_vq->type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	dst_vq->io_modes = VB2_MMAP | VB2_USERPTR | VB2_DMABUF;
	dst_vq->drv_priv = ctx;
	dst_vq->ops = &mtk_mdp_m2m_qops;
	dst_vq->mem_ops = &vb2_dma_contig_memops;
	dst_vq->buf_struct_size = sizeof(struct v4l2_m2m_buffer);
	dst_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;

	return vb2_queue_init(dst_vq);
}

static int mtk_mdp_m2m_open(struct file *file)
{
	struct mtk_mdp_dev *mdp = video_drvdata(file);
	struct video_device *vfd = video_devdata(file);
	struct mtk_mdp_ctx *ctx = NULL;
	int ret;

	if (mutex_lock_interruptible(&mdp->lock))
		return -ERESTARTSYS;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		ret = -ENOMEM;
		goto err_ctx_alloc;
	}

	mutex_init(&ctx->qlock);
	mutex_init(&ctx->slock);
	ctx->idx = ffz(mdp->ctx_mask[0]);
	v4l2_fh_init(&ctx->fh, vfd);
	file->private_data = &ctx->fh;
	ret = mtk_mdp_ctrls_create(ctx);
	if (ret)
		goto error_ctrls;

	/* Use separate control handler per file handle */
	ctx->fh.ctrl_handler = &ctx->ctrl_handler;
	v4l2_fh_add(&ctx->fh);

	ctx->mdp_dev = mdp;
	/* Default color format */
	ctx->s_frame.fmt = mtk_mdp_get_format(0);
	ctx->d_frame.fmt = mtk_mdp_get_format(0);
	/* Setup the device context for mem2mem mode. */
	ctx->state = MTK_MDP_CTX_M2M;
	ctx->flags = 0;

	INIT_WORK(&ctx->work, mtk_mdp_m2m_worker);
	ctx->m2m_ctx = v4l2_m2m_ctx_init(mdp->m2m_dev, ctx,
					 mtk_mdp_m2m_queue_init);
	if (IS_ERR(ctx->m2m_ctx)) {
		dev_err(&mdp->pdev->dev, "Failed to initialize m2m context");
		ret = PTR_ERR(ctx->m2m_ctx);
		goto error_m2m_ctx;
	}
	ctx->fh.m2m_ctx = ctx->m2m_ctx;
	if (mdp->ctx_num++ == 0) {
		set_bit(MTK_MDP_M2M_OPEN, &mdp->state);

		ret = vpu_load_firmware(mdp->vpu_dev);
		if (ret < 0) {
			dev_err(&mdp->pdev->dev,
				"vpu_load_firmware failed\n");
			goto err_load_vpu;
		}

		ret = vpu_compare_version(mdp->vpu_dev, "0.2.8-rc1");
		if (ret < 0) {
			ret = -EINVAL;
			dev_err(&mdp->pdev->dev, "invalid vpu firmware\n");
			goto err_load_vpu;
		}

		ret = mtk_mdp_vpu_register(mdp->pdev);
		if (ret < 0) {
			dev_err(&mdp->pdev->dev, "mdp_vpu register failed\n");
			goto err_load_vpu;
		}
	}

	mtk_mdp_vpu_init(&ctx->vpu);
	set_bit(ctx->idx, &mdp->ctx_mask[0]);
	mdp->ctx[ctx->idx] = ctx;
	mutex_unlock(&mdp->lock);

	return 0;

err_load_vpu:
	mdp->ctx_num--;
	v4l2_m2m_ctx_release(ctx->m2m_ctx);
error_m2m_ctx:
	mtk_mdp_ctrls_delete(ctx);
error_ctrls:
	v4l2_fh_del(&ctx->fh);
	v4l2_fh_exit(&ctx->fh);
	kfree(ctx);
err_ctx_alloc:
	mutex_unlock(&mdp->lock);

	return ret;
}

static int mtk_mdp_m2m_release(struct file *file)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(file->private_data);
	struct mtk_mdp_dev *mdp = ctx->mdp_dev;

	flush_workqueue(mdp->workqueue);
	mutex_lock(&mdp->lock);
	v4l2_m2m_ctx_release(ctx->m2m_ctx);
	mutex_destroy(&ctx->qlock);
	mtk_mdp_ctrls_delete(ctx);
	v4l2_fh_del(&ctx->fh);
	v4l2_fh_exit(&ctx->fh);
	mdp->ctx[ctx->idx] = NULL;
	clear_bit(ctx->idx, &mdp->ctx_mask[0]);
	if (mdp->ctx_num > 0) {
		mtk_mdp_vpu_deinit(&ctx->vpu);
		mdp->ctx_num--;
	} else {
		clear_bit(MTK_MDP_M2M_OPEN, &mdp->state);
		mdp->ctx_num = 0;
	}
	kfree(ctx);

	mutex_unlock(&mdp->lock);
	return 0;
}

static unsigned int mtk_mdp_m2m_poll(struct file *file,
				     struct poll_table_struct *wait)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(file->private_data);
	struct mtk_mdp_dev *mdp = ctx->mdp_dev;
	int ret;

	if (mutex_lock_interruptible(&mdp->lock))
		return -ERESTARTSYS;

	ret = v4l2_m2m_poll(file, ctx->m2m_ctx, wait);
	mutex_unlock(&mdp->lock);

	return ret;
}

static int mtk_mdp_m2m_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct mtk_mdp_ctx *ctx = fh_to_ctx(file->private_data);
	struct mtk_mdp_dev *mdp = ctx->mdp_dev;
	int ret;

	if (mutex_lock_interruptible(&mdp->lock))
		return -ERESTARTSYS;

	ret = v4l2_m2m_mmap(file, ctx->m2m_ctx, vma);
	mutex_unlock(&mdp->lock);

	return ret;
}

static const struct v4l2_file_operations mtk_mdp_m2m_fops = {
	.owner		= THIS_MODULE,
	.open		= mtk_mdp_m2m_open,
	.release	= mtk_mdp_m2m_release,
	.poll		= mtk_mdp_m2m_poll,
	.unlocked_ioctl	= video_ioctl2,
	.mmap		= mtk_mdp_m2m_mmap,
};

static struct v4l2_m2m_ops mtk_mdp_m2m_ops = {
	.device_run	= mtk_mdp_m2m_device_run,
	.job_abort	= mtk_mdp_m2m_job_abort,
};

int mtk_mdp_register_m2m_device(struct mtk_mdp_dev *mdp)
{
	struct device *dev = &mdp->pdev->dev;
	int ret;

	mdp->vdev.fops = &mtk_mdp_m2m_fops;
	mdp->vdev.ioctl_ops = &mtk_mdp_m2m_ioctl_ops;
	mdp->vdev.release = video_device_release_empty;
	mdp->vdev.lock = &mdp->lock;
	mdp->vdev.vfl_dir = VFL_DIR_M2M;
	mdp->vdev.v4l2_dev = &mdp->v4l2_dev;
	snprintf(mdp->vdev.name, sizeof(mdp->vdev.name), "%s:m2m",
		 MTK_MDP_MODULE_NAME);
	video_set_drvdata(&mdp->vdev, mdp);

	mdp->m2m_dev = v4l2_m2m_init(&mtk_mdp_m2m_ops);
	if (IS_ERR(mdp->m2m_dev)) {
		dev_err(dev, "failed to initialize v4l2-m2m device\n");
		ret = PTR_ERR(mdp->m2m_dev);
		goto err_m2m_init;
	}

	v4l2_disable_ioctl_locking(&mdp->vdev, VIDIOC_QBUF);
	v4l2_disable_ioctl_locking(&mdp->vdev, VIDIOC_DQBUF);
	v4l2_disable_ioctl_locking(&mdp->vdev, VIDIOC_S_CTRL);

	ret = video_register_device(&mdp->vdev, VFL_TYPE_GRABBER, 2);
	if (ret) {
		dev_err(dev, "failed to register video device\n");
		goto err_vdev_register;
	}

	v4l2_info(&mdp->v4l2_dev, "driver registered as /dev/video%d",
		  mdp->vdev.num);
	return 0;

err_vdev_register:
	v4l2_m2m_release(mdp->m2m_dev);
err_m2m_init:
	video_device_release(&mdp->vdev);

	return ret;
}

void mtk_mdp_unregister_m2m_device(struct mtk_mdp_dev *mdp)
{
	if (!mdp)
		return;

	video_device_release(&mdp->vdev);
	v4l2_m2m_release(mdp->m2m_dev);
}
