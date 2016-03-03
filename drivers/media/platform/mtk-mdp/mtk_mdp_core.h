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


#ifndef __MTK_MDP_CORE_H__
#define __MTK_MDP_CORE_H__

#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/pm_runtime.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/videodev2.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <media/v4l2-mem2mem.h>
#include <media/videobuf2-core.h>
#include <media/videobuf2-dma-contig.h>
#include <media/videobuf2-vmalloc.h>

#include "mtk_mdp_vpu.h"


#define MTK_MDP_MODULE_NAME		"mtk-mdp"

#define MTK_MDP_SHUTDOWN_TIMEOUT	((100*HZ)/1000)
#define MTK_MDP_MAX_DEVS		1
#define MTK_MDP_MAX_CTRL_NUM		10

#define MTK_MDP_PARAMS			(1 << 0)
#define MTK_MDP_SRC_FMT			(1 << 1)
#define MTK_MDP_DST_FMT			(1 << 2)
#define MTK_MDP_CTX_M2M			(1 << 3)
#define MTK_MDP_CTX_STOP_REQ		(1 << 6)
#define MTK_MDP_CTX_ABORT		(1 << 7)
#define MTK_MDP_CTX_ERROR		(1 << 8)

enum mtk_mdp_dev_flags {
	/* for global */
	MTK_MDP_SUSPEND,

	/* for m2m node */
	MTK_MDP_M2M_OPEN,
	MTK_MDP_M2M_RUN,
	MTK_MDP_M2M_PEND,
	MTK_MDP_M2M_SUSPENDED,
	MTK_MDP_M2M_SUSPENDING,
};

enum mtk_mdp_color_fmt {
	MTK_MDP_RGB = 0x1,
	MTK_MDP_YUV420 = 0x2,
	MTK_MDP_YUV422 = 0x4,
	MTK_MDP_YUV444 = 0x8,
};

#define is_rgb(x) (!!((x) & 0x1))
#define is_yuv420(x) (!!((x) & 0x2))
#define is_yuv422(x) (!!((x) & 0x4))

/**
 * struct mtk_mdp_fmt - the driver's internal color format data
 * @name: format description
 * @pixelformat: the fourcc code for this format, 0 if not applicable
 * @num_planes: number of physically non-contiguous data planes
 * @nr_comp: number of physically contiguous data planes
 * @depth: per plane driver's private 'number of bits per pixel'
 * @flags: flags indicating which operation mode format applies to
 */
struct mtk_mdp_fmt {
	char				*name;
	u32				pixelformat;
	u32				color;
	u16				num_planes;
	u16				num_comp;
	u8				depth[VIDEO_MAX_PLANES];
	u32				flags;
};

/**
 * struct mtk_mdp_addr - the image processor physical address set
 * @y:	 luminance plane address
 * @cb:	 Cb plane address
 * @cr:	 Cr plane address
 */
struct mtk_mdp_addr {
	dma_addr_t y;
	dma_addr_t cb;
	dma_addr_t cr;
};

/* struct mtk_mdp_ctrls - the image processor control set
 * @rotate: rotation degree
 * @hflip: horizontal flip
 * @vflip: vertical flip
 * @global_alpha: the alpha value of current frame
 */
struct mtk_mdp_ctrls {
	struct v4l2_ctrl *rotate;
	struct v4l2_ctrl *hflip;
	struct v4l2_ctrl *vflip;
	struct v4l2_ctrl *global_alpha;
};

/**
 * struct mtk_mdp_frame - source/target frame properties
 * @f_width:	SRC : SRCIMG_WIDTH, DST : OUTPUTDMA_WHOLE_IMG_WIDTH
 * @f_height:	SRC : SRCIMG_HEIGHT, DST : OUTPUTDMA_WHOLE_IMG_HEIGHT
 * @crop:	cropped(source)/scaled(destination) size
 * @payload:	image size in bytes (w x h x bpp)
 * @pitch:	bytes per line of image in memory
 * @addr:	image frame buffer physical addresses
 * @fmt:	color format pointer
 * @colorspace: value indicating v4l2_colorspace
 * @alpha:	frame's alpha value
 */
struct mtk_mdp_frame {
	u32				f_width;
	u32				f_height;
	struct v4l2_rect		crop;
	unsigned long			payload[VIDEO_MAX_PLANES];
	unsigned int			pitch[VIDEO_MAX_PLANES];
	struct mtk_mdp_addr		addr;
	const struct mtk_mdp_fmt	*fmt;
	u32				colorspace;
	u8				alpha;
};

struct mtk_mdp_ctx;

/**
 *  struct mtk_mdp_pix_max - image pixel size limits in various IP configurations
 *
 *  @org_scaler_bypass_w: max pixel width when the scaler is disabled
 *  @org_scaler_bypass_h: max pixel height when the scaler is disabled
 *  @org_scaler_input_w: max pixel width when the scaler is enabled
 *  @org_scaler_input_h: max pixel height when the scaler is enabled
 *  @real_rot_dis_w: max pixel src cropped height with the rotator is off
 *  @real_rot_dis_h: max pixel src croppped width with the rotator is off
 *  @real_rot_en_w: max pixel src cropped width with the rotator is on
 *  @real_rot_en_h: max pixel src cropped height with the rotator is on
 *  @target_rot_dis_w: max pixel dst scaled width with the rotator is off
 *  @target_rot_dis_h: max pixel dst scaled height with the rotator is off
 *  @target_rot_en_w: max pixel dst scaled width with the rotator is on
 *  @target_rot_en_h: max pixel dst scaled height with the rotator is on
 */
struct mtk_mdp_pix_max {
	u16 org_scaler_bypass_w;
	u16 org_scaler_bypass_h;
	u16 org_scaler_input_w;
	u16 org_scaler_input_h;
	u16 real_rot_dis_w;
	u16 real_rot_dis_h;
	u16 real_rot_en_w;
	u16 real_rot_en_h;
	u16 target_rot_dis_w;
	u16 target_rot_dis_h;
	u16 target_rot_en_w;
	u16 target_rot_en_h;
};

/**
 *  struct mtk_mdp_pix_min - image pixel size limits in various IP configurations
 *
 *  @org_w: minimum source pixel width
 *  @org_h: minimum source pixel height
 *  @real_w: minimum input crop pixel width
 *  @real_h: minimum input crop pixel height
 *  @target_rot_dis_w: minimum output scaled pixel height when rotator is off
 *  @target_rot_dis_h: minimum output scaled pixel height when rotator is off
 *  @target_rot_en_w: minimum output scaled pixel height when rotator is on
 *  @target_rot_en_h: minimum output scaled pixel height when rotator is on
 */
struct mtk_mdp_pix_min {
	u16 org_w;
	u16 org_h;
	u16 real_w;
	u16 real_h;
	u16 target_rot_dis_w;
	u16 target_rot_dis_h;
	u16 target_rot_en_w;
	u16 target_rot_en_h;
};

struct mtk_mdp_pix_align {
	u16 org_h;
	u16 org_w;
	u16 offset_h;
	u16 real_w;
	u16 real_h;
	u16 target_w;
	u16 target_h;
};

/**
 * struct mtk_mdp_variant - image processor variant information
 */
struct mtk_mdp_variant {
	struct mtk_mdp_pix_max		*pix_max;
	struct mtk_mdp_pix_min		*pix_min;
	struct mtk_mdp_pix_align	*pix_align;
	u16				in_buf_cnt;
	u16				out_buf_cnt;
	u16				h_sc_up_max;
	u16				v_sc_up_max;
	u16				h_sc_down_max;
	u16				v_sc_down_max;
};

struct mtk_mdp_hw_clks {
	struct clk *rdma0_clk;
	struct clk *rdma1_clk;
	struct clk *rsz0_clk;
	struct clk *rsz1_clk;
	struct clk *rsz2_clk;
	struct clk *wdma_clk;
	struct clk *wrot0_clk;
	struct clk *wrot1_clk;
	struct clk *mutex_clk;
};

/**
 * struct mtk_mdp_dev - abstraction for image processor entity
 * @lock:	the mutex protecting this data structure
 * @vpulock:	the mutex protecting the communication with VPU
 * @pdev:	pointer to the image processor platform device
 * @variant:	the IP variant information
 * @id:		image processor device index (0..MTK_MDP_MAX_DEVS)
 * @clks:	clocks required for image processor operation
 * @irq_queue:	interrupt handler waitqueue
 * @m2m_dev:	v4l2 memory-to-memory device data
 * @state:	flags used to synchronize m2m and capture mode operation
 * @alloc_ctx:	videobuf2 memory allocator context
 * @vdev:	video device for image processor instance
 * @larb:	clocks required for image processor operation
 * @workqueue:	decode work queue
 * @vpu_dev:	VPU platform device
 * @ctx:	array of driver context
 * @ctx_mask:	used to mark which contexts are opened
 * @ctx_num:	counter of driver context
 */
struct mtk_mdp_dev {
	struct mutex			lock;
	struct mutex			vpulock;
	struct platform_device		*pdev;
	struct mtk_mdp_variant		*variant;
	u16				id;
	struct mtk_mdp_hw_clks		clks;
	wait_queue_head_t		irq_queue;
	struct v4l2_m2m_dev		*m2m_dev;
	unsigned long			state;
	struct vb2_alloc_ctx		*alloc_ctx;
	struct video_device		vdev;
	struct v4l2_device		v4l2_dev;
	struct device			*larb[2];
	struct workqueue_struct		*workqueue;
	struct platform_device		*vpu_dev;
	struct mtk_mdp_ctx		*ctx[MTK_MDP_MAX_CTX];
	unsigned long		ctx_mask[BITS_TO_LONGS(MTK_MDP_MAX_CTX)];
	int				ctx_num;
};

/**
 * mtk_mdp_ctx - the device context data
 * @s_frame:		source frame properties
 * @d_frame:		destination frame properties
 * @idx:		index of the context that this structure describes
 * @flags:		additional flags for image conversion
 * @state:		flags to keep track of user configuration
 * @rotation:		rotates the image by specified angle
 * @hflip:		mirror the picture horizontally
 * @vflip:		mirror the picture vertically
 * @mdp_dev:		the image processor device this context applies to
 * @m2m_ctx:		memory-to-memory device context
 * @fh:			v4l2 file handle
 * @ctrl_handler:	v4l2 controls handler
 * @ctrls		image processor control set
 * @ctrls_rdy:		true if the control handler is initialized
 * @vpu:		VPU instance
 * @qlock:		vb2 queue lock
 * @slock:		the mutex protecting this data structure
 * @work:		worker for image processing
 */
struct mtk_mdp_ctx {
	struct mtk_mdp_frame		s_frame;
	struct mtk_mdp_frame		d_frame;
	u32				flags;
	u32				state;
	int				idx;
	int				rotation;
	u32				hflip:1;
	u32				vflip:1;
	struct mtk_mdp_dev		*mdp_dev;
	struct v4l2_m2m_ctx		*m2m_ctx;
	struct v4l2_fh			fh;
	struct v4l2_ctrl_handler	ctrl_handler;
	struct mtk_mdp_ctrls		ctrls;
	bool				ctrls_rdy;

	struct mtk_mdp_vpu		vpu;
	struct mutex			qlock;
	struct mutex			slock;
	struct work_struct		work;
};

int mtk_mdp_register_m2m_device(struct mtk_mdp_dev *mdp);
void mtk_mdp_unregister_m2m_device(struct mtk_mdp_dev *mdp);
void mtk_mdp_m2m_job_finish(struct mtk_mdp_ctx *ctx, int vb_state);
void mtk_mdp_ctx_error(struct mtk_mdp_ctx *ctx);

u32 get_plane_size(struct mtk_mdp_frame *fr, unsigned int plane);
const struct mtk_mdp_fmt *mtk_mdp_get_format(int index);
const struct mtk_mdp_fmt *mtk_mdp_find_fmt(u32 *pixelformat, u32 index);
int mtk_mdp_enum_fmt_mplane(struct v4l2_fmtdesc *f);
int mtk_mdp_try_fmt_mplane(struct mtk_mdp_ctx *ctx, struct v4l2_format *f);
void mtk_mdp_set_frame_size(struct mtk_mdp_frame *frame, int width, int height);
int mtk_mdp_g_fmt_mplane(struct mtk_mdp_ctx *ctx, struct v4l2_format *f);
void mtk_mdp_check_crop_change(u32 tmp_w, u32 tmp_h, u32 *w, u32 *h);
int mtk_mdp_try_crop(struct mtk_mdp_ctx *ctx, struct v4l2_crop *cr);
int mtk_mdp_check_scaler_ratio(struct mtk_mdp_variant *var, int sw, int sh,
			       int dw, int dh, int rot);
int mtk_mdp_ctrls_create(struct mtk_mdp_ctx *ctx);
void mtk_mdp_ctrls_delete(struct mtk_mdp_ctx *ctx);
int mtk_mdp_prepare_addr(struct mtk_mdp_ctx *ctx, struct vb2_buffer *vb,
		 struct mtk_mdp_frame *frame, struct mtk_mdp_addr *addr);

struct mtk_mdp_frame *mtk_mdp_ctx_get_frame(struct mtk_mdp_ctx *ctx,
					    enum v4l2_buf_type type);

void mtk_mdp_hw_set_input_addr(struct mtk_mdp_ctx *ctx,
			       struct mtk_mdp_addr *addr);
void mtk_mdp_hw_set_output_addr(struct mtk_mdp_ctx *ctx,
				struct mtk_mdp_addr *addr);
void mtk_mdp_hw_set_in_size(struct mtk_mdp_ctx *ctx);
void mtk_mdp_hw_set_in_image_format(struct mtk_mdp_ctx *ctx);
void mtk_mdp_hw_set_out_size(struct mtk_mdp_ctx *ctx);
void mtk_mdp_hw_set_out_image_format(struct mtk_mdp_ctx *ctx);
void mtk_mdp_hw_set_rotation(struct mtk_mdp_ctx *ctx);
void mtk_mdp_hw_set_global_alpha(struct mtk_mdp_ctx *ctx);
int mtk_mdp_hw_set_sfr_update(struct mtk_mdp_ctx *ctx);

int mtk_mdp_process_done(void *priv, int vb_state);

#endif /* __MTK_MDP_CORE_H__ */
