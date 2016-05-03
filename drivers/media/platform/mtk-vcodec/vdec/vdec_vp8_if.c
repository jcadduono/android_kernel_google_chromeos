/*
 * Copyright (c) 2016 MediaTek Inc.
 * Author: Jungchang Tsao <jungchang.tsao@mediatek.com>
 *	   PC Chen <pc.chen@mediatek.com>
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

#include "../mtk_vcodec_intr.h"
#include "../vdec_vpu_if.h"
#include "../vdec_drv_base.h"

#define VP8_VP_WRAP_SZ				(45 * 4096)
#define VP8_SEGID_DRAM_ADDR			0x3c
#define VP8_HW_DATA_ADDR			0x93C
#define VP8_HW_DATA_VALUE			0x940
#define VP8_BSASET			        0x100
#define VP8_BSDSET				0x104
#define VP8_DEC_DATA_PROCESSING_LOOP		96

#define VP8_RW_CKEN_SET				0x0
#define VP8_RW_DCM_CON				0x18
#define VP8_WO_VLD_SRST				0x108
#define VP8_RW_MISC_SYS_SEL			0x84
#define VP8_RW_MISC_SPEC_CON			0xC8
#define VP8_WO_VLD_SRST				0x108
#define VP8_RW_VP8_CTRL				0xA4
#define VP8_RW_MISC_DCM_CON			0xEC
#define VP8_RW_MISC_SRST			0xF4
#define VP8_RW_MISC_FUNC_CON			0xCC

#define VP8_MAX_FRM_BUFF_NUM				5
#define VP8_HW_DATA_SZ					272
#define VP8_DEC_DATA_SZ					300

/**
 * struct vdec_vp8_dec_info - decode misc information
 * @vp_wrapper_dma    : wrapper buffer dma
 * @prev_y_dma        : previous decoded frame buffer Y plane address
 * @cur_y_fb_dma      : current plane Y frame buffer dma
 * @cur_c_fb_dma      : current plane C frame buffer dma
 * @bs_dma	      : bitstream dma
 * @bs_sz	      : current plane C frame buffer dma
 * @resolution_changed: resolution change flag
 * @show_frame	      : display this frame or not
 * @wait_key_frame    : wait key frame coming
 */
struct vdec_vp8_dec_info {
	uint64_t vp_wrapper_dma;
	uint64_t prev_y_dma;
	uint64_t cur_y_fb_dma;
	uint64_t cur_c_fb_dma;
	uint64_t bs_dma;
	uint32_t bs_sz;
	uint32_t resolution_changed;
	uint32_t show_frame;
	uint32_t wait_key_frame;
};

/**
 * struct vdec_vp8_vsi - VPU shared information
 * @dec			: decoding information
 * @pic			: picture information
 * @dec_data		: decode data
 * @segid_wrapper_work	: seg id wrapper buffer
 * @load_data		: flag to indicate reload decode data
 */
struct vdec_vp8_vsi {
	struct vdec_vp8_dec_info dec;
	struct vdec_pic_info pic;
	unsigned int dec_data[VP8_DEC_DATA_SZ];
	unsigned int segid_wrapper_work[VP8_HW_DATA_SZ][4];
	unsigned int load_data;
};

/**
 * struct vdec_vp8_hw_reg_base - HW register base
 * @sys		: base address for sys
 * @misc	: base address for misc
 * @ld		: base address for ld
 * @top		: base address for top
 * @cm		: base address for cm
 * @hwd		: base address for hwd
 * @hwb		: base address for hwb
*/
struct vdec_vp8_hw_reg_base {
	void __iomem *sys;
	void __iomem *misc;
	void __iomem *ld;
	void __iomem *top;
	void __iomem *cm;
	void __iomem *hwd;
	void __iomem *hwb;
};

/**
 * struct vdec_vp8_vpu_inst - VPU instance for VP8 decode
 * @wq_hd	: Wait queue to wait VPU message ack
 * @signaled	: 1 - Host has received ack message from VPU, 0 - not recevie
 * @failure	: VPU execution result status
 * @inst_addr	: VPU decoder instance addr
 */
struct vdec_vp8_vpu_inst {
	wait_queue_head_t wq_hd;
	int signaled;
	int failure;
	unsigned int inst_addr;
};

/* frame buffer (fb) list
 * [dec_fb_list]   - decode fb are initialized to 0 and populated in
 * [dec_use_list]  - fb is set after decode and is moved to this list
 * [dec_free_list] - fb is not needed for reference will be moved from
 *		     [dec_use_list] to [dec_free_list] and
 *		     once user remove fb from [dec_free_list],
 *		     it is circulated back to [dec_fb_list]
 * [disp_fb_list]  - display fb are initialized to 0 and populated in
 * [disp_rdy_list] - fb is set after decode and is moved to this list
 *                   once user remove fb from [disp_rdy_list] it is
 *                   circulated back to [disp_fb_list]
 */

/**
 * struct vdec_vp8_inst - VP8 decoder instance
 * @cur_fb		: current frame buffer
 * @dec_fb		: decode frame buffer node
 * @disp_fb		: display frame buffer node
 * @dec_fb_list		: list to store decode frame buffer
 * @dec_use_list	: list to store frame buffer in use
 * @dec_free_list	: list to store free frame buffer
 * @disp_fb_list	: list to store display frame buffer
 * @disp_rdy_list	: list to store display ready frame buffer
 * @vp_wrapper_buf	: decoder working buffer
 * @reg_base		: hw register base address
 * @frm_cnt		: decode frame count
 * @ctx			: V4L2 context
 * @dev			: platform device
 * @vpu			: VPU instance for decoder
 * @vsi			: VPU share information
 */
struct vdec_vp8_inst {
	struct vdec_fb *cur_fb;
	struct vdec_fb_node dec_fb[VP8_MAX_FRM_BUFF_NUM];
	struct vdec_fb_node disp_fb[VP8_MAX_FRM_BUFF_NUM];
	struct list_head dec_fb_list;
	struct list_head dec_use_list;
	struct list_head dec_free_list;
	struct list_head disp_fb_list;
	struct list_head disp_rdy_list;
	struct mtk_vcodec_mem vp_wrapper_buf;
	struct vdec_vp8_hw_reg_base reg_base;
	unsigned int frm_cnt;
	struct mtk_vcodec_ctx *ctx;
	struct vdec_vpu_inst vpu;
	struct vdec_vp8_vsi *vsi;
};

static void get_hw_reg_base(struct vdec_vp8_inst *inst)
{
	inst->reg_base.top = mtk_vcodec_get_reg_addr(inst->ctx, VDEC_TOP);
	inst->reg_base.cm = mtk_vcodec_get_reg_addr(inst->ctx, VDEC_CM);
	inst->reg_base.hwd = mtk_vcodec_get_reg_addr(inst->ctx, VDEC_HWD);
	inst->reg_base.sys = mtk_vcodec_get_reg_addr(inst->ctx, VDEC_SYS);
	inst->reg_base.misc = mtk_vcodec_get_reg_addr(inst->ctx, VDEC_MISC);
	inst->reg_base.ld = mtk_vcodec_get_reg_addr(inst->ctx, VDEC_LD);
	inst->reg_base.hwb = mtk_vcodec_get_reg_addr(inst->ctx, VDEC_HWB);
}

static void write_hw_data(struct vdec_vp8_inst *inst)
{
	int i, j;
	unsigned int seg_id_addr;
	unsigned int val;
	void __iomem *cm = inst->reg_base.cm;

	seg_id_addr = readl(inst->reg_base.top + VP8_SEGID_DRAM_ADDR) >> 4;

	for (i = 0; i < VP8_HW_DATA_SZ; i++) {
		for (j = 3; j >= 0; j--) {
			val = (1 << 16) + ((seg_id_addr + i) << 2) + j;
			writel(val, cm + VP8_HW_DATA_ADDR);

			val = inst->vsi->segid_wrapper_work[i][j];
			writel(val, cm + VP8_HW_DATA_VALUE);
		}
	}
}

static void read_hw_data(struct vdec_vp8_inst *inst)
{
	int i, j;
	unsigned int seg_id_addr;
	unsigned int val;
	void __iomem *cm = inst->reg_base.cm;

	seg_id_addr = readl(inst->reg_base.top + VP8_SEGID_DRAM_ADDR) >> 4;

	for (i = 0; i < VP8_HW_DATA_SZ; i++) {
		for (j = 3; j >= 0; j--) {
			val = ((seg_id_addr + i) << 2) + j;
			writel(val, cm + VP8_HW_DATA_ADDR);

			val = readl(cm + VP8_HW_DATA_VALUE);
			inst->vsi->segid_wrapper_work[i][j] = val;
		}
	}
}

static void enable_hw_rw_dec_data(struct vdec_vp8_inst *inst)
{
	unsigned int reg_val = 0;
	void __iomem *sys = inst->reg_base.sys;
	void __iomem *misc = inst->reg_base.misc;
	void __iomem *ld = inst->reg_base.ld;
	void __iomem *hwb = inst->reg_base.hwb;
	void __iomem *hwd = inst->reg_base.hwd;

	writel(0x1, sys + VP8_RW_CKEN_SET);
	writel(0x101, ld + VP8_WO_VLD_SRST);
	writel(0x101, hwb + VP8_WO_VLD_SRST);

	writel(1, sys);
	reg_val = readl(misc + VP8_RW_MISC_SRST);
	writel((reg_val & 0xFFFFFFFE), misc + VP8_RW_MISC_SRST);

	writel(0x1, misc + VP8_RW_MISC_SYS_SEL);
	writel(0x17F, misc + VP8_RW_MISC_SPEC_CON);
	writel(0x71201100, misc + VP8_RW_MISC_FUNC_CON);
	writel(0x0, ld + VP8_WO_VLD_SRST);
	writel(0x0, hwb + VP8_WO_VLD_SRST);
	writel(0x1, sys + VP8_RW_DCM_CON);
	writel(0x1, misc + VP8_RW_MISC_DCM_CON);
	writel(0x1, hwd + VP8_RW_VP8_CTRL);
}

static void store_dec_data(struct vdec_vp8_inst *inst)
{
	int i, j;
	unsigned int addr = 0, val = 0;
	void __iomem *hwd = inst->reg_base.hwd;
	unsigned int *p = &inst->vsi->dec_data[2];

	for (i = 0; i < VP8_DEC_DATA_PROCESSING_LOOP; i++) {
		writel(addr, hwd + VP8_BSASET);
		for (j = 0; j < 3 ; j++) {
			val = *p++;
			writel(val, hwd + VP8_BSDSET);
		}
		addr += 4;
	}
}

static void load_dec_data(struct vdec_vp8_inst *inst)
{
	int i;
	unsigned int addr = 0;
	unsigned int *p = &inst->vsi->dec_data[2];
	void __iomem *hwd = inst->reg_base.hwd;

	for (i = 0; i < VP8_DEC_DATA_PROCESSING_LOOP; i++) {
		writel(addr, hwd + VP8_BSASET);
		*p++ = readl(hwd + VP8_BSDSET);
		*p++ = readl(hwd + VP8_BSDSET);
		*p++ = readl(hwd + VP8_BSDSET) & 0xFFFFFF;
		addr += 4;
	}
}

static void get_pic_info(struct vdec_vp8_inst *inst, struct vdec_pic_info *pic)
{
	pic->pic_w = inst->vsi->pic.pic_w;
	pic->pic_h = inst->vsi->pic.pic_h;
	pic->buf_w = inst->vsi->pic.buf_w;
	pic->buf_h = inst->vsi->pic.buf_h;
	pic->y_bs_sz = inst->vsi->pic.y_bs_sz;
	pic->c_bs_sz = inst->vsi->pic.c_bs_sz;
	pic->y_len_sz = inst->vsi->pic.y_len_sz;
	pic->c_len_sz = inst->vsi->pic.c_len_sz;

	mtk_vcodec_debug(inst, "pic(%d, %d), buf(%d, %d)",
			 pic->pic_w, pic->pic_h, pic->buf_w, pic->buf_h);
	mtk_vcodec_debug(inst, "Y(%d, %d), C(%d, %d)", pic->y_bs_sz,
			 pic->y_len_sz, pic->c_bs_sz, pic->c_len_sz);
}

static int vp8_dec_finish(struct vdec_vp8_inst *inst)
{
	struct vdec_fb_node *node;
	uint64_t prev_y_dma = inst->vsi->dec.prev_y_dma;

	mtk_vcodec_debug(inst, "prev fb base dma=%llx", prev_y_dma);

	/* put last decode ok frame to dec_free_list */
	if (0 != prev_y_dma) {
		list_for_each_entry(node, &inst->dec_use_list, list) {
			struct vdec_fb *fb = (struct vdec_fb *)node->fb;

			if (prev_y_dma == (unsigned long)fb->base_y.dma_addr) {
				list_move_tail(&node->list,
					       &inst->dec_free_list);
				break;
			}
		}
	}

	/* dec_fb_list -> dec_use_list */
	node = list_first_entry(&inst->dec_fb_list, struct vdec_fb_node, list);
	node->fb = inst->cur_fb;
	list_move_tail(&node->list, &inst->dec_use_list);

	/* disp_fb_list -> disp_rdy_list */
	if (inst->vsi->dec.show_frame) {
		node = list_first_entry(&inst->disp_fb_list,
					struct vdec_fb_node, list);
		node->fb = inst->cur_fb;
		list_move_tail(&node->list, &inst->disp_rdy_list);
	}

	return 0;
}

static void move_fb_list_use_to_free(struct vdec_vp8_inst *inst)
{
	struct vdec_fb_node *node, *tmp;

	list_for_each_entry_safe(node, tmp, &inst->dec_use_list, list)
		list_move_tail(&node->list, &inst->dec_free_list);
}

static void init_list(struct vdec_vp8_inst *inst)
{
	int i;

	INIT_LIST_HEAD(&inst->dec_fb_list);
	INIT_LIST_HEAD(&inst->dec_use_list);
	INIT_LIST_HEAD(&inst->dec_free_list);
	INIT_LIST_HEAD(&inst->disp_fb_list);
	INIT_LIST_HEAD(&inst->disp_rdy_list);

	for (i = 0; i < VP8_MAX_FRM_BUFF_NUM; i++) {
		INIT_LIST_HEAD(&inst->dec_fb[i].list);
		inst->dec_fb[i].fb = NULL;
		list_add_tail(&inst->dec_fb[i].list, &inst->dec_fb_list);

		INIT_LIST_HEAD(&inst->disp_fb[i].list);
		inst->disp_fb[i].fb = NULL;
		list_add_tail(&inst->disp_fb[i].list, &inst->disp_fb_list);
	}
}

static void add_fb_to_free_list(struct vdec_vp8_inst *inst, void *fb)
{
	struct vdec_fb_node *node;

	if (fb) {
		node = list_first_entry(&inst->dec_fb_list,
					struct vdec_fb_node, list);
		node->fb = fb;
		list_move_tail(&node->list, &inst->dec_free_list);
	}
}

static int alloc_all_working_buf(struct vdec_vp8_inst *inst)
{
	int err;
	struct mtk_vcodec_mem *mem = &inst->vp_wrapper_buf;

	mem->size = VP8_VP_WRAP_SZ;
	err = mtk_vcodec_mem_alloc(inst->ctx, mem);
	if (err) {
		mtk_vcodec_err(inst, "Cannot allocate vp wrapper buffer");
		return -ENOMEM;
	}

	inst->vsi->dec.vp_wrapper_dma = (u64)mem->dma_addr;
	return 0;
}

static void free_all_working_buf(struct vdec_vp8_inst *inst)
{
	struct mtk_vcodec_mem *mem = &inst->vp_wrapper_buf;

	if (mem->va)
		mtk_vcodec_mem_free(inst->ctx, mem);

	inst->vsi->dec.vp_wrapper_dma = 0;
}

static int vdec_vp8_init(struct mtk_vcodec_ctx *ctx, unsigned long *h_vdec)
{
	struct vdec_vp8_inst *inst;
	int err;

	inst = kzalloc(sizeof(*inst), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;

	inst->ctx = ctx;

	inst->vpu.id = IPI_VDEC_VP8;
	inst->vpu.dev = ctx->dev->vpu_plat_dev;
	inst->vpu.ctx = ctx;
	inst->vpu.handler = vpu_dec_ipi_handler;

	err = vpu_dec_init(&inst->vpu);
	if (err) {
		mtk_vcodec_err(inst, "vdec_vp8 init err=%d", err);
		goto error_free_inst;
	}

	inst->vsi = (struct vdec_vp8_vsi *)inst->vpu.vsi;
	init_list(inst);
	err = alloc_all_working_buf(inst);
	if (err)
		goto error_free_buf;

	get_hw_reg_base(inst);
	mtk_vcodec_debug(inst, "VP8 Instance >> %p", inst);

	*h_vdec = (unsigned long)inst;
	return 0;

error_free_buf:
	free_all_working_buf(inst);
error_free_inst:
	kfree(inst);
	return err;
}

static int vdec_vp8_decode(unsigned long h_vdec, struct mtk_vcodec_mem *bs,
			   struct vdec_fb *fb, bool *res_chg)
{
	struct vdec_vp8_inst *inst = (struct vdec_vp8_inst *)h_vdec;
	struct vdec_vp8_dec_info *dec = &inst->vsi->dec;
	struct vdec_vpu_inst *vpu = &inst->vpu;
	unsigned char *bs_va;
	unsigned int data;
	int err = 0;
	uint64_t y_fb_dma;
	uint64_t c_fb_dma;

	y_fb_dma = fb ? (u64)fb->base_y.dma_addr : 0;
	c_fb_dma = fb ? (u64)fb->base_c.dma_addr : 0;

	mtk_vcodec_debug(inst, "+ [%d] FB y_dma=%llx c_dma=%llx fb=%p",
			 inst->frm_cnt, y_fb_dma, c_fb_dma, fb);

	inst->cur_fb = fb;

	/* bs NULL means flush decoder */
	if (bs == NULL) {
		move_fb_list_use_to_free(inst);
		return vpu_dec_reset(vpu);
	}

	bs_va = (unsigned char *)bs->va;
	data = (*(bs_va + 9) << 24) | (*(bs_va + 8) << 16) |
	       (*(bs_va + 7) << 8) | *(bs_va + 6);

	dec->bs_dma = (unsigned long)bs->dma_addr;
	dec->bs_sz = bs->size;
	dec->cur_y_fb_dma = y_fb_dma;
	dec->cur_c_fb_dma = c_fb_dma;

	mtk_vcodec_debug(inst, "\n + FRAME[%d] +\n", inst->frm_cnt);

	write_hw_data(inst);
	enable_hw_rw_dec_data(inst);
	store_dec_data(inst);

	err = vpu_dec_start(vpu, &data, 1);
	if (err) {
		add_fb_to_free_list(inst, fb);
		if (dec->wait_key_frame) {
			mtk_vcodec_debug(inst, "wait key frame !");
			return 0;
		}

		goto error;
	}

	if (dec->resolution_changed) {
		mtk_vcodec_debug(inst, "- resolution_changed -");
		*res_chg = true;
		add_fb_to_free_list(inst, fb);
		return 0;
	}

	/* wait decoder done interrupt */
	mtk_vcodec_wait_for_done_ctx(inst->ctx, MTK_INST_IRQ_RECEIVED,
				     WAIT_INTR_TIMEOUT_MS);

	if (inst->vsi->load_data)
		load_dec_data(inst);

	vp8_dec_finish(inst);
	read_hw_data(inst);

	err = vpu_dec_end(vpu);
	if (err)
		goto error;

	mtk_vcodec_debug(inst, "\n - FRAME[%d] - show=%d\n", inst->frm_cnt,
			 dec->show_frame);
	inst->frm_cnt++;
	*res_chg = false;
	return 0;

error:
	mtk_vcodec_err(inst, "\n - FRAME[%d] - err=%d\n", inst->frm_cnt, err);
	return err;
}

static void get_disp_fb(struct vdec_vp8_inst *inst, struct vdec_fb **out_fb)
{
	struct vdec_fb_node *node;
	struct vdec_fb *fb;

	node = list_first_entry_or_null(&inst->disp_rdy_list,
					struct vdec_fb_node, list);
	if (node) {
		list_move_tail(&node->list, &inst->disp_fb_list);
		fb = (struct vdec_fb *)node->fb;
		fb->status |= FB_ST_DISPLAY;
		mtk_vcodec_debug(inst, "[FB] get disp fb %p st=%d",
				 node->fb, fb->status);
	} else {
		fb = NULL;
		mtk_vcodec_debug(inst, "[FB] there is no disp fb");
	}

	*out_fb = fb;
}

static void get_free_fb(struct vdec_vp8_inst *inst, struct vdec_fb **out_fb)
{
	struct vdec_fb_node *node;
	struct vdec_fb *fb;

	node = list_first_entry_or_null(&inst->dec_free_list,
					struct vdec_fb_node, list);
	if (node) {
		list_move_tail(&node->list, &inst->dec_fb_list);
		fb = (struct vdec_fb *)node->fb;
		fb->status |= FB_ST_FREE;
		mtk_vcodec_debug(inst, "[FB] get free fb %p st=%d",
				 node->fb, fb->status);
	} else {
		fb = NULL;
		mtk_vcodec_debug(inst, "[FB] there is no free fb");
	}

	*out_fb = fb;
}

static void get_crop_info(struct vdec_vp8_inst *inst, struct v4l2_crop *cr)
{
	cr->c.left = 0;
	cr->c.top = 0;
	cr->c.width = inst->vsi->pic.pic_w;
	cr->c.height = inst->vsi->pic.pic_h;
	mtk_vcodec_debug(inst, "get crop info l=%d, t=%d, w=%d, h=%d",
			 cr->c.left, cr->c.top, cr->c.width, cr->c.height);
}

static int vdec_vp8_get_param(unsigned long h_vdec,
			      enum vdec_get_param_type type, void *out)
{
	struct vdec_vp8_inst *inst = (struct vdec_vp8_inst *)h_vdec;

	switch (type) {
	case GET_PARAM_DISP_FRAME_BUFFER:
		get_disp_fb(inst, out);
		break;

	case GET_PARAM_FREE_FRAME_BUFFER:
		get_free_fb(inst, out);
		break;

	case GET_PARAM_PIC_INFO:
		get_pic_info(inst, out);
		break;

	case GET_PARAM_CROP_INFO:
		get_crop_info(inst, out);
		break;

	case GET_PARAM_DPB_SIZE:
		*((unsigned int *)out) = 4;
		break;

	default:
		mtk_vcodec_err(inst, "invalid get parameter type=%d", type);
		return -EINVAL;
	}

	return 0;
}

static int vdec_vp8_deinit(unsigned long h_vdec)
{
	struct vdec_vp8_inst *inst = (struct vdec_vp8_inst *)h_vdec;

	mtk_vcodec_debug_enter(inst);

	vpu_dec_deinit(&inst->vpu);
	free_all_working_buf(inst);
	kfree(inst);

	return 0;
}

static struct vdec_common_if vdec_vp8_if = {
	vdec_vp8_init,
	vdec_vp8_decode,
	vdec_vp8_get_param,
	vdec_vp8_deinit,
};

struct vdec_common_if *get_vp8_dec_comm_if(void)
{
	return &vdec_vp8_if;
}
