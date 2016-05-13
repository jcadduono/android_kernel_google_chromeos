/*
 * Copyright (c) 2016 MediaTek Inc.
 * Author: Daniel Hsiao <daniel.hsiao@mediatek.com>
 *		Kai-Sean Yang <kai-sean.yang@mediatek.com>
 *		Tiffany Lin <tiffany.lin@mediatek.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/time.h>

#include "../mtk_vcodec_intr.h"
#include "../vdec_drv_base.h"
#include "../vdec_vpu_if.h"

#define VP9_SUPER_FRAME_BS_SZ 64
#define MAX_VP9_DPB_SIZE	9

#define REFS_PER_FRAME 3
#define MAX_NUM_REF_FRAMES 8
#define VP9_MAX_FRM_BUF_NUM 9
#define VP9_MAX_FRM_BUF_NODE_NUM (VP9_MAX_FRM_BUF_NUM * 2)
#define MAX_CODED_WIDTH		4096U
#define MAX_CODED_HEIGHT	2304U


struct vdec_vp9_frm_hdr {
	unsigned int width;
	unsigned int height;
	unsigned char show_frame;
};

struct vdec_vp9_work_buf {
	unsigned int buf_w;
	unsigned int buf_h;
	struct mtk_vcodec_mem mv_buf;
};

struct vp9_input_ctx {
	unsigned long v_fifo_sa;
	unsigned long v_fifo_ea;
	unsigned long p_fifo_sa;
	unsigned long p_fifo_ea;
	unsigned long v_frm_sa;
	unsigned long v_frm_ea;
	unsigned long p_frm_sa;
	unsigned long p_frm_end;
	unsigned int frm_sz;
	unsigned int uncompress_sz;
};

struct vp9_dram_buf {
	unsigned long va;
	unsigned long pa;
	unsigned int sz;
	unsigned int vpua;
};

struct vp9_fb_info {
	struct vdec_fb *fb;
	struct vp9_dram_buf y_buf;
	struct vp9_dram_buf c_buf;
	struct vp9_dram_buf ufo_len_y;
	struct vp9_dram_buf ufo_len_c;
	unsigned int y_width;
	unsigned int y_height;
	unsigned int y_crop_width;
	unsigned int y_crop_height;

	unsigned int c_width;
	unsigned int c_height;
	unsigned int c_crop_width;
	unsigned int c_crop_height;

	unsigned int frm_num;
};

struct vp9_ref_cnt_buf {
	struct vp9_fb_info buf;
	unsigned int ref_cnt;
};

struct vp9_scale_factors {
	int x_scale_fp;
	int y_scale_fp;
	int x_step_q4;
	int y_step_q4;
	unsigned int ref_scaling_en;
};

struct vp9_ref_buf {
	struct vp9_fb_info *buf;
	struct vp9_scale_factors scale_factors;
	unsigned int idx;
};

struct vp9_sf_ref_fb {
	struct vdec_fb fb;
	int used;
	int idx;
};

/*
 * struct vdec_vp9_vsi - shared buffer between host and VPU firmware
 */
struct vdec_vp9_vsi {
	unsigned char sf_bs_buf[VP9_SUPER_FRAME_BS_SZ];
	struct vp9_sf_ref_fb sf_ref_fb[VP9_MAX_FRM_BUF_NUM-1];
	int sf_next_ref_fb_idx;
	unsigned int sf_frm_cnt;
	unsigned int sf_frm_offset[VP9_MAX_FRM_BUF_NUM-1];
	unsigned int sf_frm_sz[VP9_MAX_FRM_BUF_NUM-1];
	unsigned int sf_frm_idx;
	unsigned int sf_init;
	struct vdec_fb fb;
	struct mtk_vcodec_mem bs;
	struct vdec_fb cur_fb;
	unsigned int pic_w;
	unsigned int pic_h;
	unsigned int buf_w;
	unsigned int buf_h;
	unsigned int buf_sz_y_bs;
	unsigned int buf_sz_c_bs;
	unsigned int buf_len_sz_y;
	unsigned int buf_len_sz_c;
	unsigned int profile;
	unsigned int show_frame;
	unsigned int show_existing_frame;
	unsigned int frm_to_show;
	unsigned int refresh_frm_flags;
	unsigned int resolution_changed;

	struct vp9_input_ctx input_ctx;
	struct vp9_ref_cnt_buf frm_bufs[VP9_MAX_FRM_BUF_NUM];
	int ref_frm_map[MAX_NUM_REF_FRAMES];

	unsigned int new_fb_idx;
	unsigned int frm_num;

	struct vp9_dram_buf seg_id_buf;
	struct vp9_dram_buf tile_buf;
	struct vp9_dram_buf count_tbl_buf;
	struct vp9_dram_buf prob_tbl_buf;
	struct vp9_dram_buf mv_buf;
	struct vp9_ref_buf frm_refs[REFS_PER_FRAME];
};

struct vdec_vp9_inst {
	struct vdec_vp9_work_buf work_buf;
	struct vdec_vp9_frm_hdr frm_hdr;
	struct vdec_fb_node dec_fb[VP9_MAX_FRM_BUF_NODE_NUM];
	struct list_head available_fb_node_list;
	struct list_head fb_use_list;
	struct list_head fb_free_list;
	struct list_head fb_disp_list;
	struct vdec_fb *cur_fb;
	unsigned int frm_cnt;
	unsigned int total_frm_cnt;
	void *ctx;
	struct vdec_vpu_inst vpu;
	struct vdec_vp9_vsi *vsi;
	unsigned int show_reg;
	struct mtk_vcodec_mem mem;
};

static bool vp9_is_sf_ref_fb(struct vdec_vp9_inst *inst, struct vdec_fb *fb)
{
	int i;
	struct vdec_vp9_vsi *vsi = inst->vsi;

	for (i = 0; i < ARRAY_SIZE(vsi->sf_ref_fb); i++) {
		if (fb == &vsi->sf_ref_fb[i].fb)
			return true;
	}
	return false;
}

static struct vdec_fb *vp9_rm_from_fb_use_list(struct vdec_vp9_inst
					*inst, void *addr)
{
	struct vdec_fb *fb = NULL;
	struct vdec_fb_node *node;

	list_for_each_entry(node, &inst->fb_use_list, list) {
		fb = (struct vdec_fb *)node->fb;
		if (fb->base_y.va == addr) {
			list_move_tail(&node->list,
				       &inst->available_fb_node_list);
			break;
		}
	}
	return fb;
}

static void vp9_add_to_fb_free_list(struct vdec_vp9_inst *inst,
			     struct vdec_fb *fb)
{
	struct vdec_fb_node *node;

	if (fb) {
		node = list_first_entry_or_null(&inst->available_fb_node_list,
					struct vdec_fb_node, list);

		if (node) {
			node->fb = fb;
			list_move_tail(&node->list, &inst->fb_free_list);
		}
	} else {
		mtk_vcodec_debug(inst, "No free fb node");
	}
}

static void vp9_free_sf_ref_fb(struct vdec_fb *fb)
{
	struct vp9_sf_ref_fb *sf_ref_fb =
		container_of(fb, struct vp9_sf_ref_fb, fb);

	sf_ref_fb->used = 0;
}

static void vp9_ref_cnt_fb(struct vdec_vp9_inst *inst, int *idx,
			   int new_idx)
{
	struct vdec_vp9_vsi *vsi = inst->vsi;
	int ref_idx = *idx;

	if (ref_idx >= 0 && vsi->frm_bufs[ref_idx].ref_cnt > 0) {
		vsi->frm_bufs[ref_idx].ref_cnt--;

		if (vsi->frm_bufs[ref_idx].ref_cnt == 0) {
			if (!vp9_is_sf_ref_fb(inst,
					      vsi->frm_bufs[ref_idx].buf.fb)) {
				struct vdec_fb *fb;

				fb = vp9_rm_from_fb_use_list(inst,
				     vsi->frm_bufs[ref_idx].buf.fb->base_y.va);
				vp9_add_to_fb_free_list(inst, fb);
			} else
				vp9_free_sf_ref_fb(vsi->frm_bufs[ref_idx].buf.fb);
		}
	}

	*idx = new_idx;
	vsi->frm_bufs[new_idx].ref_cnt++;
}

static void vp9_free_all_sf_ref_fb(struct vdec_vp9_inst *inst)
{
	int i;
	struct vdec_vp9_vsi *vsi = inst->vsi;

	for (i = 0; i < ARRAY_SIZE(vsi->sf_ref_fb); i++) {
		if (vsi->sf_ref_fb[i].fb.base_y.va) {
			mtk_vcodec_mem_free(inst->ctx,
				&vsi->sf_ref_fb[i].fb.base_y);
			mtk_vcodec_mem_free(inst->ctx,
				&vsi->sf_ref_fb[i].fb.base_c);
			vsi->sf_ref_fb[i].used = 0;
		}
	}
}

/* For each sub-frame except the last one, the driver will dynamically
 * allocate reference buffer by calling vp9_get_sf_ref_fb()
 * The last sub-frame will use the original fb provided by the
 * vp9_dec_decode() interface
 */
static int vp9_get_sf_ref_fb(struct vdec_vp9_inst *inst)
{
	int idx;
	struct mtk_vcodec_mem *mem_basy_y;
	struct mtk_vcodec_mem *mem_basy_c;
	struct vdec_vp9_vsi *vsi = inst->vsi;

	if ((inst->frm_hdr.width > MAX_CODED_WIDTH) ||
		(inst->frm_hdr.height > MAX_CODED_HEIGHT)) {
		mtk_vcodec_err(inst, "Invalid w/h %d/%d",
									inst->frm_hdr.width,
									inst->frm_hdr.height);
		return -1;
	}

	for (idx = 0;
			idx < ARRAY_SIZE(vsi->sf_ref_fb);
			idx++) {
		if (vsi->sf_ref_fb[idx].fb.base_y.va &&
		    vsi->sf_ref_fb[idx].used == 0) {
			return idx;
		}
	}

	for (idx = 0;
			idx < ARRAY_SIZE(vsi->sf_ref_fb);
			idx++) {
		if (vsi->sf_ref_fb[idx].fb.base_y.va == NULL)
			break;
	}

	if (idx == ARRAY_SIZE(vsi->sf_ref_fb)) {
		mtk_vcodec_err(inst, "List Full");
		return -1;
	}

	mem_basy_y = &vsi->sf_ref_fb[idx].fb.base_y;
	mem_basy_y->size = vsi->buf_sz_y_bs +
		    vsi->buf_len_sz_y;

	if (mtk_vcodec_mem_alloc(inst->ctx, mem_basy_y)) {
		mtk_vcodec_err(inst, "Cannot allocate sf_ref_buf y_buf");
		return -1;
	}

	mem_basy_c = &vsi->sf_ref_fb[idx].fb.base_c;
	mem_basy_c->size = vsi->buf_sz_c_bs +
		    vsi->buf_len_sz_c;

	if (mtk_vcodec_mem_alloc(inst->ctx, mem_basy_c)) {
		mtk_vcodec_err(inst, "Cannot allocate sf_ref_fb c_buf");
		return -1;
	}
	vsi->sf_ref_fb[idx].used = 0;
	vsi->sf_ref_fb[idx].idx = idx;

	return idx;
}

static bool vp9_alloc_work_buf(struct vdec_vp9_inst *inst)
{
	struct vdec_vp9_vsi *vsi = inst->vsi;
	int result;
	struct mtk_vcodec_mem *mem;

	if ((vsi->pic_w > MAX_CODED_WIDTH) ||
			(vsi->pic_h > MAX_CODED_HEIGHT)) {
		mtk_vcodec_err(inst, "Invalid w/h %d/%d",
									inst->frm_hdr.width,
									inst->frm_hdr.height);
		return false;
	}

	inst->frm_hdr.width = vsi->pic_w;
	inst->frm_hdr.height = vsi->pic_h;
	inst->work_buf.buf_w = vsi->buf_w;
	inst->work_buf.buf_h = vsi->buf_h;

	mtk_vcodec_debug(inst, "BUF CHG(%d): w/h/sb_w/sb_h=%d/%d/%d/%d",
		     vsi->resolution_changed,
		     inst->frm_hdr.width,
		     inst->frm_hdr.height,
		     inst->work_buf.buf_w,
		     inst->work_buf.buf_h);

	mem = &inst->work_buf.mv_buf;

	if (mem->va)
		mtk_vcodec_mem_free(inst->ctx, mem);

	mem->size = ((inst->work_buf.buf_w / 64) *
		    (inst->work_buf.buf_h / 64) + 2) * 36 * 16;

	result = mtk_vcodec_mem_alloc(inst->ctx, mem);
	if (result) {
		mem->size = 0;
		mtk_vcodec_err(inst, "Cannot allocate mv_buf");
		return false;
	}
	/* Set the va again */
	vsi->mv_buf.va = (unsigned long)mem->va;
	vsi->mv_buf.pa = (unsigned long)mem->dma_addr;
	vsi->mv_buf.sz = (unsigned int)mem->size;

	vp9_free_all_sf_ref_fb(inst);
	vsi->sf_next_ref_fb_idx = vp9_get_sf_ref_fb(inst);

	return true;
}

static bool vp9_add_to_fb_disp_list(struct vdec_vp9_inst *inst,
			     struct vdec_fb *fb)
{
	struct vdec_fb_node *node;

	if (!fb) {
		mtk_vcodec_err(inst, "fb == NULL");
		return false;
	}

	node = list_first_entry_or_null(&inst->available_fb_node_list,
					struct vdec_fb_node, list);
	if (node) {
		node->fb = fb;
		list_move_tail(&node->list, &inst->fb_disp_list);
	} else {
		mtk_vcodec_err(inst, "No available fb node");
		return false;
	}

	return true;
}

/* If any buffer updating is signaled it should be done here. */
static void vp9_swap_frm_bufs(struct vdec_vp9_inst *inst)
{
	struct vdec_vp9_vsi *vsi = inst->vsi;
	struct vp9_fb_info *frm_to_show;
	int ref_index = 0, mask;

	for (mask = vsi->refresh_frm_flags; mask; mask >>= 1) {
		if (mask & 1)
			vp9_ref_cnt_fb(inst, &vsi->ref_frm_map[ref_index],
				       vsi->new_fb_idx);
		++ref_index;
	}

	frm_to_show = &vsi->frm_bufs[vsi->new_fb_idx].buf;
	vsi->frm_bufs[vsi->new_fb_idx].ref_cnt--;

	if (frm_to_show->fb != inst->cur_fb) {
		/* This frame is show exist frame and no decode output
		  * copy frame data from frm_to_show to current CAPTURE
		  * buffer
		  */
		if ((frm_to_show->fb != NULL) &&
				(inst->cur_fb->base_y.size >=
				frm_to_show->fb->base_y.size)) {
			memcpy((void *)inst->cur_fb->base_y.va,
					(void *)frm_to_show->fb->base_y.va,
					inst->work_buf.buf_w *
					inst->work_buf.buf_h);
			memcpy((void *)inst->cur_fb->base_c.va,
					(void *)frm_to_show->fb->base_c.va,
					inst->work_buf.buf_w *
					inst->work_buf.buf_h / 2);
		} else {
			/* After resolution change case, current CAPTURE buffer
			  * may have less buffer size than frm_to_show buffer
			  * size
			  */
			if (frm_to_show->fb != NULL)
				mtk_vcodec_err(inst,
					"inst->cur_fb->base_y.size=%lx, frm_to_show->fb.base_y.size=%lx",
					inst->cur_fb->base_y.size,
					frm_to_show->fb->base_y.size);
		}
		if (!vp9_is_sf_ref_fb(inst, inst->cur_fb)) {
			if (inst->frm_hdr.show_frame)
				vp9_add_to_fb_disp_list(inst, inst->cur_fb);
		}
	} else {
		if (!vp9_is_sf_ref_fb(inst, inst->cur_fb)) {
			if (inst->frm_hdr.show_frame)
				vp9_add_to_fb_disp_list(inst, frm_to_show->fb);
		}
	}

	/* when ref_cnt ==0, move this fb to fb_free_list. v4l2 driver will
	 * clean fb_free_list
	 */
	if (vsi->frm_bufs[vsi->new_fb_idx].ref_cnt == 0) {
		if (!vp9_is_sf_ref_fb(
			inst, vsi->frm_bufs[vsi->new_fb_idx].buf.fb)) {
			struct vdec_fb *fb;

			fb = vp9_rm_from_fb_use_list(inst,
			     vsi->frm_bufs[vsi->new_fb_idx].buf.fb->base_y.va);

			vp9_add_to_fb_free_list(inst, fb);
		} else {
			vp9_free_sf_ref_fb(vsi->frm_bufs[vsi->new_fb_idx].buf.fb);
		}
	}

	/* if this super frame and it is not last sub-frame, get next fb for
	 * sub-frame decode
	 */
	if (vsi->sf_frm_cnt > 0 && vsi->sf_frm_idx != vsi->sf_frm_cnt - 1)
		vsi->sf_next_ref_fb_idx = vp9_get_sf_ref_fb(inst);
}

static bool vp9_wait_dec_end(struct vdec_vp9_inst *inst)
{
	struct mtk_vcodec_ctx *ctx = inst->ctx;

	mtk_vcodec_wait_for_done_ctx(inst->ctx,
						MTK_INST_IRQ_RECEIVED,
						WAIT_INTR_TIMEOUT_MS);

	if (ctx->irq_status & MTK_VDEC_IRQ_STATUS_DEC_SUCCESS)
		return true;
	else
		return false;
}

static struct vdec_vp9_inst *vp9_alloc_inst(struct mtk_vcodec_ctx *ctx)
{
	int result;
	struct mtk_vcodec_mem mem;
	struct vdec_vp9_inst *inst;

	memset(&mem, 0, sizeof(mem));
	mem.size = sizeof(struct vdec_vp9_inst);
	result = mtk_vcodec_mem_alloc(ctx, &mem);
	if (result)
		return NULL;

	inst = mem.va;
	inst->mem = mem;

	return inst;
}

static void vp9_free_inst(struct vdec_vp9_inst *inst)
{
	struct mtk_vcodec_mem mem;

	mem = inst->mem;
	if (mem.va)
		mtk_vcodec_mem_free(inst->ctx, &mem);
}

static bool vp9_decode_end_proc(struct vdec_vp9_inst *inst)
{
	struct vdec_vp9_vsi *vsi = inst->vsi;
	bool ret = false;

	if (!vsi->show_existing_frame) {
		ret = vp9_wait_dec_end(inst);
		if (!ret) {
			mtk_vcodec_err(inst, "Decode failed, Decode Timeout @[%d]",
					   vsi->frm_num);
			return false;
		}

		if (vpu_dec_end(&inst->vpu)) {
			mtk_vcodec_err(inst, "vp9_dec_vpu_end failed");
			return false;
		}
		mtk_vcodec_debug(inst, "Decode Ok @%d (%d/%d)", vsi->frm_num,
					inst->frm_hdr.width, inst->frm_hdr.height);
	} else {
		mtk_vcodec_debug(inst, "Decode Ok @%d (show_existing_frame)",
					vsi->frm_num);
	}

	vp9_swap_frm_bufs(inst);
	vsi->frm_num++;
	return true;
}

static bool vp9_is_last_sub_frm(struct vdec_vp9_inst *inst)
{
	struct vdec_vp9_vsi *vsi = inst->vsi;

	if (vsi->sf_frm_cnt <= 0 || vsi->sf_frm_idx == vsi->sf_frm_cnt)
		return true;

	return false;
}

static struct vdec_fb *vp9_rm_from_fb_disp_list(struct vdec_vp9_inst *inst)
{
	struct vdec_fb_node *node;
	struct vdec_fb *fb = NULL;

	node = list_first_entry_or_null(&inst->fb_disp_list,
					struct vdec_fb_node, list);
	if (node) {
		fb = (struct vdec_fb *)node->fb;
		fb->status |= FB_ST_DISPLAY;
		list_move_tail(&node->list, &inst->available_fb_node_list);
		mtk_vcodec_debug(inst, "[FB] get disp fb %p st=%d",
				 node->fb, fb->status);
	} else
		mtk_vcodec_debug(inst, "[FB] there is no disp fb");

	return fb;
}

static bool vp9_add_to_fb_use_list(struct vdec_vp9_inst *inst,
			    struct vdec_fb *fb)
{
	struct vdec_fb_node *node;

	if (!fb) {
		mtk_vcodec_debug(inst, "fb == NULL");
		return false;
	}

	node = list_first_entry_or_null(&inst->available_fb_node_list,
					struct vdec_fb_node, list);
	if (node) {
		node->fb = fb;
		list_move_tail(&node->list, &inst->fb_use_list);
	} else {
		mtk_vcodec_err(inst, "No free fb node");
		return false;
	}
	return true;
}

static void vp9_reset(struct vdec_vp9_inst *inst)
{
	struct vdec_fb_node *node, *tmp;

	list_for_each_entry_safe(node, tmp, &inst->fb_use_list, list)
		list_move_tail(&node->list, &inst->fb_free_list);

	vp9_free_all_sf_ref_fb(inst);
	inst->vsi->sf_next_ref_fb_idx = vp9_get_sf_ref_fb(inst);

	if (vpu_dec_reset(&inst->vpu))
		mtk_vcodec_err(inst, "vp9_dec_vpu_reset failed");

	/* Set the va again, since vpu_dec_reset will clear mv_buf in vpu */
	inst->vsi->mv_buf.va = (unsigned long)inst->work_buf.mv_buf.va;
	inst->vsi->mv_buf.pa = (unsigned long)inst->work_buf.mv_buf.dma_addr;
	inst->vsi->mv_buf.sz = (unsigned long)inst->work_buf.mv_buf.size;
}

static void init_all_fb_lists(struct vdec_vp9_inst *inst)
{
	int i;

	INIT_LIST_HEAD(&inst->available_fb_node_list);
	INIT_LIST_HEAD(&inst->fb_use_list);
	INIT_LIST_HEAD(&inst->fb_free_list);
	INIT_LIST_HEAD(&inst->fb_disp_list);

	for (i = 0; i < ARRAY_SIZE(inst->dec_fb); i++) {
		INIT_LIST_HEAD(&inst->dec_fb[i].list);
		inst->dec_fb[i].fb = NULL;
		list_add_tail(&inst->dec_fb[i].list,
			      &inst->available_fb_node_list);
	}
}

static void get_pic_info(struct vdec_vp9_inst *inst, struct vdec_pic_info *pic)
{
	pic->y_bs_sz = inst->vsi->buf_sz_y_bs;
	pic->c_bs_sz = inst->vsi->buf_sz_c_bs;
	pic->y_len_sz = inst->vsi->buf_len_sz_y;
	pic->c_len_sz = inst->vsi->buf_len_sz_c;

	pic->pic_w = inst->frm_hdr.width;
	pic->pic_h = inst->frm_hdr.height;
	pic->buf_w = inst->work_buf.buf_w;
	pic->buf_h = inst->work_buf.buf_h;

	mtk_vcodec_debug(inst, "pic(%d, %d), buf(%d, %d)",
		 pic->pic_w, pic->pic_h, pic->buf_w, pic->buf_h);
	mtk_vcodec_debug(inst, "Y(%d, %d), C(%d, %d)", pic->y_bs_sz,
		 pic->y_len_sz, pic->c_bs_sz, pic->c_len_sz);
}

static void get_disp_fb(struct vdec_vp9_inst *inst, struct vdec_fb **out_fb)
{

	*out_fb = vp9_rm_from_fb_disp_list(inst);
	if (*out_fb)
		(*out_fb)->status |= FB_ST_DISPLAY;
}

static void get_free_fb(struct vdec_vp9_inst *inst, struct vdec_fb **out_fb)
{
	struct vdec_fb_node *node;
	struct vdec_fb *fb = NULL;

	node = list_first_entry_or_null(&inst->fb_free_list,
					struct vdec_fb_node, list);
	if (node) {
		list_move_tail(&node->list, &inst->available_fb_node_list);
		fb = (struct vdec_fb *)node->fb;
		fb->status |= FB_ST_FREE;
		mtk_vcodec_debug(inst, "[FB] get free fb %p st=%d",
				 node->fb, fb->status);
	} else {
		mtk_vcodec_debug(inst, "[FB] there is no free fb");
	}

	*out_fb = fb;
}

static int vdec_vp9_deinit(unsigned long h_vdec)
{
	struct vdec_vp9_inst *inst = (struct vdec_vp9_inst *)h_vdec;
	struct mtk_vcodec_mem *mem;
	int ret = 0;

	ret = vpu_dec_deinit(&inst->vpu);
	if (ret)
		mtk_vcodec_err(inst, "vpu_dec_deinit failed");

	mem = &inst->work_buf.mv_buf;
	if (mem->va)
		mtk_vcodec_mem_free(inst->ctx, mem);

	vp9_free_all_sf_ref_fb(inst);
	vp9_free_inst(inst);

	return ret;
}

static int vdec_vp9_init(struct mtk_vcodec_ctx *ctx, unsigned long *h_vdec)
{
	struct vdec_vp9_inst *inst;

	inst = vp9_alloc_inst(ctx);
	if (!inst)
		return -ENOMEM;

	inst->frm_cnt = 0;
	inst->total_frm_cnt = 0;
	inst->ctx = ctx;

	inst->vpu.id = IPI_VDEC_VP9;
	inst->vpu.dev = ctx->dev->vpu_plat_dev;
	inst->vpu.ctx = ctx;
	inst->vpu.handler = vpu_dec_ipi_handler;

	if (vpu_dec_init(&inst->vpu)) {
		mtk_vcodec_err(inst, "vp9_dec_vpu_init failed");
		goto err_deinit_inst;
	}

	inst->vsi = (struct vdec_vp9_vsi *)inst->vpu.vsi;
	init_all_fb_lists(inst);

	(*h_vdec) = (unsigned long)inst;
	return 0;

err_deinit_inst:
	vp9_free_inst(inst);

	return -EINVAL;
}

static int vdec_vp9_decode(unsigned long h_vdec, struct mtk_vcodec_mem *bs,
		   struct vdec_fb *fb, bool *res_chg)
{
	int ret = 0;
	struct vdec_vp9_inst *inst = (struct vdec_vp9_inst *)h_vdec;
	struct vdec_vp9_vsi *vsi = inst->vsi;
	u32 data[3];
	int i;

	*res_chg = false;

	if ((bs == NULL) && (fb == NULL)) {
		mtk_vcodec_debug(inst, "[EOS]");
		vp9_reset(inst);
		return ret;
	}

	if (bs == NULL) {
		mtk_vcodec_err(inst, "bs == NULL");
		return -EINVAL;;
	}

	mtk_vcodec_debug(inst, "Input BS Size = %ld", bs->size);

	while (1) {
		struct vdec_fb *cur_fb = NULL;

		data[0] = *((unsigned int *)bs->va);
		data[1] = *((unsigned int *)(bs->va + 4));
		data[2] = *((unsigned int *)(bs->va + 8));

		vsi->bs = *bs;

		if (fb)
			vsi->fb = *fb;

		if (!vsi->sf_init) {
			unsigned int sf_bs_sz;
			unsigned int sf_bs_off;
			unsigned char *sf_bs_src;
			unsigned char *sf_bs_dst;

			sf_bs_sz = bs->size > VP9_SUPER_FRAME_BS_SZ ?
								VP9_SUPER_FRAME_BS_SZ : bs->size;
			sf_bs_off = VP9_SUPER_FRAME_BS_SZ - sf_bs_sz;
			sf_bs_src = bs->va + bs->size - sf_bs_sz;
			sf_bs_dst = vsi->sf_bs_buf + sf_bs_off;
			memcpy(sf_bs_dst, sf_bs_src, sf_bs_sz);
		} else {
			if ((vsi->sf_frm_cnt > 0) &&
				(vsi->sf_frm_idx < vsi->sf_frm_cnt)) {
				unsigned int idx = vsi->sf_frm_idx;

				memcpy((void *)vsi->input_ctx.v_frm_sa,
					   (void *)(vsi->input_ctx.v_frm_sa +
					   vsi->sf_frm_offset[idx]),
					   vsi->sf_frm_sz[idx]);
			}
		}
		ret = vpu_dec_start(&inst->vpu, data, 3);
		if (ret) {
			mtk_vcodec_err(inst, "vpu_dec_start failed");
			goto DECODE_ERROR;
		}

		if (vsi->resolution_changed) {
			if (!vp9_alloc_work_buf(inst)) {
				ret = -EINVAL;
				goto DECODE_ERROR;
			}
		}

		if (vsi->sf_frm_cnt > 0) {
			cur_fb = &vsi->sf_ref_fb[vsi->sf_next_ref_fb_idx].fb;

			if (vsi->sf_frm_idx < vsi->sf_frm_cnt)
				inst->cur_fb = cur_fb;
			else
				inst->cur_fb = fb;
		} else {
			inst->cur_fb = fb;
		}

		vsi->frm_bufs[vsi->new_fb_idx].buf.fb = inst->cur_fb;
		if (!vp9_is_sf_ref_fb(inst, inst->cur_fb))
			vp9_add_to_fb_use_list(inst, inst->cur_fb);

		mtk_vcodec_debug(inst, "[#pic %d]", vsi->frm_num);

		/* the same as VP9_SKIP_FRAME */
		inst->frm_hdr.show_frame = vsi->show_frame;

		if (vsi->show_existing_frame)
			mtk_vcodec_debug(inst,
				"drv->new_fb_idx=%d, drv->frm_to_show=%d",
				vsi->new_fb_idx, vsi->frm_to_show);

		if (vsi->show_existing_frame && (vsi->frm_to_show <
					VP9_MAX_FRM_BUF_NUM)) {
			mtk_vcodec_err(inst,
				"Skip Decode drv->new_fb_idx=%d, drv->frm_to_show=%d",
				vsi->new_fb_idx, vsi->frm_to_show);

			vp9_ref_cnt_fb(inst, &vsi->new_fb_idx,
							vsi->frm_to_show);
			ret = -EINVAL;
			goto DECODE_ERROR;
		}

		/* VPU assign the buffer pointer in its address space,
		 * reassign here
		 */
		for (i = 0; i < ARRAY_SIZE(vsi->frm_refs); i++) {
			unsigned int idx = vsi->frm_refs[i].idx;

			vsi->frm_refs[i].buf = &vsi->frm_bufs[idx].buf;
		}

		if (vsi->resolution_changed) {
			*res_chg = true;
			mtk_vcodec_debug(inst, "VDEC_ST_RESOLUTION_CHANGED");

			ret = 0;
			goto DECODE_ERROR;
		}

		if (vp9_decode_end_proc(inst) != true) {
			mtk_vcodec_err(inst, "vp9_decode_end_proc");
			ret = -EINVAL;
			goto DECODE_ERROR;
		}

		inst->total_frm_cnt++;
		if (vp9_is_last_sub_frm(inst))
			break;

	}
	inst->frm_cnt++;

DECODE_ERROR:
	if (ret < 0)
		vp9_add_to_fb_free_list(inst, fb);

	return ret;
}

static void get_crop_info(struct vdec_vp9_inst *inst, struct v4l2_crop *cr)
{
	cr->c.left = 0;
	cr->c.top = 0;
	cr->c.width = inst->frm_hdr.width;
	cr->c.height = inst->frm_hdr.height;
	mtk_vcodec_debug(inst, "get crop info l=%d, t=%d, w=%d, h=%d\n",
			 cr->c.left, cr->c.top, cr->c.width, cr->c.height);
}

static int vdec_vp9_get_param(unsigned long h_vdec,
			enum vdec_get_param_type type, void *out)
{
	struct vdec_vp9_inst *inst = (struct vdec_vp9_inst *)h_vdec;
	int ret = 0;

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
	case GET_PARAM_DPB_SIZE:
		*((unsigned int *)out) = MAX_VP9_DPB_SIZE;
		break;
	case GET_PARAM_CROP_INFO:
		get_crop_info(inst, out);
		break;
	default:
		mtk_vcodec_err(inst, "not supported param type %d", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static struct vdec_common_if vdec_vp9_if = {
	vdec_vp9_init,
	vdec_vp9_decode,
	vdec_vp9_get_param,
	vdec_vp9_deinit,
};

struct vdec_common_if *get_vp9_dec_comm_if(void);

struct vdec_common_if *get_vp9_dec_comm_if(void)
{
	return &vdec_vp9_if;
}
