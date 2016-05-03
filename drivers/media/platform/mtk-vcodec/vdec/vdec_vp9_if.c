/*
 * Copyright (c) 2016 MediaTek Inc.
 * Author: Daniel Hsiao <daniel.hsiao@mediatek.com>
 *             Kai-Sean Yang <kai-sean.yang@mediatek.com>
 *		  Tiffany Lin <tiffany.lin@mediatek.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
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

#define REFS_PER_FRAME 3
#define REF_FRAMES_LOG2 3
#define REF_FRAMES (1 << REF_FRAMES_LOG2)
#define VP9_MAX_FRM_BUFF_NUM (9 + 0)
#define VP9_MAX_FRM_BUFF_NODE_NUM (9 + 9)


struct vdec_vp9_frm_hdr {
	unsigned int width;
	unsigned int height;
	unsigned char show_frame;
	unsigned char resolution_changed;
};

struct vdec_vp9_work_buf {
	unsigned int frmbuf_width;
	unsigned int frmbuf_height;
	struct mtk_vcodec_mem seg_id_buf;
	struct mtk_vcodec_mem tile_buf;
	struct mtk_vcodec_mem count_tbl_buf;
	struct mtk_vcodec_mem prob_tbl_buf;
	struct mtk_vcodec_mem mv_buf;
	struct vdec_fb sf_ref_buf[VP9_MAX_FRM_BUFF_NUM-1];
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
 * struct vdec_vp9_vsi - shared buffer between host and VPU driver
 */
struct vdec_vp9_vsi {
	unsigned char sf_bs_buf[VP9_SUPER_FRAME_BS_SZ];
	struct vp9_sf_ref_fb sf_ref_fb[VP9_MAX_FRM_BUFF_NUM-1];
	int sf_next_ref_fb_idx;
	unsigned int sf_frm_cnt;
	unsigned int sf_frm_offset[VP9_MAX_FRM_BUFF_NUM-1];
	unsigned int sf_frm_sz[VP9_MAX_FRM_BUFF_NUM-1];
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
	unsigned int show_frm;
	unsigned int show_exist;
	unsigned int frm_to_show;
	unsigned int refresh_frm_flags;
	unsigned int resolution_changed;

	struct vp9_input_ctx input_ctx;
	struct vp9_ref_cnt_buf frm_bufs[VP9_MAX_FRM_BUFF_NUM];
	int ref_frm_map[REF_FRAMES];
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
	struct vdec_fb_node dec_fb[VP9_MAX_FRM_BUFF_NODE_NUM];
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
	struct file *log;
	struct mtk_vcodec_mem mem;
};

static int vp9_setup_buf(struct vdec_vp9_inst *inst)
{
	struct vdec_vp9_vsi *vsi = inst->vpu.vsi;

	vsi->mv_buf.va = (unsigned long)inst->work_buf.mv_buf.va;
	vsi->mv_buf.pa = (unsigned long)inst->work_buf.mv_buf.dma_addr;
	vsi->mv_buf.sz = (unsigned long)inst->work_buf.mv_buf.size;

	if ((vsi->mv_buf.va == 0) || (vsi->mv_buf.pa == 0) ||
		(vsi->mv_buf.sz == 0))
		return -EINVAL;

	mtk_vcodec_debug(inst, "VP9_MV_BUF_Addr: 0x%lX (0x%lX)",
		     vsi->mv_buf.va, vsi->mv_buf.pa);
	return 0;
}

static bool vp9_is_sf_ref_fb(struct vdec_vp9_inst *inst, struct vdec_fb *fb)
{
	int i;
	struct vdec_vp9_vsi *vsi = inst->vsi;

	for (i = 0; i < VP9_MAX_FRM_BUFF_NUM - 1; i++) {
		if (fb == &vsi->sf_ref_fb[i].fb)
			break;
	}

	if (i == VP9_MAX_FRM_BUFF_NUM - 1)
		return false;

	return true;
}

static struct vdec_fb *vp9_rm_from_fb_use_list(struct vdec_vp9_inst
					*inst, void *addr)
{
	struct vdec_fb *fb;
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

static bool vp9_add_to_fb_free_list(struct vdec_vp9_inst *inst,
			     struct vdec_fb *fb)
{
	struct vdec_fb_node *node;

	if (fb) {
		node = list_first_entry_or_null(&inst->available_fb_node_list,
					struct vdec_fb_node, list);
		if (node) {
			node->fb = fb;
			list_move_tail(&node->list, &inst->fb_free_list);
		} else
			mtk_vcodec_debug(inst, "No free fb node");
	}

	return true;
}

static bool vp9_free_sf_ref_fb(struct vdec_vp9_inst *inst, struct vdec_fb *fb)
{
	struct vp9_sf_ref_fb *sf_ref_fb =
		container_of(fb, struct vp9_sf_ref_fb, fb);

	sf_ref_fb->used = 0;

	return true;
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
				vp9_free_sf_ref_fb(
					inst, vsi->frm_bufs[ref_idx].buf.fb);
		}
	}

	*idx = new_idx;
	vsi->frm_bufs[new_idx].ref_cnt++;
}

static void vp9_free_all_sf_ref_fb(struct vdec_vp9_inst *inst)
{
	int i;
	struct vdec_vp9_vsi *vsi = inst->vsi;

	for (i = 0; i < VP9_MAX_FRM_BUFF_NUM - 1; i++) {
		if (inst->work_buf.sf_ref_buf[i].base_y.va) {
			mtk_vcodec_mem_free(inst->ctx,
				    &inst->work_buf.sf_ref_buf[i].base_y);
			mtk_vcodec_mem_free(inst->ctx,
				    &inst->work_buf.sf_ref_buf[i].base_c);
			vsi->sf_ref_fb[i].used = 0;
		}
	}
}

static int vp9_get_sf_ref_fb(struct vdec_vp9_inst *inst)
{
	int i;
	struct mtk_vcodec_mem *mem;
	struct vdec_vp9_vsi *vsi = inst->vsi;
	struct vdec_fb *fb_dst_ptr, *fb_src_ptr;

	for (i = 0; i < VP9_MAX_FRM_BUFF_NUM - 1; i++) {
		if (inst->work_buf.sf_ref_buf[i].base_y.va &&
		    vsi->sf_ref_fb[i].used == 0) {
			return i;
		}
	}

	for (i = 0; i < VP9_MAX_FRM_BUFF_NUM - 1; i++) {
		if (inst->work_buf.sf_ref_buf[i].base_y.va == NULL)
			break;
	}

	if (i == VP9_MAX_FRM_BUFF_NUM - 1) {
		mtk_vcodec_err(inst, "List Full");
		return -1;
	}

	mem = &inst->work_buf.sf_ref_buf[i].base_y;
	mem->size = vsi->buf_sz_y_bs +
		    vsi->buf_len_sz_y;

	if ((inst->frm_hdr.width > 4096) ||
		(inst->frm_hdr.height > 2304)) {
		mtk_vcodec_err(inst, "Invalid w/h %d/%d",
			inst->frm_hdr.width,
			inst->frm_hdr.height);
		return -1;
	}

	if (mtk_vcodec_mem_alloc(inst->ctx, mem)) {
		mtk_vcodec_err(inst, "Cannot allocate sf_ref_buf y_buf");
		return -1;
	}

	mtk_vcodec_debug(inst, "allocate sf_ref_buf y_buf = 0x%lx, %d",
			mem->size,
			inst->work_buf.frmbuf_width *
			inst->work_buf.frmbuf_height);

	fb_dst_ptr = &vsi->sf_ref_fb[i].fb;
	fb_src_ptr = &inst->work_buf.sf_ref_buf[i];
	fb_dst_ptr->base_y.va = fb_src_ptr->base_y.va;
	fb_dst_ptr->base_y.dma_addr = fb_src_ptr->base_y.dma_addr;
	fb_dst_ptr->base_y.size = fb_src_ptr->base_y.size;

	mem = &inst->work_buf.sf_ref_buf[i].base_c;
	mem->size = vsi->buf_sz_c_bs +
		    vsi->buf_len_sz_c;

	if (mtk_vcodec_mem_alloc(inst->ctx, mem)) {
		mtk_vcodec_err(inst, "Cannot allocate sf_ref_buf c_buf");
		return -1;
	}

	mtk_vcodec_debug(inst, "allocate sf_ref_buf c_buf = 0x%lx, %d",
			mem->size,
			inst->work_buf.frmbuf_width *
			inst->work_buf.frmbuf_height / 2);

	fb_dst_ptr->base_c.va = fb_src_ptr->base_c.va;
	fb_dst_ptr->base_c.dma_addr = fb_src_ptr->base_c.dma_addr;
	fb_dst_ptr->base_c.size = fb_src_ptr->base_c.size;

	vsi->sf_ref_fb[i].used = 0;
	vsi->sf_ref_fb[i].idx = i;

	return i;
}

bool vp9_realloc_work_buf(struct vdec_vp9_inst *inst)
{
	struct vdec_vp9_vsi *vsi = inst->vsi;
	int result;
	struct mtk_vcodec_mem *mem;

	inst->frm_hdr.width = vsi->pic_w;
	inst->frm_hdr.height = vsi->pic_h;
	inst->work_buf.frmbuf_width = vsi->buf_w;
	inst->work_buf.frmbuf_height = vsi->buf_h;

	mtk_vcodec_debug(inst, "BUF CHG(%d): w/h/sb_w/sb_h=%d/%d/%d/%d",
		     inst->frm_hdr.resolution_changed,
		     inst->frm_hdr.width,
		     inst->frm_hdr.height,
		     inst->work_buf.frmbuf_width,
		     inst->work_buf.frmbuf_height);

	if ((inst->frm_hdr.width > 4096) ||
		(inst->frm_hdr.height > 2304)) {
		mtk_vcodec_err(inst, "Invalid w/h %d/%d",
			inst->frm_hdr.width,
			inst->frm_hdr.height);
		return false;
	}

	mem = &inst->work_buf.mv_buf;
	/* Free First */
	if (mem->va)
		mtk_vcodec_mem_free(inst->ctx, mem);
	/* Alloc Later */
	mem->size = ((inst->work_buf.frmbuf_width / 64) *
		    (inst->work_buf.frmbuf_height / 64) + 2) * 36 * 16;

	result = mtk_vcodec_mem_alloc(inst->ctx, mem);
	if (result) {
		mtk_vcodec_err(inst, "Cannot allocate mv_buf");
		return false;
	}
	/* Set the va again */
	vsi->mv_buf.va = (unsigned long)inst->work_buf.mv_buf.va;
	vsi->mv_buf.pa = (unsigned long)inst->work_buf.mv_buf.dma_addr;
	vsi->mv_buf.sz = (unsigned long)inst->work_buf.mv_buf.size;

	vp9_free_all_sf_ref_fb(inst);
	vsi->sf_next_ref_fb_idx = vp9_get_sf_ref_fb(inst);
	result = vp9_setup_buf(inst);
	if (result) {
		mtk_vcodec_err(inst, "Cannot vp9_setup_buf");
		return false;
	}

	inst->frm_hdr.resolution_changed = true;

	return true;
}

static bool vp9_add_to_fb_disp_list(struct vdec_vp9_inst *inst,
			     struct vdec_fb *fb)
{
	struct vdec_fb_node *node;

	if (!fb)
		return false;

	node = list_first_entry_or_null(&inst->available_fb_node_list,
					struct vdec_fb_node, list);
	if (node) {
		node->fb = fb;
		list_move_tail(&node->list, &inst->fb_disp_list);
	} else {
		mtk_vcodec_debug(inst, "List Full");
		return false;
	}

	mtk_vcodec_debug_leave(inst);

	return true;
}

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
		if ((frm_to_show->fb != NULL) &&
			(inst->cur_fb->base_y.size >=
				frm_to_show->fb->base_y.size)) {
			memcpy((void *)inst->cur_fb->base_y.va,
				(void *)frm_to_show->fb->base_y.va,
				inst->work_buf.frmbuf_width *
				inst->work_buf.frmbuf_height);
			memcpy((void *)inst->cur_fb->base_c.va,
				(void *)frm_to_show->fb->base_c.va,
				inst->work_buf.frmbuf_width *
				inst->work_buf.frmbuf_height / 2);
		} else {
			mtk_vcodec_debug(inst,
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

	if (vsi->frm_bufs[vsi->new_fb_idx].ref_cnt == 0) {
		if (!vp9_is_sf_ref_fb(
			inst, vsi->frm_bufs[vsi->new_fb_idx].buf.fb)) {
			struct vdec_fb *fb;

			fb = vp9_rm_from_fb_use_list(inst,
			     vsi->frm_bufs[vsi->new_fb_idx].buf.fb->base_y.va);

			vp9_add_to_fb_free_list(inst, fb);
		} else
			vp9_free_sf_ref_fb(
				inst, vsi->frm_bufs[vsi->new_fb_idx].buf.fb);
	}

	if (vsi->sf_frm_cnt > 0 && vsi->sf_frm_idx != vsi->sf_frm_cnt - 1)
		vsi->sf_next_ref_fb_idx = vp9_get_sf_ref_fb(inst);
}

static bool vp9_wait_dec_end(struct vdec_vp9_inst *inst)
{
	struct mtk_vcodec_ctx *ctx = inst->ctx;
	unsigned int irq_status;

	mtk_vcodec_wait_for_done_ctx(inst->ctx,
						MTK_INST_IRQ_RECEIVED,
						WAIT_INTR_TIMEOUT_MS);

	irq_status = ctx->irq_status;
	mtk_vcodec_debug(inst, "isr return %x", irq_status);

	if (irq_status & 0x10000)
		return true;
	else
		return false;
}

struct vdec_vp9_inst *vp9_alloc_inst(void *ctx)
{
	int result;
	struct mtk_vcodec_mem mem;
	struct vdec_vp9_inst *inst;

	mem.size = sizeof(struct vdec_vp9_inst) * 2;
	result = mtk_vcodec_mem_alloc(ctx, &mem);
	if (result)
		return NULL;

	inst = mem.va;
	inst->mem = mem;

	return inst;
}

void vp9_free_handle(struct vdec_vp9_inst *inst)
{
	struct mtk_vcodec_mem mem;

	mem = inst->mem;
	if (mem.va)
		mtk_vcodec_mem_free(inst->ctx, &mem);
}

bool vp9_init_proc(struct vdec_vp9_inst *inst,
		   struct vdec_pic_info *pic_info)
{
	struct vdec_vp9_vsi *vsi = inst->vsi;

	pic_info->pic_w = vsi->pic_w;
	pic_info->pic_h = vsi->pic_h;
	pic_info->buf_w = vsi->buf_w;
	pic_info->buf_h = vsi->buf_h;

	mtk_vcodec_debug(inst,
			"(PicW,PicH,BufW,BufH) = (%d,%d,%d,%d) profile=%d",
			pic_info->pic_w, pic_info->pic_h,
			pic_info->buf_w, pic_info->buf_h, vsi->profile);

	inst->frm_hdr.width = vsi->pic_w;
	inst->frm_hdr.height = vsi->pic_h;
	inst->work_buf.frmbuf_width = vsi->buf_w;
	inst->work_buf.frmbuf_height = vsi->buf_h;

	/* ----> HW limitation */
	if ((inst->frm_hdr.width > 4096) ||
		(inst->frm_hdr.height > 2304)) {
		mtk_vcodec_err(inst, "Invalid w/h %d/%d",
			inst->frm_hdr.width,
			inst->frm_hdr.height);
		return false;
	}

	if (vsi->profile > 0) {
		mtk_vcodec_err(inst, "vp9_dec DO NOT support profile(%d) > 0",
			     vsi->profile);
		return false;
	}
	if ((inst->work_buf.frmbuf_width > 4096) ||
	    (inst->work_buf.frmbuf_height > 2304)) {
		mtk_vcodec_err(inst, "vp9_dec DO NOT support (W,H) = (%d,%d)",
			     inst->work_buf.frmbuf_width,
			     inst->work_buf.frmbuf_height);
		return false;
	}
	/* <---- HW limitation */

	return true;
}

bool vp9_check_proc(struct vdec_vp9_inst *inst)
{
	struct vdec_vp9_vsi *vsi = inst->vsi;
	bool ret = false;

	mtk_vcodec_debug_enter(inst);

	if (vsi->show_exist) {
		vp9_swap_frm_bufs(inst);
		mtk_vcodec_debug(inst, "Decode Ok @%d (show_exist)",
				 vsi->frm_num);
		vsi->frm_num++;
		return true;
	}

	ret = vp9_wait_dec_end(inst);
	if (!ret) {
		mtk_vcodec_err(inst, "Decode NG, Decode Timeout @[%d]",
			       vsi->frm_num);
		return false;
	}

	if (vpu_dec_end(&inst->vpu)) {
		mtk_vcodec_err(inst, "vp9_dec_vpu_end failed");
		return false;
	}

	vp9_swap_frm_bufs(inst);
	mtk_vcodec_debug(inst, "Decode Ok @%d (%d/%d)", vsi->frm_num,
		     inst->frm_hdr.width, inst->frm_hdr.height);

	vsi->frm_num++;

	mtk_vcodec_debug_leave(inst);

	return true;
}

bool vp9_is_last_sub_frm(struct vdec_vp9_inst *inst)
{
	struct vdec_vp9_vsi *vsi = inst->vsi;

	if (vsi->sf_frm_cnt <= 0 || vsi->sf_frm_idx == vsi->sf_frm_cnt)
		return true;

	return false;
}

struct vdec_fb *vp9_rm_from_fb_disp_list(struct vdec_vp9_inst
		*inst)
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

bool vp9_add_to_fb_use_list(struct vdec_vp9_inst *inst,
			    struct vdec_fb *fb)
{
	struct vdec_fb_node *node;

	if (!fb)
		return false;

	node = list_first_entry_or_null(&inst->available_fb_node_list,
					struct vdec_fb_node, list);
	if (node) {
		node->fb = fb;
		list_move_tail(&node->list, &inst->fb_use_list);
	} else {
		mtk_vcodec_debug(inst, "No free fb node");
		return false;
	}

	mtk_vcodec_debug_leave(inst);

	return true;
}

struct vdec_fb *vp9_rm_from_fb_free_list(struct vdec_vp9_inst
		*inst)
{
	struct vdec_fb_node *node;
	struct vdec_fb *fb = NULL;

	node = list_first_entry_or_null(&inst->fb_free_list,
					struct vdec_fb_node, list);
	if (node) {
		fb = (struct vdec_fb *)node->fb;
		fb->status |= FB_ST_FREE;
		list_move_tail(&node->list, &inst->available_fb_node_list);
		mtk_vcodec_debug(inst, "[FB] get free fb %p st=%d",
				 node->fb, fb->status);
	} else
		mtk_vcodec_debug(inst, "[FB] there is no free fb");

	mtk_vcodec_debug_leave(inst);

	return fb;
}

bool vp9_fb_use_list_to_fb_free_list(struct vdec_vp9_inst *inst)
{
	struct vdec_fb_node *node, *tmp;

	list_for_each_entry_safe(node, tmp, &inst->fb_use_list, list)
		list_move_tail(&node->list, &inst->fb_free_list);

	mtk_vcodec_debug_leave(inst);
	return true;
}

void vp9_reset(struct vdec_vp9_inst *inst)
{
	vp9_fb_use_list_to_fb_free_list(inst);

	vp9_free_all_sf_ref_fb(inst);
	inst->vsi->sf_next_ref_fb_idx = vp9_get_sf_ref_fb(inst);

	if (vpu_dec_reset(&inst->vpu))
		mtk_vcodec_debug(inst, "vp9_dec_vpu_reset failed");

	if (vp9_setup_buf(inst))
		mtk_vcodec_debug(inst, "vp9_setup_buf failed");
}

static void init_list(struct vdec_vp9_inst *inst)
{
	int i;

	INIT_LIST_HEAD(&inst->available_fb_node_list);
	INIT_LIST_HEAD(&inst->fb_use_list);
	INIT_LIST_HEAD(&inst->fb_free_list);
	INIT_LIST_HEAD(&inst->fb_disp_list);

	for (i = 0; i < VP9_MAX_FRM_BUFF_NODE_NUM; i++) {
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
	pic->buf_w = inst->work_buf.frmbuf_width;
	pic->buf_h = inst->work_buf.frmbuf_height;

	mtk_vcodec_debug(inst, "pic(%d, %d), buf(%d, %d)",
		 pic->pic_w, pic->pic_h, pic->buf_w, pic->buf_h);
	mtk_vcodec_debug(inst, "Y(%d, %d), C(%d, %d)", pic->y_bs_sz,
		 pic->y_len_sz, pic->c_bs_sz, pic->c_len_sz);
}

static void get_disp_fb(struct vdec_vp9_inst *inst, struct vdec_fb **out_fb)
{
	mtk_vcodec_debug_enter(inst);

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
		fb = NULL;
		mtk_vcodec_debug(inst, "[FB] there is no free fb");
	}

	*out_fb = fb;
}

static int vdec_vp9_deinit(unsigned long h_vdec)
{
	struct vdec_vp9_inst *inst = (struct vdec_vp9_inst *)h_vdec;
	struct mtk_vcodec_mem *mem;
	int ret = 0;

	mtk_vcodec_debug_enter(inst);

	if (vpu_dec_deinit(&inst->vpu)) {
		mtk_vcodec_err(inst, "[E]vpu_dec_deinit");
		ret = -EINVAL;
	}

	mem = &inst->work_buf.mv_buf;
	if (mem->va)
		mtk_vcodec_mem_free(inst->ctx, mem);

	vp9_free_all_sf_ref_fb(inst);
	vp9_free_handle(inst);

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
		mtk_vcodec_err(inst, "[E]vp9_dec_vpu_init - %d",
						inst->vpu.inst_addr);
		goto err_deinit_inst;
	}

	inst->vsi = (struct vdec_vp9_vsi *)inst->vpu.vsi;
	init_list(inst);

	(*h_vdec) = (unsigned long)inst;
	return 0;

err_deinit_inst:
	vp9_free_handle(inst);

	return -EINVAL;
}

static int vdec_vp9_decode(unsigned long h_vdec, struct mtk_vcodec_mem *bs,
		   struct vdec_fb *fb, bool *res_chg)
{
	int ret = 0;
	struct vdec_vp9_inst *inst = (struct vdec_vp9_inst *)h_vdec;
	struct vdec_vp9_frm_hdr *frm_hdr = &inst->frm_hdr;
	struct vdec_vp9_vsi *vsi = inst->vsi;
	unsigned int data[3];
	int i;

	mtk_vcodec_debug_enter(inst);

	*res_chg = false;

	if ((bs == NULL) && (fb == NULL)) {
		mtk_vcodec_debug(inst, "[EOS]");
		vp9_reset(inst);
		return ret;
	}

	if (bs != NULL)
		mtk_vcodec_debug(inst, "Input BS Size = %ld", bs->size);

	memcpy((void *)inst + sizeof(*inst), (void *)inst,
	       sizeof(*inst));

	while (1) {
		struct vdec_fb *cur_fb;

		frm_hdr->resolution_changed = false;

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
			ret = -EINVAL;
			goto DECODE_ERROR;
		}

		if (vsi->resolution_changed) {
			if (!vp9_realloc_work_buf(inst)) {
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
		inst->frm_hdr.show_frame = vsi->show_frm;

		if (vsi->show_exist)
			mtk_vcodec_debug(inst,
				"drv->new_fb_idx=%d, drv->frm_to_show=%d",
				vsi->new_fb_idx, vsi->frm_to_show);

		if (vsi->show_exist && (vsi->frm_to_show <
					VP9_MAX_FRM_BUFF_NUM)) {
			mtk_vcodec_debug(inst,
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
		for (i = 0; i < REFS_PER_FRAME; i++) {
			unsigned int idx = vsi->frm_refs[i].idx;

			vsi->frm_refs[i].buf = &vsi->frm_bufs[idx].buf;
		}

		if (frm_hdr->resolution_changed) {
			unsigned int width = inst->frm_hdr.width;
			unsigned int height = inst->frm_hdr.height;
			unsigned int frmbuf_width =
				inst->work_buf.frmbuf_width;
			unsigned int frmbuf_height =
				inst->work_buf.frmbuf_height;
			struct mtk_vcodec_mem tmp_buf =	inst->work_buf.mv_buf;
			struct vp9_dram_buf tmp_buf2 = vsi->mv_buf;
			struct vdec_fb tmp_buf3 =
				inst->work_buf.sf_ref_buf[0];

			memcpy((void *)inst, (void *)inst + sizeof(*inst),
			       sizeof(*inst));

			inst->frm_hdr.width = width;
			inst->frm_hdr.height = height;
			inst->work_buf.frmbuf_width = frmbuf_width;
			inst->work_buf.frmbuf_height = frmbuf_height;
			inst->work_buf.mv_buf = tmp_buf;
			inst->vsi->mv_buf = tmp_buf2;
			inst->work_buf.sf_ref_buf[0] = tmp_buf3;

			*res_chg = true;
			mtk_vcodec_debug(inst, "VDEC_ST_RESOLUTION_CHANGED");
			vp9_add_to_fb_free_list(inst, fb);
			ret = 0;
			goto DECODE_ERROR;
		}

		if (vp9_check_proc(inst) != true) {
			mtk_vcodec_err(inst, "vp9_check_proc");
			ret = -EINVAL;
			goto DECODE_ERROR;
		}

		inst->total_frm_cnt++;
		if (vp9_is_last_sub_frm(inst))
			break;

		/* for resolution change backup */
		memcpy((void *)inst + sizeof(*inst), (void *)inst,
		       sizeof(*inst));
	}
	inst->frm_cnt++;

	mtk_vcodec_debug_leave(inst);

DECODE_ERROR:
	if (ret < 0)
		vp9_add_to_fb_free_list(inst, fb);

	mtk_vcodec_debug_leave(inst);

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
		*((unsigned int *)out) = 9;
		break;
	case GET_PARAM_CROP_INFO:
		get_crop_info(inst, out);
		break;
	default:
		mtk_vcodec_err(inst, "not support type %d", type);
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

struct vdec_common_if *get_vp9_dec_comm_if(void)
{
	return &vdec_vp9_if;
}
