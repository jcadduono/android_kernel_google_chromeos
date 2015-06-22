/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/bug.h>
#include <linux/export.h>
#include <linux/clk-provider.h>
#include <linux/delay.h>
#include <linux/regmap.h>
#include <linux/math64.h>

#include <asm/div64.h>

#include "clk-rcg.h"
#include "common.h"

#define CMD_REG			0x0
#define CMD_UPDATE		BIT(0)
#define CMD_ROOT_EN		BIT(1)
#define CMD_DIRTY_CFG		BIT(4)
#define CMD_DIRTY_N		BIT(5)
#define CMD_DIRTY_M		BIT(6)
#define CMD_DIRTY_D		BIT(7)
#define CMD_ROOT_OFF		BIT(31)

#define CFG_REG			0x4
#define CFG_SRC_DIV_SHIFT	0
#define CFG_SRC_SEL_SHIFT	8
#define CFG_SRC_SEL_MASK	(0x7 << CFG_SRC_SEL_SHIFT)
#define CFG_MODE_SHIFT		12
#define CFG_MODE_MASK		(0x3 << CFG_MODE_SHIFT)
#define CFG_MODE_DUAL_EDGE	(0x2 << CFG_MODE_SHIFT)

#define M_REG			0x8
#define N_REG			0xc
#define D_REG			0x10
#define FEPLL_500_SRC		0x2

static int clk_rcg2_is_enabled(struct clk_hw *hw)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);
	u32 cmd;
	int ret;

	ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CMD_REG, &cmd);
	if (ret < 0)
		return false;

	return (cmd & CMD_ROOT_OFF) == 0;
}

static u8 clk_rcg2_get_parent(struct clk_hw *hw)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);
	int num_parents = __clk_get_num_parents(hw->clk);
	u32 cfg;
	int i, ret;

	ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG, &cfg);
	if (ret)
		goto err;

	cfg &= CFG_SRC_SEL_MASK;
	cfg >>= CFG_SRC_SEL_SHIFT;

	for (i = 0; i < num_parents; i++)
		if (cfg == rcg->parent_map[i].cfg)
			return i;

err:
	pr_debug("%s: Cannot find parent of %s clock, using default.\n",
			__func__, __clk_get_name(hw->clk));
	return 0;
}

static int update_config(struct clk_rcg2 *rcg)
{
	int count, ret;
	u32 cmd;
	struct clk_hw *hw = &rcg->clkr.hw;
	const char *name = __clk_get_name(hw->clk);

	ret = regmap_update_bits(rcg->clkr.regmap, rcg->cmd_rcgr + CMD_REG,
				 CMD_UPDATE, CMD_UPDATE);
	if (ret)
		return ret;

	/* Wait for update to take effect */
	for (count = 500; count > 0; count--) {
		/* ignore errors until retry count is exhausted. */
		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CMD_REG,
									&cmd);
		if (ret >= 0 && !(cmd & CMD_UPDATE))
			return 0;
		udelay(1);
	}

	WARN(1, "%s: rcg didn't update its configuration.", name);
	return ret ? ret : -ETIMEDOUT;
}

static int clk_rcg2_set_parent(struct clk_hw *hw, u8 index)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);
	int ret;
	u32 cfg = rcg->parent_map[index].cfg << CFG_SRC_SEL_SHIFT;

	ret = regmap_update_bits(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG,
				 CFG_SRC_SEL_MASK, cfg);
	if (ret)
		return ret;

	return update_config(rcg);
}

/*
 * Calculate m/n:d rate
 *
 *          parent_rate     m
 *   rate = ----------- x  ---
 *            hid_div       n
 */
static unsigned long
calc_rate(unsigned long rate, u32 m, u32 n, u32 mode, u32 hid_div)
{
	if (hid_div) {
		rate *= 2;
		rate /= hid_div + 1;
	}

	if (mode) {
		u64 tmp = rate;
		tmp *= m;
		do_div(tmp, n);
		rate = tmp;
	}

	return rate;
}

static unsigned long
clk_rcg2_recalc_rate(struct clk_hw *hw, unsigned long parent_rate)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);
	u32 cfg, hid_div, m = 0, n = 0, mode = 0, mask;
	int ret;

	ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG, &cfg);
	if (ret)
		return 0UL;

	if (rcg->mnd_width) {
		mask = BIT(rcg->mnd_width) - 1;
		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + M_REG, &m);
		if (ret)
			return 0;

		m &= mask;

		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + N_REG, &n);
		if (ret)
			return 0;

		n =  ~n;
		n &= mask;

		n += m;
		mode = cfg & CFG_MODE_MASK;
		mode >>= CFG_MODE_SHIFT;
	}

	mask = BIT(rcg->hid_width) - 1;
	hid_div = cfg >> CFG_SRC_DIV_SHIFT;
	hid_div &= mask;

	return calc_rate(parent_rate, m, n, mode, hid_div);
}

static long _freq_tbl_determine_rate(struct clk_hw *hw,
		const struct freq_tbl *f, unsigned long rate,
		unsigned long *p_rate, struct clk_hw **p_hw)
{
	unsigned long clk_flags;
	struct clk *p;

	f = qcom_find_freq(f, rate);
	if (!f)
		return 0L;

	clk_flags = __clk_get_flags(hw->clk);
	p = clk_get_parent_by_index(hw->clk, f->src);
	if (clk_flags & CLK_SET_RATE_PARENT) {
		if (f->pre_div) {
			rate /= 2;
			rate *= f->pre_div + 1;
		}

		if (f->n) {
			u64 tmp = rate;
			tmp = tmp * f->n;
			do_div(tmp, f->m);
			rate = tmp;
		}
	} else {
		rate =  __clk_get_rate(p);
	}
	*p_hw = __clk_get_hw(p);
	*p_rate = rate;

	return f->freq;
}

static long clk_rcg2_determine_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long *p_rate, struct clk_hw **p_hw)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);

	return _freq_tbl_determine_rate(hw, rcg->freq_tbl, rate, p_rate, p_hw);
}

static int clk_rcg2_configure(struct clk_rcg2 *rcg, const struct freq_tbl *f)
{
	u32 cfg, mask;
	struct clk_hw *hw = &rcg->clkr.hw;
	int ret, index = qcom_find_src_index(hw, rcg->parent_map, f->src);

	if (index < 0)
		return index;

	if (rcg->mnd_width && f->n) {
		mask = BIT(rcg->mnd_width) - 1;
		ret = regmap_update_bits(rcg->clkr.regmap,
					rcg->cmd_rcgr + M_REG, mask, f->m);
		if (ret)
			return ret;

		ret = regmap_update_bits(rcg->clkr.regmap,
				rcg->cmd_rcgr + N_REG, mask, ~(f->n - f->m));
		if (ret)
			return ret;

		ret = regmap_update_bits(rcg->clkr.regmap,
				rcg->cmd_rcgr + D_REG, mask, ~f->n);
		if (ret)
			return ret;
	}

	mask = BIT(rcg->hid_width) - 1;
	mask |= CFG_SRC_SEL_MASK | CFG_MODE_MASK;
	cfg = f->pre_div << CFG_SRC_DIV_SHIFT;
	cfg |= rcg->parent_map[index].cfg << CFG_SRC_SEL_SHIFT;
	if (rcg->mnd_width && f->n && (f->m != f->n))
		cfg |= CFG_MODE_DUAL_EDGE;
	ret = regmap_update_bits(rcg->clkr.regmap,
			rcg->cmd_rcgr + CFG_REG, mask, cfg);
	if (ret)
		return ret;

	return update_config(rcg);
}

static int __clk_rcg2_set_rate(struct clk_hw *hw, unsigned long rate)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);
	const struct freq_tbl *f;

	f = qcom_find_freq(rcg->freq_tbl, rate);
	if (!f)
		return -EINVAL;

	return clk_rcg2_configure(rcg, f);
}

static int clk_rcg2_set_rate(struct clk_hw *hw, unsigned long rate,
			    unsigned long parent_rate)
{
	return __clk_rcg2_set_rate(hw, rate);
}

static int clk_rcg2_set_rate_and_parent(struct clk_hw *hw,
		unsigned long rate, unsigned long parent_rate, u8 index)
{
	return __clk_rcg2_set_rate(hw, rate);
}

const struct clk_ops clk_rcg2_ops = {
	.is_enabled = clk_rcg2_is_enabled,
	.get_parent = clk_rcg2_get_parent,
	.set_parent = clk_rcg2_set_parent,
	.recalc_rate = clk_rcg2_recalc_rate,
	.determine_rate = clk_rcg2_determine_rate,
	.set_rate = clk_rcg2_set_rate,
	.set_rate_and_parent = clk_rcg2_set_rate_and_parent,
};
EXPORT_SYMBOL_GPL(clk_rcg2_ops);

struct frac_entry {
	int num;
	int den;
};

static const struct frac_entry frac_table_675m[] = {	/* link rate of 270M */
	{ 52, 295 },	/* 119 M */
	{ 11, 57 },	/* 130.25 M */
	{ 63, 307 },	/* 138.50 M */
	{ 11, 50 },	/* 148.50 M */
	{ 47, 206 },	/* 154 M */
	{ 31, 100 },	/* 205.25 M */
	{ 107, 269 },	/* 268.50 M */
	{ },
};

static struct frac_entry frac_table_810m[] = { /* Link rate of 162M */
	{ 31, 211 },	/* 119 M */
	{ 32, 199 },	/* 130.25 M */
	{ 63, 307 },	/* 138.50 M */
	{ 11, 60 },	/* 148.50 M */
	{ 50, 263 },	/* 154 M */
	{ 31, 120 },	/* 205.25 M */
	{ 119, 359 },	/* 268.50 M */
	{ },
};

static int clk_edp_pixel_set_rate(struct clk_hw *hw, unsigned long rate,
			      unsigned long parent_rate)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);
	struct freq_tbl f = *rcg->freq_tbl;
	const struct frac_entry *frac;
	int delta = 100000;
	s64 src_rate = parent_rate;
	s64 request;
	u32 mask = BIT(rcg->hid_width) - 1;
	u32 hid_div;

	if (src_rate == 810000000)
		frac = frac_table_810m;
	else
		frac = frac_table_675m;

	for (; frac->num; frac++) {
		int ret;

		request = rate;
		request *= frac->den;
		request = div_s64(request, frac->num);
		if ((src_rate < (request - delta)) ||
		    (src_rate > (request + delta)))
			continue;

		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG,
				&hid_div);
		if (ret)
			return ret;

		f.pre_div = hid_div;
		f.pre_div >>= CFG_SRC_DIV_SHIFT;
		f.pre_div &= mask;
		f.m = frac->num;
		f.n = frac->den;

		return clk_rcg2_configure(rcg, &f);
	}

	return -EINVAL;
}

static int clk_edp_pixel_set_rate_and_parent(struct clk_hw *hw,
		unsigned long rate, unsigned long parent_rate, u8 index)
{
	/* Parent index is set statically in frequency table */
	return clk_edp_pixel_set_rate(hw, rate, parent_rate);
}

static long clk_edp_pixel_determine_rate(struct clk_hw *hw, unsigned long rate,
				 unsigned long *p_rate, struct clk_hw **p)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);
	const struct freq_tbl *f = rcg->freq_tbl;
	const struct frac_entry *frac;
	int delta = 100000;
	s64 src_rate = *p_rate;
	s64 request;
	u32 mask = BIT(rcg->hid_width) - 1;
	u32 hid_div;

	/* Force the correct parent */
	*p = __clk_get_hw(clk_get_parent_by_index(hw->clk, f->src));

	if (src_rate == 810000000)
		frac = frac_table_810m;
	else
		frac = frac_table_675m;

	for (; frac->num; frac++) {
		int ret;

		request = rate;
		request *= frac->den;
		request = div_s64(request, frac->num);
		if ((src_rate < (request - delta)) ||
		    (src_rate > (request + delta)))
			continue;

		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG,
				&hid_div);
		if (ret)
			return 0L;

		hid_div >>= CFG_SRC_DIV_SHIFT;
		hid_div &= mask;

		return calc_rate(src_rate, frac->num, frac->den, !!frac->den,
				 hid_div);
	}

	return 0L;
}

const struct clk_ops clk_edp_pixel_ops = {
	.is_enabled = clk_rcg2_is_enabled,
	.get_parent = clk_rcg2_get_parent,
	.set_parent = clk_rcg2_set_parent,
	.recalc_rate = clk_rcg2_recalc_rate,
	.set_rate = clk_edp_pixel_set_rate,
	.set_rate_and_parent = clk_edp_pixel_set_rate_and_parent,
	.determine_rate = clk_edp_pixel_determine_rate,
};
EXPORT_SYMBOL_GPL(clk_edp_pixel_ops);

static long clk_byte_determine_rate(struct clk_hw *hw, unsigned long rate,
			 unsigned long *p_rate, struct clk_hw **p_hw)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);
	const struct freq_tbl *f = rcg->freq_tbl;
	unsigned long parent_rate, div;
	u32 mask = BIT(rcg->hid_width) - 1;
	struct clk *p;

	if (rate == 0)
		return 0L;

	p = clk_get_parent_by_index(hw->clk, f->src);
	*p_hw = __clk_get_hw(p);
	*p_rate = parent_rate = __clk_round_rate(p, rate);

	div = DIV_ROUND_UP((2 * parent_rate), rate) - 1;
	div = min_t(u32, div, mask);

	return calc_rate(parent_rate, 0, 0, 0, div);
}

static int clk_byte_set_rate(struct clk_hw *hw, unsigned long rate,
			 unsigned long parent_rate)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);
	struct freq_tbl f = *rcg->freq_tbl;
	unsigned long div;
	u32 mask = BIT(rcg->hid_width) - 1;

	div = DIV_ROUND_UP((2 * parent_rate), rate) - 1;
	div = min_t(u32, div, mask);

	f.pre_div = div;

	return clk_rcg2_configure(rcg, &f);
}

static int clk_byte_set_rate_and_parent(struct clk_hw *hw,
		unsigned long rate, unsigned long parent_rate, u8 index)
{
	/* Parent index is set statically in frequency table */
	return clk_byte_set_rate(hw, rate, parent_rate);
}

const struct clk_ops clk_byte_ops = {
	.is_enabled = clk_rcg2_is_enabled,
	.get_parent = clk_rcg2_get_parent,
	.set_parent = clk_rcg2_set_parent,
	.recalc_rate = clk_rcg2_recalc_rate,
	.set_rate = clk_byte_set_rate,
	.set_rate_and_parent = clk_byte_set_rate_and_parent,
	.determine_rate = clk_byte_determine_rate,
};
EXPORT_SYMBOL_GPL(clk_byte_ops);

static const struct frac_entry frac_table_pixel[] = {
	{ 3, 8 },
	{ 2, 9 },
	{ 4, 9 },
	{ 1, 1 },
	{ }
};

static long clk_pixel_determine_rate(struct clk_hw *hw, unsigned long rate,
				 unsigned long *p_rate, struct clk_hw **p)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);
	unsigned long request, src_rate;
	int delta = 100000;
	const struct freq_tbl *f = rcg->freq_tbl;
	const struct frac_entry *frac = frac_table_pixel;
	struct clk *parent = clk_get_parent_by_index(hw->clk, f->src);

	*p = __clk_get_hw(parent);

	for (; frac->num; frac++) {
		request = (rate * frac->den) / frac->num;

		src_rate = __clk_round_rate(parent, request);
		if ((src_rate < (request - delta)) ||
			(src_rate > (request + delta)))
			continue;

		*p_rate = src_rate;
		return (src_rate * frac->num) / frac->den;
	}

	return 0L;
}

static int clk_pixel_set_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	struct clk_rcg2 *rcg = to_clk_rcg2(hw);
	struct freq_tbl f = *rcg->freq_tbl;
	const struct frac_entry *frac = frac_table_pixel;
	unsigned long request, src_rate;
	int delta = 100000;
	u32 mask = BIT(rcg->hid_width) - 1;
	u32 hid_div;
	struct clk *parent = clk_get_parent_by_index(hw->clk, f.src);

	for (; frac->num; frac++) {
		int ret;
		request = (rate * frac->den) / frac->num;

		src_rate = __clk_round_rate(parent, request);
		if ((src_rate < (request - delta)) ||
			(src_rate > (request + delta)))
			continue;

		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG,
				&hid_div);
		if (ret)
			return ret;

		f.pre_div = hid_div;
		f.pre_div >>= CFG_SRC_DIV_SHIFT;
		f.pre_div &= mask;
		f.m = frac->num;
		f.n = frac->den;

		return clk_rcg2_configure(rcg, &f);
	}
	return -EINVAL;
}

static int clk_pixel_set_rate_and_parent(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate, u8 index)
{
	/* Parent index is set statically in frequency table */
	return clk_pixel_set_rate(hw, rate, parent_rate);
}

const struct clk_ops clk_pixel_ops = {
	.is_enabled = clk_rcg2_is_enabled,
	.get_parent = clk_rcg2_get_parent,
	.set_parent = clk_rcg2_set_parent,
	.recalc_rate = clk_rcg2_recalc_rate,
	.set_rate = clk_pixel_set_rate,
	.set_rate_and_parent = clk_pixel_set_rate_and_parent,
	.determine_rate = clk_pixel_determine_rate,
};
EXPORT_SYMBOL_GPL(clk_pixel_ops);


static int clk_cdiv_rcg2_is_enabled(struct clk_hw *hw)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);
	u32 cmd = 0;
	int ret;

	ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CMD_REG, &cmd);
	if (ret < 0)
		return false;

	return (cmd & CMD_ROOT_OFF) == 0;
}

static u8 clk_cdiv_rcg2_get_parent(struct clk_hw *hw)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);
	int num_parents = __clk_get_num_parents(hw->clk);
	u32 cfg;
	int i, ret;

	ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG, &cfg);
	if (ret)
		goto err;

	cfg &= CFG_SRC_SEL_MASK;
	cfg >>= CFG_SRC_SEL_SHIFT;

	for (i = 0; i < num_parents; i++)
		if (cfg == rcg->parent_map[i].cfg)
			return i;
err:
	pr_debug("%s: Cannot find parent of %s clock, using default.\n",
			__func__, __clk_get_name(hw->clk));
	return 0;
}

static int cdiv_update_config(struct clk_cdiv_rcg2 *rcg)
{
	int count, ret;
	struct clk_hw *hw = &rcg->clkr.hw;
	const char *name = __clk_get_name(hw->clk);

	ret = regmap_update_bits(rcg->clkr.regmap, rcg->cmd_rcgr + CMD_REG,
				 CMD_UPDATE, CMD_UPDATE);
	if (ret)
		return ret;

	/* Wait for update to take effect */
	for (count = 500; count > 0; count--) {
		u32 cmd = ~0U;

		/* ignore regmap errors - until we exhaust retry count. */
		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CMD_REG,
									&cmd);

		if (ret >= 0 && !(cmd & CMD_UPDATE))
			return 0;

		udelay(1);
	}

	WARN(ret, "%s: rcg didn't update its configuration.", name);
	return ret ? ret : -ETIMEDOUT;
}

static int clk_cdiv_rcg2_set_parent(struct clk_hw *hw, u8 index)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);
	int ret;

	ret = regmap_update_bits(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG,
				 CFG_SRC_SEL_MASK,
				 rcg->parent_map[index].cfg << CFG_SRC_SEL_SHIFT);
	if (ret)
		return ret;

	return cdiv_update_config(rcg);
}

static unsigned long
clk_cdiv_rcg2_recalc_rate(struct clk_hw *hw, unsigned long parent_rate)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);
	u32 cfg, hid_div , m = 0 , n = 0 , mode = 0 , mask , rate , cdiv;
	int ret;

	ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG, &cfg);
	if (ret)
		return 0UL;

	if (rcg->mnd_width) {
		mask = BIT(rcg->mnd_width) - 1;
		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + M_REG, &m);
		if (ret)
			return 0UL;

		m &= mask;
		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + N_REG, &n);
		if (ret)
			return 0UL;

		n =  ~n;
		n &= mask;

		n += m;
		mode = cfg & CFG_MODE_MASK;
		mode >>= CFG_MODE_SHIFT;
	}

	mask = BIT(rcg->hid_width) - 1;
	hid_div = cfg >> CFG_SRC_DIV_SHIFT;
	hid_div &= mask;
	rate = calc_rate(parent_rate, m, n, mode, hid_div);

	ret = regmap_read(rcg->clkr.regmap, rcg->cdiv.offset, &cdiv);
	if (ret)
		return 0UL;

	cdiv &= (rcg->cdiv.mask << rcg->cdiv.shift);
	cdiv =  (cdiv >> rcg->cdiv.shift);
	if (cdiv)
		rate *= cdiv + 1;
	return rate;
}

static long _cdiv_rcg2_freq_tbl_determine_rate(struct clk_hw *hw,
		const struct freq_tbl *f, unsigned long rate,
		unsigned long *p_rate, struct clk_hw **p_hw)
{
	unsigned long clk_flags;
	struct clk *p;

	f = qcom_find_freq(f, rate);
	if (!f)
		return 0L;

	clk_flags = __clk_get_flags(hw->clk);
	p = clk_get_parent_by_index(hw->clk, f->src);
	*p_hw = __clk_get_hw(p);
	if (clk_flags & CLK_SET_RATE_PARENT) {
		if (f->pre_div)
			rate *= f->pre_div;
		if (f->n) {
			u64 tmp = rate;

			tmp = tmp * f->n;
			do_div(tmp, f->m);
			rate = tmp;
		}
	} else {
		rate =	__clk_get_rate(p);
	}
	*p_rate = rate;

	return f->freq;
}


static long clk_cdiv_rcg2_determine_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long *p_rate, struct clk_hw **p_hw)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);

	return _cdiv_rcg2_freq_tbl_determine_rate(hw, rcg->freq_tbl,
							rate, p_rate, p_hw);
}

static int clk_cdiv_rcg2_configure(struct clk_cdiv_rcg2 *rcg,
						const struct freq_tbl *f)
{
	u32 cfg, mask;
	u32 i;
	int ret;

	if (rcg->mnd_width && f->n) {
		mask = BIT(rcg->mnd_width) - 1;
		ret = regmap_update_bits(rcg->clkr.regmap,
				rcg->cmd_rcgr + M_REG, mask, f->m);
		if (ret)
			return ret;

		ret = regmap_update_bits(rcg->clkr.regmap,
				rcg->cmd_rcgr + N_REG, mask, ~(f->n - f->m));
		if (ret)
			return ret;

		ret = regmap_update_bits(rcg->clkr.regmap,
				rcg->cmd_rcgr + D_REG, mask, ~f->n);
		if (ret)
			return ret;
	}


	if (rcg->cdiv.mask && f->pre_div > 16) {

		/* The division is handled by two dividers. Both of which can
		 * divide by a maximum value of 16. To achieve a division of
		 * 256 = 16 * 16, we use a divider of 16 in the RCGR and the
		 * other divider of 16 in the MISC Register.
		 */
		for (i = 2; i <= 16; i++) {
			if (f->pre_div % i == 0)
				cfg = i;
		}

		if (f->pre_div/cfg > 16)
			return -EINVAL;
		mask = (rcg->cdiv.mask)<<rcg->cdiv.shift;
		ret = regmap_update_bits(rcg->clkr.regmap,
					rcg->cdiv.offset, mask,
				((cfg - 1) << rcg->cdiv.shift) & mask);
		if (ret)
			return ret;
		cfg = (2 * (f->pre_div / cfg)) - 1;
	} else {
		ret = regmap_write(rcg->clkr.regmap, rcg->cdiv.offset, 0x0);
		if (ret)
			return ret;
		cfg = ((2 * f->pre_div) - 1) << CFG_SRC_DIV_SHIFT;
	}

	mask = BIT(rcg->hid_width) - 1;
	mask |= CFG_SRC_SEL_MASK | CFG_MODE_MASK;
	cfg |= rcg->parent_map[f->src].cfg << CFG_SRC_SEL_SHIFT;
	if (rcg->mnd_width && f->n)
		cfg |= CFG_MODE_DUAL_EDGE;
	ret = regmap_update_bits(rcg->clkr.regmap,
			rcg->cmd_rcgr + CFG_REG, mask, cfg);
	if (ret)
		return ret;

	return cdiv_update_config(rcg);
}

static int __clk_cdiv_rcg2_set_rate(struct clk_hw *hw, unsigned long rate)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);
	const struct freq_tbl *f;

	f = qcom_find_freq(rcg->freq_tbl, rate);
	if (!f)
		return -EINVAL;

	return clk_cdiv_rcg2_configure(rcg, f);
}

static int clk_cdiv_rcg2_set_rate(struct clk_hw *hw, unsigned long rate,
			    unsigned long parent_rate)
{
	return __clk_cdiv_rcg2_set_rate(hw, rate);
}

static int clk_cdiv_rcg2_set_rate_and_parent(struct clk_hw *hw,
		unsigned long rate, unsigned long parent_rate, u8 index)
{
	return __clk_cdiv_rcg2_set_rate(hw, rate);
}

const struct clk_ops clk_cdiv_rcg2_ops = {
	.is_enabled			= clk_cdiv_rcg2_is_enabled,
	.get_parent			= clk_cdiv_rcg2_get_parent,
	.set_parent			= clk_cdiv_rcg2_set_parent,
	.recalc_rate			= clk_cdiv_rcg2_recalc_rate,
	.determine_rate			= clk_cdiv_rcg2_determine_rate,
	.set_rate			= clk_cdiv_rcg2_set_rate,
	.set_rate_and_parent		= clk_cdiv_rcg2_set_rate_and_parent,
};
EXPORT_SYMBOL_GPL(clk_cdiv_rcg2_ops);

static int clk_muxr_is_enabled(struct clk_hw *hw)
{
	return 0;
}

static u8 clk_muxr_get_parent(struct clk_hw *hw)
{
	struct clk_muxr_misc *rcg = to_clk_muxr_misc(hw);
	int num_parents = __clk_get_num_parents(hw->clk);
	u32 cfg;
	int i, ret;

	ret = regmap_read(rcg->clkr.regmap, rcg->muxr.offset, &cfg);
	if (ret)
		goto err;

	cfg >>= rcg->muxr.shift;
	cfg &= rcg->muxr.mask;

	for (i = 0; i < num_parents; i++)
		if (cfg == rcg->parent_map[i].cfg)
			return i;

err:
	pr_debug("%s: Cannot find parent of %s clock, using default.\n",
			__func__, __clk_get_name(hw->clk));
	return 0;
}

static int clk_muxr_set_parent(struct clk_hw *hw, u8 index)
{
	struct clk_muxr_misc *rcg = to_clk_muxr_misc(hw);
	int ret;

	ret = regmap_update_bits(rcg->clkr.regmap, rcg->muxr.offset,
				 (rcg->muxr.mask<<rcg->muxr.shift),
				 rcg->parent_map[index].cfg << rcg->muxr.shift);
	if (ret)
		return ret;

	return 0;
}

static unsigned long
clk_muxr_recalc_rate(struct clk_hw *hw, unsigned long parent_rate)
{
	struct clk_muxr_misc *rcg = to_clk_muxr_misc(hw);
	u32 misc;
	int ret;

	ret = regmap_read(rcg->clkr.regmap, rcg->misc.offset, &misc);
	if (ret)
		return 0UL;

	misc &= rcg->misc.mask;
	misc >>= rcg->misc.shift;

	return parent_rate * (misc + 1);
}

static long clk_muxr_determine_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long *p_rate, struct clk_hw **p_hw)
{
	struct clk_muxr_misc *rcg = to_clk_muxr_misc(hw);
	const struct freq_tbl *f;
	unsigned long clk_flags;
	struct clk *p;

	f = qcom_find_freq(rcg->freq_tbl, rate);
	if (!f)
		return 0L;

	clk_flags = __clk_get_flags(hw->clk);
	p = clk_get_parent_by_index(hw->clk, f->src);
	*p_hw = __clk_get_hw(p);
	if (clk_flags & CLK_SET_RATE_PARENT) {
		if (f->pre_div)
			rate *= f->pre_div;
	} else {
		rate =	__clk_get_rate(p);
	}
	*p_rate = rate;

	return f->freq;
}

static int __clk_muxr_set_rate(struct clk_hw *hw, unsigned long rate)
{
	struct clk_muxr_misc *rcg = to_clk_muxr_misc(hw);
	const struct freq_tbl *f;
	int ret;

	f = qcom_find_freq(rcg->freq_tbl, rate);
	if (!f)
		return -EINVAL;

	ret = regmap_update_bits(rcg->clkr.regmap, rcg->muxr.offset,
				rcg->muxr.mask << rcg->muxr.shift,
				rcg->parent_map[f->src].cfg << rcg->muxr.shift);
	if (ret)
		return ret;

	ret = regmap_update_bits(rcg->clkr.regmap, rcg->misc.offset,
				rcg->misc.mask << rcg->misc.shift,
				(f->pre_div - 1) << rcg->misc.shift);
	return ret;
}

static int clk_muxr_set_rate(struct clk_hw *hw, unsigned long rate,
			    unsigned long parent_rate)
{
	return __clk_muxr_set_rate(hw, rate);
}

static int clk_muxr_set_rate_and_parent(struct clk_hw *hw,
		unsigned long rate, unsigned long parent_rate, u8 index)
{
	return __clk_muxr_set_rate(hw, rate);
}

const struct clk_ops clk_muxr_misc_ops = {
	.is_enabled	=	clk_muxr_is_enabled,
	.get_parent	=	clk_muxr_get_parent,
	.set_parent	=	clk_muxr_set_parent,
	.recalc_rate	=	clk_muxr_recalc_rate,
	.determine_rate	=	clk_muxr_determine_rate,
	.set_rate	=	clk_muxr_set_rate,
	.set_rate_and_parent	=	clk_muxr_set_rate_and_parent,
};
EXPORT_SYMBOL_GPL(clk_muxr_misc_ops);


static int clk_cpu_rcg2_is_enabled(struct clk_hw *hw)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);
	u32 cmd;
	int ret;

	ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CMD_REG, &cmd);
	if (ret)
		return 0;

	return (cmd & CMD_ROOT_OFF) == 0;

}

static u8 clk_cpu_rcg2_get_parent(struct clk_hw *hw)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);
	int num_parents = __clk_get_num_parents(hw->clk);
	u32 cfg;
	int i, ret;

	ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG, &cfg);
	if (ret)
		goto err;

	cfg &= CFG_SRC_SEL_MASK;
	cfg >>= CFG_SRC_SEL_SHIFT;

	for (i = 0; i < num_parents; i++)
		if (cfg == rcg->parent_map[i].cfg)
			return i;

err:
	pr_debug("%s: Cannot find parent of %s clock, using default.\n",
			__func__, __clk_get_name(hw->clk));
	return 0;
}

static int cpu_rcg2_update_config(struct clk_cdiv_rcg2 *rcg)
{
	int count, ret;
	u32 cmd;
	struct clk_hw *hw = &rcg->clkr.hw;
	const char *name = __clk_get_name(hw->clk);

	ret = regmap_update_bits(rcg->clkr.regmap, rcg->cmd_rcgr + CMD_REG,
				 CMD_UPDATE, CMD_UPDATE);
	if (ret)
		return ret;

	/* Wait for update to take effect */
	for (count = 500; count > 0; count--) {
		/* ignore regmap errors until we exhaust retry count.*/
		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CMD_REG,
									&cmd);
		if (ret >= 0 && !(cmd & CMD_UPDATE))
			return 0;

		udelay(1);
	}

	WARN(1, "%s: rcg didn't update its configuration.", name);
	return ret ? ret : -ETIMEDOUT;
}

static int clk_cpu_rcg2_set_parent(struct clk_hw *hw, u8 index)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);
	int ret;

	ret = regmap_update_bits(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG,
				 CFG_SRC_SEL_MASK,
				 rcg->parent_map[index].cfg << CFG_SRC_SEL_SHIFT);
	if (ret)
		return ret;

	return cpu_rcg2_update_config(rcg);
}


/*
 * These are used for looking up the actual divider ratios
 * the divider used for DDR PLL Post divider is not linear,
 * hence we need this look up table
 */
static const unsigned char ddrpll_div[] = {
		12,
		13,
		14,
		15,
		16,
		17,
		18,
		19,
		20,
		21,
		22,
		24,
		26,
		28
};

static unsigned long
clk_cpu_rcg2_recalc_rate(struct clk_hw *hw, unsigned long parent_rate)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);
	u32 cfg, hid_div , m = 0 , n = 0 , mode = 0 , mask , cdiv;
	unsigned long rate;
	u32 src;
	int ret;

	ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + CFG_REG, &cfg);
	if (ret)
		return 0UL;

	if (rcg->mnd_width) {
		mask = BIT(rcg->mnd_width) - 1;
		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + M_REG, &m);
		if (ret)
			return 0UL;

		m &= mask;

		ret = regmap_read(rcg->clkr.regmap, rcg->cmd_rcgr + N_REG, &n);
		if (ret)
			return 0UL;

		n =  ~n;
		n &= mask;

		n += m;
		mode = cfg & CFG_MODE_MASK;
		mode >>= CFG_MODE_SHIFT;
	}

	mask = BIT(rcg->hid_width) - 1;
	hid_div = cfg >> CFG_SRC_DIV_SHIFT;
	hid_div &= mask;
	rate = calc_rate(parent_rate, m, n, mode, hid_div);
	src = (cfg >> CFG_SRC_SEL_SHIFT) & 0xf;
	if (src == 0x1) {
		ret = regmap_read(rcg->clkr.regmap, rcg->cdiv.offset, &cdiv);
		if (ret)
			return 0UL;

		cdiv &= (rcg->cdiv.mask << rcg->cdiv.shift);
		cdiv = cdiv >> rcg->cdiv.shift;
		do_div(rate , ddrpll_div[cdiv]);
		rate *= 16;
		do_div(rate , 1000000);
		rate = rate * 1000000;
	}
	return rate;
}

static long _cpu_rcg2_freq_tbl_determine_rate(struct clk_hw *hw,
		const struct freq_tbl *f, unsigned long rate,
		unsigned long *p_rate, struct clk_hw **p_hw)
{
	unsigned long clk_flags;
	struct clk *p;

	f = qcom_find_freq(f, rate);
	if (!f)
		return 0L;

	clk_flags = __clk_get_flags(hw->clk);
	p = clk_get_parent_by_index(hw->clk, f->src);
	*p_hw = __clk_get_hw(p);
	rate = __clk_get_rate(p);
	*p_rate = rate;

	return f->freq;
}

static long clk_cpu_rcg2_determine_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long *p_rate, struct clk_hw **p_hw)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);

	return _cpu_rcg2_freq_tbl_determine_rate(hw, rcg->freq_tbl,
							rate, p_rate, p_hw);
}


static int clk_cpu_rcg2_configure(struct clk_cdiv_rcg2 *rcg,
						const struct freq_tbl *f)
{
	u32 cfg, mask;
	int ret;

	if (rcg->mnd_width && f->n) {
		mask = BIT(rcg->mnd_width) - 1;
		ret = regmap_update_bits(rcg->clkr.regmap,
				rcg->cmd_rcgr + M_REG, mask, f->m);
		if (ret)
			return ret;

		ret = regmap_update_bits(rcg->clkr.regmap,
				rcg->cmd_rcgr + N_REG, mask, ~(f->n - f->m));
		if (ret)
			return ret;

		ret = regmap_update_bits(rcg->clkr.regmap,
				rcg->cmd_rcgr + D_REG, mask, ~f->n);
		if (ret)
			return ret;
	}

	if ((rcg->parent_map[f->src].cfg == 0x01)) {
		mask = (BIT(rcg->hid_width) - 1);
		mask |= CFG_SRC_SEL_MASK | CFG_MODE_MASK;
		cfg = FEPLL_500_SRC << CFG_SRC_SEL_SHIFT;
		cfg |= (1 << CFG_SRC_DIV_SHIFT);
		ret = regmap_update_bits(rcg->clkr.regmap,
					rcg->cmd_rcgr + CFG_REG, mask, cfg);
		if (ret)
			return ret;
		cpu_rcg2_update_config(rcg);
		mask = (rcg->cdiv.mask)<<rcg->cdiv.shift;
		ret = regmap_update_bits(rcg->clkr.regmap,
					rcg->cdiv.offset, mask,
				(f->pre_div << rcg->cdiv.shift) & mask);
		udelay(1);
		mask = BIT(rcg->hid_width) - 1;
		mask |= CFG_SRC_SEL_MASK | CFG_MODE_MASK;
		cfg = 1 << CFG_SRC_DIV_SHIFT;
	} else {
		mask = BIT(rcg->hid_width) - 1;
		mask |= CFG_SRC_SEL_MASK | CFG_MODE_MASK;
		cfg = f->pre_div << CFG_SRC_DIV_SHIFT;
	}

	cfg |= rcg->parent_map[f->src].cfg << CFG_SRC_SEL_SHIFT;
	if (rcg->mnd_width && f->n)
		cfg |= CFG_MODE_DUAL_EDGE;
	ret = regmap_update_bits(rcg->clkr.regmap,
					rcg->cmd_rcgr + CFG_REG, mask, cfg);
	if (ret)
		return ret;

	return cpu_rcg2_update_config(rcg);
}

static int __clk_cpu_rcg2_set_rate(struct clk_hw *hw, unsigned long rate)
{
	struct clk_cdiv_rcg2 *rcg = to_clk_cdiv_rcg2(hw);
	const struct freq_tbl *f;

	f = qcom_find_freq(rcg->freq_tbl, rate);
	if (!f)
		return -EINVAL;

	return clk_cpu_rcg2_configure(rcg, f);
}

static int clk_cpu_rcg2_set_rate(struct clk_hw *hw, unsigned long rate,
			    unsigned long parent_rate)
{
	return __clk_cpu_rcg2_set_rate(hw, rate);
}

static int clk_cpu_rcg2_set_rate_and_parent(struct clk_hw *hw,
		unsigned long rate, unsigned long parent_rate, u8 index)
{
	return __clk_cpu_rcg2_set_rate(hw, rate);
}

const struct clk_ops clk_cpu_rcg2_ops = {
	.is_enabled	=	clk_cpu_rcg2_is_enabled,
	.get_parent	=	clk_cpu_rcg2_get_parent,
	.set_parent	=	clk_cpu_rcg2_set_parent,
	.recalc_rate	=	clk_cpu_rcg2_recalc_rate,
	.determine_rate	=	clk_cpu_rcg2_determine_rate,
	.set_rate	=	clk_cpu_rcg2_set_rate,
	.set_rate_and_parent	=	clk_cpu_rcg2_set_rate_and_parent,
};
EXPORT_SYMBOL_GPL(clk_cpu_rcg2_ops);
