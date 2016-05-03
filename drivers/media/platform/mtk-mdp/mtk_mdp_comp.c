/*
 * Copyright (c) 2015-2016 MediaTek Inc.
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

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <soc/mediatek/smi.h>

#include "mtk_mdp_comp.h"


static const char * const mtk_mdp_comp_stem[MTK_MDP_COMP_TYPE_MAX] = {
	[MTK_MDP_RDMA] = "mdp_rdma",
	[MTK_MDP_RSZ] = "mdp_rsz",
	[MTK_MDP_WDMA] = "mdp_wdma",
	[MTK_MDP_WROT] = "mdp_wrot",
};

struct mtk_mdp_comp_match {
	enum mtk_mdp_comp_type type;
	int alias_id;
};

static const struct mtk_mdp_comp_match mtk_mdp_matches[MTK_MDP_COMP_ID_MAX] = {
	[MTK_MDP_COMP_RDMA0]	= { MTK_MDP_RDMA,	0 },
	[MTK_MDP_COMP_RDMA1]	= { MTK_MDP_RDMA,	1 },
	[MTK_MDP_COMP_RSZ0]	= { MTK_MDP_RSZ,	0 },
	[MTK_MDP_COMP_RSZ1]	= { MTK_MDP_RSZ,	1 },
	[MTK_MDP_COMP_RSZ2]	= { MTK_MDP_RSZ,	2 },
	[MTK_MDP_COMP_WDMA]	= { MTK_MDP_WDMA,	0 },
	[MTK_MDP_COMP_WROT0]	= { MTK_MDP_WROT,	0 },
	[MTK_MDP_COMP_WROT1]	= { MTK_MDP_WROT,	1 },
};

int mtk_mdp_comp_get_id(struct device_node *node,
			enum mtk_mdp_comp_type comp_type)
{
	int id = of_alias_get_id(node, mtk_mdp_comp_stem[comp_type]);
	int i;

	for (i = 0; i < ARRAY_SIZE(mtk_mdp_matches); i++) {
		if (comp_type == mtk_mdp_matches[i].type &&
		    id == mtk_mdp_matches[i].alias_id)
			return i;
	}

	return -EINVAL;
}

void mtk_mdp_comp_clock_on(struct device *dev, struct mtk_mdp_comp *comp)
{
	int i, err;

	if (!comp)
		return;

	if (comp->larb_dev) {
		err = mtk_smi_larb_get(comp->larb_dev);
		if (err)
			dev_err(dev, "failed to get larb, err %d\n", err);
	}

	for (i = 0; i < ARRAY_SIZE(comp->clk); i++) {
		if (!comp->clk[i])
			continue;
		err = clk_prepare_enable(comp->clk[i]);
		if (err)
			dev_err(dev, "failed to enable clock, err %d\n",
				err);
	}
}

void mtk_mdp_comp_clock_off(struct device *dev, struct mtk_mdp_comp *comp)
{
	int i;

	if (!comp)
		return;

	for (i = 0; i < ARRAY_SIZE(comp->clk); i++) {
		if (!comp->clk[i])
			continue;
		clk_disable_unprepare(comp->clk[i]);
	}

	if (comp->larb_dev)
		mtk_smi_larb_put(comp->larb_dev);
}

int mtk_mdp_comp_init(struct device *dev, struct device_node *node,
		      struct mtk_mdp_comp *comp, enum mtk_mdp_comp_id comp_id)
{
	struct device_node *larb_node;
	struct platform_device *larb_pdev;
	int i;

	if (comp_id < 0 || comp_id >= MTK_MDP_COMP_ID_MAX)
		return -EINVAL;

	comp->dev_node = of_node_get(node);
	comp->id = comp_id;
	comp->type = mtk_mdp_matches[comp_id].type;
	comp->regs = of_iomap(node, 0);

	for (i = 0; i < ARRAY_SIZE(comp->clk); i++) {
		comp->clk[i] = of_clk_get(node, i);
		if (IS_ERR(comp->clk[i]))
			comp->clk[i] = NULL;
	}

	/* Only DMA capable components need the LARB property */
	comp->larb_dev = NULL;
	if (comp->type != MTK_MDP_RDMA &&
	    comp->type != MTK_MDP_WDMA &&
	    comp->type != MTK_MDP_WROT)
		return 0;

	larb_node = of_parse_phandle(node, "mediatek,larb", 0);
	if (!larb_node) {
		dev_err(dev,
			"Missing mediadek,larb phandle in %s node\n",
			node->full_name);
		return -EINVAL;
	}

	larb_pdev = of_find_device_by_node(larb_node);
	if (!larb_pdev) {
		dev_warn(dev, "Waiting for larb device %s\n",
			 larb_node->full_name);
		of_node_put(larb_node);
		return -EPROBE_DEFER;
	}
	of_node_put(larb_node);

	comp->larb_dev = &larb_pdev->dev;

	return 0;
}

void mtk_mdp_comp_deinit(struct device *dev, struct mtk_mdp_comp *comp)
{
	if (!comp)
		return;
	of_node_put(comp->dev_node);
}
