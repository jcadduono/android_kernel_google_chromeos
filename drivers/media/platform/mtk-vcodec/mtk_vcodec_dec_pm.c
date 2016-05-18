/*
* Copyright (c) 2016 MediaTek Inc.
* Author: Tiffany Lin <tiffany.lin@mediatek.com>
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
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/pm_runtime.h>
#include <soc/mediatek/smi.h>

#include "mtk_vcodec_dec_pm.h"
#include "mtk_vcodec_util.h"
#include "mtk_vpu.h"

int mtk_vcodec_init_dec_pm(struct mtk_vcodec_dev *mtkdev)
{
	struct device_node *node;
	struct platform_device *pdev;
	struct device *dev;
	struct mtk_vcodec_pm *pm;
	int ret = 0;

	pdev = mtkdev->plat_dev;
	pm = &mtkdev->pm;
	pm->mtkdev = mtkdev;
	dev = &pdev->dev;
	node = of_parse_phandle(pdev->dev.of_node, "mediatek,larb", 0);
	if (!node) {
		mtk_v4l2_err("of_parse_phandle mediatek,larb fail!");
		return -1;
	}

	pdev = of_find_device_by_node(node);
	if (WARN_ON(!pdev)) {
		of_node_put(node);
		return -1;
	}
	pm->larbvdec = &pdev->dev;

	pdev = mtkdev->plat_dev;
	pm->dev = &pdev->dev;

	pm->vcodecpll = devm_clk_get(&pdev->dev, "vcodecpll");
	if (pm->vcodecpll == NULL) {
		mtk_v4l2_err("devm_clk_get vcodecpll fail");
		ret = -1;
	}

	pm->univpll_d2 = devm_clk_get(&pdev->dev, "univpll_d2");
	if (pm->univpll_d2 == NULL) {
		mtk_v4l2_err("devm_clk_get univpll_d2 fail");
		ret = -1;
	}

	pm->clk_cci400_sel = devm_clk_get(&pdev->dev, "clk_cci400_sel");
	if (pm->clk_cci400_sel == NULL) {
		mtk_v4l2_err("devm_clk_get clk_cci400_sel fail");
		ret = -1;
	}

	pm->vdec_sel = devm_clk_get(&pdev->dev, "vdec_sel");
	if (pm->vdec_sel == NULL) {
		mtk_v4l2_err("devm_clk_get vdec_sel fail");
		ret = -1;
	}

	pm->vdecpll = devm_clk_get(&pdev->dev, "vdecpll");
	if (pm->vdecpll == NULL) {
		mtk_v4l2_err("devm_clk_get vdecpll fail");
		ret = -1;
	}

	pm->vencpll = devm_clk_get(&pdev->dev, "vencpll");
	if (pm->vencpll == NULL) {
		mtk_v4l2_err("devm_clk_get vencpll fail");
		ret = -1;
	}

	pm->venc_lt_sel = devm_clk_get(&pdev->dev, "venc_lt_sel");
	if (pm->venc_lt_sel == NULL) {
		mtk_v4l2_err("devm_clk_get venc_lt_sel fail");
		ret = -1;
	}

	pm->vcodecpll_370p5_ck = devm_clk_get(&pdev->dev, "vcodecpll_370p5_ck");
	if (pm->vcodecpll_370p5_ck == NULL) {
		mtk_v4l2_err("devm_clk_get vcodecpll_370p5_ck fail");
		ret = -1;
	}

	pm_runtime_enable(&pdev->dev);

	return ret;
}

void mtk_vcodec_release_dec_pm(struct mtk_vcodec_dev *dev)
{
	pm_runtime_disable(dev->pm.dev);
}

void mtk_vcodec_dec_pw_on(struct mtk_vcodec_pm *pm)
{
	int ret;

	ret = pm_runtime_get_sync(pm->dev);
	if (ret)
		mtk_v4l2_err("pm_runtime_get_sync fail %d", ret);
}

void mtk_vcodec_dec_pw_off(struct mtk_vcodec_pm *pm)
{
	int ret;

	ret = pm_runtime_put_sync(pm->dev);
	if (ret)
		mtk_v4l2_err("pm_runtime_put_sync fail %d", ret);
}

void mtk_vcodec_dec_clock_on(struct mtk_vcodec_pm *pm)
{
	int ret;

	ret = clk_set_rate(pm->vcodecpll, 1482 * 1000000);
	if (ret)
		mtk_v4l2_err("clk_set_rate vcodecpll fail %d", ret);

	ret = clk_set_rate(pm->vencpll, 800 * 1000000);
	if (ret)
		mtk_v4l2_err("clk_set_rate vencpll fail %d", ret);

	ret = clk_prepare_enable(pm->vcodecpll);
	if (ret)
		mtk_v4l2_err("clk_prepare_enable vcodecpll fail %d", ret);

	ret = clk_prepare_enable(pm->vencpll);
	if (ret)
		mtk_v4l2_err("clk_prepare_enable vencpll fail %d", ret);

	ret = clk_prepare_enable(pm->vcodecpll_370p5_ck);
	if (ret)
		mtk_v4l2_err("clk_prepare_enable vcodecpll_370p5_ck fail %d",
				ret);

	ret = clk_prepare_enable(pm->venc_lt_sel);
	if (ret)
		mtk_v4l2_err("clk_prepare_enable venc_lt_sel fail %d", ret);

	ret = clk_set_parent(pm->venc_lt_sel, pm->vcodecpll_370p5_ck);
	if (ret)
		mtk_v4l2_err("clk_set_parent venc_lt_sel vcodecpll_370p5_ck fail %d",
				ret);


	ret = clk_prepare_enable(pm->univpll_d2);
	if (ret)
		mtk_v4l2_err("clk_prepare_enable univpll_d2 fail %d", ret);

	ret = clk_prepare_enable(pm->clk_cci400_sel);
	if (ret)
		mtk_v4l2_err("clk_prepare_enable clk_cci400_sel fail %d", ret);

	ret = clk_set_parent(pm->clk_cci400_sel, pm->univpll_d2);
	if (ret)
		mtk_v4l2_err("clk_set_parent clk_cci400_sel univpll_d2 fail %d",
				ret);

	ret = clk_prepare_enable(pm->vdecpll);
	if (ret)
		mtk_v4l2_err("clk_prepare_enable vdecpll fail %d", ret);

	ret = clk_prepare_enable(pm->vdec_sel);
	if (ret)
		mtk_v4l2_err("clk_prepare_enable vdec_sel fail %d", ret);

	ret = clk_set_parent(pm->vdec_sel, pm->vdecpll);
	if (ret)
		mtk_v4l2_err("clk_set_parent vdec_sel vdecpll fail %d", ret);

	ret = mtk_smi_larb_get(pm->larbvdec);
	if (ret)
		mtk_v4l2_err("mtk_smi_larb_get larbvdec fail %d", ret);

}

void mtk_vcodec_dec_clock_off(struct mtk_vcodec_pm *pm)
{
	mtk_smi_larb_put(pm->larbvdec);
	clk_disable_unprepare(pm->vdec_sel);
	clk_disable_unprepare(pm->vdecpll);
	clk_disable_unprepare(pm->univpll_d2);
	clk_disable_unprepare(pm->clk_cci400_sel);
	clk_disable_unprepare(pm->venc_lt_sel);
	clk_disable_unprepare(pm->vcodecpll_370p5_ck);
	clk_disable_unprepare(pm->vencpll);
	clk_disable_unprepare(pm->vcodecpll);
}

