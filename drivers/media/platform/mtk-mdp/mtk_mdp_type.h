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


#ifndef __MTK_MDP_TYPE_H__
#define __MTK_MDP_TYPE_H__


#define DP_COLORFMT_PACK(VIDEO, PLANE, COPLANE, HF, VF, BITS, GROUP, SWAP, ID) \
	(((VIDEO) << 27) | ((PLANE) << 24) | ((COPLANE) << 22) |\
	((HF) << 20) | ((VF) << 18) | ((BITS) << 8) | ((GROUP) << 6) |\
	((SWAP) << 5) | ((ID) << 0))

enum DP_COLOR_ENUM {
	DP_COLOR_UNKNOWN = 0,
	DP_COLOR_NV12 = DP_COLORFMT_PACK(0, 2, 1, 1, 1, 8, 1, 0, 12),
	/* Mediatek proprietary format */
	DP_COLOR_420_MT21 = DP_COLORFMT_PACK(5, 2, 1, 1, 1, 256, 1, 0, 12),
	DP_COLOR_I420 = DP_COLORFMT_PACK(0, 3, 0, 1, 1, 8, 1, 0, 8),
};

#endif  /* __MTK_MDP_TYPE_H__ */

