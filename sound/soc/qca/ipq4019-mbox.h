/*
 * Copyright (c) 2016 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _IPQ4019_MBOX_H_
#define _IPQ4019_MBOX_H_

#include "ipq4019-adss.h"

#define ADSS_MBOX_INVALID_PCM			(0xFFFFFFFF)
#define ADSS_MBOX_REG_BASE			(0x7700000 + 0x6000)
#define ADSS_MBOX_RANGE				(0xFA000)
#define ADSS_MBOX_SPDIF_IRQ			(163 + 32)
#define ADSS_MBOX0_IRQ				(156 + 32)
#define ADSS_MBOX1_IRQ				(157 + 32)
#define ADSS_MBOX2_IRQ				(158 + 32)
#define ADSS_MBOX3_IRQ				(159 + 32)

#define CHANNEL_A_VDWORD_START 0
#define CHANNEL_B_VDWORD_START 18

#define CHANNEL_A_VDWORD_1 (CHANNEL_A_VDWORD_START + 0)
#define CHANNEL_A_VDWORD_2 (CHANNEL_A_VDWORD_START + 1)
#define CHANNEL_A_VDWORD_3 (CHANNEL_A_VDWORD_START + 2)
#define CHANNEL_A_VDWORD_4 (CHANNEL_A_VDWORD_START + 3)
#define CHANNEL_A_VDWORD_5 (CHANNEL_A_VDWORD_START + 4)
#define CHANNEL_A_VDWORD_6 (CHANNEL_A_VDWORD_START + 5)

#define CHANNEL_B_VDWORD_1 (CHANNEL_B_VDWORD_START + 0)
#define CHANNEL_B_VDWORD_2 (CHANNEL_B_VDWORD_START + 1)
#define CHANNEL_B_VDWORD_3 (CHANNEL_B_VDWORD_START + 2)
#define CHANNEL_B_VDWORD_4 (CHANNEL_B_VDWORD_START + 3)
#define CHANNEL_B_VDWORD_5 (CHANNEL_B_VDWORD_START + 4)
#define CHANNEL_B_VDWORD_6 (CHANNEL_B_VDWORD_START + 5)

#define CHANNEL_A_CDWORD_START 12
#define CHANNEL_B_CDWORD_START 30

#define CHANNEL_A_CDWORD_1 (CHANNEL_A_CDWORD_START + 0)
#define CHANNEL_B_CDWORD_2 (CHANNEL_B_CDWORD_START + 0)

/* Acc to IEC 60958-3, bit 0.0 = 0 is consumer
 *		       bit 0.1 = 1is compressed playback
 *		       bit 3.0 = 1 is sampling freq No specified
 */
#define SPDIF_CONSUMER_COMPRESD 0x01000006

enum {
	ADSS_MBOX_NR_CHANNELS = 5,
};

struct ipq4019_mbox_desc {
	unsigned int	length	: 12,	/* bit 11-00 */
			size	: 12,	/* bit 23-12 */
			vuc	: 1,	/* bit 24 */
			ei	: 1,	/* bit 25 */
			rsvd1	: 4,	/* bit 29-26 */
			EOM	: 1,	/* bit 30 */
			OWN	: 1,	/* bit 31 */
			BufPtr	: 28,   /* bit 27-00 */
			rsvd2	:  4,   /* bit 31-28 */
			NextPtr	: 28,   /* bit 27-00 */
			rsvd3	:  4;   /* bit 31-28 */

	unsigned int vuc_dword[36];
};

#define MBOX_DMA_MASK		DMA_BIT_MASK(28)

struct ipq4019_mbox_rt_dir_priv {
	/* Desc array in virtual space */
	struct ipq4019_mbox_desc *dma_virt_head;

	/* Desc array for DMA */
	dma_addr_t dma_phys_head;
	struct device *dev;
	unsigned int ndescs;
	irq_handler_t callback;
	void *dai_priv;
	unsigned long status;
	u32 channel_id;
	u32 err_stats;
	u32 last_played_is_null;
	u32 write;
	u32 read;
};

struct ipq4019_mbox_rt_priv {
	void __iomem *mbox_reg_base;
	int irq_no;
	int mbox_started;
	struct ipq4019_mbox_rt_dir_priv dir_priv[2];
};

/* Replaces struct ath_i2s_softc */
struct ipq4019_pcm_pltfm_priv {
	struct snd_pcm_substream *playback;
	struct snd_pcm_substream *capture;
};

int ipq4019_mbox_fifo_reset(int channel_id);
int ipq4019_mbox_dma_start(int channel_id);
int ipq4019_mbox_dma_stop(int channel_id, u32 delay_in_ms);
int ipq4019_mbox_dma_reset_swap(int channel_id);
int ipq4019_mbox_dma_swap(int channel_id, snd_pcm_format_t format);
int ipq4019_mbox_dma_prepare(int channel_id);
int ipq4019_mbox_dma_resume(int channel_id);
int ipq4019_mbox_form_ring(int channel_id, dma_addr_t baseaddr, u8 *base,
				int period_bytes, int bufsize);
int ipq4019_mbox_dma_release(int channel);
int ipq4019_mbox_dma_init(struct device *dev, int channel_id,
	irq_handler_t callback, void *private_data);
void ipq4019_mbox_vuc_setup(int channel_id);
u32 ipq4019_mbox_get_played_offset(u32 channel_id);
int ipq4019_mbox_dma_deinit(u32 channel_id);
void ipq4019_mbox_desc_own(u32 channel_id, int desc_no, int own);

static inline u32 ipq4019_convert_id_to_channel(u32 id)
{
	return (id / 2);
}

static inline u32 ipq4019_convert_id_to_dir(u32 id)
{
	return (id % 2);
}

#endif /* _IPQ40XX_MBOX_H_ */
