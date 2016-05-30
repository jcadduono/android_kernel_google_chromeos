/* Copyright (c) 2016, The Linux Foundation. All rights reserved.
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
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/bitops.h>
#include <sound/pcm.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/reset.h>
#include <linux/spinlock.h>

#include "ipq4019-adss.h"

static void __iomem *adss_audio_local_base;
static struct reset_control *audio_blk_rst;
static spinlock_t i2s_ctrl_lock;
static spinlock_t glb_mode_lock;

/* I2S Interface Enable */
static void ipq4019_glb_i2s_interface_en(int enable)
{
	u32 cfg;
	unsigned long flags;

	spin_lock_irqsave(&i2s_ctrl_lock, flags);
	cfg = readl(adss_audio_local_base + ADSS_GLB_CHIP_CTRL_I2S_REG);
	cfg &= ~GLB_CHIP_CTRL_I2S_INTERFACE_EN;
	if (enable)
		cfg |= GLB_CHIP_CTRL_I2S_INTERFACE_EN;
	writel(cfg, adss_audio_local_base + ADSS_GLB_CHIP_CTRL_I2S_REG);
	spin_unlock_irqrestore(&i2s_ctrl_lock, flags);
	/*
	 * As per the audio controller susbsytem after writing to
	 * the register wait 5ms for the i2s settle down.
	 */
	mdelay(5);
}

/*
 * I2S Module Reset
 */
static void ipq4019_glb_i2s_reset(void)
{
	writel(GLB_I2S_RESET_VAL, adss_audio_local_base + ADSS_GLB_I2S_RST_REG);
	mdelay(5);
	writel(0x0, adss_audio_local_base + ADSS_GLB_I2S_RST_REG);
}

/*
 * Enable I2S/TDM and Playback/Capture Audio Mode
 */
void ipq4019_glb_audio_mode(int mode, int dir)
{
	u32 cfg;
	unsigned long flags;

	spin_lock_irqsave(&glb_mode_lock, flags);
	cfg = readl(adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	if (mode == I2S && dir == PLAYBACK) {
		cfg &= ~GLB_AUDIO_MODE_XMIT_MASK;
		cfg |= GLB_AUDIO_MODE_XMIT_I2S;
	} else if (mode == I2S && dir == CAPTURE) {
		cfg &= ~GLB_AUDIO_MODE_RECV_MASK;
		cfg |= GLB_AUDIO_MODE_RECV_I2S;
	} else if (mode == TDM && dir == PLAYBACK) {
		cfg &= ~GLB_AUDIO_MODE_XMIT_MASK;
		cfg |= GLB_AUDIO_MODE_XMIT_TDM;
	} else if (mode == TDM && dir == CAPTURE) {
		cfg &= ~GLB_AUDIO_MODE_RECV_MASK;
		cfg |= GLB_AUDIO_MODE_RECV_TDM;
	}
	writel(cfg, adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	spin_unlock_irqrestore(&glb_mode_lock, flags);
}
EXPORT_SYMBOL(ipq4019_glb_audio_mode);

/* I2S0 TX Data Port Enable */
/* Todo : Check if bits 6:4 configures only
	  I2S0 or other channels as well */
void ipq4019_glb_tx_data_port_en(u32 enable)
{
	u32 cfg;
	unsigned long flags;

	spin_lock_irqsave(&glb_mode_lock, flags);
	cfg = readl(adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	cfg &= ~GLB_AUDIO_MODE_I2S0_TXD_OE;
	if (enable)
		cfg |= GLB_AUDIO_MODE_I2S0_TXD_OE;
	writel(cfg, adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	spin_unlock_irqrestore(&glb_mode_lock, flags);
}
EXPORT_SYMBOL(ipq4019_glb_tx_data_port_en);

/*
 * I2S3 RX Data Port Enable
 */
void ipq4019_glb_rx_data_port_en(u32 enable)
{
	u32 cfg;
	unsigned long flags;

	spin_lock_irqsave(&glb_mode_lock, flags);
	cfg = readl(adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	cfg &= ~GLB_AUDIO_MODE_I2S3_RXD_OE;
	if (enable)
		cfg |= GLB_AUDIO_MODE_I2S3_RXD_OE;
	writel(cfg, adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	spin_unlock_irqrestore(&glb_mode_lock, flags);
}
EXPORT_SYMBOL(ipq4019_glb_rx_data_port_en);

/*
 * Cross 1K Boundary
 */
static void ipq4019_glb_audio_mode_B1K(void)
{
	u32 cfg;
	unsigned long flags;

	spin_lock_irqsave(&glb_mode_lock, flags);
	cfg =  readl(adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	cfg &= ~GLB_AUDIO_MODE_B1K;
	cfg |= GLB_AUDIO_MODE_B1K;
	writel(cfg, adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	spin_unlock_irqrestore(&glb_mode_lock, flags);
}

/*
 * Frame Sync Port Enable for I2S0 TX
 */
void ipq4019_glb_tx_framesync_port_en(u32 enable)
{
	u32 cfg;
	unsigned long flags;

	spin_lock_irqsave(&glb_mode_lock, flags);
	cfg =  readl(adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	cfg &= ~GLB_AUDIO_MODE_I2S0_FS_OE;
	if (enable)
		cfg |= GLB_AUDIO_MODE_I2S0_FS_OE;
	writel(cfg, adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	spin_unlock_irqrestore(&glb_mode_lock, flags);
}
EXPORT_SYMBOL(ipq4019_glb_tx_framesync_port_en);

/*
 * Frame Sync Port Enable for I2S3 RX
 */
void ipq4019_glb_rx_framesync_port_en(u32 enable)
{
	u32 cfg;
	unsigned long flags;

	spin_lock_irqsave(&glb_mode_lock, flags);
	cfg =  readl(adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	cfg &= ~GLB_AUDIO_MODE_I2S3_FS_OE;
	if (enable)
		cfg |= GLB_AUDIO_MODE_I2S3_FS_OE;
	writel(cfg, adss_audio_local_base + ADSS_GLB_AUDIO_MODE_REG);
	spin_unlock_irqrestore(&glb_mode_lock, flags);
}
EXPORT_SYMBOL(ipq4019_glb_rx_framesync_port_en);

void ipq4019_glb_clk_enable_oe(u32 dir)
{
	u32 cfg;
	unsigned long flags;

	spin_lock_irqsave(&i2s_ctrl_lock, flags);
	cfg = readl(adss_audio_local_base + ADSS_GLB_CLK_I2S_CTRL_REG);

	if (dir == PLAYBACK) {
		cfg |= (GLB_CLK_I2S_CTRL_TX_BCLK_OE |
			GLB_CLK_I2S_CTRL_TX_MCLK_OE);
	} else {
		cfg |= (GLB_CLK_I2S_CTRL_RX_BCLK_OE |
			GLB_CLK_I2S_CTRL_RX_MCLK_OE);
	}
	writel(cfg, adss_audio_local_base + ADSS_GLB_CLK_I2S_CTRL_REG);
	spin_unlock_irqrestore(&i2s_ctrl_lock, flags);
}
EXPORT_SYMBOL(ipq4019_glb_clk_enable_oe);

static const struct of_device_id ipq4019_audio_adss_id_table[] = {
	{ .compatible = "qca,ipq4019-audio-adss" },
	{},
};
MODULE_DEVICE_TABLE(of, ipq4019_audio_adss_id_table);

static int ipq4019_audio_adss_probe(struct platform_device *pdev)
{
	struct resource *res;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	adss_audio_local_base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(adss_audio_local_base))
		return PTR_ERR(adss_audio_local_base);

	audio_blk_rst = devm_reset_control_get(&pdev->dev, "blk_rst");
	if (IS_ERR(audio_blk_rst))
		return PTR_ERR(audio_blk_rst);

	spin_lock_init(&i2s_ctrl_lock);
	spin_lock_init(&glb_mode_lock);

	/*
	 * Reset order is critical here.
	 * First audio block should be out of reset,
	 * followed by I2S block.
	 * Since the audio block is brought out of
	 * reset by hardware by default, it is not
	 * required to be done in software explicitly.
	 */
	ipq4019_glb_i2s_reset();

	ipq4019_glb_i2s_interface_en(ENABLE);

	ipq4019_glb_audio_mode_B1K();

	return 0;
}

static int ipq4019_audio_adss_remove(struct platform_device *pdev)
{
	ipq4019_glb_i2s_interface_en(DISABLE);
	return 0;
}

static struct platform_driver ipq4019_audio_adss_driver = {
	.probe = ipq4019_audio_adss_probe,
	.remove = ipq4019_audio_adss_remove,
	.driver = {
		.name = "ipq4019-adss",
		.of_match_table = ipq4019_audio_adss_id_table,
	},
};

module_platform_driver(ipq4019_audio_adss_driver);

MODULE_ALIAS("platform:ipq4019-adss");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("IPQ4019 Audio subsytem driver");
