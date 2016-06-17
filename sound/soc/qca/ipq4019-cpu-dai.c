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
#include <linux/clk.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/soc.h>
#include <sound/pcm_params.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/of_device.h>
#include <linux/clk-provider.h>
#include <linux/clk-private.h>

#include "ipq4019-mbox.h"
#include "ipq4019-adss.h"

struct dai_priv_st {
	int stereo_tx;
	int stereo_rx;
	int mbox_tx;
	int mbox_rx;
	int tx_enabled;
	int rx_enabled;
	struct platform_device *pdev;
};
static struct dai_priv_st dai_priv[MAX_INTF];

static struct clk *audio_tx_bclk;
static struct clk *audio_tx_mclk;
static struct clk *audio_rx_bclk;
static struct clk *audio_rx_mclk;

/* Get Stereo channel ID based on I2S intf and direction */
int ipq4019_get_stereo_id(struct snd_pcm_substream *substream, int intf)
{
	switch (substream->stream) {
	case SNDRV_PCM_STREAM_PLAYBACK:
		return dai_priv[intf].stereo_tx;
	case SNDRV_PCM_STREAM_CAPTURE:
		return dai_priv[intf].stereo_rx;
	}
	return -EINVAL;
}
EXPORT_SYMBOL(ipq4019_get_stereo_id);

/* Get MBOX channel ID based on I2S/TDM/SPDIF intf and direction */
int ipq4019_get_mbox_id(struct snd_pcm_substream *substream, int intf)
{
	switch (substream->stream) {
	case SNDRV_PCM_STREAM_PLAYBACK:
		return dai_priv[intf].mbox_tx;
	case SNDRV_PCM_STREAM_CAPTURE:
		return dai_priv[intf].mbox_rx;
	}
	return -EINVAL;
}
EXPORT_SYMBOL(ipq4019_get_mbox_id);

static u32 ipq4019_get_act_bit_width(u32 bit_width)
{
	switch (bit_width) {
	case SNDRV_PCM_FORMAT_S8:
	case SNDRV_PCM_FORMAT_U8:
		return __BIT_8;
	case SNDRV_PCM_FORMAT_S16_LE:
	case SNDRV_PCM_FORMAT_S16_BE:
	case SNDRV_PCM_FORMAT_U16_LE:
	case SNDRV_PCM_FORMAT_U16_BE:
		return __BIT_16;
	case SNDRV_PCM_FORMAT_S24_3LE:
	case SNDRV_PCM_FORMAT_S24_3BE:
	case SNDRV_PCM_FORMAT_U24_3LE:
	case SNDRV_PCM_FORMAT_U24_3BE:
		return __BIT_32;
	case SNDRV_PCM_FORMAT_S24_LE:
	case SNDRV_PCM_FORMAT_S24_BE:
	case SNDRV_PCM_FORMAT_U24_LE:
	case SNDRV_PCM_FORMAT_U24_BE:
		return __BIT_24;
	case SNDRV_PCM_FORMAT_S32_LE:
	case SNDRV_PCM_FORMAT_S32_BE:
	case SNDRV_PCM_FORMAT_U32_LE:
	case SNDRV_PCM_FORMAT_U32_BE:
		return __BIT_32;
	}
	return __BIT_INVAL;
}

static int ipq4019_audio_clk_set(struct clk *clk, struct device *dev,
					u32 val)
{
	int ret;

	ret = clk_set_rate(clk, val);
	if (ret != 0) {
		dev_err_ratelimited(dev, "Error in setting %s\n",
						__clk_get_name(clk));
		return ret;
	}

	ret = clk_prepare_enable(clk);
	if (ret != 0) {
		dev_err_ratelimited(dev, "Error in enable %s\n",
					__clk_get_name(clk));
		return ret;
	}

	return 0;
}

static void ipq4019_audio_clk_disable(struct clk **clk, struct device *dev)
{
	if (__clk_is_enabled(*clk))
		clk_disable_unprepare(*clk);
}

static int ipq4019_audio_startup(struct snd_pcm_substream *substream,
				struct snd_soc_dai *dai)
{
	u32 intf = dai->driver->id;

	switch (substream->stream) {
	case SNDRV_PCM_STREAM_PLAYBACK:
		/* Check if the direction is enabled */
		if (dai_priv[intf].tx_enabled != ENABLE)
			return -EFAULT;

		ipq4019_glb_tx_data_port_en(ENABLE);
		ipq4019_glb_tx_framesync_port_en(ENABLE);
		break;
	case SNDRV_PCM_STREAM_CAPTURE:
		/* Check if the direction is enabled */
		if (dai_priv[intf].rx_enabled != ENABLE)
			return -EFAULT;

		ipq4019_glb_rx_data_port_en(ENABLE);
		ipq4019_glb_rx_framesync_port_en(ENABLE);
		break;
	default:
		return -EINVAL;
	}

	if (intf == I2S || intf == I2S1 || intf == I2S2) {
		/* Select I2S mode */
		ipq4019_glb_audio_mode(I2S, substream->stream);
	}

	return 0;
}

static int ipq4019_audio_hw_params(struct snd_pcm_substream *substream,
					struct snd_pcm_hw_params *params,
					struct snd_soc_dai *dai)
{
	u32 bit_width, channels, rate;
	u32 intf = dai->driver->id;
	u32 stereo_id = ipq4019_get_stereo_id(substream, intf);
	u32 mbox_id = ipq4019_get_mbox_id(substream, intf);
	u32 bit_act;
	int ret;
	u32 mclk, bclk;
	struct device *dev = &(dai_priv[intf].pdev->dev);

	bit_width = params_format(params);
	channels = params_channels(params);
	rate = params_rate(params);

	bit_act = ipq4019_get_act_bit_width(bit_width);
	bclk = rate * bit_act * channels;
	mclk = bclk * MCLK_MULTI;

	/*
	 * Stereo config reset here will resets I2S buffers and state machine
	 * and the configuration sequence to be in the below order.
	 */
	ipq4019_stereo_config_reset(stereo_id);
	ipq4019_stereo_config_enable(DISABLE, stereo_id);
	ipq4019_glb_clk_enable_oe(substream->stream);
	ipq4019_config_master(ENABLE, stereo_id);

	ret = ipq4019_cfg_bit_width(bit_width, stereo_id);
	if (ret) {
		pr_err("BitWidth %d not supported ret: %d\n", bit_width, ret);
		return ret;
	}

	ipq4019_stereo_config_mic_reset(ENABLE, stereo_id);

	mdelay(5);

	ret = ipq4019_mbox_fifo_reset(mbox_id);
	if (ret) {
		pr_err("%s: ret: %d Error in dma fifo reset\n",
					__func__, ret);
		return ret;
	}

	ipq4019_stereo_config_mic_reset(DISABLE, stereo_id);
	ipq4019_stereo_config_enable(ENABLE, stereo_id);

	switch (substream->stream) {
	case SNDRV_PCM_STREAM_PLAYBACK:
		ret = ipq4019_audio_clk_set(audio_tx_mclk, dev, mclk);
		if (ret)
			return ret;

		ret = ipq4019_audio_clk_set(audio_tx_bclk, dev, bclk);
		if (ret)
			return ret;
		break;

	case SNDRV_PCM_STREAM_CAPTURE:
		ret = ipq4019_audio_clk_set(audio_rx_mclk, dev, mclk);
		if (ret)
			return ret;

		ret = ipq4019_audio_clk_set(audio_rx_bclk, dev, bclk);
		if (ret)
			return ret;
		break;
	}

	return 0;
}

static void ipq4019_audio_shutdown(struct snd_pcm_substream *substream,
					struct snd_soc_dai *dai)
{
	u32 intf = dai->driver->id;
	struct device *dev = &(dai_priv[intf].pdev->dev);

	switch (substream->stream) {
	case SNDRV_PCM_STREAM_PLAYBACK:
		ipq4019_glb_tx_data_port_en(DISABLE);
		ipq4019_glb_tx_framesync_port_en(DISABLE);

		/* Disable the clocks */
		ipq4019_audio_clk_disable(&audio_tx_bclk, dev);
		ipq4019_audio_clk_disable(&audio_tx_mclk, dev);
		break;
	case SNDRV_PCM_STREAM_CAPTURE:
		ipq4019_glb_rx_data_port_en(DISABLE);
		ipq4019_glb_rx_framesync_port_en(DISABLE);

		/* Disable the clocks */
		ipq4019_audio_clk_disable(&audio_rx_bclk, dev);
		ipq4019_audio_clk_disable(&audio_rx_mclk, dev);
		break;
	}

	/* Disable the I2S Stereo block */
	ipq4019_stereo_config_enable(DISABLE,
			ipq4019_get_stereo_id(substream, intf));
}

static struct snd_soc_dai_ops ipq4019_audio_ops = {
	.startup	= ipq4019_audio_startup,
	.hw_params	= ipq4019_audio_hw_params,
	.shutdown	= ipq4019_audio_shutdown,
};

static struct snd_soc_dai_driver ipq4019_cpu_dais[] = {
	{
		.playback = {
			.rates		= RATE_16000_96000,
			.formats	= SNDRV_PCM_FMTBIT_S16 |
					SNDRV_PCM_FMTBIT_S32,
			.channels_min	= CH_STEREO,
			.channels_max	= CH_STEREO,
			.rate_min	= FREQ_16000,
			.rate_max	= FREQ_96000,
		},
		.capture = {
			.rates		= RATE_16000_96000,
			.formats	= SNDRV_PCM_FMTBIT_S16 |
					SNDRV_PCM_FMTBIT_S32,
			.channels_min	= CH_STEREO,
			.channels_max	= CH_STEREO,
			.rate_min	= FREQ_16000,
			.rate_max	= FREQ_96000,
		},
		.ops = &ipq4019_audio_ops,
		.id = I2S,
		.name = "qca-i2s-dai"
	},
};

static const struct snd_soc_component_driver ipq4019_i2s_component = {
	.name           = "qca-cpu-dai",
};

static const struct of_device_id ipq4019_cpu_dai_id_table[] = {
	{ .compatible = "qca,ipq4019-i2s", .data = (void *)I2S },
	{},
};
MODULE_DEVICE_TABLE(of, ipq4019_cpu_dai_id_table);

static int ipq4019_dai_probe(struct platform_device *pdev)
{
	const struct of_device_id *match;
	struct device_node *np = pdev->dev.of_node;
	int ret;
	int intf;

	match = of_match_device(ipq4019_cpu_dai_id_table, &pdev->dev);
	if (!match)
		return -ENODEV;

	intf = (u32)match->data;

	/* TX is enabled only when both DMA and Stereo TX channel
	 * is specified in the DTSi
	 */
	if (!(of_property_read_u32(np, "dma-tx-channel",
					&dai_priv[intf].mbox_tx)
		|| of_property_read_u32(np, "stereo-tx-port",
					&dai_priv[intf].stereo_tx))) {
		dai_priv[intf].tx_enabled = ENABLE;
	}

	/* RX is enabled only when both DMA and Stereo RX channel
	 * is specified in the DTSi.
	 */
	if (!(of_property_read_u32(np, "dma-rx-channel",
					&dai_priv[intf].mbox_rx))) {
		if (!(of_property_read_u32(np, "stereo-rx-port",
					&dai_priv[intf].stereo_rx)))
			dai_priv[intf].rx_enabled = ENABLE;
	}

	/* Either TX or Rx should have been enabled for a DMA/Stereo Channel */
	if (!(dai_priv[intf].tx_enabled || dai_priv[intf].rx_enabled)) {
		dev_err(&pdev->dev, "%s: error reading node properties\n",
								np->name);
		return -EFAULT;
	}

	/* Get Clks */
	audio_tx_mclk = devm_clk_get(&pdev->dev, "audio_tx_mclk");
	if (IS_ERR(audio_tx_mclk)) {
		dev_err(&pdev->dev, "Could not get tx_mclk\n");
		return PTR_ERR(audio_tx_mclk);
	}

	audio_tx_bclk = devm_clk_get(&pdev->dev, "audio_tx_bclk");
	if (IS_ERR(audio_tx_bclk)) {
		dev_err(&pdev->dev, "Could not get tx_bclk\n");
		return PTR_ERR(audio_tx_bclk);
	}

	audio_rx_mclk = devm_clk_get(&pdev->dev, "audio_rx_mclk");
	if (IS_ERR(audio_rx_mclk)) {
		dev_err(&pdev->dev, "Could not get rx_mclk\n");
		return PTR_ERR(audio_rx_mclk);
	}

	audio_rx_bclk = devm_clk_get(&pdev->dev, "audio_rx_bclk");
	if (IS_ERR(audio_rx_bclk)) {
		dev_err(&pdev->dev, "Could not get rx_bclk\n");
		return PTR_ERR(audio_rx_bclk);
	}

	dai_priv[intf].pdev = pdev;
	ret = snd_soc_register_component(&pdev->dev, &ipq4019_i2s_component,
			 ipq4019_cpu_dais, ARRAY_SIZE(ipq4019_cpu_dais));
	if (ret)
		dev_err(&pdev->dev,
			"ret: %d error registering soc dais\n", ret);

	return ret;
}

static int ipq4019_dai_remove(struct platform_device *pdev)
{
	snd_soc_unregister_component(&pdev->dev);
	return 0;
}

static struct platform_driver ipq4019_dai_driver = {
	.probe = ipq4019_dai_probe,
	.remove = ipq4019_dai_remove,
	.driver = {
		.name = "qca-cpu-dai",
		.of_match_table = ipq4019_cpu_dai_id_table,
	},
};

module_platform_driver(ipq4019_dai_driver);

MODULE_ALIAS("platform:qca-cpu-dai");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("IPQ4019 CPU DAI DRIVER");
