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

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/gpio.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>
#include <linux/gpio.h>
#include <linux/slab.h>
#include <sound/core.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/pcm.h>
#include <sound/jack.h>
#include <asm/io.h>

static struct snd_soc_dai_link ipq4019_snd_dai[] = {
	{
		.name		= "IPQ4019 Media1",
		.stream_name	= "I2S",
		/* CPU DAI Name */
		.cpu_dai_name	= "soc:ipq4019-pcm-i2s@0",
		/* Platform Driver Name */
		.platform_name	= "7709000.qca-pcm-i2s",
		/* Codec DAI Name */
		.codec_dai_name = "HiFi",
		/*Codec Driver Name */
		.codec_name = "soc:max98357a@0",
		.dai_fmt = (SND_SOC_DAIFMT_I2S |
				SND_SOC_DAIFMT_NB_NF |
				SND_SOC_DAIFMT_CBS_CFS),
	},
	{
		.name		= "IPQ40xx Capture",
		.stream_name	= "I2S Capture",
		.cpu_dai_name	= "soc:ipq4019-pcm-i2s@0",
		.platform_name	= "7709000.qca-pcm-i2s",
		.codec_dai_name = "adau7002-hifi",
		.codec_name	= "soc:adau7002@0",
	},
};

static struct snd_soc_card snd_soc_card_qca = {
	.name		= "ipq4019_snd_card",
	.dai_link	= ipq4019_snd_dai,
	.num_links	= ARRAY_SIZE(ipq4019_snd_dai),
};

static const struct of_device_id ipq4019_audio_id_table[] = {
	{ .compatible = "qca,ipq4019-audio" },
	{},
};
MODULE_DEVICE_TABLE(of, ipq4019_audio_id_table);

static int ipq4019_audio_probe(struct platform_device *pdev)
{
	int ret;
	struct snd_soc_card *card = &snd_soc_card_qca;

	card->dev = &pdev->dev;

	ret = devm_snd_soc_register_card(&pdev->dev, card);
	if (ret)
		dev_err(&pdev->dev,"snd_soc_register_card() failed:%d\n", ret);

	return ret;
}

static struct platform_driver ipq4019_audio_driver = {
	.driver = {
		.name = "ipq4019_audio",
		.of_match_table = ipq4019_audio_id_table,
	},
	.probe = ipq4019_audio_probe,
};

module_platform_driver(ipq4019_audio_driver);

MODULE_ALIAS("platform:ipq4019_audio");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("ALSA SoC IPQ40xx Machine Driver");
