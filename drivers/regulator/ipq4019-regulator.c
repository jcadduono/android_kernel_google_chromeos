/* Copyright (c) 2015, The Linux Foundation. All rights reserved.
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

#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/of_regulator.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/io.h>

struct ipq4019_regulator_state {
	int range;
	int value;
};

struct ipq4019_regulator_config {
	const char *supply_name;
	struct ipq4019_regulator_state *states;
	int nr_states;
	int mask;
	enum regulator_type type;
	struct regulator_init_data *init_data;
	void __iomem *base;
};

struct ipq4019_regulator_data {
	struct regulator_desc desc;
	struct regulator_dev *dev;
	struct ipq4019_regulator_config *config;
	int range;
};

static int ipq4019_regulator_get_voltage(struct regulator_dev *dev)
{
	struct ipq4019_regulator_data *data = rdev_get_drvdata(dev);
	struct ipq4019_regulator_config *cfg = data->config;
	int state_idx;

	for (state_idx = 0; state_idx < cfg->nr_states; state_idx++)
		if (cfg->states[state_idx].range == data->range)
			return cfg->states[state_idx].range;

	return -EINVAL;
}

static int ipq4019_regulator_set_voltage(struct regulator_dev *dev,
					int min_uV, int max_uV,
					unsigned *selector)
{
	struct ipq4019_regulator_data *data = rdev_get_drvdata(dev);
	struct ipq4019_regulator_config *cfg = data->config;

	int state_idx, best_val = INT_MAX, val;

	for (state_idx = 0; state_idx < cfg->nr_states; state_idx++)
		if (cfg->states[state_idx].range < best_val &&
		    cfg->states[state_idx].range >= min_uV &&
		    cfg->states[state_idx].range <= max_uV) {
			best_val = cfg->states[state_idx].value;
			if (selector)
				*selector = state_idx;
		}

	if (best_val == INT_MAX)
		return -EINVAL;

	val = readl(cfg->base);
	val  = val & (~(cfg->mask));
	writel((val | best_val), cfg->base);

	data->range = cfg->states[state_idx].range;

	return 0;
}

static int ipq4019_regulator_list_voltage(struct regulator_dev *dev,
				      unsigned selector)
{
	struct ipq4019_regulator_data *data = rdev_get_drvdata(dev);
	struct ipq4019_regulator_config *cfg = data->config;

	if (selector >= cfg->nr_states)
		return -EINVAL;

	return cfg->states[selector].range;
}

static struct regulator_ops ipq4019_regulator_voltage_ops = {
	.get_voltage = ipq4019_regulator_get_voltage,
	.set_voltage = ipq4019_regulator_set_voltage,
	.list_voltage = ipq4019_regulator_list_voltage,
};

static struct ipq4019_regulator_config *
of_get_ipq4019_regulator_data(struct device *dev, struct device_node *np)
{
	struct ipq4019_regulator_config *config;
	struct property *prop;
	int prop_entries, i;

	config = devm_kzalloc(dev,
			sizeof(struct ipq4019_regulator_config),
			GFP_KERNEL);
	if (!config)
		return ERR_PTR(-ENOMEM);

	config->init_data = of_get_regulator_init_data(dev, np);
	if (!config->init_data)
		return ERR_PTR(-EINVAL);

	config->supply_name = config->init_data->constraints.name;


	/* Fetch states. */
	prop = of_find_property(np, "states", NULL);
	if (!prop) {
		dev_err(dev, "No 'states' property found\n");
		return ERR_PTR(-EINVAL);
	}

	prop_entries = prop->length / (sizeof(int)*2);

	config->states = devm_kzalloc(dev,
				sizeof(struct ipq4019_regulator_state)
				* prop_entries,
				GFP_KERNEL);
	if (!config->states)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < prop_entries; i++) {
		config->states[i].range =
			be32_to_cpup((int *)prop->value + (i * 2));
		config->states[i].value =
			be32_to_cpup((int *)prop->value + (i * 2 + 1));
	}
	config->nr_states = prop_entries;

	prop = of_find_property(np, "mask", NULL);
	if (!prop) {
		dev_err(dev, "No 'states' property found\n");
		return ERR_PTR(-EINVAL);
	}

	config->mask = be32_to_cpup((int *)prop->value);
	config->type = REGULATOR_VOLTAGE;

	return config;
}

static int ipq4019_regulator_probe(struct platform_device *pdev)
{
	struct ipq4019_regulator_config *config = dev_get_platdata(&pdev->dev);
	struct device_node *np = pdev->dev.of_node;
	struct ipq4019_regulator_data *drvdata;
	struct regulator_config cfg = { };
	int ret;
	struct resource *res;

	drvdata = devm_kzalloc(&pdev->dev,
				sizeof(struct ipq4019_regulator_data),
				GFP_KERNEL);
	if (drvdata == NULL) {
		dev_err(&pdev->dev, "Failed to allocate device data\n");
		return -ENOMEM;
	}

	if (np) {
		config = of_get_ipq4019_regulator_data(&pdev->dev, np);
		if (IS_ERR(config))
			return PTR_ERR(config);
	}

	drvdata->desc.name = kstrdup(config->supply_name, GFP_KERNEL);
	if (drvdata->desc.name == NULL) {
		dev_err(&pdev->dev, "Failed to allocate supply name\n");
		ret = -ENOMEM;
		goto err;
	}

	drvdata->config = config;

	drvdata->desc.type = REGULATOR_VOLTAGE;
	drvdata->desc.ops = &ipq4019_regulator_voltage_ops;
	drvdata->desc.n_voltages = config->nr_states;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	drvdata->config->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(drvdata->config->base)) {
		ret = PTR_ERR(drvdata->config->base);
		goto err_state;
	}

	cfg.dev = &pdev->dev;
	cfg.init_data = config->init_data;
	cfg.driver_data = drvdata;
	cfg.of_node = np;

	drvdata->dev = regulator_register(&drvdata->desc, &cfg);
	if (IS_ERR(drvdata->dev)) {
		ret = PTR_ERR(drvdata->dev);
		dev_err(&pdev->dev, "Failed to register regulator: %d\n", ret);
		goto err_state;
	}

	platform_set_drvdata(pdev, drvdata);

	return 0;

err_state:
	kfree(drvdata->config->states);
	kfree(drvdata->config);
	kfree(drvdata->desc.name);
err:
	return ret;
}

static int ipq4019_regulator_remove(struct platform_device *pdev)
{
	struct ipq4019_regulator_data *drvdata = platform_get_drvdata(pdev);

	regulator_unregister(drvdata->dev);

	kfree(drvdata->config->states);
	kfree(drvdata->config);
	kfree(drvdata->desc.name);

	return 0;
}

#if defined(CONFIG_OF)
static const struct of_device_id regulator_ipq4019_of_match[] = {
	{ .compatible = "qcom,regulator-ipq4019", },
	{},
};
#endif

static struct platform_driver ipq4019_regulator_driver = {
	.probe		= ipq4019_regulator_probe,
	.remove		= ipq4019_regulator_remove,
	.driver		= {
		.name		= "regulator-ipq4019",
		.of_match_table = of_match_ptr(regulator_ipq4019_of_match),
	},
};

static int __init ipq4019_regulator_init(void)
{
	return platform_driver_register(&ipq4019_regulator_driver);
}
subsys_initcall(ipq4019_regulator_init);

static void __exit ipq4019_regulator_exit(void)
{
	platform_driver_unregister(&ipq4019_regulator_driver);
}
module_exit(ipq4019_regulator_exit);

MODULE_DESCRIPTION("ipq4019 voltage regulator");
