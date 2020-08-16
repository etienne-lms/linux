// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) based regulator driver
 *
 * Copyright (C) 2020 ARM Ltd.
 *
 * Implements a regulator driver on top of the SCMI Voltage Protocol.
 *
 * The ARM SCMI Protocol aims in general to hide as much as possible all the
 * underlying operational details while providing an abstracted interface for
 * its users to operate upon: as a consequence the resulting operational
 * capabilities and configurability of this regulator device are much more
 * limited than the ones usually available on a standard physical regulator.
 *
 * The supported SCMI regulator ops are restricted to the bare minimum:
 *
 *  - 'status_ops': enable/disable/is_enabled
 *  - 'voltage_ops': get_voltage/set_voltage
 *		     get_voltage_sel/set_voltage_sel
 *		     list_voltage/map_voltage
 *
 * Each SCMI regulator instance is associated, through the means of a proper DT
 * entry description, to a specific SCMI Voltage Domain.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/linear_range.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/of_regulator.h>
#include <linux/scmi_protocol.h>
#include <linux/slab.h>
#include <linux/types.h>

struct scmi_regulator {
	u32 id;
	const char *name;
	struct scmi_device *sdev;
	struct regulator_dev *rdev;
	struct device_node *of_node;
	struct regulator_desc desc;
	struct regulator_config conf;
};

struct scmi_regulator_info {
	int num_doms;
	struct scmi_regulator **sregv;
};

static inline int __scmi_regulator_enable(struct regulator_dev *rdev,
					  bool enable)
{
	int ret;
	struct scmi_regulator *sreg = rdev_get_drvdata(rdev);
	const struct scmi_handle *handle = sreg->sdev->handle;

	ret = handle->voltage_ops->config_set(handle, sreg->id,
					      enable ?
					      SCMI_VOLTAGE_ARCH_STATE_ON :
					      SCMI_VOLTAGE_ARCH_STATE_OFF);
	return ret;
}

static int scmi_reg_enable(struct regulator_dev *rdev)
{
	return __scmi_regulator_enable(rdev, true);
}

static int scmi_reg_disable(struct regulator_dev *rdev)
{
	return __scmi_regulator_enable(rdev, false);
}

static int scmi_reg_is_enabled(struct regulator_dev *rdev)
{
	int ret;
	u32 config;
	struct scmi_regulator *sreg = rdev_get_drvdata(rdev);
	const struct scmi_handle *handle = sreg->sdev->handle;

	ret = handle->voltage_ops->config_get(handle, sreg->id,
					      &config);
	return ret ? 0 : config & SCMI_VOLTAGE_ARCH_STATE_ON;
}

static int scmi_reg_get_voltage(struct regulator_dev *rdev)
{
	u32 volt_uV;
	struct scmi_regulator *sreg = rdev_get_drvdata(rdev);
	const struct scmi_handle *handle = sreg->sdev->handle;

	if (handle->voltage_ops->level_get(handle, sreg->id, (s32 *)&volt_uV))
		return -EIO;

	return volt_uV;
}

static int scmi_reg_get_voltage_sel(struct regulator_dev *rdev)
{
	s32 volt_uV;
	struct scmi_regulator *sreg = rdev_get_drvdata(rdev);
	const struct scmi_handle *handle = sreg->sdev->handle;

	if (handle->voltage_ops->level_get(handle, sreg->id, &volt_uV))
		return -EIO;

	return sreg->desc.ops->map_voltage(rdev, volt_uV, volt_uV);
}

static int scmi_reg_set_voltage(struct regulator_dev *rdev, int min_uV,
				int max_uV, unsigned int *selector)
{
	struct scmi_regulator *sreg = rdev_get_drvdata(rdev);
	const struct scmi_handle *handle = sreg->sdev->handle;

	/*
	 * This should have been filtered out by non-negative
	 * constraints...just in case.
	 */
	if (min_uV < 0 || max_uV < 0) {
		dev_warn(&sreg->sdev->dev, "Negative voltages NOT supported\n");
		return -EINVAL;
	}

	if (handle->voltage_ops->level_set(handle, sreg->id, 0x0, min_uV))
		return -EIO;

	if (selector)
		*selector = sreg->desc.ops->map_voltage(rdev, min_uV, max_uV);

	return 0;
}

static int scmi_reg_set_voltage_sel(struct regulator_dev *rdev,
				    unsigned int selector)
{
	s32 volt_uV;
	struct scmi_regulator *sreg = rdev_get_drvdata(rdev);
	const struct scmi_handle *handle = sreg->sdev->handle;

	volt_uV = sreg->desc.ops->list_voltage(rdev, selector);
	if (volt_uV <= 0)
		return -EINVAL;

	if (handle->voltage_ops->level_set(handle, sreg->id, 0x0, volt_uV))
		return -EIO;

	return 0;
}

static struct regulator_ops scmi_reg_fixed_ops = {
	.enable = scmi_reg_enable,
	.disable = scmi_reg_disable,
	.is_enabled = scmi_reg_is_enabled,
};

static struct regulator_ops scmi_reg_linear_ops = {
	.enable = scmi_reg_enable,
	.disable = scmi_reg_disable,
	.is_enabled = scmi_reg_is_enabled,
	.get_voltage = scmi_reg_get_voltage,
	.set_voltage = scmi_reg_set_voltage,
	.list_voltage = regulator_list_voltage_linear,
	.map_voltage = regulator_map_voltage_linear,
};

static struct regulator_ops scmi_reg_range_ops = {
	.enable = scmi_reg_enable,
	.disable = scmi_reg_disable,
	.is_enabled = scmi_reg_is_enabled,
	.get_voltage = scmi_reg_get_voltage,
	.set_voltage = scmi_reg_set_voltage,
	.list_voltage = regulator_list_voltage_linear_range,
	.map_voltage = regulator_map_voltage_linear_range,
};

static struct regulator_ops scmi_reg_discrete_ops = {
	.enable = scmi_reg_enable,
	.disable = scmi_reg_disable,
	.is_enabled = scmi_reg_is_enabled,
	.get_voltage_sel = scmi_reg_get_voltage_sel,
	.set_voltage_sel = scmi_reg_set_voltage_sel,
	.list_voltage = regulator_list_voltage_table,
	.map_voltage = regulator_map_voltage_iterate,
};

static int scmi_config_linear_regulator_mappings(struct scmi_regulator *sreg,
					const struct scmi_voltage_info *vinfo)
{
	/*
	 * Note that SCMI voltage domains describable by linear ranges
	 * (segments) {low, high, step} are guaranteed to come in triplets by
	 * the SCMI Voltage Domain protocol support itself.
	 */
	if (vinfo->num_levels == 3) {
		s32 delta_uV;

		delta_uV = (vinfo->levels_uV[SCMI_VOLTAGE_SEGMENT_HIGH] -
				vinfo->levels_uV[SCMI_VOLTAGE_SEGMENT_LOW]);
		/* Rule out buggy negative-intervals answers from fw */
		if (delta_uV < 0) {
			dev_err(&sreg->sdev->dev,
				"Invalid volt-ranges for domain %s\n",
				sreg->name);
			return -EINVAL;
		}

		if (!delta_uV) {
			/* Just one fixed voltage exposed by SCMI */
			sreg->desc.fixed_uV =
				vinfo->levels_uV[SCMI_VOLTAGE_SEGMENT_LOW];
			sreg->desc.n_voltages = 1;
			sreg->desc.ops = &scmi_reg_fixed_ops;
		} else {
			/* One simple linear mapping. */
			sreg->desc.min_uV =
				vinfo->levels_uV[SCMI_VOLTAGE_SEGMENT_LOW];
			sreg->desc.uV_step =
				vinfo->levels_uV[SCMI_VOLTAGE_SEGMENT_STEP];
			sreg->desc.linear_min_sel = 0;
			sreg->desc.n_voltages = delta_uV / sreg->desc.uV_step;
			sreg->desc.ops = &scmi_reg_linear_ops;
		}
	} else {
		/* Multiple linear mappings. */
		int i, num_ranges, last_max = -1;
		struct linear_range *lr;

		num_ranges = vinfo->num_levels / 3;
		lr = devm_kcalloc(&sreg->sdev->dev, num_ranges,
				  sizeof(*lr), GFP_KERNEL);
		if (!lr)
			return -ENOMEM;

		sreg->desc.n_linear_ranges = num_ranges;
		sreg->desc.linear_ranges = lr;
		for (i = 0; num_ranges; num_ranges--, i += 3, lr++) {
			s32 delta_uV;

			lr->min =
				vinfo->levels_uV[i + SCMI_VOLTAGE_SEGMENT_LOW];
			lr->step =
				vinfo->levels_uV[i + SCMI_VOLTAGE_SEGMENT_STEP];
			delta_uV =
			    vinfo->levels_uV[i + SCMI_VOLTAGE_SEGMENT_HIGH] -
			    lr->min;
			if (delta_uV <= 0 || !(delta_uV / lr->step)) {
				dev_err(&sreg->sdev->dev,
					"Invalid volt-ranges for domain %s\n",
					sreg->name);
				return -EINVAL;
			}
			lr->max_sel = delta_uV / lr->step - 1;
			lr->min_sel = last_max + 1;
			last_max = lr->max_sel;
		}
		sreg->desc.n_voltages = last_max + 1;
		sreg->desc.ops = &scmi_reg_range_ops;
	}

	return 0;
}

static int scmi_config_discrete_regulator_mappings(struct scmi_regulator *sreg,
					  const struct scmi_voltage_info *vinfo)
{
	/* Discrete non linear levels are mapped to volt_table */
	sreg->desc.n_voltages = vinfo->num_levels;
	if (sreg->desc.n_voltages > 1) {
		sreg->desc.volt_table = (const unsigned int *)vinfo->levels_uV;
		sreg->desc.ops = &scmi_reg_discrete_ops;
	} else {
		sreg->desc.fixed_uV = vinfo->levels_uV[0];
		sreg->desc.ops = &scmi_reg_fixed_ops;
	}

	return 0;
}

static void get_contraints_from_info(const struct scmi_voltage_info *vinfo,
				     struct regulator_init_data *idata)
{
	unsigned long min = UINT_MAX, max = 0;

	if (vinfo->num_levels)
		return;

	if (vinfo->num_levels == 1) {
		min = vinfo->levels_uV[0];
		max = vinfo->levels_uV[0];
	} else if (vinfo->segmented) {
		min = vinfo->levels_uV[0];
		max = vinfo->levels_uV[1];
	} else {
		size_t n = 0;

		for (n = 0; n < vinfo->num_levels; n++) {
			if (vinfo->levels_uV[n] > min)
				min = vinfo->levels_uV[n];
			if (vinfo->levels_uV[n] < max)
				max = vinfo->levels_uV[n];
		}
	}

	if (min > idata->constraints.min_uV)
		idata->constraints.min_uV = min;

	if (max < idata->constraints.max_uV || !idata->constraints.max_uV)
		idata->constraints.max_uV = max;

	if (idata->constraints.min_uV != idata->constraints.max_uV)
		idata->constraints.valid_ops_mask |= REGULATOR_CHANGE_VOLTAGE;
}

static int scmi_regulator_common_init(struct scmi_regulator *sreg)
{
	int ret;
	const struct scmi_handle *handle = sreg->sdev->handle;
	struct device *dev = &sreg->sdev->dev;
	const struct scmi_voltage_info *vinfo;
	struct regulator_init_data *idata;

	vinfo = handle->voltage_ops->info_get(handle, sreg->id);
	if (!vinfo)
		return -ENODEV;

	if (!vinfo->num_levels)
		return -EINVAL;

	/*
	 * Regulator framework does not fully support negative voltages
	 * so we discard any voltage domain reported as supporting negative
	 * voltages: as a consequence each levels_uV entry is guaranteed to
	 * be non-negative from here on.
	 */
	if (vinfo->negative_volts_allowed) {
		dev_warn(dev, "Negative voltages NOT supported...skip %s\n",
			 sreg->of_node->full_name);
		return -EOPNOTSUPP;
	}

	sreg->name = devm_kasprintf(dev, GFP_KERNEL, "%s", vinfo->name);
	sreg->desc.name = devm_kasprintf(dev, GFP_KERNEL,
					 "Vscmi.%s", sreg->name);
	if (!sreg->name || !sreg->desc.name)
		return -ENOMEM;

	sreg->desc.id = sreg->id;
	sreg->desc.type = REGULATOR_VOLTAGE;
	sreg->desc.owner = THIS_MODULE;
	if (vinfo->segmented)
		ret = scmi_config_linear_regulator_mappings(sreg, vinfo);
	else
		ret = scmi_config_discrete_regulator_mappings(sreg, vinfo);
	if (ret)
		return ret;

	/* Parse and fill configured constraints */
	idata = of_get_regulator_init_data(dev, sreg->of_node, &sreg->desc);
	if (!idata)
		return -ENOMEM;

	get_contraints_from_info(vinfo, idata);

	sreg->conf.init_data = idata;
	sreg->conf.of_node = sreg->of_node;
	sreg->conf.dev = dev;
	sreg->conf.driver_data = sreg;

	return 0;
}

static int process_scmi_regulator_of_node(struct scmi_device *sdev,
					  struct device_node *np,
					  struct scmi_regulator_info *rinfo,
					  phandle phandle)
{
	int dom, ret;
	struct of_phandle_args p_args;

	ret = of_parse_phandle_with_args(np, "voltage-domains",
					 "#voltage-domain-cells", 0, &p_args);

	if (ret || p_args.args_count != 1 ||
	    phandle != p_args.np->phandle ||
	    p_args.args[0] >= rinfo->num_doms)
		return ret ?: -ENODEV;

	dom = p_args.args[0];
	if (rinfo->sregv[dom]) {
		dev_err(&sdev->dev,
			"SCMI Voltage Domain %d already in use. Skipping: %s\n",
			dom, np->full_name);
		return -EINVAL;
	}

	rinfo->sregv[dom] = devm_kzalloc(&sdev->dev,
					 sizeof(struct scmi_regulator),
					 GFP_KERNEL);
	if (!rinfo->sregv[dom])
		return -ENOMEM;

	rinfo->sregv[dom]->id = dom;
	rinfo->sregv[dom]->sdev = sdev;
	/* get hold of good nodes */
	of_node_get(np);
	rinfo->sregv[dom]->of_node = np;
	dev_info(&sdev->dev,
		 "Found valid SCMI Regulator -- OF node [%d] -> %s\n",
		 dom, np->full_name);

	return ret;
}

static int scmi_regulator_probe(struct scmi_device *sdev)
{
	int d, ret, num_doms;
	struct device_node *np = NULL;
	const struct scmi_handle *handle = sdev->handle;
	struct scmi_regulator_info *rinfo;
	phandle phandle;

	if (!handle || !handle->voltage_ops)
		return -ENODEV;

	num_doms = handle->voltage_ops->num_domains_get(handle);
	if (num_doms <= 0) {
		dev_err(&sdev->dev, "number of voltage domains invalid\n");
		return num_doms ?: -EINVAL;
	}

	rinfo = devm_kzalloc(&sdev->dev, sizeof(*rinfo), GFP_KERNEL);
	if (!rinfo)
		return -ENOMEM;

	/* Allocate pointers' array for all possible domains */
	rinfo->sregv = devm_kcalloc(&sdev->dev, num_doms,
				    sizeof(rinfo->sregv), GFP_KERNEL);
	if (!rinfo->sregv)
		return -ENOMEM;

	rinfo->num_doms = num_doms;
	phandle = dev_of_node(&sdev->dev)->phandle;
	/*
	 * Start collecting into rinfo->sregv possibly good SCMI Regulators as
	 * described by a well-formed DT entry and associated with an existing
	 * plausible SCMI Voltage Domain number.
	 */
	while ((np = of_find_compatible_node(np, NULL, "arm,regulator-scmi"))) {
		ret = process_scmi_regulator_of_node(sdev, np, rinfo, phandle);
		/* abort on any mem issue */
		if (ret == -ENOMEM)
			return ret;
	}

	/*
	 * Register a regulator for each valid regulator-DT-entry that we
	 * can successfully reach via SCMI
	 */
	for (d = 0; d < num_doms; d++) {
		struct scmi_regulator *sreg = rinfo->sregv[d];

		if (!sreg)
			continue;
		ret = scmi_regulator_common_init(sreg);
		if (ret)
			continue;
		sreg->rdev = devm_regulator_register(&sdev->dev, &sreg->desc,
						     &sreg->conf);
		if (IS_ERR(sreg->rdev)) {
			sreg->rdev = NULL;
			continue;
		}

		dev_info(&sdev->dev,
			 "Regulator %s registered for domain [%d] %s\n",
			 sreg->desc.name, sreg->id, sreg->name);
	}

	dev_set_drvdata(&sdev->dev, rinfo);

	return 0;
}

static void scmi_regulator_remove(struct scmi_device *sdev)
{
	int d;
	struct scmi_regulator_info *rinfo;

	rinfo = dev_get_drvdata(&sdev->dev);
	if (!rinfo)
		return;

	for (d = 0; d < rinfo->num_doms; d++) {
		if (!rinfo->sregv[d])
			continue;

		if (rinfo->sregv[d]->rdev)
			devm_regulator_unregister(&sdev->dev,
						  rinfo->sregv[d]->rdev);
		of_node_put(rinfo->sregv[d]->of_node);
	}
}

static const struct scmi_device_id scmi_regulator_id_table[] = {
	{ SCMI_PROTOCOL_VOLTAGE,  "regulator" },
	{ },
};
MODULE_DEVICE_TABLE(scmi, scmi_regulator_id_table);

static struct scmi_driver scmi_drv = {
	.name		= "scmi-regulator",
	.probe		= scmi_regulator_probe,
	.remove		= scmi_regulator_remove,
	.id_table	= scmi_regulator_id_table,
};

module_scmi_driver(scmi_drv);

MODULE_AUTHOR("Cristian Marussi <cristian.marussi@arm.com>");
MODULE_DESCRIPTION("ARM SCMI regulator driver");
MODULE_LICENSE("GPL v2");
