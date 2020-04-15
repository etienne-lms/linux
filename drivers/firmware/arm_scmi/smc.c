// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Message SMC/HVC
 * Transport driver
 *
 * Copyright 2020 NXP
 */

#include <linux/arm-smccc.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/slab.h>

#include "common.h"

typedef void (scmi_arm_smccc_invoke_fn)(unsigned long, struct arm_smccc_res *);

/**
 * struct scmi_smc - Structure representing a SCMI smc transport
 *
 * @cinfo: SCMI channel info
 * @shmem: Transmit/Receive shared memory area
 * @func_id: smc/hvc call function id
 */
struct scmi_smc {
	struct scmi_chan_info *cinfo;
	struct scmi_shared_mem __iomem *shmem;
	scmi_arm_smccc_invoke_fn *invoke_fn;
	u32 func_id;
};

static DEFINE_MUTEX(smc_mutex);

/* Simple wrapper functions to be able to use a function pointer */
static void _smccc_smc(unsigned long func_id, struct arm_smccc_res *res)
{
	arm_smccc_smc(func_id, 0, 0, 0, 0, 0, 0, 0, res);
}

static void _smccc_hvc(unsigned long func_id, struct arm_smccc_res *res)
{
        arm_smccc_hvc(func_id, 0, 0, 0, 0, 0, 0, 0, res);
}

static void _smccc_1_1(unsigned long func_id, struct arm_smccc_res *res)
{
	arm_smccc_1_1_invoke(func_id, 0, 0, 0, 0, 0, 0, 0, res);
}

static scmi_arm_smccc_invoke_fn *get_invoke_function(struct device *dev)
{
        const char *method;

        pr_info("probing for conduit method.\n");

        if (device_property_read_string(dev, "method", &method))
		return _smccc_1_1;

        if (!strcmp("hvc", method))
                return _smccc_hvc;

        if (!strcmp("smc", method))
                return _smccc_smc;

        dev_err(dev, "Invalid \"method\" property: %s\n", method);
        return ERR_PTR(-EINVAL);
}

static int smc_chan_setup(struct scmi_chan_info *cinfo, struct device *dev,
			  bool tx)
{
	struct device *cdev = cinfo->dev;
	struct scmi_smc *scmi_info;
	resource_size_t size;
	struct resource res;
	struct device_node *np;
	u32 func_id;
	int ret;

	if (!tx)
		return -ENODEV;

	scmi_info = devm_kzalloc(dev, sizeof(*scmi_info), GFP_KERNEL);
	if (!scmi_info)
		return -ENOMEM;

	np = of_parse_phandle(cdev->of_node, "shmem", 0);
	if (!np)
		np = of_parse_phandle(dev->of_node, "shmem", 0);
	ret = of_address_to_resource(np, 0, &res);
	of_node_put(np);
	if (ret) {
		dev_err(cdev, "failed to get SCMI Tx shared memory\n");
		return ret;
	}

	size = resource_size(&res);
	scmi_info->shmem = devm_ioremap(dev, res.start, size);
	if (!scmi_info->shmem) {
		dev_err(dev, "failed to ioremap SCMI Tx shared memory\n");
		return -EADDRNOTAVAIL;
	}

	ret = of_property_read_u32(dev->of_node, "arm,smc-id", &func_id);
	if (ret < 0)
		return ret;

	scmi_info->invoke_fn = get_invoke_function(dev);
	if (IS_ERR(scmi_info->invoke_fn))
		return PTR_ERR(scmi_info->invoke_fn);

	scmi_info->func_id = func_id;
	scmi_info->cinfo = cinfo;
	cinfo->transport_info = scmi_info;

	return 0;
}

static int smc_chan_free(int id, void *p, void *data)
{
	struct scmi_chan_info *cinfo = p;
	struct scmi_smc *scmi_info = cinfo->transport_info;

	cinfo->transport_info = NULL;
	scmi_info->cinfo = NULL;

	scmi_free_channel(cinfo, data, id);

	return 0;
}

static int smc_send_message(struct scmi_chan_info *cinfo,
			    struct scmi_xfer *xfer)
{
	struct scmi_smc *scmi_info = cinfo->transport_info;
	struct arm_smccc_res res;

	mutex_lock(&smc_mutex);

	shmem_tx_prepare(scmi_info->shmem, xfer);

	scmi_info->invoke_fn(scmi_info->func_id, &res);

	scmi_rx_callback(scmi_info->cinfo, shmem_read_header(scmi_info->shmem));

	mutex_unlock(&smc_mutex);

	return res.a0 == ~0 ? -EINVAL : 0;
}

static void smc_mark_txdone(struct scmi_chan_info *cinfo, int ret)
{
}

static void smc_fetch_response(struct scmi_chan_info *cinfo,
			       struct scmi_xfer *xfer)
{
	struct scmi_smc *scmi_info = cinfo->transport_info;

	shmem_fetch_response(scmi_info->shmem, xfer);
}

static bool
smc_poll_done(struct scmi_chan_info *cinfo, struct scmi_xfer *xfer)
{
	struct scmi_smc *scmi_info = cinfo->transport_info;

	return shmem_poll_done(scmi_info->shmem, xfer);
}

static struct scmi_transport_ops scmi_smc_ops = {
	.chan_setup = smc_chan_setup,
	.chan_free = smc_chan_free,
	.send_message = smc_send_message,
	.mark_txdone = smc_mark_txdone,
	.fetch_response = smc_fetch_response,
	.poll_done = smc_poll_done,
};

const struct scmi_desc scmi_smc_desc = {
	.ops = &scmi_smc_ops,
	.max_rx_timeout_ms = 30,
	.max_msg = 1,
	.max_msg_size = 128,
};
