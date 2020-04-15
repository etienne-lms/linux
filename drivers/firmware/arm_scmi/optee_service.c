// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Linaro Ltd.
 */

#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include <linux/uuid.h>
#include <uapi/linux/tee.h>

#include "common.h"

#define DRIVER_NAME "optee-scmi-agent"

/*
 * TA_CMD_CHANNEL_COUNT - Get number of channels supported
 *
 * param[0] (out value) - value.a: Number of communication channels
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define TA_CMD_CHANNEL_COUNT		0x0

/*
 * TA_CMD_GET_CHANNEL - Get channel identifer for a buffer pool
 *
 * param[0] (in value) - Message buffer physical start address
 * param[1] (in value) - Message buffer byte size
 * param[2] (out value) - value.a: Output channel identifier
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define TA_CMD_GET_CHANNEL		0x1


/*
 * TA_CMD_PROCESS_CHANNEL - Process message in SCMI channel
 *
 * param[0] (in value) - value.a: SCMI channel identifier
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define TA_CMD_PROCESS_CHANNEL		0x2

/**
 * struct optee_scmi_agent - OP-TEE Random Number Generator private data
 * @dev:		OP-TEE based SCMI server device.
 * @ctx:		OP-TEE context handler.
 * @session_id:		SCMI server TA session identifier.
 * @agent_count:	Count of agent channels supported by the server
 */
struct optee_scmi_agent {
	struct device *dev;
	struct tee_context *ctx;
	u32 session_id;
	unsigned int agent_count;
};

static struct optee_scmi_agent agent_private;

static int get_channel_count(void)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	dev_info(agent_private.dev, "count channels\n");

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	/* Invoke TA_CMD_CHANNEL_COUNT function of Trusted App */
	inv_arg.func = TA_CMD_CHANNEL_COUNT;
	inv_arg.session = agent_private.session_id;
	inv_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;

	ret = tee_client_invoke_func(agent_private.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		dev_err(agent_private.dev, "Failed to get agent count: 0x%x\n",
			inv_arg.ret);
		return -ENOTSUPP;
	}

	dev_info(agent_private.dev, "count channels: back: %u\n",
		 (unsigned)param[0].u.value.a);

	agent_private.agent_count = param[0].u.value.a;

	return 0;
}

static int get_channel(unsigned long pa, size_t length, int *channel_id)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];
	uint64_t addr = pa;

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	/* Invoke TA_CMD_GET_CHANNEL function of Trusted App */
	inv_arg.func = TA_CMD_GET_CHANNEL;
	inv_arg.session = agent_private.session_id;
	inv_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = addr >> 32;
	param[0].u.value.b = addr & 0xffffffff;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[1].u.value.a = length;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;

	ret = tee_client_invoke_func(agent_private.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		dev_err(agent_private.dev, "Failed to get channel: 0x%x\n",
			inv_arg.ret);
		return -ENOTSUPP;
	}

	*channel_id = param[2].u.value.a;

	return 0;
}

static int process_event(unsigned int channel_id)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	/* Invoke TA_CMD_PROCESS_CHANNEL function of Trusted App */
	inv_arg.func = TA_CMD_PROCESS_CHANNEL;
	inv_arg.session = agent_private.session_id;
	inv_arg.num_params = 4;

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = channel_id;

	ret = tee_client_invoke_func(agent_private.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		dev_err(agent_private.dev, "Failed on channel %u: 0x%x\n",
			channel_id, inv_arg.ret);
		return -EIO;
	}

	return 0;
}

/**
 * struct optee_scmi_channel - OP-TEE server assigns channel ID per shmem
 * @channle_id:		Id provided by OP-TEE for the channel
 */
struct optee_scmi_channel {
	uint32_t agent_id;
	struct scmi_chan_info *cinfo;
	struct scmi_shared_mem __iomem *shmem;
};

static int optee_scmi_get_channel(struct device *dev, struct resource *res,
				  struct optee_scmi_channel *channel)
{
	int ret;
	unsigned int id = 0;

	if (!agent_private.ctx)
		return -EPROBE_DEFER;

	if (!agent_private.agent_count)
		return -ENOENT;

	ret = get_channel(res->start, resource_size(res), &id);
	if (ret)
		return ret;

	if (channel->agent_id != id)
		dev_warn(dev, "Channel ID mismatch\n");

	return 0;
}

static int optee_chan_setup(struct scmi_chan_info *cinfo, struct device *dev,
			    bool tx)
{
	const char *desc = tx ? "Tx" : "Rx";
	int idx = tx ? 0 : 1;
	struct device *cdev = cinfo->dev;
	struct optee_scmi_channel *channel;
	u32 agent_id;
	struct device_node *shmem;
	resource_size_t size;
	struct resource res;
	int ret;

	channel = devm_kzalloc(dev, sizeof(*channel), GFP_KERNEL);
	if (!channel)
		return -ENOMEM;

	if (of_property_read_u32(dev->of_node, "agent-id", &agent_id)) {
	        dev_err(dev, "Missing \"agent-id\" property\n");
		return -EINVAL;
	}
	channel->agent_id = agent_id;

	// TODO: remove this: push buffer in invocation memeref parameter
	shmem = of_parse_phandle(cdev->of_node, "shmem", idx);
	if (!shmem) {
		dev_err(cdev, "OPTEE failed to get SCMI %s shm\n", desc);
		return -ENOENT;
	}

	ret = of_address_to_resource(shmem, 0, &res);
	of_node_put(shmem);
	if (ret) {
		dev_err(cdev, "failed to get SCMI %s shared memory\n", desc);
		return ret;
	}

	/* Get channel IDs from shm location */
	ret = optee_scmi_get_channel(dev, &res, channel);
	if (ret) {
		dev_err(dev, "failed to get OP-TEE channel %d\n", ret);
		return ret;
	}

	size = resource_size(&res);
	channel->shmem = devm_ioremap(dev, res.start, size);
	if (!channel->shmem) {
		dev_err(dev, "failed to ioremap SCMI %s shared memory\n", desc);
		return -EADDRNOTAVAIL;
	}

	cinfo->transport_info = channel;
	channel->cinfo = cinfo;

	return 0;
}

static int optee_chan_free(int id, void *p, void *data)
{
	struct scmi_chan_info *cinfo = p;
	struct optee_scmi_channel *channel = cinfo->transport_info;

	cinfo->transport_info = NULL;
	channel->cinfo = NULL;

	scmi_free_channel(cinfo, data, id);

	return 0;
}

static int optee_send_message(struct scmi_chan_info *cinfo,
			      struct scmi_xfer *xfer)
{
	struct optee_scmi_channel *channel = cinfo->transport_info;
	int ret;

	if (!channel && !agent_private.ctx)
		return -EINVAL;

	shmem_tx_prepare(channel->shmem, xfer);

	ret = process_event(channel->agent_id);
	if (ret)
		return ret;

	scmi_rx_callback(cinfo, shmem_read_header(channel->shmem));

	return 0;
}

static void optee_fetch_response(struct scmi_chan_info *cinfo,
				 struct scmi_xfer *xfer)
{
	struct optee_scmi_channel *channel = cinfo->transport_info;

	shmem_fetch_response(channel->shmem, xfer);
}

static bool optee_poll_done(struct scmi_chan_info *cinfo,
			    struct scmi_xfer *xfer)
{
	struct optee_scmi_channel *channel = cinfo->transport_info;

	return shmem_poll_done(channel->shmem, xfer);
}

static struct scmi_transport_ops scmi_optee_ops = {
	.chan_setup = optee_chan_setup,
	.chan_free = optee_chan_free,
	.send_message = optee_send_message,
	.fetch_response = optee_fetch_response,
	.poll_done = optee_poll_done,
};

const struct scmi_desc scmi_optee_desc = {
	.ops = &scmi_optee_ops,
	.max_rx_timeout_ms = 30, /* We may increase this if required */
	.max_msg = 1,
	.max_msg_size = 128,
};

static int optee_ctx_match(struct tee_ioctl_version_data *ver,
			    const void *data)
{
	return ver->impl_id == TEE_IMPL_ID_OPTEE;
}

static int optee_scmi_probe(struct device *dev)
{
	struct tee_client_device *scmi_device = to_tee_client_device(dev);
	int ret = 0, err = -ENODEV;
	struct tee_ioctl_open_session_arg sess_arg;

	memset(&sess_arg, 0, sizeof(sess_arg));

	/* Open context with TEE driver */
	agent_private.ctx = tee_client_open_context(NULL, optee_ctx_match,
						    NULL, NULL);
	if (IS_ERR(agent_private.ctx))
		return -ENODEV;

	/* Open session with SCMI server TA */
	memcpy(sess_arg.uuid, scmi_device->id.uuid.b, TEE_IOCTL_UUID_LEN);
	sess_arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	sess_arg.num_params = 0;

	ret = tee_client_open_session(agent_private.ctx, &sess_arg, NULL);
	if ((ret < 0) || (sess_arg.ret != 0)) {
		dev_err(dev, "tee_client_open_session failed, err: %x\n",
			sess_arg.ret);
		err = -EINVAL;
		goto out_ctx;
	}
	agent_private.session_id = sess_arg.session;

	err = get_channel_count();
	if (err)
		goto out_sess;

	agent_private.dev = dev;

	dev_info(dev, "OP-TEE SCMI channel probed\n");

	return 0;

out_sess:
	tee_client_close_session(agent_private.ctx, agent_private.session_id);
out_ctx:
	tee_client_close_context(agent_private.ctx);
	agent_private.ctx = NULL;

	return err;
}

static int optee_scmi_remove(struct device *dev)
{
	tee_client_close_session(agent_private.ctx, agent_private.session_id);
	tee_client_close_context(agent_private.ctx);
	agent_private.ctx = NULL;

	return 0;
}

static const struct tee_client_device_id optee_scmi_id_table[] = {
	{
		UUID_INIT(0xa8cfe406, 0xd4f5, 0x4a2e,
			  0x9f, 0x8d, 0xa2, 0x5d, 0xc7, 0x54, 0xc0, 0x99)
	},
	{ }
};

MODULE_DEVICE_TABLE(tee, optee_scmi_id_table);

static struct tee_client_driver optee_scmi_driver = {
	.id_table	= optee_scmi_id_table,
	.driver		= {
		.name		= DRIVER_NAME,
		.bus		= &tee_bus_type,
		.probe		= optee_scmi_probe,
		.remove		= optee_scmi_remove,
	},
};

static int __init optee_scmi_init(void)
{
	return driver_register(&optee_scmi_driver.driver);
}

static void __exit optee_scmi_exit(void)
{
	driver_unregister(&optee_scmi_driver.driver);
}

module_init(optee_scmi_init);
module_exit(optee_scmi_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Etienne Carriere <etienne.carriere@linaro.org>");
MODULE_DESCRIPTION("OP-TEE SCMI agent driver");
