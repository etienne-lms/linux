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
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <uapi/linux/tee.h>

#include "common.h"

#define DRIVER_NAME "optee-scmi-agent"

/*
 * TA_CMD_PROCESS_MESSAGE - Process message from an SCMI agent
 *
 * [in]         value[0].a      SCMI agent identifier
 * [in/out]     memref[1]       SCMI message
 *
 * Result:
 * TEEC_SUCCESS - Invoke command success
 * TEEC_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define TA_CMD_PROCESS_MESSAGE		0x3

/**
 * struct optee_scmi_channel - OP-TEE server assigns channel ID per shmem
 * @session_id:		Id provided by OP-TEE for a session
 * @agent_id:		SCMI Id of the agent
 * @cinfo:		SCMI channel info
 * @tee_shm:		OP-TEE hared memory
 * @notif_task:		Task used to handle notification
 */
struct optee_scmi_channel {
	u32 session_id;
	uint32_t agent_id;
	struct scmi_chan_info *cinfo;
	struct tee_shm *tee_shm;
	struct task_struct *notif_task;
};

/**
 * struct optee_scmi_agent - OP-TEE Random Number Generator private data
 * @dev:		OP-TEE based SCMI server device.
 * @ctx:		OP-TEE context handler.
 */
struct optee_scmi_agent {
	struct device *dev;
	struct tee_context *ctx;
};

static struct optee_scmi_agent agent_private;

static struct scmi_shared_mem *get_channel_shm(struct optee_scmi_channel *chan,
					       struct scmi_xfer *xfer)
{
	if (!chan->tee_shm)
		return NULL;

	return tee_shm_get_va(chan->tee_shm,
			      xfer->hdr.seq * scmi_optee_desc.max_msg_size);
}

static int process_event(struct optee_scmi_channel *channel,
			 struct scmi_xfer *xfer)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	/* Invoke TA_CMD_PROCESS_MESSAGE function of Trusted App */
	inv_arg.func = TA_CMD_PROCESS_MESSAGE;
	inv_arg.session = channel->session_id;
	inv_arg.num_params = ARRAY_SIZE(param);

	/* Fill invoke cmd params */
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = channel->agent_id;

	/* Set shared memory argument */
	param[1] = (struct tee_param) {
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT,
		.u.memref = {
			.shm = channel->tee_shm,
			.size = scmi_optee_desc.max_msg_size,
			.shm_offs = xfer->hdr.seq *
				    scmi_optee_desc.max_msg_size,
		},
	};

	ret = tee_client_invoke_func(agent_private.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		dev_err(agent_private.dev, "Agent %u faile: 0x%x\n",
			channel->agent_id, inv_arg.ret);
		return -EIO;
	}

	return 0;
}

static bool optee_chan_available(struct device *dev, int idx)
{
	u32 id;

	return !of_property_read_u32_index(dev->of_node, "agent-id", idx, &id);
}

static int optee_receive_message(struct scmi_chan_info *cinfo,
			      struct scmi_xfer *xfer)
{
	struct optee_scmi_channel *channel = cinfo->transport_info;
	struct scmi_shared_mem *shmem;
	int ret;

	if (!channel)
		return -EINVAL;

	shmem = get_channel_shm(channel, xfer);
	shmem_clear_channel(shmem);

	ret = process_event(channel, xfer);
	if (ret)
		return ret;

	scmi_rx_callback(cinfo, shmem_read_header(shmem));

	return 0;
}

static void optee_fetch_notification(struct scmi_chan_info *cinfo,
				       size_t max_len, struct scmi_xfer *xfer)
{
	struct optee_scmi_channel *channel = cinfo->transport_info;
	struct scmi_shared_mem *shmem;

	shmem = get_channel_shm(channel, xfer);

	shmem_fetch_notification(shmem, max_len, xfer);
}

static void optee_clear_channel(struct scmi_chan_info *cinfo)
{
}

static int optee_rx_thread(void * _channel)
{
	struct optee_scmi_channel *channel = _channel;
	struct scmi_xfer xfer;

	/* There is only 1 shared message */
	xfer.hdr.seq = 0;

repeat:
	set_current_state(TASK_INTERRUPTIBLE);

	if (unlikely(kthread_should_stop())) {
		set_current_state(TASK_RUNNING);
		return 0;
	}

	set_current_state(TASK_RUNNING);

	optee_receive_message(channel->cinfo, &xfer);

	goto repeat;

}

static int optee_start_notif(struct scmi_chan_info *cinfo,
			     struct optee_scmi_channel *channel)
{

	/* Create task that will provision notification message */
	channel->notif_task = kthread_create(optee_rx_thread, channel,
					     "scmi_notif-%04x",
					     channel->agent_id);
	if (IS_ERR(channel->notif_task)) {
		dev_err(cinfo->dev, "failed to create optee_rx_thread\n");
	}

	wake_up_process(channel->notif_task);

	return 0;
}

static int optee_chan_setup_shm(struct scmi_chan_info *cinfo,
				struct optee_scmi_channel *channel)
{
	struct device *cdev = cinfo->dev;
	struct scmi_shared_mem *shmem;
	int i;

	/* Allocate dynamic shared memory */
	channel->tee_shm = tee_shm_alloc(agent_private.ctx,
					 scmi_optee_desc.max_msg_size *
					 scmi_optee_desc.max_msg,
					 TEE_SHM_MAPPED);
	if (IS_ERR(channel->tee_shm)) {
		dev_err(cdev, "%s: tee_shm_alloc failed\n", __func__);
		return -ENOMEM;
	}


	/* Clear channels */
	shmem = tee_shm_get_va(channel->tee_shm, 0);
	for (i = 0; i < scmi_optee_desc.max_msg; i++) {
		uintptr_t buffer = (uintptr_t)shmem +
				   i * scmi_optee_desc.max_msg_size;

		shmem_clear_channel((void *)buffer);
	}

	return 0;
}

/* Each agent onws its session for concurrent agent access */
static int optee_open_agent_session(struct device *dev,
				    struct optee_scmi_channel *channel,
				    int agent_id)
{
	struct tee_client_device *scmi_device;
	struct tee_ioctl_open_session_arg sess_arg;
	int ret = 0;

	scmi_device = to_tee_client_device(agent_private.dev);

	memset(&sess_arg, 0, sizeof(sess_arg));
	memcpy(sess_arg.uuid, scmi_device->id.uuid.b, TEE_IOCTL_UUID_LEN);
	sess_arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	sess_arg.num_params = 0;

	ret = tee_client_open_session(agent_private.ctx, &sess_arg, NULL);
	if ((ret < 0) || (sess_arg.ret != 0)) {
		dev_err(dev, "tee_client_open_session failed, err: %x\n",
			sess_arg.ret);
		return ret;
	}

	channel->session_id = sess_arg.session;
	channel->agent_id = agent_id;

	return 0;
}

static int optee_chan_setup(struct scmi_chan_info *cinfo, struct device *dev,
			    bool tx)
{
	struct device *cdev = cinfo->dev;
	struct optee_scmi_channel *channel;
	int ret, n = tx ? 0 : 1;
	unsigned int agent;

	if (!agent_private.ctx)
		return -EPROBE_DEFER;
	if (IS_ERR(agent_private.ctx))
		return PTR_ERR(agent_private.ctx);

	channel = devm_kzalloc(dev, sizeof(*channel), GFP_KERNEL);
	if (!channel)
		return -ENOMEM;

	ret = of_property_read_u32_index(cdev->of_node, "agent-id", n, &agent);
	if (ret)
		return ret;

	ret = optee_chan_setup_shm(cinfo, channel);
	if (ret)
		return ret;

	ret = optee_open_agent_session(cdev, channel, agent);
	if (ret)
		return ret;

	if (!tx)
		optee_start_notif(cinfo, channel);

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
	struct scmi_shared_mem *shmem;
	int ret;

	if (!channel && IS_ERR_OR_NULL(agent_private.ctx))
		return -EINVAL;

	shmem = get_channel_shm(channel, xfer);
	shmem_tx_prepare(shmem, xfer);

	ret = process_event(channel, xfer);
	if (ret)
		return ret;

	scmi_rx_callback(cinfo, shmem_read_header(shmem));

	return 0;
}

static void optee_fetch_response(struct scmi_chan_info *cinfo,
				 struct scmi_xfer *xfer)
{
	struct optee_scmi_channel *channel = cinfo->transport_info;
	struct scmi_shared_mem *shmem;

	shmem = get_channel_shm(channel, xfer);

	shmem_fetch_response(shmem, xfer);
}

static bool optee_poll_done(struct scmi_chan_info *cinfo,
			    struct scmi_xfer *xfer)
{
	struct optee_scmi_channel *channel = cinfo->transport_info;
	struct scmi_shared_mem *shmem;

	shmem = get_channel_shm(channel, xfer);

	return shmem_poll_done(shmem, xfer);
}

static struct scmi_transport_ops scmi_optee_ops = {
	.chan_available = optee_chan_available,
	.chan_setup = optee_chan_setup,
	.chan_free = optee_chan_free,
	.send_message = optee_send_message,
	.fetch_response = optee_fetch_response,
	.fetch_notification = optee_fetch_notification,
	.clear_channel = optee_clear_channel,
	.poll_done = optee_poll_done,
};

const struct scmi_desc scmi_optee_desc = {
	.ops = &scmi_optee_ops,
	.max_rx_timeout_ms = 30, /* We may increase this if required */
	.max_msg = 8,
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

	agent_private.dev = dev;
	agent_private.ctx = tee_client_open_context(NULL, optee_ctx_match,
						    NULL, NULL);
	if (IS_ERR(agent_private.ctx))
		return PTR_ERR(agent_private.ctx);

	/* Open session with SCMI server TA to check it exists */
	memset(&sess_arg, 0, sizeof(sess_arg));
	memcpy(sess_arg.uuid, scmi_device->id.uuid.b, TEE_IOCTL_UUID_LEN);
	sess_arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	sess_arg.num_params = 0;

	ret = tee_client_open_session(agent_private.ctx, &sess_arg, NULL);
	if ((ret < 0) || (sess_arg.ret != 0)) {
		dev_err(dev, "open TA session failed, err: %x\n", sess_arg.ret);
		err = -ENODEV;
		goto out_ctx;
	}
	tee_client_close_session(agent_private.ctx, sess_arg.session);

	dev_info(dev, "OP-TEE SCMI channel probed\n");

	return 0;

out_ctx:
	tee_client_close_context(agent_private.ctx);

	return err;
}

static int optee_scmi_remove(struct device *dev)
{
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
