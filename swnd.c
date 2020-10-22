#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>

#include <talloc.h>

#define TEVENT_DEPRECATED 1
#include <tevent.h>

#include <netdb.h>

#include <linux/cifs/cifs_netlink.h>

#include <systemd/sd-journal.h>
#include <systemd/sd-daemon.h>

#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/handlers.h>
#include <netlink/genl/mngt.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>

#include <credentials.h>
#include <param.h>
#include <util/debug.h>
#include <witness/swnclient.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static struct nla_policy cifs_genl_policy[CIFS_GENL_ATTR_MAX + 1] = {
	[CIFS_GENL_ATTR_SWN_REGISTRATION_ID]	= { .type = NLA_U32 },
	[CIFS_GENL_ATTR_SWN_NET_NAME]		= { .type = NLA_STRING },
	[CIFS_GENL_ATTR_SWN_SHARE_NAME]		= { .type = NLA_STRING },
	[CIFS_GENL_ATTR_SWN_IP]			= { .minlen = sizeof(struct sockaddr_storage) },
	[CIFS_GENL_ATTR_SWN_NET_NAME_NOTIFY]	= { .type = NLA_FLAG },
	[CIFS_GENL_ATTR_SWN_SHARE_NAME_NOTIFY]	= { .type = NLA_FLAG },
	[CIFS_GENL_ATTR_SWN_IP_NOTIFY]		= { .type = NLA_FLAG },
	[CIFS_GENL_ATTR_SWN_USER_NAME]		= { .type = NLA_STRING },
	[CIFS_GENL_ATTR_SWN_PASSWORD]		= { .type = NLA_STRING },
	[CIFS_GENL_ATTR_SWN_DOMAIN_NAME]	= { .type = NLA_STRING },
	[CIFS_GENL_ATTR_SWN_NOTIFICATION_TYPE]	= { .type = NLA_U32 },
	[CIFS_GENL_ATTR_SWN_RESOURCE_STATE]	= { .type = NLA_U32 },
	[CIFS_GENL_ATTR_SWN_RESOURCE_NAME]	= { .type = NLA_STRING },
};

static int swn_register_handler(struct nl_cache_ops *cache_ops,
				struct genl_cmd *cmd,
				struct genl_info *info,
				void *arg);

static int swn_unregister_handler(struct nl_cache_ops *cache_ops,
				  struct genl_cmd *cmd,
				  struct genl_info *info,
				  void *arg);

static struct genl_cmd swnd_genl_family_cmds[] = {
	{
		.c_id		= CIFS_GENL_CMD_SWN_REGISTER,
		.c_name		= "swn_register",
		.c_attr_policy	= cifs_genl_policy,
		.c_msg_parser	= &swn_register_handler,
		.c_maxattr	= CIFS_GENL_ATTR_MAX,
	},
	{
		.c_id		= CIFS_GENL_CMD_SWN_UNREGISTER,
		.c_name		= "swn_unregister",
		.c_attr_policy	= cifs_genl_policy,
		.c_msg_parser	= &swn_unregister_handler,
		.c_maxattr	= CIFS_GENL_ATTR_MAX,
	},
};

static struct genl_ops swnd_genl_family_ops = {
	.o_name = CIFS_GENL_NAME,
	.o_cmds = swnd_genl_family_cmds,
	.o_ncmds = ARRAY_SIZE(swnd_genl_family_cmds),
};

struct swnd_context {
	struct loadparm_context *lp_ctx;
	struct tevent_context *ev_ctx;
	struct nl_sock *nlsk;
	int cifs_id;
	struct tevent_fd *fde;
	struct swnc_state *swn;
};

/**
 * @brief Extracts the attributes from a netlink message
 *
 * @param[in] mem_ctx The memory context to allocate the resulting swn_registration_info
 * @param[in] info The information received from the kernel
 * @param[out] rinfo The resulting registration info allocated under mem_ctx context
 * @param[out] registration_id This parameter is optional. If it is not NULL then the
 *                             registration id will be retrieved from the kernel message,
 *                             resulting in an error if it is not present.
 * @return Zero if success, error code otherwise
 */
static int get_swn_registration_info_from_genl_info(TALLOC_CTX *mem_ctx,
						    struct genl_info *info,
						    struct swn_registration_info **out,
						    int *registration_id)
{
	struct swn_registration_info *tmp = NULL;
	int ret;

	if (registration_id != NULL) {
		if (info->attrs[CIFS_GENL_ATTR_SWN_REGISTRATION_ID] != NULL) {
			*registration_id =
				nla_get_u32(info->attrs[CIFS_GENL_ATTR_SWN_REGISTRATION_ID]);
		} else {
			sd_journal_print(LOG_NOTICE, "Missing registration ID attribute");
			return EINVAL;
		}
	}

	tmp = talloc_zero(mem_ctx, struct swn_registration_info);
	if (tmp == NULL) {
		return ENOMEM;
	}

	if (info->attrs[CIFS_GENL_ATTR_SWN_NET_NAME] != NULL) {
		tmp->net_name = talloc_strdup(tmp,
				nla_get_string(info->attrs[CIFS_GENL_ATTR_SWN_NET_NAME]));
		if (tmp->net_name == NULL) {
			ret = ENOMEM;
			goto fail;
		}
	} else {
		sd_journal_print(LOG_NOTICE, "Missing network name attribute");
		ret = EINVAL;
		goto fail;
	}

	if (info->attrs[CIFS_GENL_ATTR_SWN_IP] != NULL) {
		char ip_address[INET6_ADDRSTRLEN];
		struct sockaddr_storage *addr = nla_data(info->attrs[CIFS_GENL_ATTR_SWN_IP]);
		ret = getnameinfo((struct sockaddr *)addr,
				  sizeof(struct sockaddr_storage),
				  ip_address,
				  sizeof(ip_address),
				  NULL,
				  0,
				  NI_NUMERICHOST);
		if (ret != 0) {
			sd_journal_print(LOG_NOTICE, "Failed to parse ip address: %s",
					 gai_strerror(ret));
			goto fail;
		}

		tmp->ip_address = talloc_strdup(tmp, ip_address);
		if (tmp->ip_address == NULL) {
			ret = ENOMEM;
			goto fail;
		}
	}

	if (info->attrs[CIFS_GENL_ATTR_SWN_SHARE_NAME] != NULL) {
		tmp->share_name = talloc_strdup(tmp,
				nla_get_string(info->attrs[CIFS_GENL_ATTR_SWN_SHARE_NAME]));
		if (tmp->share_name == NULL) {
			ret = ENOMEM;
			goto fail;
		}
	}

	if (info->attrs[CIFS_GENL_ATTR_SWN_NET_NAME_NOTIFY] != NULL) {
		tmp->net_name_req = nla_get_flag(info->attrs[CIFS_GENL_ATTR_SWN_NET_NAME_NOTIFY]);
	}

	if (info->attrs[CIFS_GENL_ATTR_SWN_IP_NOTIFY] != NULL) {
		tmp->ip_address_req = nla_get_flag(info->attrs[CIFS_GENL_ATTR_SWN_IP_NOTIFY]);
	}

	if (info->attrs[CIFS_GENL_ATTR_SWN_SHARE_NAME_NOTIFY] != NULL) {
		tmp->share_name_req =
			nla_get_flag(info->attrs[CIFS_GENL_ATTR_SWN_SHARE_NAME_NOTIFY]);
	}

	*out = tmp;
	return 0;

fail:
	TALLOC_FREE(tmp);
	return ret;
}

static int get_swn_credentials_from_genl_info(TALLOC_CTX *mem_ctx,
					      struct genl_info *info,
					      struct loadparm_context *lp_ctx,
					      struct cli_credentials **out)
{
	struct cli_credentials *creds = NULL;
	int ret;

	creds = cli_credentials_init(mem_ctx);
	if (creds == NULL) {
		return ENOMEM;
	}
	cli_credentials_guess(creds, lp_ctx);

	if (info->attrs[CIFS_GENL_ATTR_SWN_KRB_AUTH] != NULL) {
		cli_credentials_set_kerberos_state(creds, CRED_USE_KERBEROS_REQUIRED);
	} else {
		cli_credentials_set_kerberos_state(creds, CRED_USE_KERBEROS_DISABLED);
	}

	if (info->attrs[CIFS_GENL_ATTR_SWN_USER_NAME] != NULL) {
		const char *username = nla_get_string(info->attrs[CIFS_GENL_ATTR_SWN_USER_NAME]);
		if (!cli_credentials_set_username(creds,
						  username,
						  CRED_SPECIFIED)) {
			ret = ENOMEM;
			goto fail;
		}
	}

	if (info->attrs[CIFS_GENL_ATTR_SWN_PASSWORD] != NULL) {
		const char *password = nla_get_string(info->attrs[CIFS_GENL_ATTR_SWN_PASSWORD]);
		if (!cli_credentials_set_password(creds,
						  password,
						  CRED_SPECIFIED)) {
			ret = ENOMEM;
			goto fail;
		}
	}

	if (info->attrs[CIFS_GENL_ATTR_SWN_DOMAIN_NAME] != NULL) {
		const char *domain = nla_get_string(info->attrs[CIFS_GENL_ATTR_SWN_DOMAIN_NAME]);
		if (!cli_credentials_set_domain(creds,
						domain,
						CRED_SPECIFIED)) {
			ret = ENOMEM;
			goto fail;
		}
	}

	if ((cli_credentials_get_username(creds) == NULL ||
	     cli_credentials_get_password(creds) == NULL) &&
			cli_credentials_get_kerberos_state(creds) == CRED_USE_KERBEROS_DISABLED) {
		sd_journal_print(LOG_WARNING,
				 "Username and password attributes are required to register");
		ret = EINVAL;
		goto fail;
	}

	*out = creds;

	return 0;
fail:
	TALLOC_FREE(creds);
	return ret;
}

/**
 * @brief Sends a notification to cifs kernel module
 *
 * @param nlsk The netlink socket
 * @param cifs_genl_family_id The netlink family id
 * @param n The notification to send
 */
static int swn_notification_to_cifs(struct nl_sock *nlsk,
				    int cifs_genl_family_id,
				    uint32_t registration_id,
				    struct swn_notification *n)
{
	struct nl_msg *msg = NULL;
	void *hdr = NULL;
	int ret;

	sd_journal_print(LOG_DEBUG,
			 "Sending notification of type 0x%x",
			 n->type);

	msg = nlmsg_alloc();
	if (msg == NULL) {
		sd_journal_print(LOG_WARNING,
				 "Failed to allocate netlink message: %d (%s)",
				 ret, strerror(ret));
                return -ENOMEM;
	}

	genlmsg_put(msg,
		    NL_AUTO_PORT,
		    NL_AUTO_SEQ,
		    cifs_genl_family_id,
		    0,
		    0,
		    CIFS_GENL_CMD_SWN_NOTIFY,
		    0);

	/*
	 * This id lets the kernel find the matching registration and its
	 * internal state
	 */
	NLA_PUT_U32(msg, CIFS_GENL_ATTR_SWN_REGISTRATION_ID, registration_id);

	switch (n->type) {
	case SWN_NOTIFICATION_RESOURCE_CHANGE:
		NLA_PUT_U32(msg,
			    CIFS_GENL_ATTR_SWN_NOTIFICATION_TYPE,
			    CIFS_SWN_NOTIFICATION_RESOURCE_CHANGE);
		NLA_PUT_STRING(msg,
			       CIFS_GENL_ATTR_SWN_RESOURCE_NAME,
			       n->resource_change.name);
		switch (n->resource_change.state) {
		case SWN_RESOURCE_STATE_UNKNOWN:
			NLA_PUT_U32(msg,
				    CIFS_GENL_ATTR_SWN_RESOURCE_STATE,
				    CIFS_SWN_RESOURCE_STATE_UNKNOWN);
			break;
		case SWN_RESOURCE_STATE_AVAILABLE:
			NLA_PUT_U32(msg,
				    CIFS_GENL_ATTR_SWN_RESOURCE_STATE,
				    CIFS_SWN_RESOURCE_STATE_AVAILABLE);
			break;
		case SWN_RESOURCE_STATE_UNAVAILABLE:
			NLA_PUT_U32(msg,
				    CIFS_GENL_ATTR_SWN_RESOURCE_STATE,
				    CIFS_SWN_RESOURCE_STATE_UNAVAILABLE);
			break;
		}
		break;
	case SWN_NOTIFICATION_CLIENT_MOVE:
		NLA_PUT_U32(msg,
			    CIFS_GENL_ATTR_SWN_NOTIFICATION_TYPE,
			    CIFS_SWN_NOTIFICATION_CLIENT_MOVE);
		NLA_PUT(msg,
			CIFS_GENL_ATTR_SWN_IP,
			sizeof(struct sockaddr_storage),
			n->client_move.addr);
		break;
	case SWN_NOTIFICATION_SHARE_MOVE:
		NLA_PUT_U32(msg,
			    CIFS_GENL_ATTR_SWN_NOTIFICATION_TYPE,
			    CIFS_SWN_NOTIFICATION_SHARE_MOVE);
		NLA_PUT(msg,
			CIFS_GENL_ATTR_SWN_IP,
			sizeof(struct sockaddr_storage),
			n->share_move.addr);
		break;
	case SWN_NOTIFICATION_IP_CHANGE:
		NLA_PUT_U32(msg,
			    CIFS_GENL_ATTR_SWN_NOTIFICATION_TYPE,
			    CIFS_SWN_NOTIFICATION_IP_CHANGE);
		NLA_PUT(msg,
			CIFS_GENL_ATTR_SWN_IP,
			sizeof(struct sockaddr_storage),
			n->ip_change.addr);
		break;
	default:
		sd_journal_print(LOG_INFO,
				 "Unknown notification type '%d'",
				 n->type);
		goto fail;
	}

	ret = nl_send_auto_complete(nlsk, msg);
	if (ret < 0) {
		sd_journal_print(LOG_WARNING,
				 "Failed to send netlink message: %d (%s)",
				 ret, strerror(ret));
		goto fail;
	}

	ret = 0;

nla_put_failure:
fail:
	nlmsg_free(msg);
	return ret;
}

/*
 * After register, the wait_notification_loop_send starts the wait notification loop.
 * This loop never ends, when a notification is received a new request is created to
 * wait for the next one. The loop continues until unregister.
 */
struct wait_notif_state {
	struct swnd_context *swnd_ctx;
	uint32_t registration_id;
	struct swn_registration_info info;
};

static void wait_notification_done(struct tevent_req *req);

static struct tevent_req *wait_notification_loop_send(
					struct swnd_context *swnd_ctx,
					uint32_t registration_id,
					struct swn_registration_info *info)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct wait_notif_state *state = NULL;

	req = tevent_req_create(swnd_ctx, &state, struct wait_notif_state);
	if (req == NULL) {
		return NULL;
	}

	state->swnd_ctx = swnd_ctx;
	state->registration_id = registration_id;
	state->info.net_name = talloc_strdup(state, info->net_name);
	if (tevent_req_nomem(state->info.net_name, req)) {
		return tevent_req_post(req, swnd_ctx->ev_ctx);
	}

	state->info.ip_address = talloc_strdup(state, info->ip_address);
	if (tevent_req_nomem(state->info.ip_address, req)) {
		return tevent_req_post(req, swnd_ctx->ev_ctx);
	}

	state->info.share_name = talloc_strdup(state, info->share_name);
	if (tevent_req_nomem(state->info.share_name, req)) {
		return tevent_req_post(req, swnd_ctx->ev_ctx);
	}

	state->info.net_name_req = info->net_name_req;
	state->info.ip_address_req = info->ip_address_req;
	state->info.share_name_req = info->share_name_req;

	/* Wait for notification */
	subreq = swnc_wait_notification_send(state,
					     state->swnd_ctx->ev_ctx,
					     state->swnd_ctx->swn,
					     &state->info);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, state->swnd_ctx->ev_ctx);
	}
	tevent_req_set_callback(subreq, wait_notification_done, req);

	return req;
}

static void wait_notification_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wait_notif_state *state = tevent_req_data(
			req, struct wait_notif_state);
	struct swn_notification *notifications = NULL;
	ssize_t i;
	int ret;

	ret = swnc_wait_notification_recv(subreq,
					  state,
					  &notifications);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		if (ret != ECANCELED) {
			/* Avoid logging errors when the request is canceled */
			sd_journal_print(LOG_WARNING,
					 "AsyncNotify request failed: %d (%s)",
					 ret, strerror(ret));
		}
		return;
	}

	/* Process the notifications */
	for (i = 0; i < talloc_array_length(notifications); i++) {
		struct swn_notification *n = &notifications[i];
		ret = swn_notification_to_cifs(state->swnd_ctx->nlsk,
					       state->swnd_ctx->cifs_id,
					       state->registration_id,
					       n);
		if (ret != 0) {
			sd_journal_print(LOG_WARNING,
					 "Failed to send notification to "
					 "cifs: %d (%s)", ret, strerror(ret));
			continue;
		}
	}

	TALLOC_FREE(notifications);

	/* Wait the next notification */
	subreq = swnc_wait_notification_send(state,
					     state->swnd_ctx->ev_ctx,
					     state->swnd_ctx->swn,
					     &state->info);
	if (tevent_req_nomem(subreq, req)) {
		sd_journal_print(LOG_WARNING,
				 "Failed to send notification wait request\n");
		return;
	}
	tevent_req_set_callback(subreq, wait_notification_done, req);
}

static int wait_notification_loop_recv(struct tevent_req *req)
{
	enum tevent_req_state state;
	uint64_t err;
	int rc;

	if (!tevent_req_is_error(req, &state, &err)) {
		tevent_req_received(req);
		return 0;
	}

	switch (state) {
	case TEVENT_REQ_TIMED_OUT:
		rc = ETIMEDOUT;
		break;
	case TEVENT_REQ_NO_MEMORY:
		rc = ENOMEM;
		break;
	case TEVENT_REQ_USER_ERROR:
		rc = err;
		break;
	default:
		rc = EINVAL;
		break;
	}

	tevent_req_received(req);
	return rc;
}

/*
 * Register for notifications. It starts the wait notification loop, and if it fails tries to
 * unregister. The kernel will retry the registration at regular intervals.
 */

struct swnd_register_state {
	struct swnd_context *swnd_ctx;
	struct cli_credentials *creds;
	struct swn_registration_info *info;
	uint32_t registration_id;
};

static void swnc_register_done(struct tevent_req *req);

static int swn_register_handler(struct nl_cache_ops *cache_ops,
				struct genl_cmd *cmd,
				struct genl_info *info,
				void *arg)
{
	struct swnd_context *swnd_ctx = talloc_get_type_abort(arg, struct swnd_context);
	struct swnd_register_state *state = NULL;
	struct tevent_req *req = NULL;
	int ret;

	if (!info->attrs[cmd->c_id]) {
		return NL_SKIP;
	}

	state = talloc_zero(swnd_ctx, struct swnd_register_state);
	if (state == NULL) {
		sd_journal_print(LOG_WARNING, "Failed to allocate memory");
		return NL_SKIP;
	}
	state->swnd_ctx = swnd_ctx;

	ret = get_swn_registration_info_from_genl_info(state,
						       info,
						       &state->info,
						       &state->registration_id);
	if (ret != 0) {
		sd_journal_print(LOG_WARNING,
				 "Failed to get registration info from kernel message: %s",
				 ret);
		goto fail;
	}

	ret = get_swn_credentials_from_genl_info(state, info, swnd_ctx->lp_ctx, &state->creds);
	if (ret != 0) {
		sd_journal_print(LOG_WARNING,
				 "Failed to get credentials from kernel message: %s",
				 ret);
		goto fail;
	}

	sd_journal_print(LOG_NOTICE,
			 "Register: id='%u', net_name='%s' (%s), ip='%s' (%s), share_name='%s' (%s)",
			 state->registration_id,
			 state->info->net_name,   state->info->net_name_req ? "y" : "n",
			 state->info->ip_address, state->info->ip_address_req ? "y" : "n",
			 state->info->share_name, state->info->share_name_req ? "y" : "n");

	req = swnc_register_send(state,
				 state->swnd_ctx->ev_ctx,
				 state->swnd_ctx->lp_ctx,
				 state->swnd_ctx->swn,
				 state->creds,
				 state->info);
	if (req == NULL) {
		sd_journal_print(LOG_WARNING, "Failed to create register request");
		goto fail;
	}
	tevent_req_set_callback(req, swnc_register_done, state);

	return NL_OK;

fail:
	TALLOC_FREE(state);
	return NL_SKIP;
}

static void wait_notification_loop_done(struct tevent_req *req);
static void swnc_unregister_done(struct tevent_req *req);

static void swnc_register_done(struct tevent_req *req)
{
	struct swnd_register_state *state =
		tevent_req_callback_data(req, struct swnd_register_state);
	int ret;

	ret = swnc_register_recv(req);
	TALLOC_FREE(req);

	if (ret != 0) {
		if (ret == EEXIST) {
			sd_journal_print(LOG_INFO,
				"Already registered: id='%u', net_name='%s' (%s), ip='%s' (%s), "
				"share_name='%s' (%s)",
				state->registration_id,
				state->info->net_name,   state->info->net_name_req ? "y" : "n",
				state->info->ip_address, state->info->ip_address_req ? "y" : "n",
				state->info->share_name, state->info->share_name_req ? "y" : "n");
		} else {
			sd_journal_print(LOG_WARNING, "Failed to register: %s", strerror(ret));
		}
		return;
	}

	sd_journal_print(LOG_INFO, "Registered, starting notification wait loop");

	/* Use swnd_ctx as mem_ctx, we have to free the state now. */
	req = wait_notification_loop_send(state->swnd_ctx,
					  state->registration_id,
					  state->info);
	if (req == NULL) {
		sd_journal_print(LOG_WARNING, "Failed to allocate wait loop request");
		goto unregister;
	}
	tevent_req_set_callback(req, wait_notification_loop_done, state->swnd_ctx);

	TALLOC_FREE(state);

	return;

unregister:
	req = swnc_unregister_send(state,
				   state->swnd_ctx->ev_ctx,
				   state->swnd_ctx->swn,
				   state->info);
	if (req == NULL) {
		sd_journal_print(LOG_WARNING, "Failed to allocate unregister request");
		return;
	}
	tevent_req_set_callback(req, swnc_unregister_done, state);
}

static void wait_notification_loop_done(struct tevent_req *req)
{
	struct swnd_context *swnd_ctx = tevent_req_callback_data(req,
			struct swnd_context);
	int ret;

	ret = wait_notification_loop_recv(req);
	TALLOC_FREE(req);
	if (ret != 0 && ret != ECANCELED) {
		sd_journal_print(LOG_WARNING,
				 "Wait notification loop finished: %d (%s)",
				 ret, strerror(ret));
	}
}

/*
 * Unregister for notifications. It tries to cancel the wait notification loop.
 */
static int swn_unregister_handler(struct nl_cache_ops *cache_ops,
				  struct genl_cmd *cmd,
				  struct genl_info *nlinfo,
				  void *arg)
{
	struct swnd_context *swnd_ctx = talloc_get_type_abort(arg, struct swnd_context);
	struct swnd_register_state *state = NULL;
	struct tevent_req *req = NULL;
	int ret;

	if (!nlinfo->attrs[cmd->c_id]) {
		return NL_SKIP;
	}

	state = talloc_zero(swnd_ctx, struct swnd_register_state);
	if (state == NULL) {
		sd_journal_print(LOG_WARNING, "Failed to allocate memory");
		return NL_SKIP;
	}
	state->swnd_ctx = swnd_ctx;

	ret = get_swn_registration_info_from_genl_info(state,
						       nlinfo,
						       &state->info,
						       &state->registration_id);
	if (ret != 0) {
		sd_journal_print(LOG_WARNING,
				 "Failed to get registration info from kernel message: %s",
				 ret);
		goto fail;
	}

	sd_journal_print(LOG_NOTICE,
			 "Unregister: id='%u', net_name='%s' (%s), ip='%s' (%s), share_name='%s' (%s)",
			 state->registration_id,
			 state->info->net_name,   state->info->net_name_req ? "y" : "n",
			 state->info->ip_address, state->info->ip_address_req ? "y" : "n",
			 state->info->share_name, state->info->share_name_req ? "y" : "n");

	req = swnc_unregister_send(state->swnd_ctx,
				   state->swnd_ctx->ev_ctx,
				   state->swnd_ctx->swn,
				   state->info);
	if (req == NULL) {
		sd_journal_print(LOG_WARNING,
				 "Failed to create unregister request.\n");
		goto fail;
	}
	tevent_req_set_callback(req, swnc_unregister_done, state);

	return NL_OK;

fail:
	TALLOC_FREE(state);
	return NL_SKIP;
}

static void swnc_unregister_done(struct tevent_req *req)
{
	struct swnd_register_state *state =
		tevent_req_callback_data(req, struct swnd_register_state);
	int ret;

	ret = swnc_unregister_recv(req);
	TALLOC_FREE(req);
	if (ret != 0) {
		sd_journal_print(LOG_WARNING, "Failed to unregister: %s\n",
				 strerror(ret));
	}

	TALLOC_FREE(state);
}

static int parse_cb(struct nl_msg *msg, void *arg)
{
	return genl_handle_msg(msg, arg);
}

static void netlink_socket_read_handler(struct tevent_context *ev,
					struct tevent_fd *fde,
					uint16_t flags,
					void *private_data)
{
	struct swnd_context *swnd_ctx = talloc_get_type_abort(
			private_data, struct swnd_context);
	int ret;

	sd_journal_print(LOG_DEBUG, "Netlink socket read ready\n");

	ret = nl_recvmsgs_default(swnd_ctx->nlsk);
	if (ret != 0) {
		sd_journal_print(LOG_ERR,
				 "Failed to receive message: %s\n",
				 nl_geterror(ret));
		return;
	}
}

static void netlink_socket_close_handler(struct tevent_context *ev_ctx,
					 struct tevent_fd *fde,
					 int fd,
					 void *private_data)
{
	struct swnd_context *swnd_ctx = talloc_get_type_abort(
			private_data, struct swnd_context);
	int ret;

	sd_journal_print(LOG_DEBUG, "Closing netlink socket\n");

	nl_socket_free(swnd_ctx->nlsk);
}

static int setup_netlink_socket(struct swnd_context *swnd_ctx)
{
	int ret;
	int fd;

	swnd_ctx->nlsk = nl_socket_alloc();
	if (swnd_ctx->nlsk == NULL) {
		sd_journal_print(LOG_ERR, "Failed to allocate netlink socket");
		return ENOMEM;
	}

	nl_socket_disable_seq_check(swnd_ctx->nlsk);

	ret = genl_connect(swnd_ctx->nlsk);
	if (ret < 0) {
		sd_journal_print(LOG_ERR,
				 "Failed to connect netlink socket: %s",
				 nl_geterror(ret));
		goto fail;
	}

	/* Check if kernel has already registered the family, as we may have
	 * started before the cifs kernel module is loaded. */
	do {
		swnd_ctx->cifs_id = genl_ctrl_resolve(swnd_ctx->nlsk,
						      CIFS_GENL_NAME);
		if (ret < 0) {
			sd_journal_print(LOG_WARNING,
					 "Failed to resolve netlink family: %s",
					 nl_geterror(ret));
			sleep(5);
		}
	} while (ret < 0);

	ret = genl_ctrl_resolve_grp(swnd_ctx->nlsk,
				    CIFS_GENL_NAME,
				    CIFS_GENL_MCGRP_SWN_NAME);
	if (ret < 0) {
		sd_journal_print(LOG_ERR,
				 "Failed to resolve multicast group: %s",
				 nl_geterror(ret));
		goto fail;
	}

	ret = nl_socket_add_membership(swnd_ctx->nlsk, ret);
	if (ret < 0) {
		sd_journal_print(LOG_ERR,
				 "Failed to join multicast group: %s",
				 nl_geterror(ret));
		goto fail;
	}

	ret = genl_register_family(&swnd_genl_family_ops);
	if (ret < 0) {
		sd_journal_print(LOG_ERR,
				 "Failed to register swnd netlink ops: %s",
				 nl_geterror(ret));
		goto fail;
	}

	ret = genl_ops_resolve(swnd_ctx->nlsk, &swnd_genl_family_ops);
	if (ret < 0) {
		sd_journal_print(LOG_ERR,
				 "Failed to resolve swnd netlink ops: %s",
				 nl_geterror(ret));
		goto fail;
	}

	ret = nl_socket_modify_cb(swnd_ctx->nlsk,
				  NL_CB_VALID,
				  NL_CB_CUSTOM,
				  parse_cb,
				  swnd_ctx);
	if (ret < 0) {
		sd_journal_print(LOG_ERR,
				 "Failed to modify valid message callback: %s",
				 nl_geterror(ret));
		goto fail;
	}

	ret = nl_socket_set_nonblocking(swnd_ctx->nlsk);
	if (ret < 0) {
		sd_journal_print(LOG_ERR,
				 "Failed to set netlink socket "
				 "non-blocking: %s", nl_geterror(ret));
		goto fail;
	}

	fd = nl_socket_get_fd(swnd_ctx->nlsk);
	swnd_ctx->fde = tevent_add_fd(swnd_ctx->ev_ctx,
				      swnd_ctx,
				      fd,
				      TEVENT_FD_READ,
				      netlink_socket_read_handler,
				      swnd_ctx);
	if (swnd_ctx->fde == NULL) {
		ret = EIO;
		sd_journal_print(LOG_ERR,
				 "Failed to set netlink socket handler");
		goto fail;
	}

	tevent_fd_set_close_fn(swnd_ctx->fde, netlink_socket_close_handler);

	sd_journal_print(LOG_DEBUG, "Netlink socket created");

	return 0;
fail:
	nl_socket_free(swnd_ctx->nlsk);
	swnd_ctx->nlsk = NULL;
	return ret;
}

static void sigterm_handler(struct tevent_context *ev_ctx,
			    struct tevent_signal *se,
			    int signum,
			    int count,
			    void *siginfo,
			    void *private_data)
{
	TALLOC_CTX *mem_ctx = (TALLOC_CTX *)private_data;

	sd_journal_print(LOG_INFO, "Termination signal received, exit now\n");

	TALLOC_FREE(mem_ctx);

	exit(EXIT_SUCCESS);
}

static int setup_sigterm_handler(TALLOC_CTX *mem_ctx,
		struct tevent_context *ev_ctx)
{
	struct tevent_signal *se = NULL;

	se = tevent_add_signal(ev_ctx,
			       mem_ctx,
			       SIGTERM,
			       0,
			       sigterm_handler,
			       mem_ctx);
	if (se == NULL) {
		return ENOMEM;
	}

	return 0;
}

void samba_debug_cb(void *private_data, int level, const char *msg)
{
	int sd_lvl;

	switch (level) {
	case 0:
		sd_lvl = LOG_ERR;
		break;
	case 1:
		sd_lvl = LOG_WARNING;
		break;
	case 2:
	case 3:
		sd_lvl = LOG_NOTICE;
		break;
	case 4:
	case 5:
		sd_lvl = LOG_INFO;
		break;
	default:
		sd_lvl = LOG_DEBUG;
		break;
	}
	sd_journal_print(sd_lvl, msg);
}

static const struct option long_options[] = {
	{"debuglevel", 1, NULL, 'd'},
	{NULL, 0, NULL, 0}
};

int main(int argc, char *argv[])
{
	int c;
	int debug_level = 1;
	TALLOC_CTX *mem_ctx = NULL;
	struct swnd_context *swnd_ctx = NULL;
	int ret;

	while ((c = getopt_long(argc, argv, "d:", long_options, NULL)) != -1) {
		switch (c) {
		case 'd':
			debug_level = strtoul(optarg, NULL, 10);
			break;
		default:
			sd_journal_print(LOG_ERR, "unknown option: %c", c);
			return EXIT_FAILURE;
		}
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		sd_journal_print(LOG_ERR, "Failed to allocate talloc context");
		return EXIT_FAILURE;
	}

	swnd_ctx = talloc_zero(mem_ctx, struct swnd_context);
	if (swnd_ctx == NULL) {
		TALLOC_FREE(mem_ctx);
		sd_journal_print(LOG_ERR, "Failed to allocate swnd context");
		return EXIT_FAILURE;
	}

	swnd_ctx->ev_ctx = tevent_context_init(swnd_ctx);
	if (swnd_ctx->ev_ctx == NULL) {
		sd_journal_print(LOG_ERR, "Failed to allocate tevent context");
		TALLOC_FREE(mem_ctx);
		return EXIT_FAILURE;
	}
	tevent_loop_allow_nesting(swnd_ctx->ev_ctx);

	swnd_ctx->lp_ctx = loadparm_init_global(true);
	if (swnd_ctx->lp_ctx == NULL) {
		sd_journal_print(LOG_ERR, "Failed to initialize lp context");
		TALLOC_FREE(mem_ctx);
		return EXIT_FAILURE;
	}

	/* Setup SIGTERM handler */
	ret = setup_sigterm_handler(mem_ctx, swnd_ctx->ev_ctx);
	if (ret != 0) {
		sd_journal_print(LOG_ERR, "Failed to setup sigterm handler");
		TALLOC_FREE(mem_ctx);
		return EXIT_FAILURE;
	}

	/* Setup socket handler */
	ret = setup_netlink_socket(swnd_ctx);
	if (ret != 0) {
		sd_journal_print(LOG_ERR, "Failed to setup netlink socket");
		TALLOC_FREE(mem_ctx);
		return EXIT_FAILURE;
	}

	/* Init witness client library */
	ret = swnc_init_state(swnd_ctx, swnd_ctx->lp_ctx, &swnd_ctx->swn);
	if (ret != 0) {
		sd_journal_print(LOG_ERR,
				"Failed to initialize witness library: %s\n",
				strerror(ret));
		TALLOC_FREE(mem_ctx);
		return EXIT_FAILURE;
	}

	/* Setup samba logging */
	ret = swnc_set_debug_callback(swnd_ctx, debug_level, samba_debug_cb);
	if (ret != 0) {
		sd_journal_print(LOG_ERR,
				 "Failed to set samba debug callback: %s\n",
				  strerror(ret));
		TALLOC_FREE(mem_ctx);
		return EXIT_FAILURE;
	}

	/* Notify systemd we are ready */
	ret = sd_notify(0, "READY=1");
	if (ret < 0) {
		sd_journal_print(LOG_ERR, "sd_notify failed [%d]", ret);
	}

	/* Loop forever */
	ret = tevent_loop_wait(swnd_ctx->ev_ctx);

	/* Should not be reached */
	sd_journal_print(LOG_ERR,
			 "tevent_loop_wait() exited with %d: %s",
			 ret, (ret == 0) ? "out of events" : strerror(errno));

	TALLOC_FREE(mem_ctx);

	return EXIT_FAILURE;
}
