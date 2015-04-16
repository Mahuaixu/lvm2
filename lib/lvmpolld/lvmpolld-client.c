/*
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>

#include "daemon-io.h"
#include "lib.h"
#include "lvmpolld-client.h"
#include "lvmpolld-protocol.h"
#include "metadata-exported.h"
#include "polldaemon.h"
#include "toolcontext.h"

struct progress_info {
	unsigned error:1;
	unsigned finished:1;
	int cmd_signal;
	int cmd_retcode;
};

static int _lvmpolld_use;
static int _lvmpolld_connected;
static const char* _lvmpolld_socket;

static daemon_handle _lvmpolld = { .error = 0 };

static daemon_handle _lvmpolld_connect(const char *socket)
{
	daemon_info lvmpolld_info = {
		.path = "lvmpolld",
		.socket = socket ?: LVMPOLLD_SOCKET,
		.protocol = LVMPOLLD_PROTOCOL,
		.protocol_version = LVMPOLLD_PROTOCOL_VERSION
	};

	return daemon_open(lvmpolld_info);
}

void lvmpolld_set_active(int active)
{
	_lvmpolld_use = active;
}

void lvmpolld_set_socket(const char *socket)
{
	_lvmpolld_socket = socket;
}

int lvmpolld_use(void)
{
	if (!_lvmpolld_use)
		return 0;

	if (!_lvmpolld_connected && !_lvmpolld.error) {
		_lvmpolld = _lvmpolld_connect(_lvmpolld_socket);
		_lvmpolld_connected = _lvmpolld.socket_fd >= 0;
	}

	return _lvmpolld_connected;
}

void lvmpolld_disconnect(void)
{
	if (_lvmpolld_connected) {
		daemon_close(_lvmpolld);
		_lvmpolld_connected = 0;
	}
}

static struct progress_info _request_progress_info(const char *uuid, unsigned abort)
{
	daemon_reply repl;
	const char *e = getenv("LVM_SYSTEM_DIR");
	struct progress_info ret = { .error = 1, .finished = 1 };
	daemon_request req = daemon_request_make(LVMPD_REQ_PROGRESS);

	if (!daemon_request_extend(req, LVMPD_PARM_LVID " = %s", uuid, NULL)) {
		log_error("failed to create " LVMPD_REQ_PROGRESS " request");
		goto out_req;
	}

	if (abort &&
	    !daemon_request_extend(req, LVMPD_PARM_ABORT " = %d", abort, NULL)) {
		log_error("failed to create " LVMPD_REQ_PROGRESS " request");
		goto out_req;
	}

	if (e &&
	    !(daemon_request_extend(req, LVMPD_PARM_SYSDIR " = %s",
				    e, NULL))) {
		log_error("failed to create " LVMPD_REQ_PROGRESS " request");
		goto out_req;
	}

	repl = daemon_send(_lvmpolld, req);
	if (repl.error) {
		log_error("failed to process request/response to/from lvmpolld");
		goto out_repl;
	}

	if (!strcmp(daemon_reply_str(repl, "response", ""), LVMPD_RESP_IN_PROGRESS)) {
		ret.finished = 0;
		ret.error = 0;
	} else if (!strcmp(daemon_reply_str(repl, "response", ""), LVMPD_RESP_FINISHED)) {
		if (!strcmp(daemon_reply_str(repl, "reason", ""), LVMPD_REAS_SIGNAL))
			ret.cmd_signal = daemon_reply_int(repl, LVMPD_PARM_VALUE, 0);
		else
			ret.cmd_retcode = daemon_reply_int(repl, LVMPD_PARM_VALUE, -1);
		ret.error = 0;
	} else if (!strcmp(daemon_reply_str(repl, "response", ""), LVMPD_RESP_NOT_FOUND)) {
		log_verbose("lvmpolld: no polling operation in progress regarding LV %s", uuid);
		ret.error = 0;
	} else if (!strcmp(daemon_reply_str(repl, "response", ""), LVMPD_RESP_FAILED))
		log_error("failed to receive progress data: %s",
			  daemon_reply_str(repl, "reason", "<empty>"));
	else
		log_error("Unexpected lvmpolld response: %s",
			  daemon_reply_str(repl, "response", ""));
out_repl:
	daemon_reply_destroy(repl);
out_req:
	daemon_request_destroy(req);

	return ret;
}

/*
 * interval in seconds long
 * enough for more than a year
 * of waiting
 */
#define INTERV_SIZE 10

static int _process_poll_init(const struct cmd_context *cmd, const char *poll_type,
			      const struct poll_operation_id *id, const struct daemon_parms *parms)
{
	char *str;
	daemon_reply rep;
	daemon_request req;
	const char *e = getenv("LVM_SYSTEM_DIR");
	int r = 0; 

	str = dm_malloc(INTERV_SIZE * sizeof(char));
	if (!str)
		return r;

	if (snprintf(str, INTERV_SIZE, "%u", parms->interval) >= INTERV_SIZE) {
		log_warn("interval string conversion got truncated");
		str[INTERV_SIZE - 1] = '\0';
	}

	req = daemon_request_make(poll_type);
	if (!daemon_request_extend(req, LVMPD_PARM_LVID " = %s", id->uuid,
					LVMPD_PARM_VGNAME " = %s", id->vg_name,
					LVMPD_PARM_LVNAME " = %s", id->lv_name,
					LVMPD_PARM_INTERVAL " = %s", str,
					"cmdline = %s", cmd->cmd_line, /* FIXME: debug param only */
					NULL)) {
		log_error("failed to create %s request", poll_type);
		goto out_req;
	}

	if (parms->aborting &&
	    !(daemon_request_extend(req, LVMPD_PARM_ABORT " = %d", parms->aborting, NULL))) {
		log_error("failed to create %s request" , poll_type);
		goto out_req;
	}

	if (cmd->handles_missing_pvs &&
	    !(daemon_request_extend(req, LVMPD_PARM_HANDLE_MISSING_PVS " = %d",
				    cmd->handles_missing_pvs, NULL))) {
		log_error("failed to create %s request" , poll_type);
		goto out_req;
	}

	if (e &&
	    !(daemon_request_extend(req, LVMPD_PARM_SYSDIR " = %s",
				    e, NULL))) {
		log_error("failed to create %s request" , poll_type);
		goto out_req;
	}

	rep = daemon_send(_lvmpolld, req);

	if (!strcmp(daemon_reply_str(rep, "response", ""), LVMPD_RESP_OK))
		r = 1;
	else {
		if (rep.error)
			log_error("failed to process request with error %s (errno: %d)",
				  strerror(rep.error), rep.error);
		else
			log_error("failed to initialise lvmpolld operation: %s. The reason: %s",
				  poll_type, daemon_reply_str(rep, "reason", ""));
	}

	daemon_reply_destroy(rep);
out_req:
	daemon_request_destroy(req);
	dm_free(str);

	return r;
}

int lvmpolld_poll_init(const struct cmd_context *cmd, const struct poll_operation_id *id,
		       const struct daemon_parms *parms)
{
	int r = 0;

	if (!id->uuid) {
		log_error(INTERNAL_ERROR "use of lvmpolld requires uuid set");
		return 0;
	}

	if (!id->vg_name) {
		log_error(INTERNAL_ERROR "use of lvmpolld requires vgname set");
		return 0;
	}

	if (!id->lv_name) {
		log_error(INTERNAL_ERROR "use of lvmpolld requires lvname set");
		return 0;
	}

	if (parms->lv_type & PVMOVE) {
		log_verbose("lvmpolld: pvmove%s", parms->aborting ? "--abort" : "");
		r =  _process_poll_init(cmd, LVMPD_REQ_PVMOVE, id, parms);
	} else if (parms->lv_type & CONVERTING) {
		log_verbose("lvmpolld: convert mirror");
		r =  _process_poll_init(cmd, LVMPD_REQ_CONVERT, id, parms);
	} else if (parms->lv_type & MERGING) {
		if (parms->lv_type & SNAPSHOT) {
			log_verbose("lvmpolld: Merge snapshot");
			r =  _process_poll_init(cmd, LVMPD_REQ_MERGE, id, parms);
		}
		else if (parms->lv_type & THIN_VOLUME) {
			log_verbose("lvmpolld: Merge thin snapshot");
			r = _process_poll_init(cmd, LVMPD_REQ_MERGE_THIN, id, parms);
		}
		else {
			log_error(INTERNAL_ERROR "Unsupported poll operation");
		}
	} else
		log_error(INTERNAL_ERROR "Unsupported poll operation");

	return r;
}

int lvmpolld_request_info(const struct poll_operation_id *id, const struct daemon_parms *parms, unsigned *finished)
{
	struct progress_info info;
	int ret = 0;

	*finished = 1;

	if (!id->uuid) {
		log_error(INTERNAL_ERROR "use of lvmpolld requires uuid being set");
		return 0;
	}

	info = _request_progress_info(id->uuid, parms->aborting);
	*finished = info.finished;

	if (info.error)
		return_0;

	if (info.finished) {
		if (info.cmd_signal)
			log_error("lvmpolld: polling command got terminated by signal (%d)",
				  info.cmd_signal);
		else if (info.cmd_retcode)
			log_error("lvmpolld: polling command exited with return code: %d",
				  info.cmd_retcode);
		else  {
			log_verbose("lvmpolld: polling finished successfully");
			ret = 1;
		}
	} else
		ret = 1;

	return ret;
}
