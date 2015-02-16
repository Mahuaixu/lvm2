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

#include "libdevmapper.h"
#include "lvmpolld-data-utils.h"

lvmpolld_lv_t *pdlv_create(lvmpolld_state_t *ls, const char *lvid,
			   const char *lvname, enum poll_type type,
			   const char *sinterval, unsigned pdtimeout,
			   lvmpolld_store_t *pdst,
			   lvmpolld_parse_output_fn_t parse_fn)
{
	lvmpolld_lv_t tmp = {
		.ls = ls,
		.type = type,
		.lvid = dm_strdup(lvid),
		.lvname = dm_strdup(lvname),
		.sinterval = dm_strdup(sinterval),
		.pdtimeout = pdtimeout ?: PDTIMEOUT_DEF,
		.cmd_state = { .retcode = -1, .signal = 0 },
		.pdst = pdst,
		.parse_output_fn = parse_fn
	}, *pdlv = (lvmpolld_lv_t *) dm_malloc(sizeof(lvmpolld_lv_t));

	if (!pdlv || !tmp.lvid || !tmp.lvname || !tmp.sinterval) {
		dm_free((void *)tmp.lvid);
		dm_free((void *)tmp.lvname);
		dm_free((void *)tmp.sinterval);
		return NULL;
	}

	memcpy(pdlv, &tmp, sizeof(*pdlv));

	if (pthread_mutex_init(&pdlv->lock, NULL))
		goto err;

	return pdlv;

err:
	dm_free((void *)pdlv->sinterval);
	dm_free((void *)pdlv->lvid);
	dm_free((void *)pdlv->lvname);
	dm_free((void *)pdlv);

	return NULL;
}

void pdlv_destroy(lvmpolld_lv_t *pdlv)
{
	dm_free((void *)pdlv->lvid);
	dm_free((void *)pdlv->lvname);
	dm_free((void *)pdlv->sinterval);
	dm_free((void *)pdlv->cmdargv);

	pthread_mutex_destroy(&pdlv->lock);

	dm_free((void *)pdlv);
}

unsigned pdlv_get_polling_finished(lvmpolld_lv_t *pdlv)
{
	unsigned ret;

	pdlv_lock(pdlv);
	ret = pdlv->polling_finished;
	pdlv_unlock(pdlv);

	return ret;
}

lvmpolld_lv_state_t pdlv_get_status(lvmpolld_lv_t *pdlv)
{
	lvmpolld_lv_state_t r;

	pdlv_lock(pdlv);
	r.internal_error = pdlv_locked_internal_error(pdlv);
	r.polling_finished = pdlv_locked_polling_finished(pdlv);
	r.cmd_state = pdlv_locked_cmd_state(pdlv);
	pdlv_unlock(pdlv);

	return r;
}

void pdlv_set_cmd_state(lvmpolld_lv_t *pdlv, const lvmpolld_cmd_stat_t *cmd_state)
{
	pdlv_lock(pdlv);
	pdlv->cmd_state = *cmd_state;
	pdlv_unlock(pdlv);
}

void pdlv_set_internal_error(lvmpolld_lv_t *pdlv, unsigned error)
{
	pdlv_lock(pdlv);
	pdlv->internal_error = error;
	pdlv->polling_finished = 1;
	pdlv_unlock(pdlv);
}

void pdlv_set_polling_finished(lvmpolld_lv_t *pdlv, unsigned finished)
{
	pdlv_lock(pdlv);
	pdlv->polling_finished = finished;
	pdlv_unlock(pdlv);
}

void pdst_init(lvmpolld_store_t *pdst, const char *name)
{
	pthread_mutex_init(&pdst->lock, NULL);
	pdst->store = dm_hash_create(32);
	pdst->name = name;
}

void pdst_destroy(lvmpolld_store_t *pdst)
{
	dm_hash_destroy(pdst->store);
	pthread_mutex_destroy(&pdst->lock);
}
