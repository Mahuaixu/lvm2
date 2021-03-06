/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2009 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "tools.h"

int vgcfgrestore(struct cmd_context *cmd, int argc, char **argv)
{
	const char *vg_name = NULL;

	if (argc == 1) {
		vg_name = skip_dev_dir(cmd, argv[0], NULL);
		if (!validate_name(vg_name)) {
			log_error("Volume group name \"%s\" is invalid", vg_name);
			return EINVALID_CMD_LINE;
		}
	} else if (!(arg_count(cmd, list_ARG) && arg_count(cmd, file_ARG))) {
		log_error("Please specify a *single* volume group to restore.");
		return EINVALID_CMD_LINE;
	}

	/*
	 * FIXME: overloading the -l arg for now to display a
	 * list of archive files for a particular vg
	 */
	if (arg_count(cmd, list_ARG)) {
		if (!(arg_count(cmd,file_ARG) ?
			    archive_display_file(cmd,
				arg_str_value(cmd, file_ARG, "")) :
			    archive_display(cmd, vg_name)))
			return_ECMD_FAILED;

		return ECMD_PROCESSED;
	}

	lvmcache_seed_infos_from_lvmetad(cmd);

	if (!lock_vol(cmd, vg_name, LCK_VG_WRITE, NULL)) {
		log_error("Unable to lock volume group %s", vg_name);
		return ECMD_FAILED;
	}

	if (!lock_vol(cmd, VG_ORPHANS, LCK_VG_WRITE, NULL)) {
		log_error("Unable to lock orphans");
		unlock_vg(cmd, vg_name);
		return ECMD_FAILED;
	}

	cmd->handles_unknown_segments = 1;

	if (!(arg_count(cmd, file_ARG) ?
	      backup_restore_from_file(cmd, vg_name,
				       arg_str_value(cmd, file_ARG, ""),
				       arg_count(cmd, force_long_ARG)) :
	      backup_restore(cmd, vg_name, arg_count(cmd, force_long_ARG)))) {
		unlock_vg(cmd, VG_ORPHANS);
		unlock_vg(cmd, vg_name);
		log_error("Restore failed.");
		return ECMD_FAILED;
	}

	log_print_unless_silent("Restored volume group %s", vg_name);

	unlock_vg(cmd, VG_ORPHANS);
	unlock_vg(cmd, vg_name);
	return ECMD_PROCESSED;
}
