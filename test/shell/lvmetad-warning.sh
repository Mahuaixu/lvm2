#!/bin/sh
# Copyright (C) 2012 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

SKIP_WITH_LVMLOCKD=1
SKIP_WITHOUT_LVMETAD=1
SKIP_WITH_LVMPOLLD=1

. lib/inittest

aux prepare_pvs 2

vgcreate $vg1 "$dev1" "$dev2"
lvchange -ay $vg1 2>&1 | not grep "Failed to connect"

kill $(< LOCAL_LVMETAD)
lvchange -ay $vg1 2>&1 | grep "Failed to connect"
lvchange -aay $vg1 --sysinit 2>&1 | tee sysinit.txt
not grep "Failed to connect" sysinit.txt

aux lvmconf 'global/use_lvmetad = 0'
lvchange -ay $vg1 2>&1 | not grep "Failed to connect"
lvchange -ay $vg1 --sysinit 2>&1 | not grep "Failed to connect"

aux prepare_lvmetad
lvchange -ay $vg1 2>&1 | not grep "Failed to connect"
lvchange -ay $vg1 --sysinit 2>&1 | not grep "Failed to connect"

vgremove -ff $vg1
