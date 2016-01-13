#!/bin/sh
# Copyright (C) 2016 Red Hat, Inc. All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

SKIP_WITH_LVMETAD=1
SKIP_WITH_CLVMD=1
SKIP_WITH_LVMPOLLD=1

. lib/inittest

aux prepare_vg 1
lvcreate --type mirror -m1 -l1 --alloc anywhere -n $lv1 $vg

aux lvmconf 'log/prefix=""'

aux lvmconf "report/mark_hidden_devices = 0"
lvs --noheadings -a -o name $vg > out
grep "^${lv1}_mimage_0" out
not grep "^\[${lv1}_mimage_0\]" out
lvs --noheadings -a -o devices $vg/$lv1 > out
grep "^${lv1}_mimage_0" out
not grep "^\[${lv1}_mimage_0\]" out

aux lvmconf "report/mark_hidden_devices = 1"
lvs --noheadings -a -o name $vg > out
grep "^\[${lv1}_mimage_0\]" out
not grep "^${lv1}_mimage_0" out
lvs --noheadings -a -o devices $vg/$lv1 > out
grep "^\[${lv1}_mimage_0\]" out
not grep "^${lv1}_mimage_0" out

vgremove -ff $vg