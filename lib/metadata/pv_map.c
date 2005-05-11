/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "lib.h"
#include "pv_map.h"
#include "hash.h"
#include "pv_alloc.h"

/*
 * Areas are maintained in size order, largest first.
 */
static void _insert_area(struct list *head, struct pv_area *a)
{
	struct pv_area *pva;

	list_iterate_items(pva, head) {
		if (a->count > pva->count)
			break;
	}

	list_add(&pva->list, &a->list);
}

static int _create_single_area(struct pool *mem, struct pv_map *pvm,
			       uint32_t start, uint32_t length)
{
	struct pv_area *pva;

	if (!(pva = pool_zalloc(mem, sizeof(*pva)))) {
		stack;
		return 0;
	}

	log_debug("Allowing allocation on %s start PE %" PRIu32 " length %"
		  PRIu32, dev_name(pvm->pv->dev), start, length);
	pva->map = pvm;
	pva->start = start;
	pva->count = length;
	_insert_area(&pvm->areas, pva);

	return 1;
}

static int _create_alloc_areas_for_pv(struct pool *mem, struct pv_map *pvm,
				      uint32_t start, uint32_t count)
{
        struct pv_segment *peg;
	uint32_t pe, end, area_len;

	/* Only select extents from start to end inclusive */
	end = start + count - 1;
	if (end > pvm->pv->pe_count - 1)
		end = pvm->pv->pe_count - 1;

	pe = start;

	/* Walk through complete ordered list of device segments */
        list_iterate_items(peg, &pvm->pv->segments) {
		/* pe holds the next extent we want to check */

		/* Beyond the range we're interested in? */
		if (pe > end)
			break;

		/* Skip if we haven't reached the first seg we want yet */
		if (pe > peg->pe + peg->len - 1)
			continue;

		/* Free? */
		if (peg->lvseg)
			goto next;

		/* How much of this peg do we need? */
		area_len = (end >= peg->pe + peg->len - 1) ?
			   peg->len - (pe - peg->pe) : end - pe + 1;

		if (!_create_single_area(mem, pvm, pe, area_len)) {
			stack;
			return 0;
		}

      next:
		pe = peg->pe + peg->len;
        }

	return 1;
}

static int _create_all_areas_for_pv(struct pool *mem, struct pv_map *pvm,
				    struct list *pe_ranges)
{
	struct pe_range *aa;

	if (!pe_ranges) {
		/* Use whole PV */
		if (!_create_alloc_areas_for_pv(mem, pvm, UINT32_C(0),
						pvm->pv->pe_count)) {
			stack;
			return 0;
		}

		return 1;
	}

	list_iterate_items(aa, pe_ranges) {
		if (!_create_alloc_areas_for_pv(mem, pvm, aa->start,
						aa->count)) {
			stack;
			return 0;
		}
	}

	return 1;
}

static int _create_maps(struct pool *mem, struct list *pvs, struct list *pvms)
{
	struct pv_map *pvm;
	struct pv_list *pvl;

	list_iterate_items(pvl, pvs) {
		if (!(pvl->pv->status & ALLOCATABLE_PV))
			continue;

		if (!(pvm = pool_zalloc(mem, sizeof(*pvm)))) {
			stack;
			return 0;
		}

		pvm->pv = pvl->pv;

		list_init(&pvm->areas);
		list_add(pvms, &pvm->list);

		if (!_create_all_areas_for_pv(mem, pvm, pvl->pe_ranges)) {
			stack;
			return 0;
		}
	}

	return 1;
}

/*
 * Create list of PV areas available for this particular allocation
 */
struct list *create_pv_maps(struct pool *mem, struct volume_group *vg,
			    struct list *allocatable_pvs)
{
	struct list *pvms;

	if (!(pvms = pool_zalloc(mem, sizeof(*pvms)))) {
		log_error("create_pv_maps alloc failed");
		return NULL;
	}

	list_init(pvms);

	if (!_create_maps(mem, allocatable_pvs, pvms)) {
		log_error("Couldn't create physical volume maps in %s",
			  vg->name);
		pool_free(mem, pvms);
		return NULL;
	}

	return pvms;
}

void consume_pv_area(struct pv_area *pva, uint32_t to_go)
{
	list_del(&pva->list);

	assert(to_go <= pva->count);

	if (to_go < pva->count) {
		/* split the area */
		pva->start += to_go;
		pva->count -= to_go;
		_insert_area(&pva->map->areas, pva);
	}
}
