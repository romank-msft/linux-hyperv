// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>

#include <linux/time_it.h>

#include "internal.h"

struct time_taken time_taken_stor[TIME_TAKEN_RECORD_COUNT];
atomic_long_t time_taken_next;
atomic_long_t time_taken_overflows;
atomic_long_t time_taken_depth;

#define TIME_IT_CHUNK_SIZE (256ULL<<20)
#define TIME_IT_CHUNKS ((u64)(((u64)sizeof(time_taken_stor))/(TIME_IT_CHUNK_SIZE)))
#define TIME_IT_CHUNK_ITEMS ((u64)TIME_TAKEN_RECORD_COUNT/TIME_IT_CHUNKS)

/**********************************************************************************************************/

static int time_it_proc_show(struct seq_file *t, void *v)
{
    u64 i = 0;
    u64 last = atomic_long_read(&time_taken_next);
    while (i < last) {
        seq_printf(t, "[%lld][%lld/%lld] %s %#llx\n",
            (u64)(time_taken_stor[i].depth),
            i, last - 1,
            time_taken_stor[i].label, (u64)(time_taken_stor[i].cycles));
        ++i;
    }

	return 0;
}

static int __init proc_time_it_init(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create_single("time_it", 0, NULL, time_it_proc_show);
	pde_make_permanent(pde);
	return 0;
}
fs_initcall(proc_time_it_init);

/**********************************************************************************************************/

static int proc_time_it_stat_show(struct seq_file *t, void *v)
{
    seq_printf(t, "%#llx overflows\n", (u64)atomic_long_read(&time_taken_overflows));
    seq_printf(t, "%#llx entries\n", (u64)atomic_long_read(&time_taken_next));
    seq_printf(t, "%#llx storage size, bytes\n", (u64)sizeof(time_taken_stor));
    seq_printf(t, "%#llx max records\n", (u64)TIME_TAKEN_RECORD_COUNT);
    seq_printf(t, "%#llx chunk size, bytes\n", (u64)TIME_IT_CHUNK_SIZE);
    seq_printf(t, "%#llx chunks\n", (u64)TIME_IT_CHUNKS);
    seq_printf(t, "%#llx chunk items\n", (u64)TIME_IT_CHUNK_ITEMS);

	return 0;
}

static int __init proc_time_it_stat_init(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create_single("time_it_stat", 0, NULL, proc_time_it_stat_show);
	pde_make_permanent(pde);
	return 0;
}
fs_initcall(proc_time_it_stat_init);

/**********************************************************************************************************/

static int proc_time_it_chunk_show(struct seq_file *t, void *v)
{
    static DEFINE_MUTEX(current_chunk_lock);
    static u64 current_chunk = 0;

    u64 i;
    u64 last;

    mutex_lock(&current_chunk_lock);

    if (current_chunk >= TIME_IT_CHUNKS) {
        current_chunk = 0;
        mutex_unlock(&current_chunk_lock);
        return -ENODATA;
    }

    i = current_chunk * TIME_IT_CHUNK_ITEMS;
    last = i + TIME_IT_CHUNK_ITEMS;

    seq_printf(t, "### PROFILE_CHUNK_START: %#llx\n", current_chunk);

    while (i < last) {
        seq_printf(t, "### [%lld][%lld/%lld]: %s %#llx\n",
            (u64)(time_taken_stor[i].depth),
            i, last - 1,
            time_taken_stor[i].label, (u64)(time_taken_stor[i].cycles));
        ++i;
    }

    seq_printf(t, "### PROFILE_CHUNK_END: %#llx\n", current_chunk);
    ++current_chunk;

    mutex_unlock(&current_chunk_lock);

    return 0;
}

static int __init proc_time_it_chunk_init(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create_single("time_it_chunk", 0, NULL, proc_time_it_chunk_show);
	pde_make_permanent(pde);
	return 0;
}
fs_initcall(proc_time_it_chunk_init);
