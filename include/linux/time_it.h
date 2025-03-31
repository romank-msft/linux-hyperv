#ifndef __TIME_IT__
#define __TIME_IT__

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <asm/arch_timer.h>

struct time_taken {
    const char* label;
    struct {
        u64 depth:9;
        u64 cycles:55;
    };
} __packed;

#define TIME_TAKEN_RECORD_COUNT 0x4000000ULL

extern struct time_taken time_taken_stor[TIME_TAKEN_RECORD_COUNT];
extern atomic_long_t time_taken_next;
extern atomic_long_t time_taken_overflows;
extern atomic_long_t time_taken_depth;

#define TIME_IT(LABEL, X) \
	{ \
		do { \
            u64 __IDX; \
            u64 __TIMERCNT; \
            \
            if (atomic_long_cmpxchg_relaxed(&time_taken_next, TIME_TAKEN_RECORD_COUNT, 0) == TIME_TAKEN_RECORD_COUNT) {\
                atomic_long_fetch_inc_relaxed(&time_taken_overflows); \
            } \
            /* still a race? and the wacky modulo? */ \
            __IDX = atomic_long_fetch_inc_relaxed(&time_taken_next) % TIME_TAKEN_RECORD_COUNT; \
            \
            time_taken_stor[__IDX].label = LABEL; \
            time_taken_stor[__IDX].depth = atomic_long_fetch_inc_relaxed(&time_taken_depth); \
            __TIMERCNT = __arch_counter_get_cntvct_stable(); \
			X; \
            time_taken_stor[__IDX].cycles = __arch_counter_get_cntvct_stable() - __TIMERCNT; \
            atomic_long_fetch_dec_relaxed(&time_taken_depth); \
        } while (0); \
	} \

#endif
