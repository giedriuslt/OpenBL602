/*
 * TX rate capping for the BL602 Wi-Fi rate controller.
 *
 * The Wi-Fi LMAC/UMAC (libwifi.a) runs on the same core as the application
 * and its Minstrel-style rate controller keeps per-station state in the
 * global array `sta_stats` (struct rc_sta_stats, one entry per station).
 * The sampler in rc.o only ever picks rates inside the per-station bounds
 * stored there (mcs_max / r_idx_min / r_idx_max), which are recomputed from
 * the peer's capabilities on every (re)association (rc_init).
 *
 * Unlike wifi_mgmr_rate_config() - which pins a single fixed rate - this
 * module lowers those bounds, so automatic rate adaption stays active but
 * never selects a rate above the configured cap.
 *
 * The struct layout is not exported by any libwifi.a header; the constants
 * below were extracted from the DWARF debug info of rc.o in this SDK's
 * components/network/wifi/lib/libwifi.a and are only valid for the BL602
 * blob (hence the CFG_CHIP_BL602 guard).
 */

#include <stdint.h>
#include <string.h>

#include <bl_os_private.h>
#include "bl_defs.h"
#include "include/wifi_mgmr_ext.h"

#ifdef CFG_CHIP_BL602

/* struct rc_sta_stats layout (from libwifi.a rc.o DWARF) */
#define RC_STA_STATS_SIZEOF     200
#define RC_STA_MAX              5    /* sizeof(sta_stats) / RC_STA_STATS_SIZEOF */
#define RC_OFF_MCS_MAX          184  /* uint8_t, highest HT MCS the sampler may pick */
#define RC_OFF_R_IDX_MIN        185  /* uint8_t, lowest legacy rate index */
#define RC_OFF_R_IDX_MAX        186  /* uint8_t, highest legacy rate index */

/* Legacy rate indices (HW_RATE_* enum in rc.o): 0..3 = 1/2/5.5/11 Mbps CCK,
 * 4..11 = 6/9/12/18/24/36/48/54 Mbps OFDM */
#define RC_LEGACY_RIDX_MAX      11
#define RC_HT_MCS_MAX           7

/* Per-station rate controller state owned by libwifi.a(rc.o) */
extern uint8_t sta_stats[];

extern struct bl_hw wifi_hw;

static uint8_t s_cap_mcs = WIFI_MGMR_RATE_LIMIT_NONE;
static uint8_t s_cap_ridx = WIFI_MGMR_RATE_LIMIT_NONE;

/* Bounds computed by rc_init for the current association, saved before the
 * first clamp so the cap can be lifted without a reconnect. */
static uint8_t s_orig_mcs[RC_STA_MAX];
static uint8_t s_orig_ridx[RC_STA_MAX];
static uint8_t s_orig_valid[RC_STA_MAX];

static inline uint8_t *rc_entry(uint8_t sta_idx)
{
    return &sta_stats[(uint32_t)sta_idx * RC_STA_STATS_SIZEOF];
}

int wifi_mgmr_rate_limit_apply_sta(uint8_t sta_idx)
{
    uint8_t *st;
    uint8_t mcs, ridx, r_idx_min;

    if (sta_idx >= RC_STA_MAX) {
        return -1;
    }
    st = rc_entry(sta_idx);

    if (!s_orig_valid[sta_idx]) {
        s_orig_mcs[sta_idx] = st[RC_OFF_MCS_MAX];
        s_orig_ridx[sta_idx] = st[RC_OFF_R_IDX_MAX];
        s_orig_valid[sta_idx] = 1;
    }

    mcs = s_orig_mcs[sta_idx];
    if (s_cap_mcs < mcs) {
        mcs = s_cap_mcs;
    }

    ridx = s_orig_ridx[sta_idx];
    if (s_cap_ridx < ridx) {
        ridx = s_cap_ridx;
    }
    /* never cap below the lowest rate rc_init selected for this peer */
    r_idx_min = st[RC_OFF_R_IDX_MIN];
    if (ridx < r_idx_min) {
        ridx = r_idx_min;
    }

    /* single-byte stores: safe against the Wi-Fi task reading concurrently */
    st[RC_OFF_MCS_MAX] = mcs;
    st[RC_OFF_R_IDX_MAX] = ridx;

    return 0;
}

int wifi_mgmr_rate_limit(uint8_t max_ht_mcs, uint8_t max_legacy_ridx)
{
    if (max_ht_mcs != WIFI_MGMR_RATE_LIMIT_NONE && max_ht_mcs > RC_HT_MCS_MAX) {
        return -1;
    }
    if (max_legacy_ridx != WIFI_MGMR_RATE_LIMIT_NONE && max_legacy_ridx > RC_LEGACY_RIDX_MAX) {
        return -1;
    }

    s_cap_mcs = max_ht_mcs;
    s_cap_ridx = max_legacy_ridx;

    return wifi_mgmr_rate_limit_apply_sta(wifi_hw.sta_idx);
}

int wifi_mgmr_rate_limit_clear(void)
{
    uint8_t sta_idx = wifi_hw.sta_idx;

    s_cap_mcs = WIFI_MGMR_RATE_LIMIT_NONE;
    s_cap_ridx = WIFI_MGMR_RATE_LIMIT_NONE;

    if (sta_idx < RC_STA_MAX && s_orig_valid[sta_idx]) {
        uint8_t *st = rc_entry(sta_idx);
        st[RC_OFF_MCS_MAX] = s_orig_mcs[sta_idx];
        st[RC_OFF_R_IDX_MAX] = s_orig_ridx[sta_idx];
    }
    return 0;
}

int wifi_mgmr_rate_limit_get(uint8_t *max_ht_mcs, uint8_t *max_legacy_ridx)
{
    if (max_ht_mcs) {
        *max_ht_mcs = s_cap_mcs;
    }
    if (max_legacy_ridx) {
        *max_legacy_ridx = s_cap_ridx;
    }
    return 0;
}

void wifi_mgmr_rate_limit_connected_ind(void)
{
    /* rc_init has just rebuilt the bounds for the new association: the old
     * snapshots are stale and the caps (if any) must be applied again. */
    memset(s_orig_valid, 0, sizeof(s_orig_valid));

    if (s_cap_mcs != WIFI_MGMR_RATE_LIMIT_NONE || s_cap_ridx != WIFI_MGMR_RATE_LIMIT_NONE) {
        wifi_mgmr_rate_limit_apply_sta(wifi_hw.sta_idx);
        bl_os_printf("[RC] rate limit applied: max MCS %u, max legacy ridx %u\r\n",
                s_cap_mcs, s_cap_ridx);
    }
}

#else /* !CFG_CHIP_BL602 */

/* The rc_sta_stats offsets are only verified against the BL602 libwifi.a */

int wifi_mgmr_rate_limit_apply_sta(uint8_t sta_idx)
{
    (void)sta_idx;
    return -1;
}

int wifi_mgmr_rate_limit(uint8_t max_ht_mcs, uint8_t max_legacy_ridx)
{
    (void)max_ht_mcs;
    (void)max_legacy_ridx;
    return -1;
}

int wifi_mgmr_rate_limit_clear(void)
{
    return -1;
}

int wifi_mgmr_rate_limit_get(uint8_t *max_ht_mcs, uint8_t *max_legacy_ridx)
{
    (void)max_ht_mcs;
    (void)max_legacy_ridx;
    return -1;
}

void wifi_mgmr_rate_limit_connected_ind(void)
{
}

#endif /* CFG_CHIP_BL602 */
