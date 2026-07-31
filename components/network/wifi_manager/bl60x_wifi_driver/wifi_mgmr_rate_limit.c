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
#define RC_OFF_RATE_STATS       4    /* struct rc_rate_stats[10], the sample table */
#define RC_OFF_MCS_MAX          184  /* uint8_t, highest HT MCS the sampler may pick */
#define RC_OFF_R_IDX_MIN        185  /* uint8_t, lowest legacy rate index */
#define RC_OFF_R_IDX_MAX        186  /* uint8_t, highest legacy rate index */
#define RC_OFF_SHORT_GI         189  /* uint8_t, TX SGI allowed (set by rc_init from
                                        the AP's HT capability, its only writer) */
#define RC_OFF_NO_SAMPLES       192  /* uint16_t, valid entries in the sample table */

/* struct rc_rate_stats layout (12 bytes per entry) */
#define RC_MAX_N_SAMPLE         10
#define RC_ENTRY_SIZEOF         12
#define RC_ENTRY_OFF_ATTEMPTS   0    /* uint16_t */
#define RC_ENTRY_OFF_SUCCESS    2    /* uint16_t */
#define RC_ENTRY_OFF_PROB       4    /* uint16_t, EWMA success probability */
#define RC_ENTRY_OFF_RATE_CFG   6    /* uint16_t, rate word (format<<11|gi<<9|..|idx) */

/* Legacy rate indices (HW_RATE_* enum in rc.o): 0..3 = 1/2/5.5/11 Mbps CCK,
 * 4..11 = 6/9/12/18/24/36/48/54 Mbps OFDM */
#define RC_LEGACY_RIDX_MAX      11
#define RC_HT_MCS_MAX           7

/* struct sta_info_tag / struct vif_info_tag (from libwifi.a disassembly).
 * me_update_buffer_control() in me_utils.o recomputes mcs_max and
 * rate_map.ht from the VIF's negotiated HT MCS mask after every retry
 * chain update (~100 ms under traffic), which silently reverts any clamp
 * written only to rc_sta_stats. The mask itself is written by the
 * connection state machine (sm.o) during association only, so clamping
 * it makes every recomputation reproduce the cap. */
#define STA_INFO_TAG_SIZEOF     368
#define STA_INFO_OFF_VIF_IDX    39   /* uint8_t, 0xFF = no vif */
#define VIF_INFO_TAG_SIZEOF     1512
#define VIF_INFO_OFF_HT_MCS_MASK 347 /* bss_info: HT MCS0-7 mask for 1SS */
#define VIF_MAX                 2    /* NX_VIRT_DEV_MAX */

/* Per-station rate controller state owned by libwifi.a(rc.o) */
extern uint8_t sta_stats[];
extern uint8_t sta_info_tab[];
extern uint8_t vif_info_tab[];

extern struct bl_hw wifi_hw;

static uint8_t s_cap_mcs = WIFI_MGMR_RATE_LIMIT_NONE;
static uint8_t s_cap_ridx = WIFI_MGMR_RATE_LIMIT_NONE;
/* Build with CONFIG_WIFI_TX_SGI_DISABLE:=1 (proj_config.mk) to force long
 * GI on TX from boot; wifi_mgmr_rate_limit_sgi_tx() can still override. */
#ifdef CONF_WIFI_TX_SGI_DISABLE
static uint8_t s_sgi_tx_disabled = 1;
#else
static uint8_t s_sgi_tx_disabled = 0;
#endif

/* original VIF HT MCS mask, saved before the first clamp */
static uint8_t s_orig_vif_mask[VIF_MAX];
static uint8_t s_orig_vif_valid[VIF_MAX];

/* Bounds computed by rc_init for the current association, saved before the
 * first clamp so the cap can be lifted without a reconnect. */
static uint8_t s_orig_mcs[RC_STA_MAX];
static uint8_t s_orig_ridx[RC_STA_MAX];
static uint8_t s_orig_sgi[RC_STA_MAX];
static uint8_t s_orig_valid[RC_STA_MAX];

static inline int rate_limit_active(void)
{
    return s_cap_mcs != WIFI_MGMR_RATE_LIMIT_NONE ||
           s_cap_ridx != WIFI_MGMR_RATE_LIMIT_NONE ||
           s_sgi_tx_disabled;
}

static inline uint8_t *rc_entry(uint8_t sta_idx)
{
    return &sta_stats[(uint32_t)sta_idx * RC_STA_STATS_SIZEOF];
}

static inline uint16_t rc_rd16(uint8_t *p)
{
    return *(volatile uint16_t *)p;
}

static inline void rc_wr16(uint8_t *p, uint16_t v)
{
    *(volatile uint16_t *)p = v;
}

/* Clamp one rate word to the configured caps. Word layout (from rc.o):
 * bits 13:11 = format (0/1 legacy, 2/3 HT), bit 9 = short GI (HT),
 * HT: bits 2:0 = MCS, legacy: bits 6:0 = rate index. */
static uint16_t rc_cap_rate_word(uint16_t cfg)
{
    uint8_t format = (cfg >> 11) & 0x7;

    if (format >= 2) {
        if (s_sgi_tx_disabled) {
            cfg &= ~(uint16_t)0x200;
        }
        if (s_cap_mcs != WIFI_MGMR_RATE_LIMIT_NONE && (cfg & 0x7) > s_cap_mcs) {
            cfg = (cfg & ~(uint16_t)0x7) | s_cap_mcs;
        }
    } else {
        if (s_cap_ridx != WIFI_MGMR_RATE_LIMIT_NONE && (cfg & 0x7f) > s_cap_ridx) {
            cfg = (cfg & ~(uint16_t)0x7f) | s_cap_ridx;
        }
    }
    return cfg;
}

/* The bounds only constrain rates the sampler generates from now on.
 * Entries already in the sample table can sit above the cap (rc_init seeds
 * the highest rate_map MCS regardless of mcs_max, and table rebuilds keep
 * the two best-throughput rates), and on a good link such an entry keeps
 * winning forever. Rewrite them in place to a capped rate and reset their
 * stats so the retry chain re-converges below the cap within a few rate
 * control windows. */
static void rc_cap_sample_table(uint8_t *st)
{
    uint16_t n = rc_rd16(st + RC_OFF_NO_SAMPLES);
    uint16_t i;

    if (n > RC_MAX_N_SAMPLE) {
        n = RC_MAX_N_SAMPLE;
    }
    for (i = 0; i < n; i++) {
        uint8_t *e = st + RC_OFF_RATE_STATS + i * RC_ENTRY_SIZEOF;
        uint16_t cfg = rc_rd16(e + RC_ENTRY_OFF_RATE_CFG);
        uint16_t capped = rc_cap_rate_word(cfg);

        if (capped != cfg) {
            rc_wr16(e + RC_ENTRY_OFF_RATE_CFG, capped);
            rc_wr16(e + RC_ENTRY_OFF_ATTEMPTS, 0);
            rc_wr16(e + RC_ENTRY_OFF_SUCCESS, 0);
            rc_wr16(e + RC_ENTRY_OFF_PROB, 0);
        }
    }
}

/* Clamp (or restore) the VIF's negotiated HT MCS mask that
 * me_update_buffer_control() derives mcs_max / rate_map.ht from. */
static void rc_cap_vif_mcs_mask(uint8_t sta_idx)
{
    uint8_t vif = sta_info_tab[(uint32_t)sta_idx * STA_INFO_TAG_SIZEOF + STA_INFO_OFF_VIF_IDX];
    uint8_t *mask;
    uint8_t capped;

    if (vif >= VIF_MAX) {
        return;
    }
    mask = &vif_info_tab[(uint32_t)vif * VIF_INFO_TAG_SIZEOF + VIF_INFO_OFF_HT_MCS_MASK];

    if (!s_orig_vif_valid[vif]) {
        s_orig_vif_mask[vif] = *mask;
        s_orig_vif_valid[vif] = 1;
    }

    if (s_cap_mcs != WIFI_MGMR_RATE_LIMIT_NONE) {
        capped = s_orig_vif_mask[vif] & (uint8_t)((2u << s_cap_mcs) - 1);
        if (capped == 0) {
            capped = 0x01; /* never leave the mask empty: keep MCS0 */
        }
    } else {
        capped = s_orig_vif_mask[vif];
    }
    *mask = capped;
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
        s_orig_sgi[sta_idx] = st[RC_OFF_SHORT_GI];
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
    st[RC_OFF_SHORT_GI] = s_sgi_tx_disabled ? 0 : s_orig_sgi[sta_idx];

    if (rate_limit_active()) {
        rc_cap_sample_table(st);
    }

    /* keep me_update_buffer_control() from reverting the MCS clamp */
    rc_cap_vif_mcs_mask(sta_idx);

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
        rc_cap_vif_mcs_mask(sta_idx); /* caps cleared: restores the mask */
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

int wifi_mgmr_rate_limit_sgi_tx(uint8_t enable)
{
    s_sgi_tx_disabled = enable ? 0 : 1;
    return wifi_mgmr_rate_limit_apply_sta(wifi_hw.sta_idx);
}

void wifi_mgmr_rate_limit_connected_ind(void)
{
    /* rc_init has just rebuilt the bounds for the new association and the
     * connection state machine rewrote the VIF's BSS info: the old
     * snapshots are stale and the caps (if any) must be applied again. */
    memset(s_orig_valid, 0, sizeof(s_orig_valid));
    memset(s_orig_vif_valid, 0, sizeof(s_orig_vif_valid));

    if (rate_limit_active()) {
        wifi_mgmr_rate_limit_apply_sta(wifi_hw.sta_idx);
        bl_os_printf("[RC] rate limit applied: max MCS %u, max legacy ridx %u, TX SGI %s\r\n",
                s_cap_mcs, s_cap_ridx, s_sgi_tx_disabled ? "off" : "on");
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

int wifi_mgmr_rate_limit_sgi_tx(uint8_t enable)
{
    (void)enable;
    return -1;
}

void wifi_mgmr_rate_limit_connected_ind(void)
{
}

#endif /* CFG_CHIP_BL602 */
