/*
 * detritus.c -- Event-driven memory manager for Linux
 *
 * Licensed under the Apache License, Version 2.0.
 *
 * Architecture
 * ------------
 * ZRAM is a finite compressed buffer, not a second RAM. Pages enter it
 * through kswapd (swappiness) and through process_madvise(MADV_PAGEOUT).
 * Pages leave it only when something faults them back, the owning
 * mapping dies, or userspace prefaults them. A daemon that only feeds
 * ZRAM will fill it over days of a long-lived browser and then the
 * machine dies the same death it was built to prevent.
 *
 * Five verbs, one process. The name is the policy: detritus is thrown
 * overboard. Compression is a delay, not a destination.
 *
 *   Observe  (2s)   Snapshot MemAvailable, PSI, ZRAM mm_stat, and a
 *                   pre-ranked victim list. Never on the PSI path.
 *
 *   Nudge    (400ms) MADV_COLD on the coldest stable process. Armed only
 *                   when RAM is tightening AND ZRAM has headroom.
 *
 *   Drain    (400ms) MADV_WILLNEED on processes that hold swap. Armed
 *                   when ZRAM is occupied AND MemAvailable covers one
 *                   drain chunk. Not gated on a 800 MiB comfort line.
 *
 *   Freeze   (PSI)  SIGSTOP + trickle MADV_PAGEOUT. Reversible. Only
 *                   when ZRAM still has room — paging into a full device
 *                   cannot help, and a frozen process still owns its
 *                   swap slots.
 *
 *   Discard         SIGKILL. The only verb that frees ZRAM slots and RSS
 *                   of a process that will not unmap them. Fired when
 *                   freeze cannot work: ZRAM at cap, PSI while already
 *                   frozen, or a freeze that has not cleared pressure
 *                   within the grace window. This is detritus.
 *
 * A governor sits on top and writes vm.swappiness only when the value
 * must change. High ZRAM occupancy drops swappiness so kswapd stops
 * being a silent fill pump.
 *
 * Victim ranking:
 *   - kernel Referenced/Rss coldness
 *   - two-pass growth exclusion
 * Growing processes are the pressure source. They are never COLD,
 * PAGEOUT, or discard targets — killing the tab the user is watching
 * is the opposite of keeping the session alive.
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <syslog.h>

/* ── Tunables ──────────────────────────────────────────────────────────── */

#define PSI_THRESHOLD_US     5000
#define PSI_WINDOW_US      200000

#define MIN_VICTIM_RSS_KB  (50 * 1024)
#define RSS_GROWTH_KB      (5 * 1024)     /* exclude >5 MiB growth / 150ms */

#define ZRAM_RATIO_SLOW    0.40
#define ZRAM_RATIO_FAST    0.10

#define SCAN_INTERVAL_MS         2000
#define WORKER_INTERVAL_MS        400
#define SCAN_EVERY_N_CYCLES         5     /* 5 * 400ms = 2s */

/*
 * Memory watermarks are computed from MemTotal at start
 * (init_watermarks). Hard 400/800 MiB constants made drain unreachable
 * on a 2 GiB laptop: Chrome keeps MemAvailable under 800 MiB for the
 * whole session, so the governor sat in HOLD and discarded the browser
 * instead of WILLNEED-ing ZRAM back.
 */

/*
 * ZRAM occupancy is orig_data_size / disksize. Nudge must stop well
 * before the device is full; drain starts once anything material is
 * sitting in it and RAM can take it back.
 */
#define ZRAM_NUDGE_MAX_PCT     50
#define ZRAM_DRAIN_MIN_PCT     20
#define ZRAM_CAP_PCT           80

#define TRICKLE_CHUNK_BYTES           (2 * 1024 * 1024)
#define TRICKLE_FILL_CALM_KB_PER_SEC  (5 * 1024)
#define TRICKLE_COLDNESS_FLOOR        15

#define SWAPPINESS_IDLE     "20"
#define SWAPPINESS_NUDGE    "80"
#define SWAPPINESS_HOLD     "10"
#define SWAPPINESS_FROZEN  "100"
#define SWAPPINESS_DRAIN    "20"

/*
 * Freeze is a grace, not a home. If pressure has not cleared after
 * this many seconds, the frozen process is discarded. Same window
 * applies to MODE_HOLD: ZRAM is full, RAM is tight, nothing to drain
 * into — discard the coldest eligible process.
 *
 * Cooldown stops a single PSI storm from killing the whole session
 * in one second. After a kill we wait to see whether the slots we
 * freed were enough.
 */
#define DISCARD_GRACE_S        30
#define DISCARD_COOLDOWN_S     15

/* ── Logging ───────────────────────────────────────────────────────────── */

static void rp_log(int pri, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsyslog(pri, fmt, ap);
    va_end(ap);
    char ts[32];
    time_t now = time(NULL);
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));
    fprintf(stderr, "[detritusd %s] ", ts);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* ── Notification ──────────────────────────────────────────────────────── */

static void notify_user(const char *summary, const char *body)
{
    const char *nu   = getenv("DETRITUS_NOTIFY_USER");
    const char *disp = getenv("DISPLAY");
    const char *dbus = getenv("DBUS_SESSION_BUS_ADDRESS");
    if (!disp || !disp[0]) disp = ":0";

    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        if (nu && nu[0]) {
            char cmd[1024];
            snprintf(cmd, sizeof(cmd),
                "DISPLAY=%s%s%s notify-send -u critical -t 0 '%s' '%s'",
                disp,
                dbus && dbus[0] ? " DBUS_SESSION_BUS_ADDRESS=" : "",
                dbus && dbus[0] ? dbus : "",
                summary, body);
            execl("/bin/su", "su", "-s", "/bin/sh", nu, "-c", cmd, (char *)NULL);
        } else {
            setenv("DISPLAY", disp, 1);
            execl("/usr/bin/notify-send", "notify-send",
                  "-u", "critical", "-t", "0", summary, body, (char *)NULL);
        }
        _exit(1);
    }
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    nanosleep(&ts, NULL);
    waitpid(pid, NULL, WNOHANG);
}

/* ── Storage + ZRAM ────────────────────────────────────────────────────── */

typedef enum {
    STORAGE_HDD, STORAGE_EMMC, STORAGE_NVME, STORAGE_SSD, STORAGE_UNKNOWN
} storage_type_t;

static storage_type_t g_storage_type = STORAGE_UNKNOWN;
static int g_zram_idx = -1;

static long g_mem_total_kb = 0;
static long g_mem_floor_kb = 96 * 1024;
static long g_mem_tight_kb = 128 * 1024;
static long g_mem_drain_floor_kb = 64 * 1024;

static const char *storage_type_name(storage_type_t t)
{
    switch (t) {
        case STORAGE_HDD:  return "hdd";
        case STORAGE_EMMC: return "emmc";
        case STORAGE_NVME: return "nvme";
        case STORAGE_SSD:  return "ssd";
        default:           return "unknown";
    }
}

static int storage_is_slow(storage_type_t t)
{
    return t == STORAGE_HDD || t == STORAGE_EMMC;
}

static storage_type_t detect_storage(void)
{
    DIR *d = opendir("/sys/block");
    if (!d) return STORAGE_EMMC;
    storage_type_t result = STORAGE_UNKNOWN;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strncmp(ent->d_name, "mmcblk", 6) == 0) {
            result = STORAGE_EMMC;
            rp_log(LOG_INFO, "storage: eMMC (%s)", ent->d_name);
            break;
        }
        if (strncmp(ent->d_name, "nvme", 4) == 0) {
            result = STORAGE_NVME;
            rp_log(LOG_INFO, "storage: NVMe (%s)", ent->d_name);
            continue;
        }
        if (strlen(ent->d_name) > 200) continue;
        char path[256];
        snprintf(path, sizeof(path), "/sys/block/%s/queue/rotational", ent->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        int rot = 0;
        if (fscanf(f, "%d", &rot) != 1) rot = 0;
        fclose(f);
        if (rot) {
            result = STORAGE_HDD;
            rp_log(LOG_INFO, "storage: HDD (%s)", ent->d_name);
            break;
        } else if (result == STORAGE_UNKNOWN) {
            result = STORAGE_SSD;
        }
    }
    closedir(d);
    if (result == STORAGE_UNKNOWN) result = STORAGE_SSD;
    rp_log(LOG_INFO, "storage type: %s (%s)", storage_type_name(result),
           storage_is_slow(result) ? "slow" : "fast");
    return result;
}

static long read_memtotal_kb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char line[128];
    long v = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            if (sscanf(line + 9, "%ld", &v) != 1) v = -1;
            break;
        }
    }
    fclose(f);
    return v;
}

static long read_memavailable_kb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 0;
    char line[128];
    long v = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MemAvailable:", 13) == 0) {
            sscanf(line + 13, "%ld", &v);
            break;
        }
    }
    fclose(f);
    return v;
}

static void init_watermarks(void)
{
    long total = read_memtotal_kb();
    if (total < 256 * 1024) total = 256 * 1024;
    g_mem_total_kb = total;

    /* PSI ghost / freeze-resume. 8% of RAM, clamped 64–200 MiB. */
    g_mem_floor_kb = total * 8 / 100;
    if (g_mem_floor_kb < 64 * 1024) g_mem_floor_kb = 64 * 1024;
    if (g_mem_floor_kb > 200 * 1024) g_mem_floor_kb = 200 * 1024;

    /* Nudge threshold. 15% of RAM, clamped 96–400 MiB. */
    g_mem_tight_kb = total * 15 / 100;
    if (g_mem_tight_kb < 96 * 1024) g_mem_tight_kb = 96 * 1024;
    if (g_mem_tight_kb > 400 * 1024) g_mem_tight_kb = 400 * 1024;

    /* Drain needs one trickle chunk of headroom, not half the machine. */
    g_mem_drain_floor_kb = 48 * 1024;
    if (g_mem_drain_floor_kb > g_mem_floor_kb)
        g_mem_drain_floor_kb = g_mem_floor_kb;

    rp_log(LOG_INFO,
           "watermarks: total=%ld MiB floor=%ld tight=%ld drain_floor=%ld",
           total / 1024, g_mem_floor_kb / 1024,
           g_mem_tight_kb / 1024, g_mem_drain_floor_kb / 1024);
}

static void write_proc_sys(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        rp_log(LOG_WARNING, "cannot open %s", path);
        return;
    }
    ssize_t len = (ssize_t)strlen(value);
    if (write(fd, value, (size_t)len) != len)
        rp_log(LOG_WARNING, "write %s failed", path);
    else
        rp_log(LOG_INFO, "  %s = %s", path, value);
    close(fd);
}

static void disable_zswap(void)
{
    const char *zswap_enabled = "/sys/module/zswap/parameters/enabled";
    if (access(zswap_enabled, F_OK) != 0) return;
    FILE *f = fopen(zswap_enabled, "r");
    if (f) {
        char cur[8] = {0};
        if (fgets(cur, sizeof(cur), f) && cur[0] == 'N') {
            fclose(f);
            rp_log(LOG_INFO, "zswap already disabled");
            return;
        }
        fclose(f);
    }
    write_proc_sys(zswap_enabled, "N");
    rp_log(LOG_INFO, "disabled zswap -- zram is the sole compression layer");
}

static int parse_existing_zram_idx(void)
{
    FILE *sw = fopen("/proc/swaps", "r");
    if (!sw) return -1;
    char line[256];
    int idx = -1;
    while (fgets(line, sizeof(line), sw)) {
        char dev[128] = {0};
        if (sscanf(line, "%127s", dev) != 1) continue;
        if (sscanf(dev, "/dev/zram%d", &idx) == 1) break;
        idx = -1;
    }
    fclose(sw);
    return idx;
}

static void provision_zram(int slow)
{
    int existing = parse_existing_zram_idx();
    if (existing >= 0) {
        g_zram_idx = existing;
        rp_log(LOG_INFO, "ZRAM already active -- using zram%d", g_zram_idx);
        return;
    }

    long memtotal_kb = read_memtotal_kb();
    if (memtotal_kb <= 0) {
        rp_log(LOG_WARNING, "cannot read MemTotal");
        return;
    }
    double ratio = slow ? ZRAM_RATIO_SLOW : ZRAM_RATIO_FAST;
    long zram_mb = (long)((double)memtotal_kb / 1024.0 * ratio);
    rp_log(LOG_INFO, "provisioning ZRAM: %ld MB (%s)", zram_mb,
           storage_type_name(g_storage_type));

    if (access("/sys/block/zram0", F_OK) != 0) {
        if (system("/sbin/modprobe zram 2>/dev/null") != 0)
            rp_log(LOG_INFO, "modprobe zram non-zero (may be built-in)");
        int waited = 0;
        while (access("/sys/block/zram0", F_OK) != 0 && waited < 20) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L };
            nanosleep(&ts, NULL);
            waited++;
        }
        if (access("/sys/block/zram0", F_OK) != 0) {
            rp_log(LOG_ERR, "zram0 did not appear");
            return;
        }
    }

    int zram_idx = -1;
    FILE *hot = fopen("/sys/class/zram-control/hot_add", "r");
    if (hot) {
        if (fscanf(hot, "%d", &zram_idx) != 1) zram_idx = -1;
        fclose(hot);
    }
    if (zram_idx < 0) {
        for (int i = 0; i <= 8; i++) {
            char dp[64];
            snprintf(dp, sizeof(dp), "/sys/block/zram%d/disksize", i);
            FILE *dsf = fopen(dp, "r");
            if (!dsf) continue;
            long ds = 0;
            if (fscanf(dsf, "%ld", &ds) != 1) ds = -1;
            fclose(dsf);
            if (ds == 0) {
                zram_idx = i;
                break;
            }
        }
    }
    if (zram_idx < 0) {
        rp_log(LOG_ERR, "no free zram device");
        return;
    }

    char devpath[32];
    snprintf(devpath, sizeof(devpath), "/dev/zram%d", zram_idx);
    char size_path[64];
    snprintf(size_path, sizeof(size_path), "/sys/block/zram%d/disksize", zram_idx);
    FILE *sz = fopen(size_path, "w");
    if (!sz) {
        rp_log(LOG_ERR, "cannot write %s: %s", size_path, strerror(errno));
        return;
    }
    fprintf(sz, "%ldM", zram_mb);
    fclose(sz);

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "mkswap %s >/dev/null 2>&1", devpath);
    if (system(cmd) != 0) {
        rp_log(LOG_ERR, "mkswap %s failed", devpath);
        return;
    }
    snprintf(cmd, sizeof(cmd), "swapon -p 100 %s >/dev/null 2>&1", devpath);
    if (system(cmd) != 0) {
        rp_log(LOG_ERR, "swapon %s failed", devpath);
        return;
    }
    g_zram_idx = zram_idx;
    rp_log(LOG_INFO, "ZRAM active: %s (%ld MB)", devpath, zram_mb);
}

static void disable_partition_swap(void)
{
    FILE *sw = fopen("/proc/swaps", "r");
    if (!sw) return;
    char line[256];
    if (!fgets(line, sizeof(line), sw)) {
        fclose(sw);
        return;
    }
    while (fgets(line, sizeof(line), sw)) {
        if (strstr(line, "zram")) continue;
        if (!strstr(line, "partition")) continue;
        char dev[128] = {0};
        if (sscanf(line, "%127s", dev) == 1 && dev[0] == '/') {
            char cmd[160];
            snprintf(cmd, sizeof(cmd), "swapoff %s 2>/dev/null", dev);
            if (system(cmd) == 0)
                rp_log(LOG_INFO, "disabled partition swap: %s", dev);
        }
    }
    fclose(sw);
}

static void tune_vm_initial(void)
{
    rp_log(LOG_INFO, "tuning VM for ZRAM:");
    write_proc_sys("/proc/sys/vm/page-cluster", "0");
    write_proc_sys("/proc/sys/vm/swappiness", SWAPPINESS_IDLE);
    write_proc_sys("/proc/sys/vm/vfs_cache_pressure", "50");
    disable_partition_swap();
}

typedef struct {
    long disk_bytes;
    long orig_bytes;
    long compr_bytes;
    long mem_used_bytes;
    int  occupancy_pct;
} zram_stat_t;

static zram_stat_t read_zram_stat(void)
{
    zram_stat_t z = {0, 0, 0, 0, 0};
    if (g_zram_idx < 0) return z;

    char path[64];
    snprintf(path, sizeof(path), "/sys/block/zram%d/disksize", g_zram_idx);
    FILE *df = fopen(path, "r");
    if (df) {
        if (fscanf(df, "%ld", &z.disk_bytes) != 1) z.disk_bytes = 0;
        fclose(df);
    }

    snprintf(path, sizeof(path), "/sys/block/zram%d/mm_stat", g_zram_idx);
    FILE *mf = fopen(path, "r");
    if (mf) {
        /* orig_data_size compr_data_size mem_used_total ... */
        if (fscanf(mf, "%ld %ld %ld", &z.orig_bytes, &z.compr_bytes, &z.mem_used_bytes) < 1) {
            z.orig_bytes = z.compr_bytes = z.mem_used_bytes = 0;
        }
        fclose(mf);
    }

    if (z.disk_bytes > 0)
        z.occupancy_pct = (int)((z.orig_bytes * 100) / z.disk_bytes);
    if (z.occupancy_pct < 0) z.occupancy_pct = 0;
    if (z.occupancy_pct > 100) z.occupancy_pct = 100;
    return z;
}

/* ── Shared snapshot ───────────────────────────────────────────────────── */

#define MAX_CANDIDATES 8

typedef struct {
    pid_t pid;
    long  rss_kb;
    long  swap_kb;
    char  name[64];
    int   coldness_pct;
} candidate_t;

typedef enum {
    MODE_IDLE,
    MODE_NUDGE,
    MODE_DRAIN,
    MODE_HOLD,
    MODE_FROZEN
} pager_mode_t;

static const char *mode_name(pager_mode_t m)
{
    switch (m) {
        case MODE_NUDGE:  return "nudge";
        case MODE_DRAIN:  return "drain";
        case MODE_HOLD:   return "hold";
        case MODE_FROZEN: return "frozen";
        default:          return "idle";
    }
}

static candidate_t      g_candidates[MAX_CANDIDATES];
static int              g_n_candidates = 0;
static pthread_mutex_t  g_cand_lock = PTHREAD_MUTEX_INITIALIZER;

static pid_t            g_frozen_pid = -1;
static char             g_frozen_name[64] = {0};
static time_t           g_frozen_since = 0;
static pthread_mutex_t  g_frozen_lock = PTHREAD_MUTEX_INITIALIZER;

static time_t           g_hold_since = 0;
static time_t           g_last_discard = 0;
static char             g_last_discard_name[64] = {0};
static pthread_mutex_t  g_discard_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned long    g_trickle_bytes_interval = 0;
static pthread_mutex_t  g_trickle_lock = PTHREAD_MUTEX_INITIALIZER;

static pager_mode_t     g_mode = MODE_IDLE;
static zram_stat_t      g_zram;
static pthread_mutex_t  g_gov_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *SKIP_NAMES[] = {
    "Xorg",
    "marco", "xfwm4", "kwin_x11", "kwin_wayland", "mutter",
    "mate-panel", "mate-settings-d",
    "mate-session", "nemo-desktop",
    "rookshell",
    "pipewire", "pipewire-pulse", "wireplumber",
    "ibus-daemon", "fcitx", "fcitx5",
    "detritusd", "rookpager",
    "oom_drill", "stress", "stress-ng",
    NULL
};

static int is_skip(const char *name)
{
    for (int i = 0; SKIP_NAMES[i]; i++)
        if (strcmp(name, SKIP_NAMES[i]) == 0) return 1;
    return 0;
}

static long lookup_notify_uid(void)
{
    const char *notify_user = getenv("DETRITUS_NOTIFY_USER");
    if (!notify_user || !notify_user[0]) return -1;
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "id -u %s 2>/dev/null", notify_user);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    long uid = -1;
    if (fscanf(p, "%ld", &uid) != 1) uid = -1;
    pclose(p);
    return uid;
}

/* Rss, Referenced, Swap from smaps_rollup. Returns 0 on success. */
static int read_smaps_rollup(pid_t pid, long *rss_kb, long *referenced_kb, long *swap_kb)
{
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/smaps_rollup", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    *rss_kb = -1;
    *referenced_kb = -1;
    *swap_kb = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Rss:", 4) == 0)
            sscanf(line + 4, "%ld", rss_kb);
        else if (strncmp(line, "Referenced:", 11) == 0)
            sscanf(line + 11, "%ld", referenced_kb);
        else if (strncmp(line, "Swap:", 5) == 0)
            sscanf(line + 5, "%ld", swap_kb);
    }
    fclose(f);
    return (*rss_kb >= 0 && *referenced_kb >= 0) ? 0 : -1;
}

static double current_psi_some(unsigned long long *total_out)
{
    FILE *f = fopen("/proc/pressure/memory", "r");
    if (!f) return -1.0;
    double avg10 = -1.0;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "some", 4) == 0) {
            unsigned long long total = 0;
            sscanf(line, "some avg10=%lf avg60=%*f avg300=%*f total=%llu",
                   &avg10, &total);
            if (total_out) *total_out = total;
            break;
        }
    }
    fclose(f);
    return avg10;
}

static unsigned long long read_psi_total(void)
{
    unsigned long long total = 0;
    current_psi_some(&total);
    return total;
}

/* ── Status file (Gonzo contract, schema_version 1, additive fields) ── */

#define DETRITUS_STATUS_DIR  "/run/detritus"
#define DETRITUS_STATUS_PATH DETRITUS_STATUS_DIR "/status.json"
#define DETRITUS_SCHEMA_VERSION 1
#define GONZOCACHE_PRELOADED_LIST "/var/lib/gonzocache/preloaded.list"

static long read_gonzocache_resident_kb(void)
{
    FILE *lf = fopen(GONZOCACHE_PRELOADED_LIST, "r");
    if (!lf) return 0;
    long total_resident_kb = 0;
    char line[256];
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    while (fgets(line, sizeof(line), lf)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        if (line[0] == '\0') continue;
        int fd = open(line, O_RDONLY);
        if (fd < 0) continue;
        struct stat st;
        if (fstat(fd, &st) != 0 || st.st_size == 0) {
            close(fd);
            continue;
        }
        size_t file_len = (size_t)st.st_size;
        void *map = mmap(NULL, file_len, PROT_READ, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) {
            close(fd);
            continue;
        }
        size_t n_pages = (file_len + page_size - 1) / page_size;
        unsigned char *vec = malloc(n_pages);
        if (vec) {
            if (mincore(map, file_len, vec) == 0) {
                size_t resident_pages = 0;
                for (size_t i = 0; i < n_pages; i++)
                    if (vec[i] & 1) resident_pages++;
                total_resident_kb += (long)(resident_pages * page_size / 1024);
            }
            free(vec);
        }
        munmap(map, file_len);
        close(fd);
    }
    fclose(lf);
    return total_resident_kb;
}

static void write_status_file(void)
{
    static int dir_ready = 0;
    if (!dir_ready) {
        mkdir(DETRITUS_STATUS_DIR, 0755);
        chmod(DETRITUS_STATUS_DIR, 0755);
        dir_ready = 1;
    }

    char tmp_path[64];
    snprintf(tmp_path, sizeof(tmp_path), DETRITUS_STATUS_DIR "/.status.XXXXXX");
    int fd = mkstemp(tmp_path);
    if (fd < 0) return;
    fchmod(fd, 0644);
    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(tmp_path);
        return;
    }

    unsigned long long psi_total = 0;
    double psi_avg10 = current_psi_some(&psi_total);
    long memtotal_kb = read_memtotal_kb();
    long mem_avail_kb = read_memavailable_kb();

    static long prev_mem_avail_kb = -1;
    static time_t prev_sample_time = 0;
    time_t now = time(NULL);
    double mem_rate_kb_per_sec = 0.0;
    if (prev_mem_avail_kb >= 0 && now > prev_sample_time) {
        long delta_kb = mem_avail_kb - prev_mem_avail_kb;
        time_t delta_sec = now - prev_sample_time;
        mem_rate_kb_per_sec = (double)labs(delta_kb) / (double)delta_sec;
    }
    prev_mem_avail_kb = mem_avail_kb;
    prev_sample_time = now;

    pthread_mutex_lock(&g_frozen_lock);
    pid_t frozen_pid = g_frozen_pid;
    char frozen_name[64];
    memcpy(frozen_name, g_frozen_name, sizeof(frozen_name));
    pthread_mutex_unlock(&g_frozen_lock);

    pthread_mutex_lock(&g_trickle_lock);
    unsigned long trickle_bytes = g_trickle_bytes_interval;
    g_trickle_bytes_interval = 0;
    pthread_mutex_unlock(&g_trickle_lock);

    pthread_mutex_lock(&g_gov_lock);
    pager_mode_t mode = g_mode;
    zram_stat_t zram = g_zram;
    pthread_mutex_unlock(&g_gov_lock);

    pthread_mutex_lock(&g_cand_lock);
    candidate_t cand[MAX_CANDIDATES];
    int n_cand = g_n_candidates;
    memcpy(cand, g_candidates, sizeof(candidate_t) * (size_t)n_cand);
    pthread_mutex_unlock(&g_cand_lock);

    long gonzocache_resident_kb = read_gonzocache_resident_kb();

    fprintf(f,
        "{\n"
        "  \"schema_version\": %d,\n"
        "  \"timestamp_unix\": %ld,\n"
        "  \"psi_avg10\": %.3f,\n"
        "  \"psi_total_us\": %llu,\n"
        "  \"trickle_bytes_interval\": %lu,\n"
        "  \"mem_rate_kb_per_sec\": %.1f,\n"
        "  \"gonzocache_resident_kb\": %ld,\n"
        "  \"mem_total_kb\": %ld,\n"
        "  \"mem_available_kb\": %ld,\n"
        "  \"storage_type\": \"%s\",\n"
        "  \"mode\": \"%s\",\n"
        "  \"zram_disk_kb\": %ld,\n"
        "  \"zram_orig_kb\": %ld,\n"
        "  \"zram_compr_kb\": %ld,\n"
        "  \"zram_occupancy_pct\": %d,\n"
        "  \"frozen\": %s,\n",
        DETRITUS_SCHEMA_VERSION, (long)now,
        psi_avg10 >= 0 ? psi_avg10 : 0.0, psi_total,
        trickle_bytes, mem_rate_kb_per_sec, gonzocache_resident_kb,
        memtotal_kb, mem_avail_kb, storage_type_name(g_storage_type),
        mode_name(mode),
        zram.disk_bytes / 1024, zram.orig_bytes / 1024, zram.compr_bytes / 1024,
        zram.occupancy_pct,
        frozen_pid > 0 ? "true" : "false");

    pthread_mutex_lock(&g_discard_lock);
    char last_discard_name[64];
    memcpy(last_discard_name, g_last_discard_name, sizeof(last_discard_name));
    pthread_mutex_unlock(&g_discard_lock);

    if (frozen_pid > 0)
        fprintf(f, "  \"frozen_pid\": %d,\n  \"frozen_name\": \"%s\",\n",
                (int)frozen_pid, frozen_name);
    if (last_discard_name[0])
        fprintf(f, "  \"last_discard_name\": \"%s\",\n", last_discard_name);

    fprintf(f, "  \"candidates\": [\n");
    for (int i = 0; i < n_cand; i++)
        fprintf(f,
            "    { \"pid\": %d, \"name\": \"%s\", \"rss_kb\": %ld, \"coldness_pct\": %d, \"swap_kb\": %ld }%s\n",
            (int)cand[i].pid, cand[i].name, cand[i].rss_kb,
            cand[i].coldness_pct, cand[i].swap_kb,
            (i == n_cand - 1) ? "" : ",");
    fprintf(f, "  ]\n}\n");

    fflush(f);
    fsync(fd);
    fclose(f);
    if (rename(tmp_path, DETRITUS_STATUS_PATH) != 0)
        unlink(tmp_path);
}

/* ── Governor ──────────────────────────────────────────────────────────── */

static void set_swappiness(const char *value)
{
    static char last[8] = {0};
    if (strcmp(last, value) == 0) return;
    write_proc_sys("/proc/sys/vm/swappiness", value);
    strncpy(last, value, sizeof(last) - 1);
}

static pager_mode_t compute_mode(long mem_avail_kb, int zram_pct, int frozen)
{
    if (frozen) return MODE_FROZEN;

    int zram_capped = zram_pct >= ZRAM_CAP_PCT;
    int zram_fat    = zram_pct >= ZRAM_DRAIN_MIN_PCT;
    int zram_room   = zram_pct < ZRAM_NUDGE_MAX_PCT;
    int can_drain   = mem_avail_kb >= g_mem_drain_floor_kb;
    int ram_tight   = mem_avail_kb < g_mem_tight_kb;

    /*
     * HOLD only when the device is actually full AND there is not
     * even a drain-chunk of free RAM. Fat-and-tight used to go
     * straight to HOLD; that is why ZRAM never emptied on 2 GiB.
     */
    if (zram_capped && !can_drain)
        return MODE_HOLD;
    if (zram_fat && can_drain)
        return MODE_DRAIN;
    if (ram_tight && zram_room)
        return MODE_NUDGE;
    return MODE_IDLE;
}

static void apply_governor(long mem_avail_kb, zram_stat_t zram, int frozen)
{
    pager_mode_t mode = compute_mode(mem_avail_kb, zram.occupancy_pct, frozen);

    pthread_mutex_lock(&g_gov_lock);
    pager_mode_t prev = g_mode;
    g_mode = mode;
    g_zram = zram;
    if (mode == MODE_HOLD) {
        if (g_hold_since == 0) g_hold_since = time(NULL);
    } else {
        g_hold_since = 0;
    }
    pthread_mutex_unlock(&g_gov_lock);

    switch (mode) {
        case MODE_NUDGE:  set_swappiness(SWAPPINESS_NUDGE);  break;
        case MODE_DRAIN:  set_swappiness(SWAPPINESS_DRAIN);  break;
        case MODE_HOLD:   set_swappiness(SWAPPINESS_HOLD);   break;
        case MODE_FROZEN: set_swappiness(SWAPPINESS_FROZEN); break;
        default:          set_swappiness(SWAPPINESS_IDLE);   break;
    }

    if (mode != prev)
        rp_log(LOG_INFO, "governor: %s -> %s (MemAvailable=%ld MiB zram=%d%%)",
               mode_name(prev), mode_name(mode),
               mem_avail_kb / 1024, zram.occupancy_pct);
}

/* ── Scanner ───────────────────────────────────────────────────────────── */

#define MAX_SCAN 512

typedef struct {
    pid_t pid;
    long  rss1;
    long  rss2;
    long  uid;
    char  name[64];
} scan_t;

/*
 * Two-pass RSS snapshot (rookpager) plus smaps_rollup coldness/swap
 * (detritusd). Cheap status pass first; smaps_rollup only on survivors.
 * Results stored coldest-first in g_candidates.
 */
static void scanner_refresh(long target_uid)
{
    scan_t *buf = calloc(MAX_SCAN, sizeof(scan_t));
    if (!buf) return;

    int n = 0;
    DIR *pd = opendir("/proc");
    if (pd) {
        struct dirent *ent;
        while ((ent = readdir(pd)) != NULL && n < MAX_SCAN) {
            if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
            if (strlen(ent->d_name) > 7) continue;

            char sp[32];
            snprintf(sp, sizeof(sp), "/proc/%s/status", ent->d_name);
            FILE *sf = fopen(sp, "r");
            if (!sf) continue;
            pid_t pid = 0;
            long uid = -1, rss = 0;
            char name[64] = {0};
            char line[256];
            while (fgets(line, sizeof(line), sf)) {
                if      (strncmp(line, "Pid:", 4) == 0)  sscanf(line + 4, "%d",  &pid);
                else if (strncmp(line, "Uid:", 4) == 0)  sscanf(line + 4, "%ld", &uid);
                else if (strncmp(line, "Name:", 5) == 0) sscanf(line + 5, "%63s", name);
                else if (strncmp(line, "VmRSS:", 6) == 0) sscanf(line + 6, "%ld", &rss);
            }
            fclose(sf);

            if (target_uid >= 0 && uid != target_uid) continue;
            if (rss < MIN_VICTIM_RSS_KB) continue;
            if (is_skip(name)) continue;

            buf[n].pid  = pid;
            buf[n].rss1 = rss;
            buf[n].rss2 = 0;
            buf[n].uid  = uid;
            memcpy(buf[n].name, name, 63);
            buf[n].name[63] = 0;
            n++;
        }
        closedir(pd);
    }

    struct timespec gap = { .tv_sec = 0, .tv_nsec = 150000000L };
    nanosleep(&gap, NULL);

    for (int i = 0; i < n; i++) {
        char sp[32];
        snprintf(sp, sizeof(sp), "/proc/%d/status", buf[i].pid);
        FILE *sf = fopen(sp, "r");
        if (!sf) {
            buf[i].rss2 = -1;
            continue;
        }
        char line[256];
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                sscanf(line + 6, "%ld", &buf[i].rss2);
                break;
            }
        }
        fclose(sf);
    }

    candidate_t local[MAX_CANDIDATES];
    int n_local = 0;

    for (int i = 0; i < n; i++) {
        if (buf[i].rss2 <= 0) continue;
        long growth = buf[i].rss2 - buf[i].rss1;
        if (growth > RSS_GROWTH_KB) {
            rp_log(LOG_INFO, "scanner: excluding '%s' (growing %ld MB/150ms)",
                   buf[i].name, growth / 1024);
            continue;
        }

        long rss_kb = 0, referenced_kb = 0, swap_kb = 0;
        if (read_smaps_rollup(buf[i].pid, &rss_kb, &referenced_kb, &swap_kb) != 0) {
            rss_kb = buf[i].rss2;
            referenced_kb = buf[i].rss2;
            swap_kb = 0;
        }
        if (rss_kb < MIN_VICTIM_RSS_KB) continue;

        int coldness = (rss_kb > 0)
            ? (int)(100 - (referenced_kb * 100 / rss_kb))
            : 0;
        if (coldness < 0) coldness = 0;
        if (coldness > 100) coldness = 100;

        int j = n_local < MAX_CANDIDATES ? n_local : MAX_CANDIDATES - 1;
        if (n_local < MAX_CANDIDATES) n_local++;
        while (j > 0 && local[j - 1].coldness_pct < coldness) {
            if (j < MAX_CANDIDATES) local[j] = local[j - 1];
            j--;
        }
        if (j < MAX_CANDIDATES) {
            local[j].pid = buf[i].pid;
            local[j].rss_kb = rss_kb;
            local[j].swap_kb = swap_kb;
            local[j].coldness_pct = coldness;
            memcpy(local[j].name, buf[i].name, 63);
            local[j].name[63] = 0;
        }
    }

    pthread_mutex_lock(&g_cand_lock);
    memcpy(g_candidates, local, sizeof(local));
    g_n_candidates = n_local;
    pthread_mutex_unlock(&g_cand_lock);

    free(buf);
}

/* ── VMA walk + process_madvise ────────────────────────────────────────── */

typedef struct { uintptr_t start; uintptr_t end; } vma_t;

static int collect_reclaimable_vmas(pid_t pid, vma_t *vmas, int max_vmas)
{
    char maps_path[32];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;
    int nvmas = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && nvmas < max_vmas) {
        uintptr_t start, end, offset;
        unsigned long inode;
        char perms[8] = {0}, dev[16] = {0}, rest[128] = {0};
        if (sscanf(line, "%lx-%lx %7s %lx %15s %lu %127[^\n]",
                   &start, &end, perms, &offset, dev, &inode, rest) < 6)
            continue;
        if (perms[0] != 'r' || perms[1] != 'w' || perms[3] != 'p') continue;
        if (inode != 0 || strcmp(dev, "00:00") != 0) continue;
        char *nm = rest;
        while (*nm == ' ') nm++;
        if (strncmp(nm, "[v", 2) == 0) continue;
        if (end - start < 65536) continue;
        vmas[nvmas].start = start;
        vmas[nvmas].end = end;
        nvmas++;
    }
    fclose(f);
    return nvmas;
}

static void signal_process_tree(pid_t root, int sig)
{
    /*
     * Collect first, then signal. For SIGKILL the parent must die last:
     * killing it first reparents children to init and the ppid walk
     * misses them, leaving renderers alive with the slots we meant to
     * free.
     */
    pid_t kids[256];
    int nkids = 0;
    DIR *pd = opendir("/proc");
    if (pd) {
        struct dirent *ent;
        while ((ent = readdir(pd)) != NULL && nkids < 256) {
            if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
            if (strlen(ent->d_name) > 7) continue;
            char sp[32];
            snprintf(sp, sizeof(sp), "/proc/%s/status", ent->d_name);
            FILE *sf = fopen(sp, "r");
            if (!sf) continue;
            pid_t pid = 0, ppid = 0;
            char line[128];
            while (fgets(line, sizeof(line), sf)) {
                if      (strncmp(line, "Pid:", 4) == 0)  sscanf(line + 4, "%d", &pid);
                else if (strncmp(line, "PPid:", 5) == 0) sscanf(line + 5, "%d", &ppid);
            }
            fclose(sf);
            if (ppid == root && pid > 1) kids[nkids++] = pid;
        }
        closedir(pd);
    }
    if (sig == SIGKILL) {
        for (int i = 0; i < nkids; i++) kill(kids[i], sig);
        if (root > 1) kill(root, sig);
    } else {
        if (root > 1) kill(root, sig);
        for (int i = 0; i < nkids; i++) kill(kids[i], sig);
    }
}

#define PAGEOUT_CHUNK             (256 * 1024)
#define PAGEOUT_YIELD_HIGH_US     100000
#define PAGEOUT_YIELD_MED_US      250000
#define PAGEOUT_YIELD_LOW_US      500000
#define PAGEOUT_STALL_THRESH_US     2000
#define EVAL_STRIDE               (8 * PAGEOUT_CHUNK)
#define IOV_BATCH                          16

static void trickle_pageout_process(pid_t pid, const char *name)
{
    setpriority(PRIO_PROCESS, 0, 19);
    syscall(SYS_ioprio_set, 1, 0, (3 << 13) | 0);

    int pidfd = (int)syscall(SYS_pidfd_open, (long)pid, 0);
    if (pidfd < 0) {
        rp_log(LOG_WARNING, "pidfd_open(%d): %s", pid, strerror(errno));
        goto done;
    }

    vma_t vmas[512];
    int nvmas = collect_reclaimable_vmas(pid, vmas, 512);
    if (nvmas == 0) {
        close(pidfd);
        goto done;
    }

    long total_bytes = 0;
    int chunks = 0;
    long bytes_since_eval = 0;
    int yield_us = PAGEOUT_YIELD_MED_US;
    unsigned long long psi_baseline = read_psi_total();

    {
        long mem_now_kb = read_memavailable_kb();
        if      (mem_now_kb < 400 * 1024) yield_us = PAGEOUT_YIELD_HIGH_US;
        else if (mem_now_kb < 800 * 1024) yield_us = PAGEOUT_YIELD_MED_US;
        else                               yield_us = PAGEOUT_YIELD_LOW_US;
        psi_baseline = read_psi_total();
    }

    for (int i = 0; i < nvmas; i++) {
        uintptr_t cursor = vmas[i].start;
        while (cursor < vmas[i].end) {
            if (bytes_since_eval >= EVAL_STRIDE) {
                unsigned long long psi_now = read_psi_total();
                unsigned long long stall = psi_now - psi_baseline;
                psi_baseline = psi_now;
                bytes_since_eval = 0;

                long mem_now_kb = read_memavailable_kb();
                if      (mem_now_kb < 400 * 1024) yield_us = PAGEOUT_YIELD_HIGH_US;
                else if (mem_now_kb < 800 * 1024) yield_us = PAGEOUT_YIELD_MED_US;
                else                               yield_us = PAGEOUT_YIELD_LOW_US;

                if (stall >= PAGEOUT_STALL_THRESH_US) {
                    if      (yield_us == PAGEOUT_YIELD_HIGH_US) yield_us = PAGEOUT_YIELD_MED_US;
                    else if (yield_us == PAGEOUT_YIELD_MED_US)  yield_us = PAGEOUT_YIELD_LOW_US;
                }
            }

            struct iovec iov[IOV_BATCH];
            int niov = 0;
            size_t batch_len = 0;
            while (niov < IOV_BATCH && cursor < vmas[i].end) {
                size_t len = vmas[i].end - cursor;
                if (len > (size_t)PAGEOUT_CHUNK) len = PAGEOUT_CHUNK;
                iov[niov].iov_base = (void *)cursor;
                iov[niov].iov_len = len;
                niov++;
                cursor += len;
                batch_len += len;
            }

            long ret = syscall(SYS_process_madvise, pidfd, iov, niov, MADV_PAGEOUT, 0);
            if (ret == 0) {
                total_bytes += (long)batch_len;
                bytes_since_eval += (long)batch_len;
                chunks += niov;
            } else if (errno == ENOSYS) {
                rp_log(LOG_WARNING, "process_madvise: needs kernel 5.10+");
                close(pidfd);
                goto done;
            }

            struct timespec ts = {
                .tv_sec  = yield_us / 1000000,
                .tv_nsec = (yield_us % 1000000) * 1000L,
            };
            nanosleep(&ts, NULL);
        }
    }
    close(pidfd);
    rp_log(LOG_INFO, "trickle pageout: %ld MiB of '%s' -> ZRAM  chunks=%d",
           total_bytes / (1024 * 1024), name, chunks);
done:
    setpriority(PRIO_PROCESS, 0, 0);
}

typedef struct { pid_t pid; char name[64]; } pageout_arg_t;
static pageout_arg_t g_pageout_buf;

static void *pageout_thread(void *arg)
{
    pageout_arg_t *a = (pageout_arg_t *)arg;
    trickle_pageout_process(a->pid, a->name);
    return NULL;
}

/* ── Worker: nudge / drain on a 400ms cadence ──────────────────────────── */

static size_t adaptive_chunk_bytes(double fill_rate_kb_per_sec)
{
    if (fill_rate_kb_per_sec <= TRICKLE_FILL_CALM_KB_PER_SEC)
        return TRICKLE_CHUNK_BYTES;
    double multiplier = fill_rate_kb_per_sec / (double)TRICKLE_FILL_CALM_KB_PER_SEC;
    return (size_t)((double)TRICKLE_CHUNK_BYTES * multiplier);
}

static int advise_chunk(pid_t pid, vma_t *vmas, int nvmas,
                        int *vma_idx, uintptr_t *cursor,
                        size_t chunk_ceiling, int advice)
{
    if (*vma_idx >= nvmas) {
        *vma_idx = 0;
        *cursor = (nvmas > 0) ? vmas[0].start : 0;
    }
    if (nvmas == 0) return -1;

    int pidfd = (int)syscall(SYS_pidfd_open, (long)pid, 0);
    if (pidfd < 0) return -1;

    size_t remaining = vmas[*vma_idx].end - *cursor;
    size_t chunk_len = (remaining < chunk_ceiling) ? remaining : chunk_ceiling;
    struct iovec iov = { .iov_base = (void *)(*cursor), .iov_len = chunk_len };
    long ret = syscall(SYS_process_madvise, pidfd, &iov, 1, advice, 0);
    close(pidfd);
    if (ret < 0) return -1;

    *cursor += chunk_len;
    if (*cursor >= vmas[*vma_idx].end) {
        (*vma_idx)++;
        if (*vma_idx < nvmas) *cursor = vmas[*vma_idx].start;
    }
    return (int)chunk_len;
}

static void *worker_thread(void *arg)
{
    (void)arg;
    setpriority(PRIO_PROCESS, 0, 19);
    syscall(SYS_ioprio_set, 1, 0, (3 << 13) | 0);

    long target_uid = lookup_notify_uid();
    struct timespec cycle = {
        .tv_sec  = WORKER_INTERVAL_MS / 1000,
        .tv_nsec = (WORKER_INTERVAL_MS % 1000) * 1000000L,
    };

    pid_t last_pid = -1;
    vma_t vmas[512];
    int nvmas = 0, vma_idx = 0;
    uintptr_t cursor = 0;
    long prev_avail_kb = -1;
    struct timespec prev_sample_ts = {0, 0};
    int cycles_since_scan = SCAN_EVERY_N_CYCLES;

    for (;;) {
        nanosleep(&cycle, NULL);

        long mem_avail_kb = read_memavailable_kb();
        zram_stat_t zram = read_zram_stat();

        pthread_mutex_lock(&g_frozen_lock);
        int frozen = (g_frozen_pid > 0);
        pid_t frozen_pid = g_frozen_pid;
        pthread_mutex_unlock(&g_frozen_lock);

        apply_governor(mem_avail_kb, zram, frozen);

        struct timespec now_ts;
        clock_gettime(CLOCK_MONOTONIC, &now_ts);
        double fill_rate_kb_per_sec = 0.0;
        if (prev_avail_kb >= 0) {
            double elapsed_sec =
                (now_ts.tv_sec - prev_sample_ts.tv_sec) +
                (now_ts.tv_nsec - prev_sample_ts.tv_nsec) / 1e9;
            if (elapsed_sec > 0.01) {
                double delta_kb = (double)(prev_avail_kb - mem_avail_kb);
                if (delta_kb > 0)
                    fill_rate_kb_per_sec = delta_kb / elapsed_sec;
            }
        }
        prev_avail_kb = mem_avail_kb;
        prev_sample_ts = now_ts;

        cycles_since_scan++;
        if (cycles_since_scan >= SCAN_EVERY_N_CYCLES) {
            scanner_refresh(target_uid);
            write_status_file();
            cycles_since_scan = 0;
        }

        pthread_mutex_lock(&g_gov_lock);
        pager_mode_t mode = g_mode;
        pthread_mutex_unlock(&g_gov_lock);

        if (mode != MODE_NUDGE && mode != MODE_DRAIN) {
            last_pid = -1;
            continue;
        }

        pthread_mutex_lock(&g_cand_lock);
        candidate_t pick;
        int have = 0;
        if (mode == MODE_NUDGE) {
            if (g_n_candidates > 0 &&
                g_candidates[0].coldness_pct >= TRICKLE_COLDNESS_FLOOR &&
                g_candidates[0].pid != frozen_pid) {
                pick = g_candidates[0];
                have = 1;
            }
        } else {
            /* Drain: pick the candidate with the most pages already in ZRAM. */
            long best_swap = 0;
            for (int i = 0; i < g_n_candidates; i++) {
                if (g_candidates[i].pid == frozen_pid) continue;
                if (g_candidates[i].swap_kb > best_swap) {
                    pick = g_candidates[i];
                    best_swap = g_candidates[i].swap_kb;
                    have = 1;
                }
            }
        }
        pthread_mutex_unlock(&g_cand_lock);

        if (!have) {
            last_pid = -1;
            continue;
        }

        if (pick.pid != last_pid) {
            nvmas = collect_reclaimable_vmas(pick.pid, vmas, 512);
            vma_idx = 0;
            cursor = (nvmas > 0) ? vmas[0].start : 0;
            last_pid = pick.pid;
            if (nvmas == 0) continue;
        }

        size_t chunk_ceiling = adaptive_chunk_bytes(fill_rate_kb_per_sec);
        int advice = (mode == MODE_NUDGE) ? MADV_COLD : MADV_WILLNEED;
        int n = advise_chunk(pick.pid, vmas, nvmas, &vma_idx, &cursor,
                             chunk_ceiling, advice);
        if (n < 0) {
            last_pid = -1;
            continue;
        }

        pthread_mutex_lock(&g_trickle_lock);
        g_trickle_bytes_interval += (unsigned long)n;
        pthread_mutex_unlock(&g_trickle_lock);
    }
    return NULL;
}

/* ── Discard ────────────────────────────────────────────────────────────── */

static int discard_ready(void)
{
    time_t now = time(NULL);
    pthread_mutex_lock(&g_discard_lock);
    int ok = (g_last_discard == 0 || (now - g_last_discard) >= DISCARD_COOLDOWN_S);
    pthread_mutex_unlock(&g_discard_lock);
    return ok;
}

static void clear_frozen_state(void)
{
    g_frozen_pid = -1;
    g_frozen_name[0] = '\0';
    g_frozen_since = 0;
}

static void discard_pid(pid_t pid, const char *name, const char *reason)
{
    if (pid <= 1) return;
    if (!discard_ready()) {
        rp_log(LOG_INFO, "detritus: cooldown — not killing '%s' yet", name);
        return;
    }

    rp_log(LOG_CRIT, "detritus: SIGKILL '%s' (pid %d) -- %s", name, (int)pid, reason);
    signal_process_tree(pid, SIGKILL);

    pthread_mutex_lock(&g_discard_lock);
    g_last_discard = time(NULL);
    strncpy(g_last_discard_name, name, sizeof(g_last_discard_name) - 1);
    g_last_discard_name[sizeof(g_last_discard_name) - 1] = '\0';
    pthread_mutex_unlock(&g_discard_lock);

    pthread_mutex_lock(&g_frozen_lock);
    if (g_frozen_pid == pid) clear_frozen_state();
    pthread_mutex_unlock(&g_frozen_lock);

    char body[256];
    snprintf(body, sizeof(body), "Discarded %s to reclaim memory.", name);
    notify_user("detritusd", body);
}

static int pick_discard_victim(pid_t *pid_out, char *name_out, size_t name_len)
{
    pthread_mutex_lock(&g_cand_lock);
    int have = 0;
    long best = -1;
    pid_t pid = -1;
    char name[64] = {0};
    /*
     * Prefer the candidate that frees the most (rss + swap) among the
     * already-cold list. The list is coldest-first; we still walk it
     * because a slightly-less-cold process sitting on 400 MiB of ZRAM
     * is more detritus than a colder 60 MiB helper.
     */
    for (int i = 0; i < g_n_candidates; i++) {
        long reclaim = g_candidates[i].rss_kb + g_candidates[i].swap_kb;
        if (reclaim > best) {
            best = reclaim;
            pid = g_candidates[i].pid;
            memcpy(name, g_candidates[i].name, 63);
            name[63] = 0;
            have = 1;
        }
    }
    pthread_mutex_unlock(&g_cand_lock);
    if (!have) return 0;
    *pid_out = pid;
    strncpy(name_out, name, name_len - 1);
    name_out[name_len - 1] = '\0';
    return 1;
}

/* ── Emergency PSI path ────────────────────────────────────────────────── */

static void handle_pressure(void)
{
    double psi = current_psi_some(NULL);
    rp_log(LOG_WARNING, "PSI trigger: avg10=%.2f%%", psi);

    pthread_mutex_lock(&g_frozen_lock);
    int already_frozen = (g_frozen_pid > 0);
    pid_t cur_frozen_pid = g_frozen_pid;
    char cur_frozen_name[64];
    memcpy(cur_frozen_name, g_frozen_name, sizeof(cur_frozen_name));
    pthread_mutex_unlock(&g_frozen_lock);

    long mem_avail_kb = read_memavailable_kb();
    if (mem_avail_kb > g_mem_floor_kb) {
        rp_log(LOG_INFO, "PSI ghost -- MemAvailable=%ld MiB", mem_avail_kb / 1024);
        return;
    }

    zram_stat_t zram = read_zram_stat();

    /*
     * Freeze already failed: the process is stopped and pressure
     * returned anyway. Its slots are still occupied. Kill it.
     */
    if (already_frozen) {
        discard_pid(cur_frozen_pid, cur_frozen_name,
                   "PSI while frozen — compression did not clear pressure");
        return;
    }

    /*
     * ZRAM is full. PAGEOUT has nowhere to go. Freeze would pin the
     * slots we need. Discard is the only verb that frees them.
     */
    if (zram.occupancy_pct >= ZRAM_CAP_PCT) {
        pid_t vpid;
        char vname[64];
        if (!pick_discard_victim(&vpid, vname, sizeof(vname))) {
            rp_log(LOG_ERR, "detritus: ZRAM capped, no victim — kernel OOM killer is next");
            return;
        }
        discard_pid(vpid, vname, "ZRAM at cap under PSI");
        return;
    }

    pthread_mutex_lock(&g_cand_lock);
    pid_t vpid = -1;
    char vname[64] = {0};
    if (g_n_candidates > 0) {
        vpid = g_candidates[0].pid;
        memcpy(vname, g_candidates[0].name, 63);
        vname[63] = 0;
    }
    pthread_mutex_unlock(&g_cand_lock);

    if (vpid < 0) {
        rp_log(LOG_WARNING, "no pre-ranked victim -- nothing to do");
        return;
    }

    char check[32];
    snprintf(check, sizeof(check), "/proc/%d", vpid);
    if (access(check, F_OK) != 0) {
        rp_log(LOG_WARNING, "victim %s gone", vname);
        return;
    }

    rp_log(LOG_WARNING, "SIGSTOP: '%s' (pid %d) zram=%d%%",
           vname, vpid, zram.occupancy_pct);
    signal_process_tree(vpid, SIGSTOP);

    pthread_mutex_lock(&g_frozen_lock);
    g_frozen_pid = vpid;
    memcpy(g_frozen_name, vname, sizeof(g_frozen_name) - 1);
    g_frozen_name[sizeof(g_frozen_name) - 1] = 0;
    g_frozen_since = time(NULL);
    pthread_mutex_unlock(&g_frozen_lock);

    g_pageout_buf.pid = vpid;
    memcpy(g_pageout_buf.name, vname, sizeof(g_pageout_buf.name));
    pthread_t ptid;
    if (pthread_create(&ptid, NULL, pageout_thread, &g_pageout_buf) == 0)
        pthread_detach(ptid);

    char body[256];
    snprintf(body, sizeof(body), "Paused %s to preserve responsiveness.", vname);
    notify_user("detritusd", body);
}

static void maybe_resume_or_discard(void)
{
    pthread_mutex_lock(&g_frozen_lock);
    pid_t frozen_pid = g_frozen_pid;
    char frozen_name[64];
    time_t frozen_since = g_frozen_since;
    memcpy(frozen_name, g_frozen_name, sizeof(frozen_name));
    pthread_mutex_unlock(&g_frozen_lock);

    if (frozen_pid > 0) {
        char check[32];
        snprintf(check, sizeof(check), "/proc/%d", frozen_pid);
        if (access(check, F_OK) != 0) {
            rp_log(LOG_INFO, "frozen process %s gone", frozen_name);
            pthread_mutex_lock(&g_frozen_lock);
            clear_frozen_state();
            pthread_mutex_unlock(&g_frozen_lock);
        } else {
            long mem_avail_kb = read_memavailable_kb();
            rp_log(LOG_INFO, "resume check for %s: MemAvailable=%ld MiB",
                   frozen_name, mem_avail_kb / 1024);

            int should_resume = 0;
            const char *reason = "";
            if (mem_avail_kb > g_mem_floor_kb) {
                should_resume = 1;
                reason = "MemAvailable recovered";
            } else {
                double avg10 = current_psi_some(NULL);
                if (avg10 >= 0.0 && avg10 < 5.0) {
                    should_resume = 1;
                    reason = "avg10 < 5%";
                }
            }

            if (should_resume) {
                rp_log(LOG_INFO, "resuming %s -- %s (%ld MiB free)",
                       frozen_name, reason, mem_avail_kb / 1024);
                signal_process_tree(frozen_pid, SIGCONT);
                notify_user("detritusd", "Memory pressure cleared. Application resumed.");
                pthread_mutex_lock(&g_frozen_lock);
                clear_frozen_state();
                pthread_mutex_unlock(&g_frozen_lock);
            } else if (frozen_since > 0 &&
                       (time(NULL) - frozen_since) >= DISCARD_GRACE_S) {
                discard_pid(frozen_pid, frozen_name,
                           "freeze grace expired — pressure never cleared");
            } else {
                rp_log(LOG_INFO, "keeping %s frozen: %ld MiB free, pressure ongoing",
                       frozen_name, mem_avail_kb / 1024);
            }
        }
    }

    /*
     * HOLD means ZRAM is at cap and RAM is tight. Drain cannot run.
     * Freeze cannot free slots. After the same grace window, discard
     * the fattest cold process even if PSI has not fired again —
     * waiting for another stall is how the week-long death happens.
     */
    pthread_mutex_lock(&g_gov_lock);
    pager_mode_t mode = g_mode;
    time_t hold_since = g_hold_since;
    int zram_pct = g_zram.occupancy_pct;
    pthread_mutex_unlock(&g_gov_lock);

    if (mode == MODE_HOLD && hold_since > 0 &&
        (time(NULL) - hold_since) >= DISCARD_GRACE_S) {
        pid_t vpid;
        char vname[64];
        if (pick_discard_victim(&vpid, vname, sizeof(vname))) {
            char reason[128];
            snprintf(reason, sizeof(reason),
                     "HOLD grace expired (zram=%d%%)", zram_pct);
            discard_pid(vpid, vname, reason);
        }
    }
}

/* ── Main ──────────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_running = 1;
static void sig_handler(int sig) { (void)sig; g_running = 0; }

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    openlog("detritusd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    rp_log(LOG_INFO, "Detritus starting (uid=%d)", (int)getuid());

    if (getuid() != 0) {
        rp_log(LOG_ERR, "must run as root");
        return 1;
    }

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGCHLD, SIG_DFL);

    g_storage_type = detect_storage();
    init_watermarks();
    disable_zswap();
    provision_zram(storage_is_slow(g_storage_type));
    tune_vm_initial();

    {
        const char *critical[] = {
            "Xorg", "marco", "xfwm4", "mate-panel", "mate-settings-daemon",
            "mate-session", "nemo-desktop", "rookshell",
            "pipewire", "pipewire-pulse", "wireplumber",
            "detritusd", NULL
        };
        for (int ci = 0; critical[ci]; ci++) {
            char cmd[160];
            snprintf(cmd, sizeof(cmd),
                "for p in $(pgrep -x '%s' 2>/dev/null); do "
                "  echo -1000 > /proc/$p/oom_score_adj 2>/dev/null; done",
                critical[ci]);
            (void)system(cmd);
        }
        FILE *self_oom = fopen("/proc/self/oom_score_adj", "w");
        if (self_oom) {
            fprintf(self_oom, "-1000\n");
            fclose(self_oom);
        }
        rp_log(LOG_INFO, "OOM immunity set for critical desktop processes");
    }

    pthread_t worker_tid;
    if (pthread_create(&worker_tid, NULL, worker_thread, NULL) != 0) {
        rp_log(LOG_ERR, "pthread_create: %s", strerror(errno));
        return 1;
    }
    pthread_detach(worker_tid);
    rp_log(LOG_INFO, "worker thread started (interval=%dms scan=%dms)",
           WORKER_INTERVAL_MS, SCAN_INTERVAL_MS);

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        rp_log(LOG_ERR, "epoll_create1: %s", strerror(errno));
        return 1;
    }

    int psi_fd = open("/proc/pressure/memory", O_WRONLY | O_NONBLOCK);
    if (psi_fd < 0) {
        rp_log(LOG_ERR, "open PSI fd: %s", strerror(errno));
        return 1;
    }
    char trigger[64];
    int n = snprintf(trigger, sizeof(trigger), "some %d %d\n",
                     PSI_THRESHOLD_US, PSI_WINDOW_US);
    if (write(psi_fd, trigger, n) < 0) {
        rp_log(LOG_ERR, "PSI trigger write: %s", strerror(errno));
        return 1;
    }
    struct epoll_event ev_psi = { .events = EPOLLPRI, .data.fd = psi_fd };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, psi_fd, &ev_psi) < 0) {
        rp_log(LOG_ERR, "epoll_ctl PSI: %s", strerror(errno));
        return 1;
    }
    rp_log(LOG_INFO, "armed: some %d us / %d us", PSI_THRESHOLD_US, PSI_WINDOW_US);

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) {
        rp_log(LOG_ERR, "timerfd_create: %s", strerror(errno));
        return 1;
    }
    struct itimerspec its = {
        .it_interval = { .tv_sec = 5, .tv_nsec = 0 },
        .it_value    = { .tv_sec = 5, .tv_nsec = 0 },
    };
    timerfd_settime(tfd, 0, &its, NULL);
    struct epoll_event ev_timer = { .events = EPOLLIN, .data.fd = tfd };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev_timer) < 0) {
        rp_log(LOG_ERR, "epoll_ctl timerfd: %s", strerror(errno));
        return 1;
    }

    while (g_running) {
        struct epoll_event events[4];
        int nfds = epoll_wait(epfd, events, 4, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            rp_log(LOG_ERR, "epoll_wait: %s", strerror(errno));
            break;
        }
        for (int i = 0; i < nfds; i++) {
            int efd = events[i].data.fd;
            if (efd == psi_fd) {
                handle_pressure();
            } else if (efd == tfd) {
                uint64_t expirations;
                (void)read(tfd, &expirations, sizeof(expirations));
                maybe_resume_or_discard();
            }
        }
    }

    pthread_mutex_lock(&g_frozen_lock);
    pid_t shutdown_frozen_pid = g_frozen_pid;
    char shutdown_frozen_name[64];
    memcpy(shutdown_frozen_name, g_frozen_name, sizeof(shutdown_frozen_name));
    pthread_mutex_unlock(&g_frozen_lock);
    if (shutdown_frozen_pid > 0) {
        rp_log(LOG_INFO, "shutdown -- resuming %s", shutdown_frozen_name);
        signal_process_tree(shutdown_frozen_pid, SIGCONT);
    }
    rp_log(LOG_INFO, "shutting down");
    close(tfd);
    close(psi_fd);
    close(epfd);
    closelog();
    return 0;
}
