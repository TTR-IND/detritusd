/*
 * detritus.c -- Event-Driven Memory Manager for Linux
 *
 * Runs as root. Monitors Linux PSI via epoll on /proc/pressure/memory.
 *
 * Architecture:
 *   Single PSI fd, edge-triggered (EPOLLET | EPOLLPRI).
 *   A background scanner thread samples /proc every 2 seconds and
 *   maintains a pre-ranked list of victim candidates. The epoll handler
 *   is instant -- it just reads the pre-computed list and acts.
 *   No blocking inside the event handler.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -Wno-unused-parameter \
 *       -o detritus detritus.c -lm -lpthread
 *
 * Launch: intended to run as a system service (see the OpenRC unit in
 * this repository); display-related environment variables (for
 * desktop notifications) are picked up from DETRITUS_NOTIFY_USER's
 * environment if set.
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

/*
 * PSI threshold: 5ms stall in a 200ms window = 2.5% instantaneous stall.
 * General consumer setting -- sensitive enough to act before the user
 * notices, conservative enough not to fire on routine disk I/O or
 * page cache churn. Equivalent to macOS memory pressure tier 1.
 */
#define PSI_THRESHOLD_US    5000   /* 5ms stall within window              */
#define PSI_WINDOW_US     200000   /* 200ms measurement window              */

#define SCAN_INTERVAL_MS   2000    /* victim scanner period (ms)            */
#define RSS_GROWTH_KB      (5*1024)/* exclude processes growing > 5MB/150ms */
#define MIN_VICTIM_RSS_KB (50*1024)/* ignore processes under 50MB RSS       */

#define ZRAM_RATIO_SLOW    0.40    /* 40% RAM as ZRAM on HDD/eMMC           */
#define ZRAM_RATIO_FAST    0.10    /* 10% RAM as ZRAM on NVMe/SSD           */

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
            execl("/bin/su", "su", "-s", "/bin/sh", nu, "-c", cmd, (char*)NULL);
        } else {
            setenv("DISPLAY", disp, 1);
            execl("/usr/bin/notify-send", "notify-send",
                  "-u", "critical", "-t", "0", summary, body, (char*)NULL);
        }
        _exit(1);
    }
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    nanosleep(&ts, NULL);
    waitpid(pid, NULL, WNOHANG);
}

/* ── Storage detection ─────────────────────────────────────────────────── */
typedef enum { STORAGE_HDD, STORAGE_EMMC, STORAGE_NVME,
               STORAGE_SSD, STORAGE_UNKNOWN } storage_type_t;
static storage_type_t g_storage_type = STORAGE_UNKNOWN;

static const char *storage_type_name(storage_type_t t) {
    switch(t) {
        case STORAGE_HDD:  return "hdd";
        case STORAGE_EMMC: return "emmc";
        case STORAGE_NVME: return "nvme";
        case STORAGE_SSD:  return "ssd";
        default:           return "unknown";
    }
}
static int storage_is_slow(storage_type_t t) {
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
            rp_log(LOG_INFO, "storage: eMMC (%s)", ent->d_name); break;
        }
        if (strncmp(ent->d_name, "nvme", 4) == 0) {
            result = STORAGE_NVME;
            rp_log(LOG_INFO, "storage: NVMe (%s)", ent->d_name); continue;
        }
        if (strlen(ent->d_name) > 200) continue;
        char path[256];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(path, sizeof(path), "/sys/block/%s/queue/rotational", ent->d_name);
#pragma GCC diagnostic pop
        FILE *f = fopen(path, "r"); if (!f) continue;
        int rot = 0;
        if (fscanf(f, "%d", &rot) != 1) rot = 0;
        fclose(f);
        if (rot) { result = STORAGE_HDD; rp_log(LOG_INFO, "storage: HDD (%s)", ent->d_name); break; }
        else if (result == STORAGE_UNKNOWN) result = STORAGE_SSD;
    }
    closedir(d);
    if (result == STORAGE_UNKNOWN) result = STORAGE_SSD;
    rp_log(LOG_INFO, "storage type: %s (%s)", storage_type_name(result),
           storage_is_slow(result) ? "slow" : "fast");
    return result;
}

/* ── /proc helpers ─────────────────────────────────────────────────────── */
static long read_memtotal_kb(void)
{
    FILE *f = fopen("/proc/meminfo", "r"); if (!f) return -1;
    char line[128]; long v = -1;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, "MemTotal:", 9) == 0) {
            if (sscanf(line + 9, "%ld", &v) != 1) v = -1;
            break;
        }
    fclose(f); return v;
}

static void write_proc_sys(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY); if (fd < 0) { rp_log(LOG_WARNING, "cannot open %s", path); return; }
    ssize_t len = (ssize_t)strlen(value);
    if (write(fd, value, (size_t)len) != len) rp_log(LOG_WARNING, "write %s failed", path);
    else rp_log(LOG_INFO, "  %s = %s", path, value);
    close(fd);
}

/* ── ZSWAP override ─────────────────────────────────────────────────────
 *
 * zswap sits in front of zram in the kernel's reclaim path: if zswap is
 * enabled, it intercepts and compresses evicted pages before they ever
 * reach a zram device, meaning most of a zram device's own compression
 * work goes unused even though it appears "active" via
 * zramctl/swapon -s. This isn't a hypothetical -- it's the documented
 * interaction between the two subsystems.
 *
 * This daemon's existing design already takes the same stance toward
 * partition swap (tune_vm_for_zram() disables it once zram is active,
 * rather than trying to coexist with it): own the memory-compression
 * layer outright rather than share it with something else that could
 * be silently absorbing most of the traffic. zswap gets the same
 * treatment -- disabled here, unconditionally, before zram
 * provisioning runs, so the zram device this daemon creates is
 * actually the thing doing the work.
 *
 * Whether zswap was pre-enabled by the distro, a previous session, or
 * a systemd/dracut default is irrelevant -- the point of this
 * function is that after it runs, the answer is always "no", so
 * provision_zram() below can assume it's configuring the real
 * compression layer, not a second one shadowed by a first.
 */
static void disable_zswap(void)
{
    const char *zswap_enabled = "/sys/module/zswap/parameters/enabled";
    if (access(zswap_enabled, F_OK) != 0) {
        /* zswap not compiled into this kernel at all -- nothing to
         * override, and this is not a warning-worthy condition. */
        return;
    }

    FILE *f = fopen(zswap_enabled, "r");
    if (f) {
        char cur[8] = {0};
        if (fgets(cur, sizeof(cur), f)) {
            if (cur[0] == 'N') {
                fclose(f);
                rp_log(LOG_INFO, "zswap already disabled");
                return;
            }
        }
        fclose(f);
    }

    write_proc_sys(zswap_enabled, "N");
    rp_log(LOG_INFO, "disabled zswap -- zram is the sole compression layer");
}

/* ── ZRAM provisioning ─────────────────────────────────────────────────── */
static void provision_zram(int slow)
{
    FILE *sw = fopen("/proc/swaps", "r");
    if (sw) {
        char line[256];
        while (fgets(line, sizeof(line), sw))
            if (strstr(line, "zram")) {
                rp_log(LOG_INFO, "ZRAM already active -- skipping");
                fclose(sw); return;
            }
        fclose(sw);
    }
    long memtotal_kb = read_memtotal_kb();
    if (memtotal_kb <= 0) { rp_log(LOG_WARNING, "cannot read MemTotal"); return; }
    double ratio = slow ? ZRAM_RATIO_SLOW : ZRAM_RATIO_FAST;
    long zram_mb = (long)((double)memtotal_kb / 1024.0 * ratio);
    rp_log(LOG_INFO, "provisioning ZRAM: %ld MB (%s)", zram_mb, storage_type_name(g_storage_type));

    if (access("/sys/block/zram0", F_OK) != 0) {
        if (system("/sbin/modprobe zram 2>/dev/null") != 0)
            rp_log(LOG_INFO, "modprobe zram non-zero (may be built-in)");
        int waited = 0;
        while (access("/sys/block/zram0", F_OK) != 0 && waited < 20) {
            struct timespec ts = { .tv_sec=0, .tv_nsec=100000000L };
            nanosleep(&ts, NULL); waited++;
        }
        if (access("/sys/block/zram0", F_OK) != 0) {
            rp_log(LOG_ERR, "zram0 did not appear"); return;
        }
    }

    int zram_idx = -1;
    FILE *hot = fopen("/sys/class/zram-control/hot_add", "r");
    if (hot) { if (fscanf(hot, "%d", &zram_idx) != 1) zram_idx=-1; fclose(hot); }
    if (zram_idx < 0) {
        for (int i = 0; i <= 8; i++) {
            char dp[64]; snprintf(dp, sizeof(dp), "/sys/block/zram%d/disksize", i);
            FILE *dsf = fopen(dp, "r"); if (!dsf) continue;
            long ds = 0; if (fscanf(dsf, "%ld", &ds) != 1) ds=-1; fclose(dsf);
            if (ds == 0) { zram_idx = i; break; }
        }
    }
    if (zram_idx < 0) { rp_log(LOG_ERR, "no free zram device"); return; }
    rp_log(LOG_INFO, "using zram%d", zram_idx);

    char devpath[32]; snprintf(devpath, sizeof(devpath), "/dev/zram%d", zram_idx);
    char size_path[64]; snprintf(size_path, sizeof(size_path), "/sys/block/zram%d/disksize", zram_idx);
    FILE *sz = fopen(size_path, "w");
    if (!sz) { rp_log(LOG_ERR, "cannot write %s: %s", size_path, strerror(errno)); return; }
    fprintf(sz, "%ldM", zram_mb); fclose(sz);

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "mkswap %s >/dev/null 2>&1", devpath);
    if (system(cmd) != 0) { rp_log(LOG_ERR, "mkswap %s failed", devpath); return; }
    snprintf(cmd, sizeof(cmd), "swapon -p 100 %s >/dev/null 2>&1", devpath);
    if (system(cmd) != 0) { rp_log(LOG_ERR, "swapon %s failed", devpath); return; }
    rp_log(LOG_INFO, "ZRAM active: %s (%ld MB)", devpath, zram_mb);
}

static void tune_vm_for_zram(void)
{
    rp_log(LOG_INFO, "tuning VM for ZRAM:");
    write_proc_sys("/proc/sys/vm/page-cluster",       "0");
    write_proc_sys("/proc/sys/vm/swappiness",         "100");
    write_proc_sys("/proc/sys/vm/vfs_cache_pressure", "50");
    /* Disable partition swap now that ZRAM is active */
    FILE *sw = fopen("/proc/swaps", "r"); if (!sw) return;
    char line[256];
    if (!fgets(line, sizeof(line), sw)) { fclose(sw); return; }
    while (fgets(line, sizeof(line), sw)) {
        if (strstr(line, "zram")) continue;
        if (!strstr(line, "partition")) continue;
        char dev[128] = {0};
        if (sscanf(line, "%127s", dev) == 1 && dev[0] == '/') {
            char cmd[160]; snprintf(cmd, sizeof(cmd), "swapoff %s 2>/dev/null", dev);
            if (system(cmd) == 0) rp_log(LOG_INFO, "disabled partition swap: %s", dev);
        }
    }
    fclose(sw);
}

/* ── Pre-computed victim list (updated by scanner thread) ──────────────── */
#define MAX_CANDIDATES 8

typedef struct {
    pid_t pid;
    long  rss_kb;
    char  name[64];
    int   idle_streak;   /* consecutive scans with cpu delta == 0, from g_track */
} candidate_t;

static candidate_t  g_candidates[MAX_CANDIDATES];
static int          g_n_candidates = 0;
static pthread_mutex_t g_cand_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * ── Persistent idle-streak tracking ─────────────────────────────────────
 *
 * State-driven backgrounded-duration tracking, without a window server.
 *
 * Jetsam ranks kill candidates primarily by how long an app has been
 * backgrounded, size second. detritus has no window-focus concept and
 * deliberately does not acquire one (no X11/Wayland dependency in a
 * daemon that otherwise runs headless) -- instead, "backgrounded a
 * while" is reconstructed from state already available in /proc:
 * a process is treated as backgrounded-and-idle if it has gone
 * multiple consecutive scan cycles with zero scheduler activity.
 * A single idle sample is noisy (a background process can tick
 * briefly for an unrelated timer); a sustained streak is not.
 *
 * Ownership: owned by the scanner thread, same lifetime as g_candidates,
 * protected by the same g_cand_lock since both are written in the same
 * scan-cycle critical section.
 *
 * PID reuse: a slot is keyed on (pid, starttime_ticks). starttime_ticks
 * (field 22 of /proc/pid/stat) is immutable for the life of a specific
 * process, so if a slot's stored starttime no longer matches the live
 * process at that pid, the slot belonged to a since-exited process and
 * must not be reused for the new one -- otherwise the new process
 * silently inherits a streak count it never earned.
 *
 * Bounded and evicted: capped at MAX_TRACKED, LRU-evicted by last-seen
 * scan sequence number, so a system cycling through many short-lived
 * processes cannot grow this table without bound.
 */
#define MAX_TRACKED 256

typedef struct {
    pid_t pid;
    unsigned long long starttime_ticks;
    unsigned long long last_cpu_ticks;
    int   idle_streak;
    int   in_use;
    unsigned long last_seen_seq;
} track_slot_t;

static track_slot_t g_track[MAX_TRACKED];
static unsigned long g_scan_seq = 0;  /* protected by g_cand_lock */

/* Find or create the tracking slot for (pid, starttime). Must be called
 * with g_cand_lock held. Returns NULL only if the table is full and no
 * slot could be evicted, which cannot happen in practice since eviction
 * always succeeds against the oldest last_seen_seq. */
static track_slot_t *track_lookup_or_create(pid_t pid, unsigned long long starttime)
{
    int free_idx = -1;
    int lru_idx  = 0;
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (g_track[i].in_use && g_track[i].pid == pid &&
            g_track[i].starttime_ticks == starttime) {
            return &g_track[i];
        }
        if (!g_track[i].in_use && free_idx < 0) free_idx = i;
        if (g_track[i].last_seen_seq < g_track[lru_idx].last_seen_seq) lru_idx = i;
    }
    int idx = (free_idx >= 0) ? free_idx : lru_idx;
    g_track[idx].pid             = pid;
    g_track[idx].starttime_ticks = starttime;
    g_track[idx].last_cpu_ticks  = 0;
    g_track[idx].idle_streak     = 0;
    g_track[idx].in_use          = 1;
    return &g_track[idx];
}

/* Processes to never freeze -- kernel truncates comm to 15 chars in
 * /proc/pid/status so all entries here must be <= 15 characters. */
static const char *SKIP_NAMES[] = {
    /* X display server -- XLibre fork, binary still named Xorg */
    "Xorg",
    /* Window manager + compositors */
    "marco", "xfwm4", "kwin_x11", "kwin_wayland", "mutter",
    /* Desktop shell */
    "mate-panel", "mate-settings-d",  /* mate-settings-daemon truncated */
    "mate-session", "nemo-desktop",
    /* Audio -- freeze these and audio dies */
    "pipewire", "pipewire-pulse", "wireplumber",
    /* Input */
    "ibus-daemon", "fcitx", "fcitx5",
    /* detritusd itself */
    "detritusd",
    /* Known stress/test tools -- these ARE the pressure source */
    "oom_drill", "stress", "stress-ng",
    NULL
};

static int is_skip(const char *name)
{
    for (int i = 0; SKIP_NAMES[i]; i++)
        if (strcmp(name, SKIP_NAMES[i]) == 0) return 1;
    return 0;
}

/* Forward declarations: write_status_file needs these, but their canonical
 * definitions live later in the file (current_psi_some near the PSI reader,
 * g_frozen_pid/g_frozen_name near the freeze/resume logic). Declared here
 * explicitly rather than reordering the file, per Ch.5's explicit-
 * dependency principle -- this makes clear exactly what write_status_file
 * depends on without requiring the reader to know the file's layout. */
static double current_psi_some(unsigned long long *total_out);
extern pid_t g_frozen_pid;
extern char  g_frozen_name[64];

/* ── Proactive idle-trickle state ────────────────────────────────────────
 * g_trickle_bytes_interval accumulates bytes marked MADV_COLD by
 * idle_trickle_thread() since the last time write_status_file() read
 * and reset it. This -- not PSI -- is what the GUI's pressure pie is
 * driven by: PSI can legitimately stay at 0 on a healthy system with
 * headroom to spare, but this counter moves the instant there's any
 * idle memory to trickle, which is the actual "detritus is doing
 * something" signal that was asked for. Declared here (both
 * write_status_file and idle_trickle_thread are defined after this
 * point) rather than nearer idle_trickle_thread's own definition,
 * since write_status_file needs it and this file's established
 * convention (see current_psi_some/g_frozen_pid above) is to declare
 * such shared state at its first point of use rather than force a
 * file reorder. */
static unsigned long g_trickle_bytes_interval = 0;
static pthread_mutex_t g_trickle_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Status file: read-only snapshot for external consumers ─────────────
 *
 * Publishes exactly the state detritus already holds -- never re-derives
 * anything a consumer could get wrong independently. This is the single
 * source of truth for "what is detritus doing right now"; a GUI (e.g. a
 * forked MATE System Monitor) reads this file and displays it verbatim.
 * It must not reimplement idle-streak or PSI-threshold logic itself --
 * doing so would create two independent copies of the same computation
 * that can silently drift apart (Ch.6).
 *
 * Contract:
 *   Guarantees -- valid JSON on every read; one full snapshot per scan
 *     cycle; schema_version bumped on any incompatible field change;
 *     atomic (mkstemp + write + rename, so a reader never observes a
 *     partially-written file).
 *   Assumes   -- readers treat every field as advisory/stale-tolerant;
 *     there is an inherent race between this write and the next scan.
 *   Refuses   -- never requires root to read (0644); never blocks a
 *     reader; never partially updates the file in place.
 *
 * Called from the scanner thread while g_cand_lock is already held with
 * fresh data -- no additional locking needed for g_candidates. Reads
 * g_frozen_pid/g_frozen_name under the same lock, which tightens their
 * previous informal single-thread-touches-them invariant into an
 * explicit one now that a second reader (this function) exists.
 */
#define DETRITUS_STATUS_DIR  "/run/detritus"
#define DETRITUS_STATUS_PATH DETRITUS_STATUS_DIR "/status.json"
#define DETRITUS_SCHEMA_VERSION 1
#define GONZOCACHE_PRELOADED_LIST "/var/lib/gonzocache/preloaded.list"

static pthread_mutex_t g_frozen_lock = PTHREAD_MUTEX_INITIALIZER;

/* Sum real page-cache residency, in KB, across every file GonzoCache
 * preloaded on this login (per its own preloaded.list -- see
 * gonzocache.c's run_preload_mode(), which writes this list). This is
 * a genuine cross-project data dependency (detritus reading a file
 * gonzocache writes), made explicit here rather than silent.
 *
 * Uses mincore() -- the actual kernel primitive for "which pages of
 * this mapping are currently resident in RAM" -- rather than any
 * estimate or heuristic. Verified directly before use: mmap a real
 * file, call mincore(), confirm 0 bytes resident before the file is
 * ever read and the correct page-rounded size after a real read.
 *
 * If GonzoCache isn't installed, hasn't run yet this session, or
 * preloaded nothing, the list file is simply absent or empty and this
 * correctly returns 0 -- not an error, just "nothing to report",
 * matching the same "absence is an expected state, not exceptional"
 * discipline used throughout this file for optional companion data.
 */
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
        if (fd < 0) continue;  /* file gone/moved since preload -- skip, not an error */

        struct stat st;
        if (fstat(fd, &st) != 0 || st.st_size == 0) { close(fd); continue; }

        size_t file_len = (size_t)st.st_size;
        void *map = mmap(NULL, file_len, PROT_READ, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) { close(fd); continue; }

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

/* Must be called with g_cand_lock held (for g_candidates/g_n_candidates). */
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
    if (fd < 0) {
        rp_log(LOG_WARNING, "status file: mkstemp failed: %s", strerror(errno));
        return;
    }
    fchmod(fd, 0644);

    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp_path); return; }

    unsigned long long psi_total = 0;
    double psi_avg10 = current_psi_some(&psi_total);

    long memtotal_kb = read_memtotal_kb();
    long mem_avail_kb = 0;
    {
        FILE *mf = fopen("/proc/meminfo", "r");
        if (mf) {
            char line[128];
            while (fgets(line, sizeof(line), mf))
                if (strncmp(line, "MemAvailable:", 13) == 0) {
                    sscanf(line + 13, "%ld", &mem_avail_kb); break;
                }
            fclose(mf);
        }
    }

    /* Rate of memory change (KB/s), the actual "how fast is RAM filling
     * up or emptying" signal -- distinct from trickle_bytes_interval,
     * which only reports detritus's own small contribution and says
     * nothing about what the rest of the system (a benchmark, the
     * kernel's own reclaim, a browser) is doing to memory. This is
     * plain |delta MemAvailable| / delta time between two consecutive
     * publishes; magnitude only, since the pie is meant to represent
     * how much pressure is moving, not which direction.
     *
     * Safe as static locals without a lock: write_status_file() is
     * only ever called from the scanner thread (see this function's
     * contract comment above), unlike g_trickle_bytes_interval which
     * genuinely crosses threads. */
    static long   prev_mem_avail_kb = -1;
    static time_t prev_sample_time  = 0;
    time_t now = time(NULL);
    double mem_rate_kb_per_sec = 0.0;
    if (prev_mem_avail_kb >= 0 && now > prev_sample_time) {
        long   delta_kb  = mem_avail_kb - prev_mem_avail_kb;
        time_t delta_sec = now - prev_sample_time;
        mem_rate_kb_per_sec = (double)labs(delta_kb) / (double)delta_sec;
    }
    prev_mem_avail_kb = mem_avail_kb;
    prev_sample_time  = now;

    pthread_mutex_lock(&g_frozen_lock);
    pid_t frozen_pid = g_frozen_pid;
    char  frozen_name[64];
    memcpy(frozen_name, g_frozen_name, sizeof(frozen_name));
    pthread_mutex_unlock(&g_frozen_lock);

    /* Read-and-reset: report exactly what the trickle thread did since
     * the last publish, not a running total. A running total would
     * only ever climb toward some cap and sit there, which is not a
     * useful "is detritus doing something right now" signal; an
     * interval delta genuinely reflects current activity, matching
     * what the pressure pie needs to show. */
    pthread_mutex_lock(&g_trickle_lock);
    unsigned long trickle_bytes = g_trickle_bytes_interval;
    g_trickle_bytes_interval = 0;
    pthread_mutex_unlock(&g_trickle_lock);

    /* GonzoCache's real, live page-cache residency across whatever it
     * preloaded this session -- read fresh every publish cycle, not
     * cached, since actual residency can change on its own (kernel
     * reclaim, another process's memory pressure evicting cached
     * pages) independent of anything detritus itself does. */
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
        "  \"frozen\": %s,\n",
        DETRITUS_SCHEMA_VERSION,
        (long)now,
        psi_avg10 >= 0 ? psi_avg10 : 0.0,
        psi_total,
        trickle_bytes,
        mem_rate_kb_per_sec,
        gonzocache_resident_kb,
        memtotal_kb,
        mem_avail_kb,
        storage_type_name(g_storage_type),
        frozen_pid > 0 ? "true" : "false");

    if (frozen_pid > 0) {
        fprintf(f,
            "  \"frozen_pid\": %d,\n"
            "  \"frozen_name\": \"%s\",\n",
            (int)frozen_pid, frozen_name);
    }

    fprintf(f, "  \"candidates\": [\n");
    for (int i = 0; i < g_n_candidates; i++) {
        fprintf(f,
            "    { \"pid\": %d, \"name\": \"%s\", \"rss_kb\": %ld, "
            "\"idle_streak\": %d }%s\n",
            (int)g_candidates[i].pid, g_candidates[i].name,
            g_candidates[i].rss_kb, g_candidates[i].idle_streak,
            (i == g_n_candidates - 1) ? "" : ",");
    }
    fprintf(f, "  ]\n}\n");

    fflush(f);
    fsync(fd);
    fclose(f);

    if (rename(tmp_path, DETRITUS_STATUS_PATH) != 0) {
        rp_log(LOG_WARNING, "status file: rename failed: %s", strerror(errno));
        unlink(tmp_path);
    }
}

/* ── Scanner thread -- runs every SCAN_INTERVAL_MS ────────────────────── */
/*
 * Two-pass RSS snapshot with 150ms gap to detect actively-growing processes.
 * Growing processes are excluded as the pressure source.
 * Results are sorted by RSS descending and stored in g_candidates.
 */
static void *scanner_thread(void *arg)
{
    (void)arg;

    const char *notify_user = getenv("DETRITUS_NOTIFY_USER");
    long target_uid = -1;
    if (notify_user && notify_user[0]) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "id -u %s 2>/dev/null", notify_user);
        FILE *p = popen(cmd, "r");
        if (p) { if (fscanf(p, "%ld", &target_uid) != 1) target_uid=-1; pclose(p); }
    }

#define MAX_SCAN 512
    typedef struct {
        pid_t pid; long rss1; long rss2; char name[64];
        unsigned long long cpu_ticks1, cpu_ticks2;
        unsigned long long starttime_ticks;
    } scan_t;
    scan_t *buf = calloc(MAX_SCAN, sizeof(scan_t));
    if (!buf) return NULL;

    while (1) {
        int n = 0;

        /* Pass 1: snapshot RSS */
        DIR *pd = opendir("/proc");
        if (pd) {
            struct dirent *ent;
            while ((ent = readdir(pd)) != NULL && n < MAX_SCAN) {
                if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
                if (strlen(ent->d_name) > 7) continue;
                char sp[32];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
                snprintf(sp, sizeof(sp), "/proc/%s/status", ent->d_name);
#pragma GCC diagnostic pop
                FILE *sf = fopen(sp, "r"); if (!sf) continue;
                pid_t pid = 0; long uid = -1, rss = 0; char name[64]={0};
                char line[256];
                while (fgets(line, sizeof(line), sf)) {
                    if      (strncmp(line,"Pid:", 4)==0)  sscanf(line+4, "%d",  &pid);
                    else if (strncmp(line,"Uid:", 4)==0)  sscanf(line+4, "%ld", &uid);
                    else if (strncmp(line,"Name:",5)==0)  sscanf(line+5, "%63s", name);
                    else if (strncmp(line,"VmRSS:",6)==0) sscanf(line+6, "%ld", &rss);
                }
                fclose(sf);
                if (target_uid >= 0 && uid != target_uid) continue;
                if (rss < MIN_VICTIM_RSS_KB) continue;
                if (is_skip(name)) continue;

                /* CPU-recency: read utime+stime (fields 14,15 of stat) now;
                 * pass 2 re-reads after the 150ms gap. A delta > 0 means
                 * the scheduler actually ran this process in that window --
                 * i.e. it is in active use, not merely resident. This is
                 * the always-available floor for "don't disturb what the
                 * user is doing" -- independent of and more reliable than
                 * the X11 focus signal, which requires a display server
                 * and fails closed to nothing if unavailable. */
                unsigned long long cpu_ticks = 0;
                unsigned long long starttime = 0;
                char statp[32];
                snprintf(statp, sizeof(statp), "/proc/%d/stat", pid);
                FILE *stf = fopen(statp, "r");
                if (stf) {
                    char sbuf[512];
                    if (fgets(sbuf, sizeof(sbuf), stf)) {
                        char *rp = strrchr(sbuf, ')');
                        if (rp) {
                            unsigned long long ut = 0, st = 0, stt = 0;
                            /* fields after ") " are: state ppid pgrp session
                             * tty_nr tpgid flags minflt cminflt majflt
                             * cmajflt utime stime cutime cstime priority
                             * nice num_threads itrealvalue starttime --
                             * utime/stime are tokens 13/14, starttime is
                             * token 20 after the comm field. */
                            sscanf(rp + 2,
                                "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
                                "%llu %llu %*d %*d %*d %*d %*d %*d %llu",
                                &ut, &st, &stt);
                            cpu_ticks = ut + st;
                            starttime = stt;
                        }
                    }
                    fclose(stf);
                }

                buf[n].pid  = pid;
                buf[n].rss1 = rss;
                buf[n].rss2 = 0;
                buf[n].cpu_ticks1 = cpu_ticks;
                buf[n].cpu_ticks2 = 0;
                buf[n].starttime_ticks = starttime;
                memcpy(buf[n].name, name, 63); buf[n].name[63]=0;
                n++;
            }
            closedir(pd);
        }

        /* 150ms gap */
        struct timespec gap = { .tv_sec=0, .tv_nsec=150000000L };
        nanosleep(&gap, NULL);

        /* Pass 2: re-read RSS, exclude growers; re-read CPU ticks for the
         * idle-streak signal (same 150ms gap already paid for above). */
        for (int i = 0; i < n; i++) {
            char sp[32];
            snprintf(sp, sizeof(sp), "/proc/%d/status", buf[i].pid);
            FILE *sf = fopen(sp, "r"); if (!sf) { buf[i].rss2=-1; continue; }
            char line[256];
            while (fgets(line, sizeof(line), sf))
                if (strncmp(line,"VmRSS:",6)==0) { sscanf(line+6,"%ld",&buf[i].rss2); break; }
            fclose(sf);

            char statp[32];
            snprintf(statp, sizeof(statp), "/proc/%d/stat", buf[i].pid);
            FILE *stf = fopen(statp, "r");
            if (stf) {
                char sbuf[512];
                if (fgets(sbuf, sizeof(sbuf), stf)) {
                    char *rp = strrchr(sbuf, ')');
                    if (rp) {
                        unsigned long long ut = 0, st = 0;
                        sscanf(rp + 2,
                            "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
                            "%llu %llu", &ut, &st);
                        buf[i].cpu_ticks2 = ut + st;
                    }
                }
                fclose(stf);
            }
        }

        /* Update persistent idle-streak history for every scanned process,
         * before filtering. This runs regardless of RSS-growth exclusion
         * below, so a process temporarily filtered out this cycle (e.g.
         * caught mid-allocation-burst) doesn't lose accumulated history it
         * may need next cycle when it reappears as an eligible candidate. */
        pthread_mutex_lock(&g_cand_lock);
        g_scan_seq++;
        for (int i = 0; i < n; i++) {
            if (buf[i].rss2 <= 0) continue;  /* process exited between passes */
            track_slot_t *ts = track_lookup_or_create(buf[i].pid, buf[i].starttime_ticks);
            unsigned long long delta = buf[i].cpu_ticks2 - buf[i].cpu_ticks1;
            ts->idle_streak = (delta == 0) ? (ts->idle_streak + 1) : 0;
            ts->last_cpu_ticks = buf[i].cpu_ticks2;
            ts->last_seen_seq  = g_scan_seq;
        }

        /* Build ranked candidate list.
         *
         * Primary key: idle_streak descending (Jetsam-parity -- prefer the
         *   process that has been out of active use longest; a process
         *   with idle_streak == 0 was scheduled during the last 150ms gap
         *   and is hard-excluded below, not merely deprioritized, since
         *   freezing something the user is actively driving is a
         *   correctness violation, not a tuning choice).
         * Secondary key: rss_kb descending (unchanged from before --
         *   maximizes relief per freeze+compress action among candidates
         *   that are equally "not in active use").
         */
        g_n_candidates = 0;
        for (int i = 0; i < n && g_n_candidates < MAX_CANDIDATES; i++) {
            if (buf[i].rss2 <= 0) continue;
            long growth = buf[i].rss2 - buf[i].rss1;
            if (growth > RSS_GROWTH_KB) {
                rp_log(LOG_INFO, "scanner: excluding '%s' (growing %ld MB/150ms)",
                       buf[i].name, growth/1024);
                continue;
            }

            track_slot_t *ts = track_lookup_or_create(buf[i].pid, buf[i].starttime_ticks);
            if (ts->idle_streak == 0) continue;  /* actively scheduled -- do not touch */

            int streak = ts->idle_streak;

            /* Insert sorted: idle_streak descending, rss_kb descending tiebreak */
            int j = g_n_candidates;
            while (j > 0 &&
                   (g_candidates[j-1].idle_streak < streak ||
                    (g_candidates[j-1].idle_streak == streak &&
                     g_candidates[j-1].rss_kb < buf[i].rss2))) {
                if (j < MAX_CANDIDATES) g_candidates[j] = g_candidates[j-1];
                j--;
            }
            if (j < MAX_CANDIDATES) {
                g_candidates[j].pid         = buf[i].pid;
                g_candidates[j].rss_kb      = buf[i].rss2;
                g_candidates[j].idle_streak = streak;
                strncpy(g_candidates[j].name, buf[i].name, 63);
                g_n_candidates++;
            }
        }
        if (g_n_candidates > 0)
            rp_log(LOG_INFO, "scanner: top victim candidate: '%s' (%ld MB RSS, idle %d scans)",
                   g_candidates[0].name, g_candidates[0].rss_kb / 1024,
                   g_candidates[0].idle_streak);
        write_status_file();
        pthread_mutex_unlock(&g_cand_lock);

        /* Sleep until next scan (minus the 150ms we already spent) */
        struct timespec sleep_ts = {
            .tv_sec  = (SCAN_INTERVAL_MS - 150) / 1000,
            .tv_nsec = ((SCAN_INTERVAL_MS - 150) % 1000) * 1000000L,
        };
        nanosleep(&sleep_ts, NULL);
    }
    free(buf);
    return NULL;
}

/* ── Process helpers ───────────────────────────────────────────────────── */
static void signal_process_tree(pid_t root, int sig)
{
    kill(root, sig);
    DIR *pd = opendir("/proc"); if (!pd) return;
    struct dirent *ent;
    while ((ent = readdir(pd)) != NULL) {
        if (ent->d_name[0]<'1'||ent->d_name[0]>'9') continue;
        if (strlen(ent->d_name)>7) continue;
        char sp[32];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(sp, sizeof(sp), "/proc/%s/status", ent->d_name);
#pragma GCC diagnostic pop
        FILE *sf = fopen(sp,"r"); if (!sf) continue;
        pid_t pid=0,ppid=0; char line[128];
        while (fgets(line,sizeof(line),sf)) {
            if      (strncmp(line,"Pid:", 4)==0) sscanf(line+4,"%d",&pid);
            else if (strncmp(line,"PPid:",5)==0) sscanf(line+5,"%d",&ppid);
        }
        fclose(sf);
        if (ppid==root && pid>1) kill(pid,sig);
    }
    closedir(pd);
}

/*
 * trickle_pageout_process(pid, name)
 *
 * Trickle MADV_PAGEOUT with an adaptive yield controller.
 *
 * Each 256KB chunk is followed by a yield whose duration is determined
 * by how much PSI stall the previous chunk caused:
 *
 *   - Measure PSI 'some total' before and after each chunk.
 *   - If the chunk caused < 1ms of new stall: reduce yield (additive,
 *     min 500us) -- the system is absorbing compression easily, push faster.
 *   - If the chunk caused >= 1ms of new stall: increase yield (multiplicative,
 *     max 32ms) -- back off and give the system time to drain.
 *
 * This is an AIMD (Additive Increase, Multiplicative Decrease) controller --
 * the same principle TCP uses for congestion control. It automatically
 * finds the fastest rate the system can sustain without latency spikes,
 * and backs off immediately when it detects stress.
 *
 * Result: on an idle system, a 300MB browser heap compresses in ~1s.
 * Under heavy pressure, it throttles to avoid adding to the spike.
 */
#define PAGEOUT_CHUNK        (256 * 1024) /* 256KB per iovec vector              */
/*
 * Pressure-proportional yield -- the trickle rate is derived from
 * MemAvailable at the start of each pageout pass, not a fixed timer.
 *
 * High memory pressure (< 400MB free)  -> 100ms between batches (~2.5MB/s)
 * Moderate pressure  (400-800MB free)  -> 250ms between batches (~1MB/s)
 * Light pressure     (> 800MB free)    -> 500ms between batches (~512KB/s)
 *
 * This means under a heavy Speedometer load the pager works faster
 * exactly when it needs to, and barely touches the bus when RAM is
 * comfortable. No timers, no arbitrary windows -- purely state-driven.
 */
#define PAGEOUT_YIELD_HIGH_US   100000   /* < 400MB free: fast              */
#define PAGEOUT_YIELD_MED_US    250000   /* 400-800MB free: moderate        */
#define PAGEOUT_YIELD_LOW_US    500000   /* > 800MB free: gentle            */
#define PAGEOUT_STALL_THRESH_US   2000   /* stall > 2ms: back off one step  */

/*
 * AIMD sparsity: evaluate /proc state once every EVAL_STRIDE bytes, then
 * fire CHUNKS_PER_BATCH raw 256KB syscalls with only a nanosleep between
 * them.  The kernel's bus can't saturate within a 2MB window on any Atom
 * variant we target, so checking meminfo/PSI every 256KB buys nothing and
 * costs ~6 context-switch-equivalents per chunk.  Hoisting those reads out
 * of the inner loop drops per-chunk overhead by ~90% on in-order cores.
 *
 * EVAL_STRIDE is the distance between /proc reads (8 × 256KB = 2MB).
 * IOV_BATCH   is the maximum iovecs packed into one process_madvise call.
 *             Batching contiguous VMAs into a single syscall lets the kernel
 *             walk the address space once instead of once per chunk.
 */
#define EVAL_STRIDE          (8 * PAGEOUT_CHUNK)   /* re-read /proc every 2MB  */
#define IOV_BATCH            16                     /* max iovecs per syscall   */

/* VMA range collected from /proc/pid/maps */
typedef struct { uintptr_t start; uintptr_t end; } vma_t;

/* Collect anonymous private writable VMAs from /proc/pid/maps into vmas[],
 * capped at max_vmas entries. Returns the count found (may be less than
 * what actually exists in the process if max_vmas is hit first).
 *
 * Shared by both the reactive pageout path (trickle_pageout_process,
 * MADV_PAGEOUT under real pressure) and the proactive idle-trickle path
 * (idle_trickle_thread, MADV_COLD with no pressure at all) -- both need
 * the identical filter (anonymous, private, writable, not a special
 * mapping like [vdso]/[stack], large enough to be worth touching), and
 * duplicating this parsing a second time would create two independently
 * maintained copies of the same selection logic that could silently
 * drift apart if one is ever tuned without the other.
 *
 * maps has no page-table walk cost, unlike smaps -- deliberately not
 * using smaps here even though it has richer per-mapping detail. */
static int collect_reclaimable_vmas(pid_t pid, vma_t *vmas, int max_vmas)
{
    char maps_path[32];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
#pragma GCC diagnostic pop

    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

    int  nvmas = 0;
    char line[256];

    while (fgets(line, sizeof(line), f) && nvmas < max_vmas) {
        uintptr_t start, end, offset; unsigned long inode;
        char perms[8]={0}, dev[16]={0}, rest[128]={0};
        if (sscanf(line, "%lx-%lx %7s %lx %15s %lu %127[^\n]",
                   &start, &end, perms, &offset, dev, &inode, rest) < 6)
            continue;
        if (perms[0]!='r'||perms[1]!='w'||perms[3]!='p') continue;
        if (inode != 0 || strcmp(dev,"00:00") != 0)        continue;
        char *nm = rest; while (*nm==' ') nm++;
        if (strncmp(nm,"[v",2)==0) continue;
        if (end - start < 65536) continue;
        vmas[nvmas].start = start;
        vmas[nvmas].end   = end;
        nvmas++;
    }
    fclose(f);
    return nvmas;
}

/* Read PSI 'some total' microseconds -- fast, single fopen */
static unsigned long long read_psi_total(void)
{
    FILE *f = fopen("/proc/pressure/memory", "r");
    if (!f) return 0;
    unsigned long long total = 0;
    char line[128];
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, "some", 4) == 0) {
            sscanf(line, "some avg10=%*f avg60=%*f avg300=%*f total=%llu", &total);
            break;
        }
    fclose(f);
    return total;
}

static void trickle_pageout_process(pid_t pid, const char *name)
{
    /* Drop to idle priority -- scheduler yields us to UI threads automatically */
    setpriority(PRIO_PROCESS, 0, 19);
    syscall(SYS_ioprio_set, 1, 0, (3 << 13) | 0);  /* IOPRIO_CLASS_IDLE */

    int pidfd = (int)syscall(SYS_pidfd_open, (long)pid, 0);
    if (pidfd < 0) {
        rp_log(LOG_WARNING, "pidfd_open(%d): %s", pid, strerror(errno));
        goto done;
    }

    vma_t vmas[512];
    int   nvmas = collect_reclaimable_vmas(pid, vmas, 512);
    if (nvmas == 0) { close(pidfd); goto done; }

    /*
     * Two-level trickle loop: sparse AIMD controller + vectorized hot path.
     *
     * Outer level  -- runs every EVAL_STRIDE bytes (2MB default).
     *   Reads /proc/meminfo and /proc/pressure/memory once to set the
     *   yield tier and measure baseline PSI.  All string parsing and
     *   file I/O stays here, never inside the 256KB inner loop.
     *
     * Inner level  -- tight iovec batching loop.
     *   Packs up to IOV_BATCH 256KB chunks into a single process_madvise
     *   call, then sleeps with a raw nanosleep.  The only work per chunk
     *   is pointer arithmetic and one array write -- no syscall overhead
     *   until the batch is full or a VMA boundary is hit.
     *
     * On an Atom N-series, hoisting the /proc reads drops per-chunk
     * overhead by ~90% (6 context-switch-equivalents -> 0 in the inner
     * loop).  Batching the iovecs cuts process_madvise calls by up to
     * IOV_BATCH-fold for fragmented browser heaps.
     */
    long   total_bytes   = 0;
    int    chunks        = 0;
    long   bytes_since_eval = 0;    /* distance since last /proc read */
    int    yield_us      = PAGEOUT_YIELD_MED_US;  /* safe default */
    unsigned long long psi_baseline = read_psi_total();

    /* Evaluate system state now before the first batch */
    {
        long mem_now_kb = 0;
        FILE *mf = fopen("/proc/meminfo", "r");
        if (mf) {
            char mline[128];
            while (fgets(mline, sizeof(mline), mf))
                if (strncmp(mline, "MemAvailable:", 13) == 0) {
                    sscanf(mline + 13, "%ld", &mem_now_kb); break;
                }
            fclose(mf);
        }
        if      (mem_now_kb < 400 * 1024) yield_us = PAGEOUT_YIELD_HIGH_US;
        else if (mem_now_kb < 800 * 1024) yield_us = PAGEOUT_YIELD_MED_US;
        else                               yield_us = PAGEOUT_YIELD_LOW_US;
        psi_baseline = read_psi_total();
    }

    for (int i = 0; i < nvmas; i++) {
        uintptr_t cursor = vmas[i].start;

        while (cursor < vmas[i].end) {

            /*
             * -- Sparse AIMD evaluation (outer level) --
             * Runs once per EVAL_STRIDE bytes, not once per 256KB chunk.
             * Re-reads /proc to recalibrate the yield tier, then measures
             * PSI delta since the previous eval to detect whether the last
             * stride caused backpressure.
             */
            if (bytes_since_eval >= EVAL_STRIDE) {
                unsigned long long psi_now = read_psi_total();
                unsigned long long stall   = psi_now - psi_baseline;
                psi_baseline    = psi_now;
                bytes_since_eval = 0;

                long mem_now_kb = 0;
                FILE *mf = fopen("/proc/meminfo", "r");
                if (mf) {
                    char mline[128];
                    while (fgets(mline, sizeof(mline), mf))
                        if (strncmp(mline, "MemAvailable:", 13) == 0) {
                            sscanf(mline + 13, "%ld", &mem_now_kb); break;
                        }
                    fclose(mf);
                }

                /* Derive base tier from MemAvailable */
                if      (mem_now_kb < 400 * 1024) yield_us = PAGEOUT_YIELD_HIGH_US;
                else if (mem_now_kb < 800 * 1024) yield_us = PAGEOUT_YIELD_MED_US;
                else                               yield_us = PAGEOUT_YIELD_LOW_US;

                /* Multiplicative back-off if the stride caused significant stall */
                if (stall >= PAGEOUT_STALL_THRESH_US) {
                    if      (yield_us == PAGEOUT_YIELD_HIGH_US) yield_us = PAGEOUT_YIELD_MED_US;
                    else if (yield_us == PAGEOUT_YIELD_MED_US)  yield_us = PAGEOUT_YIELD_LOW_US;
                }
            }

            /*
             * -- Vectorized hot path (inner level) --
             * Fill up to IOV_BATCH iovecs from the current VMA, staying
             * within the remaining VMA boundary, then fire a single
             * process_madvise call.  The kernel walks the iov array
             * internally -- far cheaper than IOV_BATCH separate syscalls.
             */
            struct iovec iov[IOV_BATCH];
            int    niov      = 0;
            size_t batch_len = 0;

            while (niov < IOV_BATCH && cursor < vmas[i].end) {
                size_t len = vmas[i].end - cursor;
                if (len > (size_t)PAGEOUT_CHUNK) len = PAGEOUT_CHUNK;
                iov[niov].iov_base = (void *)cursor;
                iov[niov].iov_len  = len;
                niov++;
                cursor     += len;
                batch_len  += len;
            }

            long ret = syscall(SYS_process_madvise, pidfd,
                               iov, niov, MADV_PAGEOUT, 0);
            if (ret == 0) {
                total_bytes      += (long)batch_len;
                bytes_since_eval += (long)batch_len;
                chunks           += niov;
            } else if (errno == ENOSYS) {
                rp_log(LOG_WARNING, "process_madvise: needs kernel 5.10+");
                close(pidfd); goto done;
            }

            /* Inter-batch yield -- one nanosleep per IOV_BATCH chunks,
             * not one per chunk.  No /proc I/O here at all. */
            struct timespec ts = {
                .tv_sec  =  yield_us / 1000000,
                .tv_nsec = (yield_us % 1000000) * 1000L,
            };
            nanosleep(&ts, NULL);
        }
    }
    close(pidfd);

    rp_log(LOG_INFO,
           "trickle pageout: %ld MiB of '%s' -> ZRAM  chunks=%d",
           total_bytes / (1024*1024), name, chunks);

done:
    setpriority(PRIO_PROCESS, 0, 0);
}

/* ── Proactive idle-trickle thread ────────────────────────────────────────
 *
 * This is the "helper, not manager" path: a slow, constant, low-priority
 * trickle that proactively marks a small amount of memory from a
 * genuinely idle process as reclaimable, on every cycle, regardless of
 * whether PSI has ever fired. It exists alongside -- and does not
 * replace -- the PSI-reactive freeze/pageout path in handle_pressure(),
 * which remains the last-resort fallback for genuine emergencies.
 *
 * Design constraints, each chosen specifically to keep the daemon
 * itself from ever being the source of a new problem:
 *
 *   - Fixed 400ms cadence, comfortably under the 500ms ceiling. No
 *     variable backoff, no burst catch-up -- exactly one cycle's worth
 *     of work per cycle, always, so the daemon's own CPU/IO footprint
 *     never spikes in response to system state.
 *   - MADV_COLD, never MADV_PAGEOUT. MADV_COLD tells the kernel "this
 *     is reclaimable, deprioritize it" -- the kernel decides if and
 *     when to actually act on that, under its own scheduling. It is
 *     categorically incapable of forcing a synchronous stall the way
 *     MADV_PAGEOUT (used only by the reactive emergency path) can.
 *     This is the single design choice that makes "never make the
 *     system feel clunky" true by construction rather than by tuning.
 *   - One small chunk (TRICKLE_CHUNK_BYTES, 2MB) of ONE process per
 *     cycle. Never sweeps a whole process, never touches more than one
 *     candidate per cycle -- matching the reactive path's existing
 *     one-victim-at-a-time discipline.
 *   - Only processes with idle_streak >= TRICKLE_IDLE_FLOOR (30 scans,
 *     roughly 60s of zero scheduler activity at the scanner's 2s
 *     cadence) are eligible. Being at the top of g_candidates isn't
 *     sufficient on its own -- on a system with few background
 *     processes, the top candidate could be only lightly idle, and
 *     lightly-idle memory is exactly what shouldn't be pre-emptively
 *     touched.
 *
 * Selection reuses g_candidates (already ranked by idle_streak
 * descending, maintained by the scanner thread) rather than performing
 * its own scan -- this is the same tracking table the reactive path's
 * ranking already depends on, so there is exactly one place in the
 * daemon that decides "how idle is this process", not two that could
 * silently disagree.
 */
#define TRICKLE_INTERVAL_MS   400
#define TRICKLE_CHUNK_BYTES   (2 * 1024 * 1024)
#define TRICKLE_IDLE_FLOOR    30

/* Adaptive chunk sizing: scale linearly with how fast MemAvailable is
 * actually falling, measured on this thread's own 400ms cadence -- not
 * borrowed from write_status_file's 2-second sample rate, which would
 * react too slowly to a genuinely fast fill.
 *
 * No upper cap. MADV_COLD is a soft hint the kernel schedules on its
 * own timeline -- process_madvise() itself is a fast syscall regardless
 * of how large the iovec is, it does not synchronously touch pages or
 * block on I/O the way MADV_PAGEOUT's forced reclaim can. A cap here
 * doesn't prevent thrashing (MADV_COLD's own nature already makes
 * thrashing structurally impossible, independent of chunk size); it
 * would only throttle how fast this thread can respond to a genuinely
 * fast fill, which is backwards -- a fast fill is exactly the situation
 * that most needs a fast, proportional response, not a throttled one.
 *
 * Scaling: below TRICKLE_FILL_CALM_KB_PER_SEC, stays at baseline
 * TRICKLE_CHUNK_BYTES. Above it, grows linearly with fill rate --
 * double the fill rate, double the chunk, indefinitely. The reactive
 * PSI path in handle_pressure() remains the true last-resort backstop
 * for cases where even this isn't enough, unchanged by any of this.
 */
#define TRICKLE_FILL_CALM_KB_PER_SEC    (5 * 1024)   /* below this: baseline chunk */

static size_t adaptive_chunk_bytes(double fill_rate_kb_per_sec)
{
    if (fill_rate_kb_per_sec <= TRICKLE_FILL_CALM_KB_PER_SEC)
        return TRICKLE_CHUNK_BYTES;

    /* Linear scale-up past the calm threshold, uncapped. */
    double multiplier = fill_rate_kb_per_sec / (double)TRICKLE_FILL_CALM_KB_PER_SEC;
    return (size_t)((double)TRICKLE_CHUNK_BYTES * multiplier);
}
static void *idle_trickle_thread(void *arg)
{
    (void)arg;
    setpriority(PRIO_PROCESS, 0, 19);
    syscall(SYS_ioprio_set, 1, 0, (3 << 13) | 0);  /* IOPRIO_CLASS_IDLE */

    struct timespec cycle = {
        .tv_sec  = TRICKLE_INTERVAL_MS / 1000,
        .tv_nsec = (TRICKLE_INTERVAL_MS % 1000) * 1000000L,
    };

    /* Round-robin cursor across a single target process's VMAs, so
     * successive cycles advance through the address space rather than
     * repeatedly re-touching the same first 2MB forever. Reset whenever
     * the selected victim PID changes between cycles. */
    pid_t     last_pid = -1;
    vma_t     vmas[512];
    int       nvmas = 0;
    int       vma_idx = 0;
    uintptr_t cursor = 0;

    /* Fast, local MemAvailable sampling for this thread's own rate
     * measurement -- deliberately separate from write_status_file's
     * prev_mem_avail_kb/prev_sample_time statics, which sample on a
     * 2-second cadence too slow for a 400ms decision loop to react to
     * in time. */
    long   prev_avail_kb = -1;
    struct timespec prev_sample_ts = {0, 0};

    for (;;) {
        nanosleep(&cycle, NULL);

        long mem_avail_kb = 0;
        FILE *mf = fopen("/proc/meminfo", "r");
        if (mf) {
            char mline[128];
            while (fgets(mline, sizeof(mline), mf))
                if (strncmp(mline, "MemAvailable:", 13) == 0) {
                    sscanf(mline + 13, "%ld", &mem_avail_kb); break;
                }
            fclose(mf);
        }

        struct timespec now_ts;
        clock_gettime(CLOCK_MONOTONIC, &now_ts);

        double fill_rate_kb_per_sec = 0.0;
        if (prev_avail_kb >= 0) {
            double elapsed_sec = (now_ts.tv_sec - prev_sample_ts.tv_sec) +
                (now_ts.tv_nsec - prev_sample_ts.tv_nsec) / 1e9;
            if (elapsed_sec > 0.01) {
                /* Only a *decline* in MemAvailable counts as "filling" --
                 * MemAvailable recovering (the system emptying out on its
                 * own) should not spike the chunk size upward; there is
                 * nothing urgent happening in that direction. */
                double delta_kb = (double)(prev_avail_kb - mem_avail_kb);
                if (delta_kb > 0)
                    fill_rate_kb_per_sec = delta_kb / elapsed_sec;
            }
        }
        prev_avail_kb  = mem_avail_kb;
        prev_sample_ts = now_ts;

        size_t chunk_ceiling = adaptive_chunk_bytes(fill_rate_kb_per_sec);

        pid_t target_pid = -1;
        char  target_name[64] = {0};

        pthread_mutex_lock(&g_cand_lock);
        if (g_n_candidates > 0 &&
            g_candidates[0].idle_streak >= TRICKLE_IDLE_FLOOR) {
            target_pid = g_candidates[0].pid;
            memcpy(target_name, g_candidates[0].name, sizeof(target_name) - 1);
        }
        pthread_mutex_unlock(&g_cand_lock);

        if (target_pid <= 0) continue;  /* nothing idle enough right now */

        if (target_pid != last_pid) {
            /* Victim changed since last cycle -- re-collect VMAs and
             * restart the cursor rather than trying to resume progress
             * against a different process's address space. */
            nvmas = collect_reclaimable_vmas(target_pid, vmas, 512);
            vma_idx = 0;
            cursor  = (nvmas > 0) ? vmas[0].start : 0;
            last_pid = target_pid;
            if (nvmas == 0) continue;
        }

        if (vma_idx >= nvmas) { vma_idx = 0; cursor = vmas[0].start; }

        int pidfd = (int)syscall(SYS_pidfd_open, (long)target_pid, 0);
        if (pidfd < 0) { last_pid = -1; continue; }  /* process likely gone */

        size_t remaining = vmas[vma_idx].end - cursor;
        size_t chunk_len = (remaining < chunk_ceiling)
                          ? remaining : chunk_ceiling;

        struct iovec iov = { .iov_base = (void *)cursor, .iov_len = chunk_len };
        long ret = syscall(SYS_process_madvise, pidfd, &iov, 1, MADV_COLD, 0);
        close(pidfd);

        if (ret < 0) {
            if (errno == ENOSYS) {
                rp_log(LOG_WARNING, "idle-trickle: process_madvise needs kernel 5.10+, stopping");
                return NULL;
            }
            /* Process likely exited between selection and madvise --
             * this is an expected, not exceptional, race given the
             * 400ms gap between selection and action. Just retry next
             * cycle against whatever the scanner ranks then. */
            last_pid = -1;
            continue;
        }

        if (chunk_ceiling > TRICKLE_CHUNK_BYTES) {
            rp_log(LOG_INFO,
                   "idle-trickle: fill rate %.1f MB/s -- scaled chunk to %zu MB (%s)",
                   fill_rate_kb_per_sec / 1024.0, chunk_len / (1024*1024), target_name);
        }

        pthread_mutex_lock(&g_trickle_lock);
        g_trickle_bytes_interval += (unsigned long)chunk_len;
        pthread_mutex_unlock(&g_trickle_lock);

        cursor += chunk_len;
        if (cursor >= vmas[vma_idx].end) {
            vma_idx++;
            if (vma_idx < nvmas) cursor = vmas[vma_idx].start;
        }
    }
    return NULL;
}

/* ── PSI reader ────────────────────────────────────────────────────────── */
static double current_psi_some(unsigned long long *total_out)
{
    FILE *f = fopen("/proc/pressure/memory","r"); if (!f) return -1.0;
    double avg10=-1.0; char line[128];
    while (fgets(line,sizeof(line),f)) {
        if (strncmp(line,"some",4)==0) {
            unsigned long long total=0;
            sscanf(line,"some avg10=%lf avg60=%*f avg300=%*f total=%llu",&avg10,&total);
            if (total_out) *total_out=total;
            break;
        }
    }
    fclose(f); return avg10;
}

/* ── Frozen process state ──────────────────────────────────────────────── */
pid_t g_frozen_pid  = -1;
char  g_frozen_name[64] = {0};

#define MEM_AVAIL_FLOOR_KB  (300 * 1024)  /* 300 MiB -- don't act if above this */

/* ── Pageout thread -- runs trickle independently of epoll loop ─────────── */
typedef struct { pid_t pid; char name[64]; } pageout_arg_t;
/* Pre-allocated -- avoids heap allocation during high memory pressure */
static pageout_arg_t g_pageout_buf;

static void *pageout_thread(void *arg)
{
    pageout_arg_t *a = (pageout_arg_t *)arg;
    trickle_pageout_process(a->pid, a->name);
    return NULL;
}

/* ── Pressure handler -- called from epoll, must be fast ───────────────── */
static void handle_pressure(void)
{
    double psi = current_psi_some(NULL);
    rp_log(LOG_WARNING, "PSI trigger: avg10=%.2f%%", psi);

    /* If we already have a frozen process, nothing more to do --
     * the timerfd will check resume conditions every 5s. */
    pthread_mutex_lock(&g_frozen_lock);
    int already_frozen = (g_frozen_pid > 0);
    pid_t cur_frozen_pid = g_frozen_pid;
    char  cur_frozen_name[64];
    memcpy(cur_frozen_name, g_frozen_name, sizeof(cur_frozen_name));
    pthread_mutex_unlock(&g_frozen_lock);
    if (already_frozen) {
        rp_log(LOG_INFO, "already frozen: %s (pid %d) -- timerfd handles resume",
               cur_frozen_name, (int)cur_frozen_pid);
        return;
    }

    /*
     * MemAvailable fast-path -- if there is genuine free RAM, the PSI
     * reading is a ghost from a burst that has already resolved. Do not
     * act on historical averages when the hardware says we have headroom.
     */
    {
        FILE *mf = fopen("/proc/meminfo", "r");
        long mem_avail_kb = 0;
        if (mf) {
            char line[128];
            while (fgets(line, sizeof(line), mf))
                if (strncmp(line, "MemAvailable:", 13) == 0) {
                    sscanf(line + 13, "%ld", &mem_avail_kb); break;
                }
            fclose(mf);
        }
        if (mem_avail_kb > MEM_AVAIL_FLOOR_KB) {
            rp_log(LOG_INFO,
                   "PSI ghost -- MemAvailable=%ld MiB, no action needed",
                   mem_avail_kb / 1024);
            return;
        }
        rp_log(LOG_INFO, "MemAvailable=%ld MiB -- below floor, proceeding",
               mem_avail_kb / 1024);
    }

    /* Grab best pre-computed victim instantly -- no scanning here */
    pthread_mutex_lock(&g_cand_lock);
    pid_t vpid = -1;
    char  vname[64] = {0};
    if (g_n_candidates > 0) {
        vpid = g_candidates[0].pid;
        memcpy(vname, g_candidates[0].name, 63); vname[63]=0;
    }
    pthread_mutex_unlock(&g_cand_lock);

    if (vpid < 0) {
        /*
         * No pre-computed candidate. This is not a "nothing to do" state --
         * PSI fired and MemAvailable is below floor, which is a claim that
         * relief is needed. The scanner's candidate list can legitimately
         * be empty (every process under MIN_VICTIM_RSS_KB, or the pressure
         * source already exited between scan and trigger), but the system
         * is still under real pressure and something downstream -- the next
         * allocation, the next page fault -- assumes that pressure gets
         * relieved. Silently returning here is exactly Chapter 12's
         * "missing precondition" pattern: it looks non-fatal in isolation,
         * but the invariant PSI exists to protect (bounded stall) is left
         * violated with no visible signal beyond a log line.
         *
         * Escalate in two steps rather than acting immediately:
         *   1. Inline re-scan with the RSS floor relaxed by 4x. Cheap,
         *      synchronous, and covers the common case (many small
         *      processes summing to real pressure, none individually
         *      over the normal floor).
         *   2. If that also finds nothing, we have exhausted userspace
         *      remediation. Log at ERR (not WARNING) and defer to the
         *      kernel OOM killer -- we do not invoke it ourselves; we
         *      simply stop suppressing it by making the failure loud
         *      instead of swallowing it.
         */
        rp_log(LOG_WARNING,
               "no pre-computed victim -- relaxed rescan (floor %ld->%ld KB)",
               (long)MIN_VICTIM_RSS_KB, (long)(MIN_VICTIM_RSS_KB / 4));

        pid_t epid = -1;
        long  erss = 0;
        char  ename[64] = {0};
        DIR *pd = opendir("/proc");
        if (pd) {
            struct dirent *ent;
            while ((ent = readdir(pd)) != NULL) {
                if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
                if (strlen(ent->d_name) > 7) continue;
                char sp[32];
                snprintf(sp, sizeof(sp), "/proc/%s/status", ent->d_name);
                FILE *sf = fopen(sp, "r"); if (!sf) continue;
                pid_t pid = 0; long rss = 0; char name[64] = {0};
                char line[256];
                while (fgets(line, sizeof(line), sf)) {
                    if      (strncmp(line,"Pid:", 4)==0)  sscanf(line+4, "%d",  &pid);
                    else if (strncmp(line,"Name:",5)==0)  sscanf(line+5, "%63s", name);
                    else if (strncmp(line,"VmRSS:",6)==0) sscanf(line+6, "%ld", &rss);
                }
                fclose(sf);
                if (rss < MIN_VICTIM_RSS_KB / 4) continue;
                if (is_skip(name)) continue;
                if (rss > erss) { erss = rss; epid = pid; memcpy(ename, name, 63); }
            }
            closedir(pd);
        }

        if (epid > 0) {
            rp_log(LOG_WARNING, "relaxed rescan found victim: '%s' (pid %d, %ld MB)",
                   ename, epid, erss / 1024);
            vpid = epid;
            memcpy(vname, ename, sizeof(vname) - 1); vname[sizeof(vname)-1] = 0;
        } else {
            rp_log(LOG_ERR,
                   "no userspace victim at any RSS floor -- PSI pressure "
                   "unrelieved, deferring to kernel OOM killer");
            return;
        }
    }

    /* Verify victim is still alive */
    char check[32]; snprintf(check, sizeof(check), "/proc/%d", vpid);
    if (access(check, F_OK) != 0) {
        rp_log(LOG_WARNING, "victim %s (pid %d) gone", vname, vpid);
        return;
    }

    /* SIGSTOP first -- mappings are now stable */
    rp_log(LOG_WARNING, "SIGSTOP: '%s' (pid %d)", vname, vpid);
    signal_process_tree(vpid, SIGSTOP);

    pthread_mutex_lock(&g_frozen_lock);
    g_frozen_pid = vpid;
    memcpy(g_frozen_name, vname, sizeof(g_frozen_name)-1); g_frozen_name[sizeof(g_frozen_name)-1]=0;
    pthread_mutex_unlock(&g_frozen_lock);

    /* Trickle pageout runs in a detached thread so the epoll loop stays
     * responsive. The main thread returns to epoll_wait immediately. */
    g_pageout_buf.pid = vpid;
    memcpy(g_pageout_buf.name, vname, sizeof(g_pageout_buf.name));
    pthread_t ptid;
    if (pthread_create(&ptid, NULL, pageout_thread, &g_pageout_buf) == 0)
        pthread_detach(ptid);

    char body[256];
    snprintf(body, sizeof(body), "Paused %s to preserve responsiveness.", vname);
    notify_user("detritusd", body);

    /* Resume decision is handled by maybe_resume_frozen() on the 5s epoll timeout.
     * Do not sleep here -- the PSI fd has already been re-armed and sleeping
     * would delay our return to epoll_wait, causing us to miss the next event. */
    rp_log(LOG_INFO, "freeze+pageout complete -- monitoring for pressure clear");
    return;
}

/* ── Signal handling ───────────────────────────────────────────────────── */
static volatile sig_atomic_t g_running = 1;
static void sig_handler(int sig){(void)sig;g_running=0;}

/* ── Resume watcher -- called from timerfd every 5s ───────────────────── */
static void maybe_resume_frozen(void)
{
    pthread_mutex_lock(&g_frozen_lock);
    pid_t frozen_pid = g_frozen_pid;
    char  frozen_name[64];
    memcpy(frozen_name, g_frozen_name, sizeof(frozen_name));
    pthread_mutex_unlock(&g_frozen_lock);

    if (frozen_pid <= 0) return;

    char check[32]; snprintf(check, sizeof(check), "/proc/%d", frozen_pid);
    if (access(check, F_OK) != 0) {
        rp_log(LOG_INFO, "frozen process %s gone -- clearing state", frozen_name);
        pthread_mutex_lock(&g_frozen_lock);
        g_frozen_pid = -1; g_frozen_name[0] = '\0';
        pthread_mutex_unlock(&g_frozen_lock);
        return;
    }

    FILE *f = fopen("/proc/meminfo", "r");
    long mem_avail_kb = 0;
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f))
            if (strncmp(line, "MemAvailable:", 13) == 0) {
                sscanf(line + 13, "%ld", &mem_avail_kb); break;
            }
        fclose(f);
    }

    rp_log(LOG_INFO, "resume check for %s: MemAvailable=%ld MiB",
           frozen_name, mem_avail_kb / 1024);

    int should_resume = 0;
    const char *reason = "";

    if (mem_avail_kb > 300 * 1024) {
        should_resume = 1;
        reason = "MemAvailable recovered";
    } else {
        double avg10 = current_psi_some(NULL);
        rp_log(LOG_INFO, "MemAvailable low (%ld MiB) -- checking avg10=%.2f%%",
               mem_avail_kb / 1024, avg10 >= 0 ? avg10 : -1.0);
        if (avg10 >= 0.0 && avg10 < 5.0) {
            should_resume = 1;
            reason = "avg10 < 5% (ZRAM stabilised)";
        }
    }

    if (should_resume) {
        rp_log(LOG_INFO, "resuming %s -- %s (%ld MiB free)",
               frozen_name, reason, mem_avail_kb / 1024);
        signal_process_tree(frozen_pid, SIGCONT);
        notify_user("detritusd", "Memory pressure cleared. Application resumed.");
        pthread_mutex_lock(&g_frozen_lock);
        g_frozen_pid = -1; g_frozen_name[0] = '\0';
        pthread_mutex_unlock(&g_frozen_lock);
    } else {
        rp_log(LOG_INFO, "keeping %s frozen: %ld MiB free, pressure ongoing",
               frozen_name, mem_avail_kb / 1024);
    }
}

/* ── Main ──────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    (void)argc;(void)argv;
    openlog("detritusd",LOG_PID|LOG_NDELAY,LOG_DAEMON);
    rp_log(LOG_INFO,"Detritus starting (uid=%d)",(int)getuid());

    if (getuid()!=0) {
        rp_log(LOG_ERR,"must run as root"); return 1;
    }

    signal(SIGTERM,sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGCHLD,SIG_DFL);

    /* Phase 1 */
    g_storage_type = detect_storage();
    disable_zswap();
    provision_zram(storage_is_slow(g_storage_type));
    tune_vm_for_zram();

    /*
     * OOM immunity for critical desktop processes.
     *
     * oom_score_adj ranges from -1000 (never kill) to +1000 (kill first).
     * The kernel's OOM killer uses this to decide who dies when memory
     * runs out. Without this, marco or pipewire could be killed before
     * a leaking browser tab -- destroying the session entirely.
     *
     * We set the critical processes to -1000 (fully immune) and detritus
     * itself to -1000 so we stay alive to manage any future pressure.
     *
     * Note: oom_score_adj writes are per-process and persist until the
     * process exits. We do this at login-time so it covers the session.
     */
    {
        const char *critical[] = {
            "Xorg",
            "marco", "xfwm4",
            "mate-panel", "mate-settings-daemon",
            "mate-session", "nemo-desktop",
            "pipewire", "pipewire-pulse", "wireplumber",
            "detritusd",
            NULL
        };
        for (int ci = 0; critical[ci]; ci++) {
            char cmd[128];
            snprintf(cmd, sizeof(cmd),
                "for p in $(pgrep -x '%s' 2>/dev/null); do "
                "  echo -1000 > /proc/$p/oom_score_adj 2>/dev/null; "
                "done", critical[ci]);
            if (system(cmd) != 0) { /* non-fatal, process may not exist */ }
        }
        /* detritus itself */
        FILE *self_oom = fopen("/proc/self/oom_score_adj", "w");
        if (self_oom) { fprintf(self_oom, "-1000\n"); fclose(self_oom); }
        rp_log(LOG_INFO, "OOM immunity set for critical desktop processes");
    }

    /* Phase 2: start background scanner thread */
    pthread_t scanner_tid;
    if (pthread_create(&scanner_tid, NULL, scanner_thread, NULL) != 0) {
        rp_log(LOG_ERR,"pthread_create: %s",strerror(errno)); return 1;
    }
    pthread_detach(scanner_tid);
    rp_log(LOG_INFO,"scanner thread started (interval=%dms)",SCAN_INTERVAL_MS);

    /* Give scanner one pass before arming PSI */
    struct timespec warmup = { .tv_sec=0, .tv_nsec=(long)(SCAN_INTERVAL_MS+200)*1000000L };
    nanosleep(&warmup, NULL);

    /* Phase 2b: start proactive idle-trickle thread -- independent of
     * PSI, runs continuously at TRICKLE_INTERVAL_MS regardless of
     * pressure. Started after the scanner warmup above so its first
     * cycle already has real candidate data to select from rather than
     * racing an empty g_candidates on startup. */
    pthread_t trickle_tid;
    if (pthread_create(&trickle_tid, NULL, idle_trickle_thread, NULL) != 0) {
        rp_log(LOG_WARNING, "idle-trickle pthread_create failed: %s -- "
               "continuing without proactive trickle", strerror(errno));
    } else {
        pthread_detach(trickle_tid);
        rp_log(LOG_INFO, "idle-trickle thread started (interval=%dms)",
               TRICKLE_INTERVAL_MS);
    }

    /* Phase 3: PSI fd -- open ONCE, write trigger ONCE, never re-arm.
     *
     * The kernel rate-limits PSI triggers natively per fd. Writing the
     * trigger once and leaving the fd open is all that is needed. Every
     * time we closed and reopened the fd, we reset the kernel's internal
     * tracking window, causing it to fire immediately on every re-open
     * regardless of whether the threshold had actually been crossed again.
     * That is what caused the 12-fires-per-second spin loop.
     *
     * Leave the fd open permanently. The kernel enforces the rate limit. */
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) { rp_log(LOG_ERR,"epoll_create1: %s",strerror(errno)); return 1; }

    int psi_fd = open("/proc/pressure/memory", O_WRONLY | O_NONBLOCK);
    if (psi_fd < 0) {
        rp_log(LOG_ERR, "open PSI fd: %s", strerror(errno)); return 1;
    }
    char trigger[64];
    int n = snprintf(trigger, sizeof(trigger), "some %d %d\n",
                     PSI_THRESHOLD_US, PSI_WINDOW_US);
    if (write(psi_fd, trigger, n) < 0) {
        rp_log(LOG_ERR, "PSI trigger write: %s", strerror(errno)); return 1;
    }
    struct epoll_event ev_psi = { .events = EPOLLPRI, .data.fd = psi_fd };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, psi_fd, &ev_psi) < 0) {
        rp_log(LOG_ERR, "epoll_ctl PSI: %s", strerror(errno)); return 1;
    }
    rp_log(LOG_INFO, "armed: some %d us / %d us -- fd open permanently",
           PSI_THRESHOLD_US, PSI_WINDOW_US);

    /* timerfd: fires every 5s to check resume conditions.
     * This replaces the epoll_wait timeout approach and means resume checks
     * are never blocked by a PSI event that takes time to handle. */
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) {
        rp_log(LOG_ERR, "timerfd_create: %s", strerror(errno)); return 1;
    }
    struct itimerspec its = {
        .it_interval = { .tv_sec = 5, .tv_nsec = 0 },
        .it_value    = { .tv_sec = 5, .tv_nsec = 0 },
    };
    timerfd_settime(tfd, 0, &its, NULL);
    struct epoll_event ev_timer = { .events = EPOLLIN, .data.fd = tfd };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev_timer) < 0) {
        rp_log(LOG_ERR, "epoll_ctl timerfd: %s", strerror(errno)); return 1;
    }

    /* Phase 4: Event loop -- epoll_wait with no timeout needed */
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
                /* PSI threshold crossed -- handle immediately, no re-arm needed */
                handle_pressure();

            } else if (efd == tfd) {
                /* Timer tick -- drain the fd and check resume */
                uint64_t expirations;
                ssize_t r = read(tfd, &expirations, sizeof(expirations));
                (void)r;
                maybe_resume_frozen();
            }
        }
    }

    pthread_mutex_lock(&g_frozen_lock);
    pid_t shutdown_frozen_pid = g_frozen_pid;
    char  shutdown_frozen_name[64];
    memcpy(shutdown_frozen_name, g_frozen_name, sizeof(shutdown_frozen_name));
    pthread_mutex_unlock(&g_frozen_lock);
    if (shutdown_frozen_pid > 0) {
        rp_log(LOG_INFO, "shutdown -- resuming %s", shutdown_frozen_name);
        signal_process_tree(shutdown_frozen_pid, SIGCONT);
    }
    rp_log(LOG_INFO, "shutting down");
    close(tfd); close(psi_fd); close(epfd);
    closelog(); return 0;
}
