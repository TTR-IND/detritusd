/*
 * ╔══════════════════════════════════════════════════════════════╗
 * ║                                                              ║
 * ║   ████████╗████████╗██████╗       ██╗███╗   ██╗██████╗       ║
 * ║   ╚══██╔══╝╚══██╔══╝██╔══██╗      ██║████╗  ██║██╔══██╗      ║
 * ║      ██║      ██║   ██████╔╝      ██║██╔██╗ ██║██║  ██║      ║
 * ║      ██║      ██║   ██╔══██╗      ██║██║╚██╗██║██║  ██║      ║
 * ║      ██║      ██║   ██║  ██║      ██║██║ ╚████║██████╔╝      ║
 * ║      ╚═╝      ╚═╝   ╚═╝  ╚═╝      ╚═╝╚═╝  ╚═══╝╚═════╝       ║
 * ║                                                              ║
 * ║       Torfaen Technology Research — IND                      ║
 * ║       Copyright © 2026                                       ║
 * ║       Licensed under Apache License 2.0                      ║
 * ║                                                              ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * detritus.c -- Event-Driven Memory Manager for Linux
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
#define PSI_THRESHOLD_US    5000   /* 5ms stall within 200ms window */
#define PSI_WINDOW_US     200000

#define MIN_VICTIM_RSS_KB (50*1024)

#define ZRAM_RATIO_SLOW    0.40    /* HDD/eMMC */
#define ZRAM_RATIO_FAST    0.10    /* NVMe/SSD */

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

/* Disable zswap so zram is the sole compression layer. */
static void disable_zswap(void)
{
    const char *zswap_enabled = "/sys/module/zswap/parameters/enabled";
    if (access(zswap_enabled, F_OK) != 0) return;

    FILE *f = fopen(zswap_enabled, "r");
    if (f) {
        char cur[8] = {0};
        if (fgets(cur, sizeof(cur), f)) {
            if (cur[0] == 'N') { fclose(f); rp_log(LOG_INFO, "zswap already disabled"); return; }
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
            if (strstr(line, "zram")) { rp_log(LOG_INFO, "ZRAM already active -- skipping"); fclose(sw); return; }
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
        if (access("/sys/block/zram0", F_OK) != 0) { rp_log(LOG_ERR, "zram0 did not appear"); return; }
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
    /* Disable partition swap */
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

/* ── Victim selection ──────────────────────────────────────────────────── */
#define MAX_CANDIDATES 8

typedef struct {
    pid_t pid;
    long  rss_kb;
    char  name[64];
    int   coldness_pct;
} candidate_t;

static const char *SKIP_NAMES[] = {
    "Xorg", "marco", "xfwm4", "kwin_x11", "kwin_wayland", "mutter",
    "mate-panel", "mate-settings-d", "mate-session", "nemo-desktop",
    "pipewire", "pipewire-pulse", "wireplumber", "ibus-daemon", "fcitx", "fcitx5",
    "detritusd", "oom_drill", "stress", "stress-ng",
    NULL
};

static int is_skip(const char *name)
{
    for (int i = 0; SKIP_NAMES[i]; i++)
        if (strcmp(name, SKIP_NAMES[i]) == 0) return 1;
    return 0;
}

/* Read Rss and Referenced from smaps_rollup. Returns 0 on success. */
static int read_coldness(pid_t pid, long *rss_kb, long *referenced_kb)
{
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/smaps_rollup", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    *rss_kb = -1; *referenced_kb = -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Rss:", 4) == 0) sscanf(line + 4, "%ld", rss_kb);
        else if (strncmp(line, "Referenced:", 11) == 0) sscanf(line + 11, "%ld", referenced_kb);
    }
    fclose(f);
    return (*rss_kb >= 0 && *referenced_kb >= 0) ? 0 : -1;
}

/* Walk /proc once, rank by coldness, return coldest-first. */
static int select_cold_victims(candidate_t *out, int max_out)
{
    int n_found = 0;
    DIR *pd = opendir("/proc");
    if (!pd) return 0;
    struct dirent *ent;
    while ((ent = readdir(pd)) != NULL) {
        if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(ent->d_name);
        if (pid <= 0) continue;

        char statusp[32];
        snprintf(statusp, sizeof(statusp), "/proc/%d/status", pid);
        FILE *sf = fopen(statusp, "r");
        if (!sf) continue;
        char name[64] = {0};
        char line[256];
        while (fgets(line, sizeof(line), sf))
            if (strncmp(line, "Name:", 5) == 0) { sscanf(line + 5, "%63s", name); break; }
        fclose(sf);
        if (is_skip(name)) continue;

        long rss_kb, referenced_kb;
        if (read_coldness(pid, &rss_kb, &referenced_kb) != 0) continue;
        if (rss_kb < MIN_VICTIM_RSS_KB) continue;

        int coldness = (rss_kb > 0) ? (int)(100 - (referenced_kb * 100 / rss_kb)) : 0;
        if (coldness < 0) coldness = 0;
        if (coldness > 100) coldness = 100;

        int j = n_found < max_out ? n_found : max_out - 1;
        if (n_found < max_out) n_found++;
        while (j > 0 && out[j-1].coldness_pct < coldness) {
            if (j < max_out) out[j] = out[j-1];
            j--;
        }
        if (j < max_out) {
            out[j].pid = pid; out[j].rss_kb = rss_kb; out[j].coldness_pct = coldness;
            memcpy(out[j].name, name, sizeof(out[j].name) - 1);
            out[j].name[sizeof(out[j].name) - 1] = '\0';
        }
    }
    closedir(pd);
    return n_found;
}

static double current_psi_some(unsigned long long *total_out);
extern pid_t g_frozen_pid;
extern char  g_frozen_name[64];

static unsigned long g_trickle_bytes_interval = 0;
static pthread_mutex_t g_trickle_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Status file ───────────────────────────────────────────────────────── */
#define DETRITUS_STATUS_DIR  "/run/detritus"
#define DETRITUS_STATUS_PATH DETRITUS_STATUS_DIR "/status.json"
#define DETRITUS_SCHEMA_VERSION 1
#define GONZOCACHE_PRELOADED_LIST "/var/lib/gonzocache/preloaded.list"

static pthread_mutex_t g_frozen_lock = PTHREAD_MUTEX_INITIALIZER;

/* Sum page-cache residency across GonzoCache preloaded files using mincore(). */
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

static void write_status_file(const candidate_t *candidates, int n_candidates)
{
    static int dir_ready = 0;
    if (!dir_ready) { mkdir(DETRITUS_STATUS_DIR, 0755); chmod(DETRITUS_STATUS_DIR, 0755); dir_ready = 1; }

    char tmp_path[64];
    snprintf(tmp_path, sizeof(tmp_path), DETRITUS_STATUS_DIR "/.status.XXXXXX");
    int fd = mkstemp(tmp_path);
    if (fd < 0) { rp_log(LOG_WARNING, "status file: mkstemp failed: %s", strerror(errno)); return; }
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
                if (strncmp(line, "MemAvailable:", 13) == 0) { sscanf(line + 13, "%ld", &mem_avail_kb); break; }
            fclose(mf);
        }
    }

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

    pthread_mutex_lock(&g_trickle_lock);
    unsigned long trickle_bytes = g_trickle_bytes_interval;
    g_trickle_bytes_interval = 0;
    pthread_mutex_unlock(&g_trickle_lock);

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
        DETRITUS_SCHEMA_VERSION, (long)now, psi_avg10 >= 0 ? psi_avg10 : 0.0, psi_total,
        trickle_bytes, mem_rate_kb_per_sec, gonzocache_resident_kb,
        memtotal_kb, mem_avail_kb, storage_type_name(g_storage_type),
        frozen_pid > 0 ? "true" : "false");

    if (frozen_pid > 0)
        fprintf(f, "  \"frozen_pid\": %d,\n  \"frozen_name\": \"%s\",\n", (int)frozen_pid, frozen_name);

    fprintf(f, "  \"candidates\": [\n");
    for (int i = 0; i < n_candidates; i++)
        fprintf(f, "    { \"pid\": %d, \"name\": \"%s\", \"rss_kb\": %ld, \"coldness_pct\": %d }%s\n",
            (int)candidates[i].pid, candidates[i].name, candidates[i].rss_kb,
            candidates[i].coldness_pct, (i == n_candidates - 1) ? "" : ",");
    fprintf(f, "  ]\n}\n");

    fflush(f); fsync(fd); fclose(f);
    if (rename(tmp_path, DETRITUS_STATUS_PATH) != 0) {
        rp_log(LOG_WARNING, "status file: rename failed: %s", strerror(errno));
        unlink(tmp_path);
    }
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

#define PAGEOUT_CHUNK        (256 * 1024)
#define PAGEOUT_YIELD_HIGH_US   100000
#define PAGEOUT_YIELD_MED_US    250000
#define PAGEOUT_YIELD_LOW_US    500000
#define PAGEOUT_STALL_THRESH_US   2000
#define EVAL_STRIDE          (8 * PAGEOUT_CHUNK)
#define IOV_BATCH            16

typedef struct { uintptr_t start; uintptr_t end; } vma_t;

/* Collect anonymous private writable VMAs. */
static int collect_reclaimable_vmas(pid_t pid, vma_t *vmas, int max_vmas)
{
    char maps_path[32];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
#pragma GCC diagnostic pop
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;
    int nvmas = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && nvmas < max_vmas) {
        uintptr_t start, end, offset; unsigned long inode;
        char perms[8]={0}, dev[16]={0}, rest[128]={0};
        if (sscanf(line, "%lx-%lx %7s %lx %15s %lu %127[^\n]",
                   &start, &end, perms, &offset, dev, &inode, rest) < 6) continue;
        if (perms[0]!='r'||perms[1]!='w'||perms[3]!='p') continue;
        if (inode != 0 || strcmp(dev,"00:00") != 0) continue;
        char *nm = rest; while (*nm==' ') nm++;
        if (strncmp(nm,"[v",2)==0) continue;
        if (end - start < 65536) continue;
        vmas[nvmas].start = start; vmas[nvmas].end = end; nvmas++;
    }
    fclose(f);
    return nvmas;
}

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

/* Trickle MADV_PAGEOUT with AIMD yield controller. */
static void trickle_pageout_process(pid_t pid, const char *name)
{
    setpriority(PRIO_PROCESS, 0, 19);
    syscall(SYS_ioprio_set, 1, 0, (3 << 13) | 0);

    int pidfd = (int)syscall(SYS_pidfd_open, (long)pid, 0);
    if (pidfd < 0) { rp_log(LOG_WARNING, "pidfd_open(%d): %s", pid, strerror(errno)); goto done; }

    vma_t vmas[512];
    int nvmas = collect_reclaimable_vmas(pid, vmas, 512);
    if (nvmas == 0) { close(pidfd); goto done; }

    long total_bytes = 0;
    int chunks = 0;
    long bytes_since_eval = 0;
    int yield_us = PAGEOUT_YIELD_MED_US;
    unsigned long long psi_baseline = read_psi_total();

    /* Initial system state evaluation */
    {
        long mem_now_kb = 0;
        FILE *mf = fopen("/proc/meminfo", "r");
        if (mf) {
            char mline[128];
            while (fgets(mline, sizeof(mline), mf))
                if (strncmp(mline, "MemAvailable:", 13) == 0) { sscanf(mline + 13, "%ld", &mem_now_kb); break; }
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
            if (bytes_since_eval >= EVAL_STRIDE) {
                unsigned long long psi_now = read_psi_total();
                unsigned long long stall = psi_now - psi_baseline;
                psi_baseline = psi_now; bytes_since_eval = 0;

                long mem_now_kb = 0;
                FILE *mf = fopen("/proc/meminfo", "r");
                if (mf) {
                    char mline[128];
                    while (fgets(mline, sizeof(mline), mf))
                        if (strncmp(mline, "MemAvailable:", 13) == 0) { sscanf(mline + 13, "%ld", &mem_now_kb); break; }
                    fclose(mf);
                }
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
                iov[niov].iov_base = (void *)cursor; iov[niov].iov_len = len;
                niov++; cursor += len; batch_len += len;
            }

            long ret = syscall(SYS_process_madvise, pidfd, iov, niov, MADV_PAGEOUT, 0);
            if (ret == 0) { total_bytes += (long)batch_len; bytes_since_eval += (long)batch_len; chunks += niov; }
            else if (errno == ENOSYS) { rp_log(LOG_WARNING, "process_madvise: needs kernel 5.10+"); close(pidfd); goto done; }

            struct timespec ts = { .tv_sec = yield_us / 1000000, .tv_nsec = (yield_us % 1000000) * 1000L };
            nanosleep(&ts, NULL);
        }
    }
    close(pidfd);
    rp_log(LOG_INFO, "trickle pageout: %ld MiB of '%s' -> ZRAM  chunks=%d", total_bytes / (1024*1024), name, chunks);
done:
    setpriority(PRIO_PROCESS, 0, 0);
}

/* ── Idle trickle thread ───────────────────────────────────────────────── */
#define TRICKLE_INTERVAL_MS      400
#define TRICKLE_CHUNK_BYTES      (2 * 1024 * 1024)
#define TRICKLE_COLDNESS_FLOOR   15
#define TRICKLE_FILL_CALM_KB_PER_SEC    (5 * 1024)
#define SCAN_REFRESH_CYCLES 5

static size_t adaptive_chunk_bytes(double fill_rate_kb_per_sec)
{
    if (fill_rate_kb_per_sec <= TRICKLE_FILL_CALM_KB_PER_SEC) return TRICKLE_CHUNK_BYTES;
    double multiplier = fill_rate_kb_per_sec / (double)TRICKLE_FILL_CALM_KB_PER_SEC;
    return (size_t)((double)TRICKLE_CHUNK_BYTES * multiplier);
}

static void *idle_trickle_thread(void *arg)
{
    (void)arg;
    setpriority(PRIO_PROCESS, 0, 19);
    syscall(SYS_ioprio_set, 1, 0, (3 << 13) | 0);

    struct timespec cycle = { .tv_sec = TRICKLE_INTERVAL_MS / 1000, .tv_nsec = (TRICKLE_INTERVAL_MS % 1000) * 1000000L };
    pid_t last_pid = -1;
    vma_t vmas[512];
    int nvmas = 0, vma_idx = 0;
    uintptr_t cursor = 0;
    long prev_avail_kb = -1;
    struct timespec prev_sample_ts = {0, 0};

    candidate_t cached_candidates[MAX_CANDIDATES];
    int cached_n_candidates = 0;
    int cycles_since_scan = SCAN_REFRESH_CYCLES;

    for (;;) {
        nanosleep(&cycle, NULL);

        long mem_avail_kb = 0;
        FILE *mf = fopen("/proc/meminfo", "r");
        if (mf) {
            char mline[128];
            while (fgets(mline, sizeof(mline), mf))
                if (strncmp(mline, "MemAvailable:", 13) == 0) { sscanf(mline + 13, "%ld", &mem_avail_kb); break; }
            fclose(mf);
        }

        struct timespec now_ts;
        clock_gettime(CLOCK_MONOTONIC, &now_ts);
        double fill_rate_kb_per_sec = 0.0;
        if (prev_avail_kb >= 0) {
            double elapsed_sec = (now_ts.tv_sec - prev_sample_ts.tv_sec) + (now_ts.tv_nsec - prev_sample_ts.tv_nsec) / 1e9;
            if (elapsed_sec > 0.01) {
                double delta_kb = (double)(prev_avail_kb - mem_avail_kb);
                if (delta_kb > 0) fill_rate_kb_per_sec = delta_kb / elapsed_sec;
            }
        }
        prev_avail_kb = mem_avail_kb; prev_sample_ts = now_ts;

        size_t chunk_ceiling = adaptive_chunk_bytes(fill_rate_kb_per_sec);

        cycles_since_scan++;
        if (cycles_since_scan >= SCAN_REFRESH_CYCLES) {
            cached_n_candidates = select_cold_victims(cached_candidates, MAX_CANDIDATES);
            write_status_file(cached_candidates, cached_n_candidates);
            cycles_since_scan = 0;
        }

        candidate_t *candidates = cached_candidates;
        int n_candidates = cached_n_candidates;
        pid_t target_pid = -1;
        char target_name[64] = {0};
        if (n_candidates > 0 && candidates[0].coldness_pct >= TRICKLE_COLDNESS_FLOOR) {
            target_pid = candidates[0].pid;
            memcpy(target_name, candidates[0].name, sizeof(target_name) - 1);
        }
        if (target_pid <= 0) continue;

        if (target_pid != last_pid) {
            nvmas = collect_reclaimable_vmas(target_pid, vmas, 512);
            vma_idx = 0; cursor = (nvmas > 0) ? vmas[0].start : 0; last_pid = target_pid;
            if (nvmas == 0) continue;
        }
        if (vma_idx >= nvmas) { vma_idx = 0; cursor = vmas[0].start; }

        int pidfd = (int)syscall(SYS_pidfd_open, (long)target_pid, 0);
        if (pidfd < 0) { last_pid = -1; continue; }

        size_t remaining = vmas[vma_idx].end - cursor;
        size_t chunk_len = (remaining < chunk_ceiling) ? remaining : chunk_ceiling;

        struct iovec iov = { .iov_base = (void *)cursor, .iov_len = chunk_len };
        long ret = syscall(SYS_process_madvise, pidfd, &iov, 1, MADV_COLD, 0);
        close(pidfd);

        if (ret < 0) {
            if (errno == ENOSYS) { rp_log(LOG_WARNING, "idle-trickle: process_madvise needs kernel 5.10+, stopping"); return NULL; }
            last_pid = -1; continue;
        }

        if (chunk_ceiling > TRICKLE_CHUNK_BYTES)
            rp_log(LOG_INFO, "idle-trickle: fill rate %.1f MB/s -- scaled chunk to %zu MB (%s)",
                   fill_rate_kb_per_sec / 1024.0, chunk_len / (1024*1024), target_name);

        pthread_mutex_lock(&g_trickle_lock);
        g_trickle_bytes_interval += (unsigned long)chunk_len;
        pthread_mutex_unlock(&g_trickle_lock);

        cursor += chunk_len;
        if (cursor >= vmas[vma_idx].end) { vma_idx++; if (vma_idx < nvmas) cursor = vmas[vma_idx].start; }
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

#define MEM_AVAIL_FLOOR_KB  (300 * 1024)

/* ── Pageout thread ────────────────────────────────────────────────────── */
typedef struct { pid_t pid; char name[64]; } pageout_arg_t;
static pageout_arg_t g_pageout_buf;

static void *pageout_thread(void *arg)
{
    pageout_arg_t *a = (pageout_arg_t *)arg;
    trickle_pageout_process(a->pid, a->name);
    return NULL;
}

/* ── Pressure handler ──────────────────────────────────────────────────── */
static void handle_pressure(void)
{
    double psi = current_psi_some(NULL);
    rp_log(LOG_WARNING, "PSI trigger: avg10=%.2f%%", psi);

    pthread_mutex_lock(&g_frozen_lock);
    int already_frozen = (g_frozen_pid > 0);
    pid_t cur_frozen_pid = g_frozen_pid;
    char  cur_frozen_name[64];
    memcpy(cur_frozen_name, g_frozen_name, sizeof(cur_frozen_name));
    pthread_mutex_unlock(&g_frozen_lock);
    if (already_frozen) { rp_log(LOG_INFO, "already frozen: %s (pid %d)", cur_frozen_name, (int)cur_frozen_pid); return; }

    /* MemAvailable fast-path */
    {
        FILE *mf = fopen("/proc/meminfo", "r");
        long mem_avail_kb = 0;
        if (mf) {
            char line[128];
            while (fgets(line, sizeof(line), mf))
                if (strncmp(line, "MemAvailable:", 13) == 0) { sscanf(line + 13, "%ld", &mem_avail_kb); break; }
            fclose(mf);
        }
        if (mem_avail_kb > MEM_AVAIL_FLOOR_KB) { rp_log(LOG_INFO, "PSI ghost -- MemAvailable=%ld MiB", mem_avail_kb / 1024); return; }
        rp_log(LOG_INFO, "MemAvailable=%ld MiB -- below floor", mem_avail_kb / 1024);
    }

    candidate_t candidates[MAX_CANDIDATES];
    int n_candidates = select_cold_victims(candidates, MAX_CANDIDATES);

    pid_t vpid = -1;
    char  vname[64] = {0};
    if (n_candidates > 0) { vpid = candidates[0].pid; memcpy(vname, candidates[0].name, 63); vname[63]=0; }

    if (vpid < 0) {
        rp_log(LOG_WARNING, "no victim found -- relaxed rescan");
        pid_t epid = -1; long erss = 0; char ename[64] = {0};
        DIR *pd = opendir("/proc");
        if (pd) {
            struct dirent *ent;
            while ((ent = readdir(pd)) != NULL) {
                if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
                if (strlen(ent->d_name) > 7) continue;
                char sp[32]; snprintf(sp, sizeof(sp), "/proc/%s/status", ent->d_name);
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
        if (epid > 0) { vpid = epid; memcpy(vname, ename, sizeof(vname) - 1); vname[sizeof(vname)-1] = 0; }
        else { rp_log(LOG_ERR, "no userspace victim -- deferring to kernel OOM killer"); return; }
    }

    char check[32]; snprintf(check, sizeof(check), "/proc/%d", vpid);
    if (access(check, F_OK) != 0) { rp_log(LOG_WARNING, "victim %s gone", vname); return; }

    rp_log(LOG_WARNING, "SIGSTOP: '%s' (pid %d)", vname, vpid);
    signal_process_tree(vpid, SIGSTOP);

    pthread_mutex_lock(&g_frozen_lock);
    g_frozen_pid = vpid;
    memcpy(g_frozen_name, vname, sizeof(g_frozen_name)-1); g_frozen_name[sizeof(g_frozen_name)-1]=0;
    pthread_mutex_unlock(&g_frozen_lock);

    g_pageout_buf.pid = vpid;
    memcpy(g_pageout_buf.name, vname, sizeof(g_pageout_buf.name));
    pthread_t ptid;
    if (pthread_create(&ptid, NULL, pageout_thread, &g_pageout_buf) == 0) pthread_detach(ptid);

    char body[256];
    snprintf(body, sizeof(body), "Paused %s to preserve responsiveness.", vname);
    notify_user("detritusd", body);
    rp_log(LOG_INFO, "freeze+pageout complete -- monitoring for pressure clear");
}

/* ── Signal handling ───────────────────────────────────────────────────── */
static volatile sig_atomic_t g_running = 1;
static void sig_handler(int sig){(void)sig;g_running=0;}

/* ── Resume watcher ────────────────────────────────────────────────────── */
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
        rp_log(LOG_INFO, "frozen process %s gone", frozen_name);
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
            if (strncmp(line, "MemAvailable:", 13) == 0) { sscanf(line + 13, "%ld", &mem_avail_kb); break; }
        fclose(f);
    }

    rp_log(LOG_INFO, "resume check for %s: MemAvailable=%ld MiB", frozen_name, mem_avail_kb / 1024);

    int should_resume = 0;
    const char *reason = "";
    if (mem_avail_kb > 300 * 1024) { should_resume = 1; reason = "MemAvailable recovered"; }
    else {
        double avg10 = current_psi_some(NULL);
        if (avg10 >= 0.0 && avg10 < 5.0) { should_resume = 1; reason = "avg10 < 5% (ZRAM stabilised)"; }
    }

    if (should_resume) {
        rp_log(LOG_INFO, "resuming %s -- %s (%ld MiB free)", frozen_name, reason, mem_avail_kb / 1024);
        signal_process_tree(frozen_pid, SIGCONT);
        notify_user("detritusd", "Memory pressure cleared. Application resumed.");
        pthread_mutex_lock(&g_frozen_lock);
        g_frozen_pid = -1; g_frozen_name[0] = '\0';
        pthread_mutex_unlock(&g_frozen_lock);
    } else {
        rp_log(LOG_INFO, "keeping %s frozen: %ld MiB free, pressure ongoing", frozen_name, mem_avail_kb / 1024);
    }
}

/* ── Main ──────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    (void)argc;(void)argv;
    openlog("detritusd",LOG_PID|LOG_NDELAY,LOG_DAEMON);
    rp_log(LOG_INFO,"Detritus starting (uid=%d)",(int)getuid());

    if (getuid()!=0) { rp_log(LOG_ERR,"must run as root"); return 1; }

    signal(SIGTERM,sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGCHLD,SIG_DFL);

    g_storage_type = detect_storage();
    disable_zswap();
    provision_zram(storage_is_slow(g_storage_type));
    tune_vm_for_zram();

    /* OOM immunity for critical desktop processes */
    {
        const char *critical[] = {
            "Xorg", "marco", "xfwm4", "mate-panel", "mate-settings-daemon",
            "mate-session", "nemo-desktop", "pipewire", "pipewire-pulse",
            "wireplumber", "detritusd", NULL
        };
        for (int ci = 0; critical[ci]; ci++) {
            char cmd[128];
            snprintf(cmd, sizeof(cmd),
                "for p in $(pgrep -x '%s' 2>/dev/null); do "
                "  echo -1000 > /proc/$p/oom_score_adj 2>/dev/null; done", critical[ci]);
            if (system(cmd) != 0) { /* non-fatal */ }
        }
        FILE *self_oom = fopen("/proc/self/oom_score_adj", "w");
        if (self_oom) { fprintf(self_oom, "-1000\n"); fclose(self_oom); }
        rp_log(LOG_INFO, "OOM immunity set for critical desktop processes");
    }

    pthread_t trickle_tid;
    if (pthread_create(&trickle_tid, NULL, idle_trickle_thread, NULL) != 0)
        rp_log(LOG_WARNING, "idle-trickle pthread_create failed: %s", strerror(errno));
    else { pthread_detach(trickle_tid); rp_log(LOG_INFO, "idle-trickle thread started (interval=%dms)", TRICKLE_INTERVAL_MS); }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) { rp_log(LOG_ERR,"epoll_create1: %s",strerror(errno)); return 1; }

    int psi_fd = open("/proc/pressure/memory", O_WRONLY | O_NONBLOCK);
    if (psi_fd < 0) { rp_log(LOG_ERR, "open PSI fd: %s", strerror(errno)); return 1; }
    char trigger[64];
    int n = snprintf(trigger, sizeof(trigger), "some %d %d\n", PSI_THRESHOLD_US, PSI_WINDOW_US);
    if (write(psi_fd, trigger, n) < 0) { rp_log(LOG_ERR, "PSI trigger write: %s", strerror(errno)); return 1; }
    struct epoll_event ev_psi = { .events = EPOLLPRI, .data.fd = psi_fd };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, psi_fd, &ev_psi) < 0) { rp_log(LOG_ERR, "epoll_ctl PSI: %s", strerror(errno)); return 1; }
    rp_log(LOG_INFO, "armed: some %d us / %d us", PSI_THRESHOLD_US, PSI_WINDOW_US);

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) { rp_log(LOG_ERR, "timerfd_create: %s", strerror(errno)); return 1; }
    struct itimerspec its = { .it_interval = { .tv_sec = 5 }, .it_value = { .tv_sec = 5 } };
    timerfd_settime(tfd, 0, &its, NULL);
    struct epoll_event ev_timer = { .events = EPOLLIN, .data.fd = tfd };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev_timer) < 0) { rp_log(LOG_ERR, "epoll_ctl timerfd: %s", strerror(errno)); return 1; }

    while (g_running) {
        struct epoll_event events[4];
        int nfds = epoll_wait(epfd, events, 4, -1);
        if (nfds < 0) { if (errno == EINTR) continue; rp_log(LOG_ERR, "epoll_wait: %s", strerror(errno)); break; }
        for (int i = 0; i < nfds; i++) {
            int efd = events[i].data.fd;
            if (efd == psi_fd) handle_pressure();
            else if (efd == tfd) { uint64_t expirations; read(tfd, &expirations, sizeof(expirations)); maybe_resume_frozen(); }
        }
    }

    pthread_mutex_lock(&g_frozen_lock);
    pid_t shutdown_frozen_pid = g_frozen_pid;
    char  shutdown_frozen_name[64];
    memcpy(shutdown_frozen_name, g_frozen_name, sizeof(shutdown_frozen_name));
    pthread_mutex_unlock(&g_frozen_lock);
    if (shutdown_frozen_pid > 0) { rp_log(LOG_INFO, "shutdown -- resuming %s", shutdown_frozen_name); signal_process_tree(shutdown_frozen_pid, SIGCONT); }
    rp_log(LOG_INFO, "shutting down");
    close(tfd); close(psi_fd); close(epfd);
    closelog(); return 0;
}