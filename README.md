# detritusd

A small helper daemon for the memory management Linux already has.

The kernel already does the real work: `kswapd` and the page LRU
reclaim cold memory, and PSI tells userspace when a process is
genuinely stalled waiting on memory. detritusd does not replace that.
It adds the policy the kernel does not have on its own:

1. Treat ZRAM as a finite compressed buffer, not a second RAM.
2. Nudge cold pages toward reclaim only while that buffer has room.
3. Prefault those pages back out of ZRAM when RAM is comfortable.
4. Freeze a stable victim when PSI says a real stall is happening
   and ZRAM still has room.
5. Discard — `SIGKILL` — when compression cannot free anything.
   That is the name. A frozen process still owns its ZRAM slots.
   Only killing it releases them.

Compression is a delay. The policy is discarding detritus so the
session stays alive.

See the file header in `detritus.c` for the reasoning behind each
design choice.

## Why this revision exists

The previous detritusd release would fill ZRAM over several days of a
long-lived browser (YouTube in the background is enough) and never
empty it. After about a week the compressed device was full, kswapd
had nowhere to put anonymous pages, and the machine stalled — the
exact failure the daemon was written to prevent.

The cause was architectural, not a missed tunable:

- `vm.swappiness=100` made kswapd treat ZRAM as eager secondary RAM.
- The idle `MADV_COLD` trickle continuously marked background heaps
  reclaimable, so kswapd kept feeding ZRAM even when nothing was
  stalling.
- Nothing ever pulled pages back out. Pages leave ZRAM only on fault,
  `MADV_WILLNEED`, or process exit. A week-old Chrome process exits
  none of those for its dead generations.

rookpager, the earlier proof of concept, avoided the fill because it
had no idle COLD trickle and it refused to page out processes that
were still growing. It also had no drain path. Combined, that meant
ZRAM only moved on genuine PSI events — which is why it did not die
the same way, and also why it did less work before a stall.

This tree keeps detritusd's coldness ranking, status file, zswap
disable, and packaging, and rookpager's growth exclusion plus
pre-ranked PSI path. It adds the governor, the drain loop, and the
discard path the name always implied.

## How it works

Five verbs, one process.

**Observe (2s).** A worker thread snapshots `MemAvailable`, PSI,
`/sys/block/zramN/mm_stat`, and a short victim list. The PSI handler
never walks `/proc`. Candidates are ranked by kernel `Referenced`/`Rss`
coldness. Processes growing more than 5 MiB in 150 ms are excluded —
they are the pressure source, and paging them out causes an immediate
fault storm. If `DETRITUS_NOTIFY_USER` is set, only that uid is
considered.

**Nudge (400ms).** `process_madvise(MADV_COLD)` on the coldest stable
process. Armed only when `MemAvailable` is below 400 MiB *and* ZRAM
occupancy is under 50%. Chunk size still scales with how fast
`MemAvailable` is falling.

**Drain (400ms).** `process_madvise(MADV_WILLNEED)` on the process
holding the most pages in swap. Armed when `MemAvailable` is above
800 MiB *and* ZRAM occupancy is above 20%. This is the path that
empties ZRAM after a long session.

**Freeze (PSI, ZRAM has room).** `SIGSTOP` the coldest stable victim
and trickle `MADV_PAGEOUT`. Resume when `MemAvailable` recovers or
PSI `avg10` drops below 5%. Freeze is a 30 second grace, not a home.

**Discard.** `SIGKILL` the victim that frees the most (`rss + swap`)
from the cold list. Children are signalled before the parent so
reparent-to-init cannot hide renderers. Fires when:

- PSI arrives and ZRAM is already at 80% — PAGEOUT has nowhere to go
- PSI arrives while a process is already frozen — freeze failed
- a freeze has lasted 30 seconds and pressure never cleared
- `hold` (ZRAM capped, RAM tight) has lasted 30 seconds

15 second cooldown between kills so one PSI storm cannot empty the
session. Growing processes stay excluded — the tab being watched is
not detritus.

The skip list (display server, compositor, panel, session, audio,
input, the daemon itself) is never a discard target.

A governor sits on all four and writes `vm.swappiness` only when the
value must change:

| mode   | when                                      | swappiness |
|--------|-------------------------------------------|------------|
| idle   | RAM comfortable, ZRAM quiet               | 20         |
| nudge  | RAM tight, ZRAM has room                  | 80         |
| drain  | RAM comfortable, ZRAM occupied            | 20         |
| hold   | RAM tight, ZRAM at cap                    | 10         |
| frozen | emergency freeze active                   | 100        |

`page-cluster` stays 0. Partition swap and zswap stay off. ZRAM size
is still 40% of RAM on HDD/eMMC and 10% on NVMe/SSD.

## Status file

Live snapshot at `/run/detritus/status.json`, schema_version 1,
atomically written. Existing Gonzo fields are unchanged. Additive
fields this revision publishes:

- `mode` — `idle` / `nudge` / `drain` / `hold` / `frozen`
- `zram_disk_kb`, `zram_orig_kb`, `zram_compr_kb`, `zram_occupancy_pct`
- `swap_kb` inside each candidate object
- `last_discard_name` — last process actually killed, if any

Gonzo System Monitor can keep parsing schema 1; unknown keys are
ignored.

## Status

Developed on Devuan Excalibur (OpenRC), MATE, real hardware. Kernel
5.10+ (`process_madvise`) and `/proc/pressure/memory` required.

The core daemon has no init dependency. The installer detects PID 1
and installs an OpenRC service or a runit service accordingly.

## Requirements

detritusd disables `zswap` on startup and takes over partition swap
and ZRAM configuration. If you have tuned those yourself, read the
sections above before installing.

- Linux kernel 5.10 or newer
- `/proc/pressure/memory` present
- OpenRC or runit
- `gcc`, `make`

## Install

```bash
sudo ./install.sh
```

Builds the daemon, installs it to `/usr/local/sbin/detritusd`,
installs a service for whatever is PID 1 (OpenRC or runit), and
starts it.

Before starting, edit `/etc/conf.d/detritus`:

```
DETRITUS_NOTIFY_USER="yourusername"
```

Without this, notifications do not fire and victim selection is not
scoped to one user.

### Manual build

```bash
make
sudo make install
```

## Uninstall

```bash
sudo ./install.sh --uninstall
```

## Logs

OpenRC:

```bash
cat /var/log/detritusd.log
sudo rc-service detritusd status
```

runit:

```bash
sudo sv status detritusd
tail /var/log/detritusd/current
```

Watch for `governor:` lines. A healthy long YouTube session should
nudge while RAM is tight, then drain back to `idle` once the working
set settles and `MemAvailable` recovers. `zram_occupancy_pct` in the
status file should fall during drain, not ratchet toward 100 over
days.

## Related projects

- [Gonzo System Monitor](https://github.com/TTR-IND/gonzo-system-monitor)
  — MATE System Monitor fork that displays this daemon's status file.
- [gonzocache](https://github.com/TTR-IND/gonzocache) — independent
  page-cache preloader. detritusd reports its residency if both are
  present.

## License

Apache License 2.0. See `LICENSE`.
