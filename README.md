# detritusd

A small helper daemon for the memory management Linux already has.

The kernel already does the real work: `kswapd` and the page LRU
continuously reclaim cold memory in the background, and PSI (Pressure
Stall Information) already tells userspace exactly when a process is
genuinely stalled waiting on memory, not just "using a lot of it."
detritusd doesn't duplicate any of that. It adds two small, narrow
things the kernel has no policy for on its own:

1. **A gentle nudge toward the coldest memory before things get bad.**
   The kernel's own page-table accounting (`Referenced` vs. `Rss` in
   `/proc/pid/smaps_rollup`) already knows which process's memory
   hasn't been touched in a while. detritusd reads that signal
   on-demand and marks a small chunk of it `MADV_COLD` — a hint the
   kernel schedules on its own terms, not a forced reclaim — at a
   gentle, ongoing cadence that scales up smoothly with how fast
   memory is actually being consumed.

2. **A last-resort freeze, only when PSI says a real stall is
   happening.** If `/proc/pressure/memory` crosses a real stall
   threshold, detritusd freezes (`SIGSTOP`) the coldest large process
   it can find at that moment and pages its memory into ZRAM, then
   resumes it once pressure clears. This is the emergency fallback,
   triggered by the kernel's own signal, not a fixed threshold guessed
   in userspace.

Inspired by the outcome Apple's Jetsam aims for on macOS/iOS — keep
things responsive under heavy multitasking rather than stalling —
built entirely on primitives Linux already ships, not a from-scratch
reimplementation of memory management.

See the comments in `detritus.c` for the reasoning behind each design
choice.

## Status

**Developed and tested on Devuan Excalibur (OpenRC, no systemd), MATE
desktop, on real hardware.** It should work on any Devuan-based or
similar OpenRC-based Linux system with a reasonably recent kernel
(5.10+ for `process_madvise`; PSI support compiled in, which is
standard on most modern kernels).

Testing on a 16 year old Intel Atom
laptop yelided impressive results with Chrome staying completely stable
and very responsive during heavy video playback and benchmark tests.

It has **not** been tested on other distributions or init systems
(systemd, runit, s6, etc.). The core daemon (`detritus.c`) has no
OpenRC dependency itself — only the provided service script does — so
running it under a different init system should be straightforward,
but this hasn't been verified. If you get it running elsewhere,
contributions documenting or automating that are welcome.

## How it works, briefly

- On startup, provisions its own ZRAM device (sized relative to total
  RAM and adjusted for storage speed) and disables `zswap` if it was
  enabled, so ZRAM is the sole in-memory compression layer rather than
  one that `zswap` would otherwise intercept most traffic ahead of.
  Existing partition swap is disabled the same way once ZRAM is
  active — detritusd takes over the compression/swap layer outright
  rather than sharing it with whatever the distro configured by
  default.
- Reads `/proc/pressure/memory` via `epoll`, armed with a PSI trigger
  tuned to catch real stalls early without firing on routine I/O. This
  is the only genuinely event-driven signal in the system; everything
  else below is read on-demand, never on a background timer.
- There is no continuously-running scanner. Candidate selection
  (`select_cold_victims()`) walks `/proc` once, only at the moment
  it's actually needed, and ranks processes by how cold their memory
  is per the kernel's own `Referenced`/`Rss` accounting — not a
  userspace-derived guess accumulated over time.
- A low-priority background thread runs on a fixed, gentle cadence
  (well under the point where any polling would be noticeable) and,
  each cycle, asks for the single coldest eligible process and marks a
  small chunk of its memory `MADV_COLD`, scaling the chunk size with
  how fast `MemAvailable` is actually falling.
- On a real PSI trigger, the coldest large process at that exact
  moment is frozen and its memory is paged into ZRAM via
  `process_madvise(MADV_PAGEOUT)`, then resumed once `MemAvailable`
  recovers or PSI drops back below threshold.
- Publishes live status (`/run/detritus/status.json`) for anything
  that wants to display it — see
  [Gonzo System Monitor](https://github.com/TTR-IND/gonzo-system-monitor)
  for a GUI that consumes this.

## Requirements

**Note:** detritusd disables `zswap` on startup (if present) and takes
over partition swap and ZRAM configuration. If you've deliberately
tuned `zswap` yourself, or rely on existing partition swap, read
[How it works](#how-it-works-briefly) above before installing.

- Linux kernel 5.10 or newer (for `process_madvise`)
- `/proc/pressure/memory` present (PSI enabled in the kernel config —
  standard on most distributions since ~2019)
- OpenRC (for the provided service script; see [Status](#status) above
  for other init systems)
- `gcc`, `make` or a C build toolchain

## Install

```bash
git clone https://github.com/TTR-IND/detritus.git
cd detritus
sudo ./install.sh
```

This builds the daemon, installs it to `/usr/local/sbin/detritusd`,
installs an OpenRC service, and starts it.

### Configuration

Before starting the service (the installer will remind you), edit
`/etc/conf.d/detritus` and set:

```
DETRITUS_NOTIFY_USER="yourusername"
```

Without this, detritusd still runs its normal cycle, but:
- Desktop notifications on freeze events won't fire.
- Candidate selection won't be scoped to a single user's processes (it
  will consider processes belonging to any user on the system).

### Manual build (no service integration)

```bash
make
sudo make install
```

This only installs the binary to `/usr/local/sbin/detritusd` — you'll
need to run it yourself or write your own service integration.

## Uninstall

```bash
sudo ./install.sh --uninstall
```

## Logs

```bash
cat /var/log/detritusd.log
sudo rc-service detritusd status
```

## Status file (for integrations)

detritusd publishes a live JSON snapshot at `/run/detritus/status.json`
every ~2 seconds, world-readable, atomically written. Fields include
PSI pressure, memory-change rate, ZRAM usage, trickle activity, and
frozen-process state. See the `write_status_file()` function in
`detritus.c` for the exact schema — it's small and stable
(`schema_version` is bumped on any breaking change).

## Related projects

- [Gonzo System Monitor](https://github.com/TTR-IND/gonzo-system-monitor)
  — a fork of MATE System Monitor with a UI built to display this
  daemon's live status.
- [gonzocache](https://github.com/TTR-IND/gonzocache) — a separate
  companion daemon that preloads your most-used apps into page cache
  at login. Independent of detritusd (neither requires the other to
  be installed), but detritusd will report gonzocache's real page-cache
  residency in its own status file if both are present.

## License

Apache License 2.0. See `LICENSE`.
