# detritusd

A PSI-driven memory pressure daemon for Linux, inspired by the design
goals of Apple's Jetsam: keep applications responsive under heavy
multitasking, and prevent processes from freezing under memory
pressure, without a fixed threshold that "suddenly" kicks in.

detritusd does two independent things:

1. **Proactive idle trickle.** A continuous, low-priority background
   thread marks memory from genuinely idle processes as reclaimable
   (`MADV_COLD`), at a gentle cadence that scales up smoothly with how
   fast memory is actually being consumed. `MADV_COLD` is a hint the
   kernel schedules on its own terms rather than a forced reclaim.

2. **Reactive last-resort relief.** If the kernel's own [PSI (Pressure
   Stall Information)](https://docs.kernel.org/accounting/psi.html)
   signal crosses a real stall threshold — meaning a process is
   *actually* waiting on memory, not just "memory usage is high" —
   detritusd freezes (`SIGSTOP`) the least-recently-useful large
   process and trickles its memory into ZRAM, then resumes it the
   moment pressure clears. This is the emergency fallback, not the
   normal mode of operation.

See the comments in `detritus.c` for the reasoning behind each design
choice.

## Status

**Developed and tested on Devuan Excalibur (OpenRC, no systemd), MATE
desktop, on real hardware.** It should work on any Devuan-based or
similar OpenRC-based Linux system with a reasonably recent kernel
(5.10+ for `process_madvise`; PSI support compiled in, which is
standard on most modern kernels).

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
  tuned to catch real stalls early without firing on routine I/O.
- A background scanner ranks candidate processes by RSS and idle time
  (consecutive scan cycles with zero scheduler activity), so the
  daemon always knows, in advance, what it would act on if it needed
  to — no scanning-under-pressure delay.
- The idle-trickle thread reads the same ranked list and proactively
  marks small chunks of the most-idle candidate's memory `MADV_COLD`,
  scaling the chunk size with how fast `MemAvailable` is actually
  falling.
- On a real PSI trigger, the top candidate is frozen and its memory is
  paged into ZRAM via `process_madvise(MADV_PAGEOUT)`, then resumed
  once `MemAvailable` recovers or PSI drops back below threshold.
- Publishes live status (`/run/detritus/status.json`) for anything
  that wants to display it — see
  [Gonzo System Monitor](https://github.com/YOUR_GITHUB/gonzo-system-monitor)
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
git clone https://github.com/YOUR_GITHUB/detritus.git
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

Without this, detritus still runs and manages memory pressure, but:
- Desktop notifications on freeze events won't fire.
- Victim scanning won't be scoped to a single user's processes (it
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
sudo rc-service detritus status
```

## Status file (for integrations)

detritus publishes a live JSON snapshot at `/run/detritus/status.json`
every ~2 seconds, world-readable, atomically written. Fields include
PSI pressure, memory-change rate, ZRAM usage, trickle activity, and
frozen-process state. See the `write_status_file()` function in
`detritus.c` for the exact schema — it's small and stable
(`schema_version` is bumped on any breaking change).

## License

Apache License 2.0. See `LICENSE`.
