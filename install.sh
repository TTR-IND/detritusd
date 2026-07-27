#!/usr/bin/env bash
#
# install.sh -- installs detritus, a PSI-driven memory pressure daemon
# for Linux (OpenRC target; see README for other init systems).
#
# Design: staged, fail-loud. Each stage is a separate function; `set -e`
# plus explicit checks after anything that can silently succeed-but-fail
# (apt-get, compiler invocation, service start) mean a problem stops the
# install at the point of failure rather than leaving a half-built
# system that looks installed but isn't.
#
# Every run writes a full log to /var/log/detritus-install-<timestamp>.log,
# regardless of outcome -- if something doesn't install the way you
# expect, check that file first.
#
# Usage:
#   sudo ./install.sh              (build + install + start the service)
#   sudo ./install.sh --uninstall  (remove everything)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETRITUS_SRC="$SCRIPT_DIR/detritus.c"
DETRITUS_BIN="/usr/local/sbin/detritusd"
DETRITUS_INITD="/etc/init.d/detritusd"
DETRITUS_CONFD="/etc/conf.d/detritus"
DETRITUS_OPENRC_SRC="$SCRIPT_DIR/detritus.openrc"
DETRITUS_CONFD_SRC="$SCRIPT_DIR/detritus.conf.d"

INSTALL_LOG="/var/log/detritus-install-$(date +%Y%m%d-%H%M%S).log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[detritus-install]${NC} $*"; }
warn() { echo -e "${YELLOW}[detritus-install] WARNING:${NC} $*"; }
die()  { echo -e "${RED}[detritus-install] ERROR:${NC} $*" >&2; exit 1; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "must be run as root (sudo ./install.sh)"
    fi
}

# detritus's OpenRC service assumes OpenRC is the running init system.
# This is a hard precondition, not a dependency to fetch -- installing
# or switching init systems is far outside this script's scope. If
# you're on systemd, see the README for the (untested but plausible)
# systemd unit template.
require_openrc() {
    if [ ! -d /run/openrc ]; then
        die "OpenRC does not appear to be the running init system (no /run/openrc). This installer targets OpenRC specifically. See the README for guidance on other init systems."
    fi
    command -v rc-update  >/dev/null 2>&1 || die "rc-update not found -- is openrc installed?"
    command -v rc-service >/dev/null 2>&1 || die "rc-service not found -- is openrc installed?"
}

check_dependencies() {
    log "checking build dependencies..."
    local missing=()
    for pkg in build-essential gcc; do
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        log "installing missing packages: ${missing[*]}"
        apt-get update || die "apt-get update failed"
        apt-get install -y "${missing[@]}" || die "apt-get install failed for: ${missing[*]}"
    else
        log "all build dependencies already present"
    fi
}

install_detritus() {
    log "building detritus..."
    [ -f "$DETRITUS_SRC" ] || die "detritus.c not found at $DETRITUS_SRC"

    local tmp_bin="/tmp/detritus-build-$$"
    gcc -O2 -Wall -Wextra -Wno-unused-parameter \
        -o "$tmp_bin" "$DETRITUS_SRC" -lm -lpthread \
        || die "detritus build failed"

    log "installing detritus to $DETRITUS_BIN"
    install -m 0755 -o root -g root "$tmp_bin" "$DETRITUS_BIN"
    rm -f "$tmp_bin"
    [ -x "$DETRITUS_BIN" ] || die "detritus installed but not executable at $DETRITUS_BIN"

    log "installing OpenRC service..."
    [ -f "$DETRITUS_OPENRC_SRC" ] || die "detritus.openrc not found at $DETRITUS_OPENRC_SRC"
    [ -f "$DETRITUS_CONFD_SRC" ] || die "detritus.conf.d not found at $DETRITUS_CONFD_SRC"

    install -m 0755 -o root -g root "$DETRITUS_OPENRC_SRC" "$DETRITUS_INITD"

    # Never overwrite an existing conf.d -- it may hold a site-specific
    # DETRITUS_NOTIFY_USER from a previous install.
    if [ -f "$DETRITUS_CONFD" ]; then
        log "existing $DETRITUS_CONFD found -- leaving it untouched"
    else
        install -m 0644 -o root -g root "$DETRITUS_CONFD_SRC" "$DETRITUS_CONFD"
        warn "wrote default $DETRITUS_CONFD -- edit it to set DETRITUS_NOTIFY_USER"
        warn "  before starting the service, or freeze notifications will not fire"
        warn "  and victim scanning will not be scoped to a single user."
    fi

    log "adding detritus to the default runlevel..."
    rc-update add detritusd default || die "rc-update add failed"

    if rc-service detritusd status >/dev/null 2>&1; then
        log "detritus already running -- restarting to pick up new build"
        rc-service detritusd restart || die "rc-service restart failed"
    else
        rc-service detritusd start || die "rc-service start failed"
    fi

    sleep 1
    if ! rc-service detritusd status | grep -q started; then
        warn "detritus did not stay running -- check: cat /var/log/detritusd.log"
        warn "this is often expected in containers/VMs without /proc/pressure (PSI) support"
    else
        log "detritus is running"
    fi
}

uninstall_all() {
    log "stopping and removing detritus..."
    if command -v rc-service >/dev/null 2>&1; then
        rc-service detritusd stop 2>/dev/null || true
    fi
    if command -v rc-update >/dev/null 2>&1; then
        rc-update delete detritusd default 2>/dev/null || true
    fi
    rm -f "$DETRITUS_INITD"
    rm -f "$DETRITUS_CONFD"
    rm -f "$DETRITUS_BIN"
    rm -rf /run/detritus
    rm -f /var/log/detritusd.log
    log "uninstall complete"
}

usage() {
    cat << EOF
Usage: sudo $0 [--uninstall]

  (no args)     build, install, and start detritus
  --uninstall   remove detritus entirely

Every run writes a full log to /var/log/detritus-install-<timestamp>.log.
EOF
}

main_inner() {
    require_root
    case "${1:-}" in
        --uninstall)
            uninstall_all
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        "")
            check_dependencies
            require_openrc
            install_detritus
            ;;
        *)
            usage
            die "unrecognized argument: $1"
            ;;
    esac
    log "done."
    log "  status: rc-service detritusd status"
    log "  logs:   cat /var/log/detritusd.log"
    log "  full install log: $INSTALL_LOG"
}

main() {
    touch "$INSTALL_LOG" 2>/dev/null || INSTALL_LOG="/tmp/detritus-install-$(date +%Y%m%d-%H%M%S).log"
    main_inner "$@" 2>&1 | tee -a "$INSTALL_LOG"
    exit "${PIPESTATUS[0]}"
}

main "$@"
