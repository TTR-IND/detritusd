#!/usr/bin/env bash
#
# install.sh -- installs detritus, a PSI-driven memory pressure daemon.
#
# Init is detected from PID 1. OpenRC and runit are both first-class.
# The binary itself has no init dependency.
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
DETRITUS_RUNIT_SRC="$SCRIPT_DIR/runit"
DETRITUS_SVDIR="/etc/sv/detritusd"

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

# PID 1 is the authority. Leftover /run/openrc after an init switch
# is not. comm is usually "runit", "runit-init", "init" (OpenRC),
# or "systemd".
detect_init() {
    local comm="" exe=""
    comm="$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ' || true)"
    exe="$(readlink -f /proc/1/exe 2>/dev/null || true)"

    case "$comm" in
        runit|runit-init) echo runit; return ;;
        systemd)          echo systemd; return ;;
        openrc-init)      echo openrc; return ;;
    esac

    case "$exe" in
        *runit*)   echo runit; return ;;
        *systemd*) echo systemd; return ;;
        *openrc*)  echo openrc; return ;;
    esac

    if [ -d /run/openrc ] && command -v rc-service >/dev/null 2>&1; then
        echo openrc
        return
    fi
    if [ -d /etc/sv ] && command -v sv >/dev/null 2>&1; then
        echo runit
        return
    fi
    echo unknown
}

runit_supervise_dir() {
    if [ -d /etc/service ]; then
        echo /etc/service
    elif [ -d /var/service ]; then
        echo /var/service
    elif [ -d /etc/runit/runsvdir/default ]; then
        echo /etc/runit/runsvdir/default
    else
        echo ""
    fi
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

install_binary() {
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
}

install_conf() {
    mkdir -p "$(dirname "$DETRITUS_CONFD")"
    if [ -f "$DETRITUS_CONFD" ]; then
        log "existing $DETRITUS_CONFD found -- leaving it untouched"
    else
        [ -f "$DETRITUS_CONFD_SRC" ] || die "detritus.conf.d not found at $DETRITUS_CONFD_SRC"
        install -m 0644 -o root -g root "$DETRITUS_CONFD_SRC" "$DETRITUS_CONFD"
        warn "wrote default $DETRITUS_CONFD -- edit it to set DETRITUS_NOTIFY_USER"
        warn "  before expecting freeze notifications or per-user victim scoping."
    fi
}

install_openrc() {
    command -v rc-update  >/dev/null 2>&1 || die "rc-update not found -- OpenRC tools missing"
    command -v rc-service >/dev/null 2>&1 || die "rc-service not found -- OpenRC tools missing"
    [ -f "$DETRITUS_OPENRC_SRC" ] || die "detritus.openrc not found at $DETRITUS_OPENRC_SRC"

    log "installing OpenRC service..."
    install -m 0755 -o root -g root "$DETRITUS_OPENRC_SRC" "$DETRITUS_INITD"
    install_conf

    log "adding detritusd to the default runlevel..."
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
        log "detritus is running (OpenRC)"
    fi
}

install_runit() {
    command -v sv >/dev/null 2>&1 || die "sv not found -- runit tools missing"
    [ -d "$DETRITUS_RUNIT_SRC" ] || die "runit/ service dir not found at $DETRITUS_RUNIT_SRC"
    [ -f "$DETRITUS_RUNIT_SRC/run" ] || die "runit/run not found"

    local supervise
    supervise="$(runit_supervise_dir)"
    [ -n "$supervise" ] || die "no runit supervise directory found (/etc/service, /var/service, or /etc/runit/runsvdir/default)"

    log "installing runit service to $DETRITUS_SVDIR..."
    mkdir -p "$DETRITUS_SVDIR/log"
    install -m 0755 -o root -g root "$DETRITUS_RUNIT_SRC/run" "$DETRITUS_SVDIR/run"
    install -m 0755 -o root -g root "$DETRITUS_RUNIT_SRC/log/run" "$DETRITUS_SVDIR/log/run"
    install_conf

    # sv looks in $SVDIR. On Devuan that is /etc/service.
    export SVDIR="$supervise"

    if [ -L "$supervise/detritusd" ] || [ -d "$supervise/detritusd" ]; then
        log "detritusd already supervised -- restarting to pick up new build"
        sv restart detritusd || warn "sv restart failed -- trying down/up"
        sv down detritusd 2>/dev/null || true
        sv up detritusd || die "sv up failed"
    else
        log "enabling detritusd under $supervise..."
        ln -s "$DETRITUS_SVDIR" "$supervise/detritusd"
    fi

    # runsvdir rescans about every 5 seconds. One second is too short
    # and produces a false "did not stay running" on a healthy box.
    local i status=""
    for i in 1 2 3 4 5 6 7 8 9 10; do
        sleep 1
        status="$(sv status detritusd 2>/dev/null || true)"
        case "$status" in
            run:*) break ;;
        esac
    done
    if [ -n "$status" ]; then
        log "sv status: $status"
    fi
    case "$status" in
        run:*)
            log "detritus is running (runit)"
            ;;
        *)
            warn "supervise has not reported run: yet"
            warn "  check: SVDIR=$supervise sv status detritusd"
            warn "  logs:  tail /var/log/detritusd/current"
            if [ ! -r /proc/pressure/memory ]; then
                warn "  /proc/pressure/memory is missing — the daemon will refuse to start"
            fi
            ;;
    esac
}

uninstall_all() {
    log "stopping and removing detritus..."

    if command -v sv >/dev/null 2>&1; then
        sv down detritusd 2>/dev/null || true
        sv force-stop detritusd 2>/dev/null || true
    fi
    if command -v rc-service >/dev/null 2>&1; then
        rc-service detritusd stop 2>/dev/null || true
    fi
    if command -v rc-update >/dev/null 2>&1; then
        rc-update delete detritusd default 2>/dev/null || true
    fi

    local supervise
    supervise="$(runit_supervise_dir)"
    if [ -n "$supervise" ]; then
        rm -f "$supervise/detritusd"
    fi
    rm -rf "$DETRITUS_SVDIR"

    rm -f "$DETRITUS_INITD"
    rm -f "$DETRITUS_CONFD"
    rm -f "$DETRITUS_BIN"
    rm -rf /run/detritus
    rm -f /var/log/detritusd.log
    rm -rf /var/log/detritusd
    log "uninstall complete"
}

usage() {
    cat << EOF
Usage: sudo $0 [--uninstall]

  (no args)     build, install, and start detritus
  --uninstall   remove detritus entirely

Init is detected from PID 1 (OpenRC or runit).
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
            local init
            init="$(detect_init)"
            log "detected init: $init"
            install_binary
            case "$init" in
                runit)  install_runit ;;
                openrc) install_openrc ;;
                systemd)
                    die "PID 1 is systemd. No unit ships in this tree. Run the binary from your own unit, or switch init."
                    ;;
                *)
                    die "could not detect OpenRC or runit as PID 1. Install the binary only with: make && sudo make install"
                    ;;
            esac
            ;;
        *)
            usage
            die "unrecognized argument: $1"
            ;;
    esac
    log "done."
    log "  conf: $DETRITUS_CONFD"
    log "  full install log: $INSTALL_LOG"
}

main() {
    touch "$INSTALL_LOG" 2>/dev/null || INSTALL_LOG="/tmp/detritus-install-$(date +%Y%m%d-%H%M%S).log"
    main_inner "$@" 2>&1 | tee -a "$INSTALL_LOG"
    exit "${PIPESTATUS[0]}"
}

main "$@"
