#!/usr/bin/env bash
#
# Distribrute agent installer (Item 3c). Installs the operator daemon as a
# hardened, auto-starting systemd service — but ONLY after verifying the release
# package is the genuine signed agent (Item 3a). The supply-chain gate runs FIRST,
# before anything touches the host: a failed verification aborts the install.
#
#   install.sh verify    --package <dir> (--expect-agent-sha256 <hex> | --insecure-skip-binary-auth)
#   install.sh install   --package <dir> --backend <url> --verify-keyring <hex> --token <enroll-token> \
#                         (--expect-agent-sha256 <hex> | --insecure-skip-binary-auth) \
#                         [--device-id <id>] [--idle-mode always|nvidia-smi]
#   install.sh uninstall [--purge]
#
# Trust model (NON-circular, FAILS CLOSED). The root of trust is the agent BINARY,
# authenticated out-of-band BEFORE it is ever executed:
#   * --expect-agent-sha256 <hex> : check the binary's sha256 against a value from
#     the trusted distribution channel (website/repo over HTTPS). This breaks the
#     "package verifies itself" circularity. REQUIRED — without it install REFUSES,
#   * --insecure-skip-binary-auth : explicit dev/test bypass (warns loudly).
# To shrink what executes before the binary's own checks, the staged binary is run
# in a SCRUBBED environment (no LD_*), is rejected if it is a symlink, and is
# rejected if it declares ANY RPATH/RUNPATH (which could pull a package-local/CWD
# .so before main()). Once trusted, `verify-package` (its BAKED release pin) confirms
# the REST of the package matches the same offline-RELEASE-key-signed manifest. The
# RELEASE key never touches a host.
#
# TOCTOU-safe: the package is first copied into a private, root-owned staging dir;
# verification AND install both read from that immutable copy, so the bytes that
# were hashed are exactly the bytes installed.
#
# DESTDIR=<dir> lays files down under a prefix and SKIPS privileged steps (user
# creation, enroll, systemctl) — used by scripts/install-verify.sh to test the
# file layout + the verify gate without root.

set -euo pipefail

# --- fixed install locations (DESTDIR-prefixed for testing) ---
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/distribrute"
TOOLS_DIR="/opt/distribrute/tools"
UNIT_DIR="/etc/systemd/system"
STATE_DIR="/var/lib/distribrute"
SVC_USER="distribrute"
SVC_GROUP="distribrute"
UNIT_NAME="distribrute-agent.service"
DESTDIR="${DESTDIR:-}"

die() { echo "install.sh: $*" >&2; exit 1; }
info() { echo "[install] $*"; }
warn() { echo "[install] WARNING: $*" >&2; }
# privileged actions are skipped in DESTDIR (test) mode
real_install() { [ -z "$DESTDIR" ]; }
# #11: fail closed on a non-HTTPS backend BEFORE we lay anything down or enroll — mirrors the agent's
# own client-side URL validation so a mistyped/downgraded --backend can't ship the one-time enroll
# token or device-signed traffic in cleartext. Loopback http:// is allowed only with the explicit dev
# flag (DISTRIBRUTE_ALLOW_INSECURE_HTTP=1), never a public host — matching the binary's own rule.
assert_backend_https() {
  case "$1" in https://*) return 0 ;; esac
  if [ "${DISTRIBRUTE_ALLOW_INSECURE_HTTP:-}" = 1 ]; then
    case "$1" in
      http://localhost|http://localhost:*|http://localhost/*|http://127.*|'http://[::1]'|'http://[::1]:'*|'http://[::1]/'*)
        return 0 ;;
    esac
    die "DISTRIBRUTE_ALLOW_INSECURE_HTTP=1 permits http:// only for a loopback backend; refusing '$1'"
  fi
  die "--backend must be https:// (got '$1'); enroll tokens + device-signed traffic must not cross the wire in cleartext. For a loopback dev backend only, set DISTRIBRUTE_ALLOW_INSECURE_HTTP=1"
}
# sha256 of a file, hex only — coreutils sha256sum or BSD/macOS shasum
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "need sha256sum or shasum to verify the binary"; fi
}

usage() {
  # print the leading comment block (from line 3 to the first non-comment line)
  awk 'NR>=3 && /^#/ {sub(/^# ?/,""); print; next} NR>=3 {exit}' "$0"
  exit "${1:-1}"
}

# ---- arg parsing ----
CMD="${1:-}"; shift || true
PACKAGE=""; BACKEND=""; VERIFY_KEYRING=""; ENROLL_TOKEN=""; DEVICE_ID=""
IDLE_MODE="always"; PURGE=0; EXPECT_SHA256=""; INSECURE_SKIP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --package)             PACKAGE="${2:?}"; shift 2 ;;
    --backend)             BACKEND="${2:?}"; shift 2 ;;
    --verify-keyring)      VERIFY_KEYRING="${2:?}"; shift 2 ;;
    --token)               ENROLL_TOKEN="${2:?}"; shift 2 ;;
    --device-id)           DEVICE_ID="${2:?}"; shift 2 ;;
    --idle-mode)           IDLE_MODE="${2:?}"; shift 2 ;;
    --expect-agent-sha256) EXPECT_SHA256="${2:?}"; shift 2 ;;
    --insecure-skip-binary-auth) INSECURE_SKIP=1; shift ;;
    --purge)               PURGE=1; shift ;;
    -h|--help)             usage 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

agent_bin_in_pkg() { printf '%s/bin/distribrute-agent' "$1"; }

# Execute a (staged) package binary with a SCRUBBED environment, so no ambient
# LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT etc. can inject code into it before its
# own main() runs. Only a minimal whitelist is passed (PATH, and the dev-only
# release pin if the caller set it).
run_pkg_bin() {
  env -i PATH=/usr/bin:/bin \
    ${DISTRIBRUTE_RELEASE_PUB:+DISTRIBRUTE_RELEASE_PUB="$DISTRIBRUTE_RELEASE_PUB"} \
    "$@"
}

# A genuine release binary links only system libraries via the default loader search
# path and declares NO RPATH/RUNPATH. Reject ANY RPATH/RUNPATH so nothing — $ORIGIN,
# '.', 'lib', or any relative entry — can pull a package-local / CWD .so before
# main(). (If a future release legitimately needs an absolute system rpath, allow-
# list it explicitly here.) FAILS CLOSED if readelf is unavailable, unless the
# operator took the explicit --insecure-skip-binary-auth bypass.
check_no_rpath() {
  if ! command -v readelf >/dev/null 2>&1; then
    if [ "$INSECURE_SKIP" -eq 1 ]; then
      warn "readelf not found — skipping the RPATH/RUNPATH check (insecure bypass)"
      return 0
    fi
    die "readelf not found — cannot verify the binary declares no RPATH/RUNPATH (pass --insecure-skip-binary-auth to bypass, NOT for production)"
  fi
  if readelf -d "$1" 2>/dev/null | grep -Eq '\((RPATH|RUNPATH)\)'; then
    die "agent binary declares an RPATH/RUNPATH (could load non-system libs before main) — refusing"
  fi
}

# ---- the supply-chain gate (Item 3a): refuse to proceed unless the package is the
#      genuine signed agent. Runs the (already out-of-band-authenticated) binary in
#      a scrubbed env. ----
verify_package() {
  local pkg="$1"
  [ -d "$pkg" ] || die "package dir not found: $pkg"
  [ -f "$pkg/release.json" ] || die "no release.json in package: $pkg"
  local bin; bin="$(agent_bin_in_pkg "$pkg")"
  [ -x "$bin" ] || die "agent binary missing/!executable in package: $bin"
  info "verifying release package (signature + every file hash) ..."
  run_pkg_bin "$bin" verify-package "$pkg/release.json" "$pkg" \
    || die "PACKAGE VERIFICATION FAILED — refusing to install (possible tampering)"
}

# Copy the package into a PRIVATE, root-owned staging dir and re-point PACKAGE at
# it, so the bytes that are hashed + verified are EXACTLY the bytes installed (a
# mutable source dir can't be swapped in between — TOCTOU). Used by verify + install.
stage_package() {
  [ -n "$PACKAGE" ] || die "need --package <dir>"
  [ -d "$PACKAGE" ] || die "package dir not found: $PACKAGE"
  STAGING="$(mktemp -d "${TMPDIR:-/tmp}/distribrute-stage.XXXXXX")" || die "mktemp failed"
  chmod 700 "$STAGING"
  trap 'rm -rf "$STAGING"' EXIT
  cp -a "$PACKAGE/." "$STAGING/"
  PACKAGE="$STAGING"
}

# Out-of-band root of trust: authenticate the verifier BINARY itself BEFORE it is
# ever executed. The expected hash comes from the trusted distribution channel, not
# the package — this is what makes the bootstrap non-circular. FAILS CLOSED: without
# --expect-agent-sha256 you must explicitly pass --insecure-skip-binary-auth.
authenticate_binary() {
  local bin; bin="$(agent_bin_in_pkg "$PACKAGE")"
  # never hash/execute a symlinked binary (it could resolve outside the package)
  [ -L "$bin" ] && die "agent binary is a symlink (refusing): $bin"
  [ -f "$bin" ] && [ -x "$bin" ] || die "agent binary missing/!executable in package: $bin"
  # nothing package-local may load before the binary's own main()
  check_no_rpath "$bin"
  if [ -n "$EXPECT_SHA256" ]; then
    local got; got="$(sha256_file "$bin")"
    [ "$got" = "$EXPECT_SHA256" ] \
      || die "agent binary sha256 mismatch (got $got, expected $EXPECT_SHA256) — refusing to run it"
    info "agent binary matches the expected out-of-band sha256"
  elif [ "$INSECURE_SKIP" -eq 1 ]; then
    warn "--insecure-skip-binary-auth: NOT authenticating the binary out-of-band. Its integrity"
    warn "rests ENTIRELY on your download channel. verify-package can only prove the REST of the"
    warn "package matches this binary's baked release key. DO NOT use this in production."
  else
    die "refusing to run the package binary unauthenticated: pass --expect-agent-sha256 <hex> (from the trusted distribution channel), or --insecure-skip-binary-auth to bypass (NOT for production)"
  fi
}

do_install() {
  stage_package        # TOCTOU-safe: verify + install both read the staged copy
  authenticate_binary  # non-circular root: trust the binary before executing it
  verify_package "$PACKAGE"   # FAIL CLOSED before touching the system

  if real_install; then
    [ "$(id -u)" -eq 0 ] || die "install must run as root (or set DESTDIR for a test layout)"
    [ -n "$BACKEND" ] || die "install needs --backend <url>"
    assert_backend_https "$BACKEND"
    [ -n "$VERIFY_KEYRING" ] || die "install needs --verify-keyring <hex>"
    [ -n "$ENROLL_TOKEN" ] || die "install needs --token <enroll-token>"
  fi
  [ -n "$DEVICE_ID" ] || DEVICE_ID="$(uname -n)"

  # 1) dedicated, login-less service account (idempotent)
  if real_install && ! getent group "$SVC_GROUP" >/dev/null 2>&1; then
    groupadd --system "$SVC_GROUP"
  fi
  if real_install && ! getent passwd "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --gid "$SVC_GROUP" --no-create-home \
            --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$SVC_USER"
    info "created service user $SVC_USER"
  fi

  # 2) lay down files (DESTDIR-prefixed)
  install -D -m0755 "$(agent_bin_in_pkg "$PACKAGE")" "$DESTDIR$BIN_DIR/distribrute-agent"
  # tools dir: the authorizer-signed catalog + the full tool bundle it pins.
  # Hashcat needs nested modules/OpenCL/charset data next to the binary, so copy
  # the package tree recursively rather than only top-level files.
  rm -rf "$DESTDIR$TOOLS_DIR"
  install -d -m0755 "$DESTDIR$TOOLS_DIR"
  if [ -d "$PACKAGE/tools" ]; then
    cp -a "$PACKAGE/tools/." "$DESTDIR$TOOLS_DIR/"
    find "$DESTDIR$TOOLS_DIR" -type d -exec chmod 0755 {} \;
    find "$DESTDIR$TOOLS_DIR" -type f -exec chmod 0644 {} \;
    [ -f "$DESTDIR$TOOLS_DIR/hashcat" ] && chmod 0755 "$DESTDIR$TOOLS_DIR/hashcat"
  fi
  # systemd unit
  install -D -m0644 "$PACKAGE/systemd/$UNIT_NAME" "$DESTDIR$UNIT_DIR/$UNIT_NAME"
  # per-host GPU device drop-in (DeviceAllow for each present /dev/nvidiaN)
  write_gpu_dropin
  # config: write agent.env from the sample, but DON'T clobber an existing one
  write_config

  # 3) state dir (systemd also manages it via StateDirectory, but enroll needs it now)
  install -d -m0700 "$DESTDIR$STATE_DIR"
  if real_install; then
    chown "$SVC_USER:$SVC_GROUP" "$DESTDIR$STATE_DIR"
  fi

  # 4) enroll the device with the one-time token (idempotent — skip if already enrolled)
  if real_install; then
    if [ -f "$STATE_DIR/device.json" ]; then
      info "device already enrolled — skipping enroll"
    else
      info "enrolling device '$DEVICE_ID' ..."
      run_as_service \
        DISTRIBRUTE_BACKEND_URL="$BACKEND" \
        DISTRIBRUTE_DEVICE_ID="$DEVICE_ID" \
        DISTRIBRUTE_ENROLL_TOKEN="$ENROLL_TOKEN" \
        DISTRIBRUTE_STATE_DIR="$STATE_DIR" \
        "$BIN_DIR/distribrute-agent" register \
        || die "enroll failed — fix backend/token and re-run"
    fi
    # 5) start + enable
    systemctl daemon-reload
    systemctl enable --now "$UNIT_NAME"
    info "installed + started $UNIT_NAME"
    systemctl --no-pager --lines=0 status "$UNIT_NAME" || true
  else
    info "DESTDIR set — laid down files only (skipped user/enroll/systemctl)"
  fi
}

# run a command as the unconfined service user, passing through KEY=VAL env args
run_as_service() {
  local envs=() ; while [[ "$1" == *=* ]]; do envs+=("$1"); shift; done
  runuser -u "$SVC_USER" -- env "${envs[@]}" "$@"
}

write_gpu_dropin() {
  local d="$DESTDIR$UNIT_DIR/$UNIT_NAME.d"
  install -d -m0755 "$d"
  {
    echo "# auto-generated by install.sh — DeviceAllow for each present GPU node"
    echo "[Service]"
    local n found=0
    for n in /dev/nvidia[0-9]*; do
      [ -e "$n" ] || continue
      echo "DeviceAllow=$n rw"; found=1
    done
    # NB: plain `[ ] && echo` as the last statement would return nonzero and trip
    # `set -e` when a GPU IS present — use an explicit if so the block exits 0.
    if [ "$found" -eq 0 ]; then
      echo "# (no /dev/nvidiaN present at install time — CPU-only host)"
    fi
  } > "$d/10-gpu.conf"
}

write_config() {
  local target="$DESTDIR$CONF_DIR/agent.env"
  install -d -m0755 "$DESTDIR$CONF_DIR"
  if [ -f "$target" ]; then
    info "keeping existing $CONF_DIR/agent.env (not overwriting operator config)"
    return
  fi
  local sample="$PACKAGE/config/agent.env.sample"
  [ -f "$sample" ] || die "package missing config/agent.env.sample"
  # start from the sample, then substitute the values we were given
  sed \
    -e "s#^DISTRIBRUTE_BACKEND_URL=.*#DISTRIBRUTE_BACKEND_URL=${BACKEND:-https://backend.example.com}#" \
    -e "s#^DISTRIBRUTE_VERIFY_KEYRING=.*#DISTRIBRUTE_VERIFY_KEYRING=${VERIFY_KEYRING:-REPLACE_WITH_VERIFY_PUBKEY_HEX}#" \
    -e "s#^DISTRIBRUTE_TOOL_CATALOG=.*#DISTRIBRUTE_TOOL_CATALOG=$TOOLS_DIR/tool_catalog.json#" \
    -e "s#^DISTRIBRUTE_TOOLS_DIR=.*#DISTRIBRUTE_TOOLS_DIR=$TOOLS_DIR#" \
    -e "s#^DISTRIBRUTE_IDLE_MODE=.*#DISTRIBRUTE_IDLE_MODE=$IDLE_MODE#" \
    "$sample" > "$target"
  chmod 0640 "$target"
  if real_install; then
    chown "root:$SVC_GROUP" "$target"
  fi
  info "wrote $CONF_DIR/agent.env"
}

do_uninstall() {
  real_install || die "uninstall has nothing to do in DESTDIR mode"
  [ "$(id -u)" -eq 0 ] || die "uninstall must run as root"
  if systemctl list-unit-files "$UNIT_NAME" >/dev/null 2>&1; then
    systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
  fi
  rm -f "$UNIT_DIR/$UNIT_NAME"
  rm -rf "${UNIT_DIR:?}/$UNIT_NAME.d"
  systemctl daemon-reload 2>/dev/null || true
  rm -f "$BIN_DIR/distribrute-agent"
  rm -rf "$TOOLS_DIR"
  if [ "$PURGE" -eq 1 ]; then
    rm -rf "$CONF_DIR" "$STATE_DIR"
    if getent passwd "$SVC_USER" >/dev/null 2>&1; then userdel "$SVC_USER" 2>/dev/null || true; fi
    info "purged config, state, and service user"
  else
    info "removed binary/unit/tools; kept $CONF_DIR + $STATE_DIR (use --purge to remove)"
  fi
}

case "$CMD" in
  verify)
    stage_package        # stage first so the hash + exec hit an immutable copy (TOCTOU)
    authenticate_binary  # same fail-closed out-of-band binary check as install
    verify_package "$PACKAGE"; info "package OK" ;;
  install)   do_install ;;
  uninstall) do_uninstall ;;
  -h|--help|"") usage 0 ;;
  *) die "unknown command: $CMD (want verify|install|uninstall)" ;;
esac
