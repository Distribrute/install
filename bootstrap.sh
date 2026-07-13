#!/usr/bin/env bash
#
# Distribrute operator agent — one-command bootstrap.
#
#     curl -fsSL https://raw.githubusercontent.com/Distribrute/install/v1/bootstrap.sh | bash
#     # keep an interactive token prompt when piping:
#     bash <(curl -fsSL https://raw.githubusercontent.com/Distribrute/install/v1/bootstrap.sh)
#     # fully non-interactive:
#     curl -fsSL https://raw.githubusercontent.com/Distribrute/install/v1/bootstrap.sh | DISTRIBRUTE_ENROLL_TOKEN=<tok> bash
#
# Fetch this script from the public Distribrute/install repo (GitHub TLS) — NOT the release CDN.
# That independent channel is what makes the baked Release key a real trust anchor: a compromised
# CDN can't hand you a bootstrap that skips the checks. Do NOT run it via `curl <cdn> | sudo bash`;
# it self-escalates with sudo ONLY for the final system install, after the package is verified.
#
# This is the STABLE entrypoint. It carries no per-release values (only the stable Release public
# key): version, tarball URL + hash, agent hash, backend URL, and Verify keyring come from a small
# signed MANIFEST fetched from the CDN. Cutting a release only re-publishes the manifest + tarball.
#
# What it does, all FAIL-CLOSED:
#   1. preflight  — Linux + x86_64; curl/tar/sha256sum/readelf present; become root.
#   2. manifest   — fetch + parse latest/manifest.env; validate every field.
#   3. gpu detect — nvidia-smi present => idle-gated work; else warn (CPU earns nothing).
#   4. token      — read the one-time enrollment token from the TTY (never echoed) or
#                   $DISTRIBRUTE_ENROLL_TOKEN. The token gates BACKEND ACCESS (enroll ->
#                   lease), NOT the download; the binary is public/open-source.
#   5. download   — fetch the tarball, verify TARBALL_SHA256 (fail closed), extract.
#   6. install    — hand off to install/install.sh, which RE-checks the binary sha256
#                   (AGENT_SHA256, out-of-band root of trust) + the release signature
#                   (baked pin), enrolls, and starts the systemd service.
#      container  — no usable systemd (vast.ai etc.): reuse install.sh's verify gate,
#                   then enroll + run the agent in the FOREGROUND from the verified tree.
#
# TRUST MODEL. The root of trust is AGENT_SHA256, delivered in the manifest over TLS from
# the CDN. install.sh authenticates the binary against it BEFORE executing it, then the
# binary's BAKED release pin verifies the rest of the package. A paranoid operator can
# reproduce AGENT_SHA256 from source (see VERIFYING.md) and compare — no trust in our
# build box required. The manifest + this script carry only PUBLIC keys and hashes; there
# are NO secrets here, and none are ever written by this script.
set -euo pipefail

# ------------------------------------------------------------------ config / overrides
# DISTRIBRUTE_INSTALL_BASE : CDN base (default get.distribrute.com). Overridable for a
#   private mirror or the local dry-run harness (scripts/bootstrap-dryrun.sh).
INSTALL_BASE="${DISTRIBRUTE_INSTALL_BASE:-https://get.distribrute.com}"
INSTALL_BASE="${INSTALL_BASE%/}"
MANIFEST_URL="${DISTRIBRUTE_MANIFEST_URL:-$INSTALL_BASE/latest/manifest.env}"
# DESTDIR : TEST SEAM. When set, install.sh lays files under this prefix and SKIPS the
#   privileged steps (user/enroll/systemctl) — used by the dry-run to exercise the whole
#   flow without touching the host.
DESTDIR="${DESTDIR:-}"

# ------------------------------------------------------------------ release trust anchor (#10)
# The offline RELEASE public key, BAKED into this script. Its authenticity comes from the channel
# that delivered this script — the public Distribrute/install repo over GitHub TLS, a trust domain
# INDEPENDENT of the release CDN. bootstrap verifies the manifest's detached Ed25519 signature
# against this key BEFORE trusting AGENT_SHA256, so a compromised CDN/S3/CloudFront cannot forge a
# release without the offline RELEASE key. The dry-run injects a mock key via
# DISTRIBRUTE_RELEASE_PUB_PEM=<file> to exercise this same path.
RELEASE_PUB_PEM_BAKED='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA8TXjpQn68nWVWGxkbCvtKxYW2CUKMMNmcaDJAPcT7/A=
-----END PUBLIC KEY-----'
MANIFEST_SIG_URL="${DISTRIBRUTE_MANIFEST_SIG_URL:-$INSTALL_BASE/latest/manifest.env.sig}"

SELF_SRC="${BASH_SOURCE[0]:-$0}"
if [ -f "$SELF_SRC" ]; then SELF_DIR="$(cd "$(dirname "$SELF_SRC")" && pwd)"; else SELF_DIR=""; fi

die()  { echo "bootstrap: $*" >&2; exit 1; }
info() { echo "[bootstrap] $*"; }
warn() { echo "[bootstrap] WARNING: $*" >&2; }
# In DESTDIR (test) mode we never touch the real host: no sudo, relaxed URL schemes.
test_mode() { [ -n "$DESTDIR" ]; }

# curl with fail-closed defaults. In production we additionally pin the scheme to https
# (the manifest carries the integrity roots, so its own transport must be authentic); the
# dry-run harness serves over loopback http, so relax the scheme only in test mode.
fetch() { # fetch <url> <out-file>
  if test_mode; then
    curl -fL --retry 2 -o "$2" "$1"
  else
    curl -fL --proto '=https' --tlsv1.2 --retry 2 -o "$2" "$1"
  fi
}

is_hex64() { printf '%s' "$1" | grep -Eq '^[0-9a-f]{64}$'; }

# Resolve the Release pubkey PEM: dry-run injects a mock key file; production uses the baked one.
release_pub_pem() {
  if [ -n "${DISTRIBRUTE_RELEASE_PUB_PEM:-}" ] && [ -f "$DISTRIBRUTE_RELEASE_PUB_PEM" ]; then
    cat "$DISTRIBRUTE_RELEASE_PUB_PEM"
  else
    printf '%s\n' "$RELEASE_PUB_PEM_BAKED"
  fi
}

# #10: verify the release manifest's detached Ed25519 signature against the BAKED Release pubkey,
# BEFORE trusting any field (AGENT_SHA256 is the root of trust). FAILS CLOSED. The escape hatch
# (DISTRIBRUTE_INSECURE_SKIP_MANIFEST_SIG=1) exists only for constrained hosts lacking openssl 3.0+
# — using it drops the off-CDN anchor back to plain CDN-TLS trust, so it warns loudly.
verify_manifest_sig() { # verify_manifest_sig <manifest-file>
  if [ "${DISTRIBRUTE_INSECURE_SKIP_MANIFEST_SIG:-0}" = 1 ]; then
    warn "DISTRIBRUTE_INSECURE_SKIP_MANIFEST_SIG=1 — NOT verifying the manifest signature; the"
    warn "release's authenticity now rests only on CDN TLS. NOT for production."
    return 0
  fi
  command -v openssl >/dev/null 2>&1 \
    || die "openssl is required to verify the release signature (install it, or set DISTRIBRUTE_INSECURE_SKIP_MANIFEST_SIG=1 to bypass — NOT for production)."
  local sig="$TMP/manifest.env.sig" pem="$TMP/release.pem"
  fetch "$MANIFEST_SIG_URL" "$sig" || die "could not fetch the manifest signature from $MANIFEST_SIG_URL"
  release_pub_pem > "$pem"
  if openssl pkeyutl -verify -pubin -inkey "$pem" -rawin -in "$1" -sigfile "$sig" >/dev/null 2>&1; then
    info "manifest signature verified against the baked Release key"
  else
    die "manifest signature INVALID against the baked Release key — refusing (possible CDN tampering)."
  fi
}

# #10: run a command as root ONLY when needed — directly if already root or in test mode, else via
# sudo. The whole verify pipeline (manifest sig, download, sha256, extract) runs UNPRIVILEGED; we
# escalate ONLY here, for the system install, AFTER the package is cryptographically authenticated.
run_root() {
  if [ "$(id -u)" -eq 0 ] || test_mode; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -E "$@"
  else
    die "need root to install the system service, but sudo is unavailable — re-run as root."
  fi
}

# ------------------------------------------------------------------ 1) preflight
[ "$(uname -s)" = "Linux" ] || die "Linux only (found $(uname -s)); the agent is a Linux x86_64 GPU daemon."
case "$(uname -m)" in
  x86_64 | amd64) : ;;
  *) die "x86_64 only (found $(uname -m))." ;;
esac
for t in curl tar sha256sum readelf; do
  command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t (install it and re-run)."
done

# #10: we do NOT escalate to root here. The entire verify pipeline below — manifest signature,
# tarball download, sha256 check, and extraction of untrusted CDN bytes — runs as the invoking
# user, so a flaw in curl/tar/the parser never executes as root. run_root escalates via sudo ONLY
# for the final system install, after the package is cryptographically authenticated. (Running the
# whole thing under `sudo bash` still works — run_root then just no-ops the escalation.)
if ! test_mode && [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
  die "must be able to become root to install the system service, but sudo is not available. Re-run as root."
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/distribrute-bootstrap.XXXXXX")" || die "mktemp failed"
chmod 700 "$TMP"
# NOTE: for the FOREGROUND (container) path we `exec` the agent, which replaces this
# process, so this trap does NOT fire and the verified package tree survives. It fires
# only on an early error, or after install.sh has laid the package down system-wide.
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# ------------------------------------------------------------------ 2) manifest
info "fetching release manifest: $MANIFEST_URL"
MANIFEST="$TMP/manifest.env"
fetch "$MANIFEST_URL" "$MANIFEST" || die "could not fetch the release manifest from $MANIFEST_URL"

# #10: AUTHENTICATE the manifest with the offline Release key BEFORE parsing or trusting any field.
# This is what moves the root of trust off the CDN: AGENT_SHA256 (and the tarball hash) are now
# signed by a key the CDN attacker doesn't hold.
verify_manifest_sig "$MANIFEST"

# Parse KEY=VALUE lines WITHOUT sourcing (a compromised manifest must not run as code).
# Only the known keys are honored; everything else is ignored.
VERSION=""; TARBALL_URL=""; TARBALL_SHA256=""; AGENT_SHA256=""; BACKEND_URL=""; VERIFY_KEYRING=""
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    ''|'#'*) continue ;;
  esac
  key="${line%%=*}"
  val="${line#*=}"
  key="${key#"${key%%[![:space:]]*}"}"; key="${key%"${key##*[![:space:]]}"}"   # trim
  # strip surrounding single/double quotes if present
  case "$val" in
    \"*\") val="${val#\"}"; val="${val%\"}" ;;
    \'*\') val="${val#\'}"; val="${val%\'}" ;;
  esac
  case "$key" in
    VERSION)        VERSION="$val" ;;
    TARBALL_URL)    TARBALL_URL="$val" ;;
    TARBALL_SHA256) TARBALL_SHA256="$val" ;;
    AGENT_SHA256)   AGENT_SHA256="$val" ;;
    BACKEND_URL)    BACKEND_URL="$val" ;;
    VERIFY_KEYRING) VERIFY_KEYRING="$val" ;;
    *) : ;;
  esac
done < "$MANIFEST"

# validate — every field present + well-formed, else refuse
[ -n "$VERSION" ] || die "manifest missing VERSION"
printf '%s' "$VERSION" | grep -Eq '^[A-Za-z0-9._+-]+$' || die "manifest VERSION malformed: $VERSION"
[ -n "$TARBALL_URL" ] || die "manifest missing TARBALL_URL"
[ -n "$BACKEND_URL" ] || die "manifest missing BACKEND_URL"
[ -n "$VERIFY_KEYRING" ] || die "manifest missing VERIFY_KEYRING"
is_hex64 "$TARBALL_SHA256" || die "manifest TARBALL_SHA256 is not 64-hex: $TARBALL_SHA256"
is_hex64 "$AGENT_SHA256"   || die "manifest AGENT_SHA256 is not 64-hex: $AGENT_SHA256"
if ! test_mode; then
  case "$TARBALL_URL" in https://*) : ;; *) die "manifest TARBALL_URL must be https://: $TARBALL_URL" ;; esac
  case "$BACKEND_URL" in https://*) : ;; *) die "manifest BACKEND_URL must be https://: $BACKEND_URL" ;; esac
fi
# the Verify keyring is one-or-more comma-separated 32-byte (64-hex) X25519 pubkeys
_kr="$VERIFY_KEYRING"
while [ -n "$_kr" ]; do
  case "$_kr" in *,*) k="${_kr%%,*}"; _kr="${_kr#*,}" ;; *) k="$_kr"; _kr="" ;; esac
  is_hex64 "$k" || die "manifest VERIFY_KEYRING entry is not a 64-hex X25519 pubkey: $k"
done
info "manifest OK — version $VERSION"

# ------------------------------------------------------------------ 3) GPU detect
# nvidia-smi lists a GPU => run idle-gated (yield the card when someone else needs it).
# No GPU => 'always' + a loud warning: this is GPU prize work; a CPU-only host earns nothing.
if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1 && [ -n "$(nvidia-smi -L 2>/dev/null)" ]; then
  IDLE_MODE="nvidia-smi"
  info "GPU detected: $(nvidia-smi -L 2>/dev/null | head -1) -> idle-mode=nvidia-smi (yields when the GPU is busy)"
else
  IDLE_MODE="always"
  warn "no NVIDIA GPU detected (nvidia-smi -L failed). This is GPU work — a CPU-only host will NOT"
  warn "earn. Proceeding with idle-mode=always; install a GPU + driver for real throughput."
fi

# ------------------------------------------------------------------ 4) enrollment token
# The token gates BACKEND ACCESS (enroll -> lease work), not the download. Read it from the
# controlling terminal (NOT stdin — stdin is the piped script) and never echo it.
TOKEN="${DISTRIBRUTE_ENROLL_TOKEN:-}"
if [ -z "$TOKEN" ]; then
  if [ -r /dev/tty ]; then
    printf 'Paste your Distribrute enrollment token (mint one in the admin panel; input hidden): ' > /dev/tty
    IFS= read -rs TOKEN < /dev/tty || true
    printf '\n' > /dev/tty
  fi
fi
if [ -z "$TOKEN" ]; then
  die "no enrollment token and no TTY to prompt on. Either run:
      bash <(curl -fsSL $INSTALL_BASE)
  (keeps an interactive prompt), or pass it non-interactively:
      curl -fsSL $INSTALL_BASE | DISTRIBRUTE_ENROLL_TOKEN=<token> sudo -E bash
  Mint a one-time token in the admin panel."
fi

# ------------------------------------------------------------------ 5) download + verify tarball
info "downloading agent package: $TARBALL_URL"
TARBALL="$TMP/agent.tar.gz"
fetch "$TARBALL_URL" "$TARBALL" || die "could not download the agent package from $TARBALL_URL"
GOT="$(sha256sum "$TARBALL" | awk '{print $1}')"
[ "$GOT" = "$TARBALL_SHA256" ] || die "tarball sha256 MISMATCH (got $GOT, manifest $TARBALL_SHA256) — refusing."
info "tarball sha256 verified"

EXDIR="$TMP/extract"
mkdir -p "$EXDIR"
# #10: refuse a hostile archive BEFORE extracting. No absolute paths and no `..` traversal (can't
# escape $EXDIR), and ONLY regular files + directories — a genuine release has no symlinks, hardlinks,
# or devices (the release signer refuses symlinks too), so anything else is tampering.
if tar -tzf "$TARBALL" | grep -Eq '^/|(^|/)\.\.(/|$)'; then
  die "agent package contains an absolute or traversing path — refusing to extract (possible tampering)."
fi
if tar -tvzf "$TARBALL" | grep -qvE '^[-d]'; then
  die "agent package contains a non-regular entry (symlink/hardlink/device) — refusing to extract (possible tampering)."
fi
tar -xzf "$TARBALL" -C "$EXDIR" --no-same-owner || die "failed to extract the agent package"
# build-release-package.sh archives a top-level package/ dir; be tolerant of either shape.
if [ -d "$EXDIR/package" ] && [ -f "$EXDIR/package/release.json" ]; then
  PKG="$EXDIR/package"
elif [ -f "$EXDIR/release.json" ]; then
  PKG="$EXDIR"
else
  found="$(find "$EXDIR" -maxdepth 3 -name release.json -print -quit 2>/dev/null || true)"
  if [ -z "$found" ] || [ ! -f "$found" ]; then
    die "unexpected tarball layout: no release.json found"
  fi
  PKG="$(dirname "$found")"
fi

# ------------------------------------------------------------------ locate install.sh
# Prefer a sibling install.sh (repo checkout); otherwise fetch it from the SAME independent
# channel this bootstrap script came from — the public Distribrute/install repo over GitHub TLS,
# NOT the release CDN. #10: install.sh is part of the trust root (it authenticates the binary +
# package signature before anything runs), so it must ride the same off-CDN trust as this script;
# fetching it from the CDN would hand a CDN attacker a verifier that could simply skip the checks.
SCRIPT_BASE="${DISTRIBRUTE_SCRIPT_BASE:-https://raw.githubusercontent.com/Distribrute/install/v1}"
SCRIPT_BASE="${SCRIPT_BASE%/}"
if [ -n "${DISTRIBRUTE_INSTALL_SH:-}" ]; then
  INSTALL_SH="$DISTRIBRUTE_INSTALL_SH"
elif [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/install.sh" ]; then
  INSTALL_SH="$SELF_DIR/install.sh"
else
  INSTALL_SH="$TMP/install.sh"
  info "fetching installer: $SCRIPT_BASE/install.sh"
  fetch "$SCRIPT_BASE/install.sh" "$INSTALL_SH" || die "could not fetch install.sh from $SCRIPT_BASE/install.sh"
fi
[ -f "$INSTALL_SH" ] || die "installer not found: $INSTALL_SH"

# The binary-authentication flag we hand install.sh: normally the out-of-band sha256 from
# the manifest; the insecure bypass exists ONLY for the dry-run against a mock binary.
BINAUTH=(--expect-agent-sha256 "$AGENT_SHA256")
if [ "${DISTRIBRUTE_INSECURE_SKIP_BINARY_AUTH:-0}" = "1" ]; then
  warn "DISTRIBRUTE_INSECURE_SKIP_BINARY_AUTH=1 — telling install.sh to skip out-of-band binary auth. NOT for production."
  BINAUTH=(--insecure-skip-binary-auth)
fi

# ------------------------------------------------------------------ 6) install (systemd) or foreground (container)
systemd_usable() {
  test_mode && return 0                       # dry-run always drives the install.sh path
  command -v systemctl >/dev/null 2>&1 || return 1
  [ -d /run/systemd/system ] || return 1      # canonical "systemd is the init" check (sd_booted)
  return 0
}

run_systemd_install() {
  info "installing via systemd (install.sh) ..."
  local args=(
    install
    --package "$PKG"
    --backend "$BACKEND_URL"
    --verify-keyring "$VERIFY_KEYRING"
    --token "$TOKEN"
    --idle-mode "$IDLE_MODE"
    "${BINAUTH[@]}"
  )
  [ -n "${DISTRIBRUTE_DEVICE_ID:-}" ] && args+=(--device-id "$DISTRIBRUTE_DEVICE_ID")
  # DESTDIR passes through the environment (install.sh reads it); empty in production. run_root
  # (#10) escalates to root ONLY here — the verify pipeline above already ran unprivileged.
  run_root env DESTDIR="$DESTDIR" bash "$INSTALL_SH" "${args[@]}"
  if test_mode; then
    info "dry-run complete — install.sh laid the package down under DESTDIR=$DESTDIR (enroll/systemctl skipped)."
  else
    info "done. The agent is enrolled and running under systemd."
    info "  status: systemctl status distribrute-agent   |   logs: journalctl -u distribrute-agent -f"
  fi
}

# Container / no-systemd fallback (vast.ai and friends). We do NOT shell out to the
# container image installer (container/install.sh) here: that path has a DIFFERENT trust
# root (a digest-pinned OCI image + a separately-fetched authorizer pin/catalog), which
# this tarball manifest does not carry. Reusing install.sh's gate keeps ONE verifier and
# ONE root of trust (AGENT_SHA256). Operators who specifically want the Docker/Podman
# deployment on a full host should use container/install.sh with an @sha256 image digest
# (see install/README.md).
run_foreground() {
  warn "no usable systemd (container?). Falling back to a FOREGROUND run."
  info "verifying the release package (reusing install.sh's fail-closed gate) ..."
  bash "$INSTALL_SH" verify --package "$PKG" "${BINAUTH[@]}" \
    || die "package verification failed — refusing to run (possible tampering)."

  local bin="$PKG/bin/distribrute-agent"
  [ -x "$bin" ] || die "verified package has no executable agent binary at $bin"
  local state="${DISTRIBRUTE_STATE_DIR:-/var/lib/distribrute}"
  local workd="${DISTRIBRUTE_WORK_DIR:-/run/distribrute}"
  local device_id="${DISTRIBRUTE_DEVICE_ID:-$(uname -n)}"
  # #10: the verify above ran unprivileged; the state dir (default /var/lib) + daemon need root, so
  # escalate from HERE on via run_root (a no-op when already root, as in most containers).
  run_root mkdir -p "$state" "$workd"
  run_root chmod 700 "$state" "$workd" 2>/dev/null || true
  warn "container/foreground mode: the device key lives in $state. Mount it on PERSISTENT"
  warn "storage — enrollment tokens are one-time, so a wiped state dir can't re-enroll."

  # enroll once (idempotent). Scrubbed env: nothing ambient loads before the (verified) binary.
  if [ -f "$state/device.json" ]; then
    info "device already enrolled ($state/device.json) — skipping enroll"
  else
    info "enrolling device '$device_id' ..."
    run_root env -i PATH=/usr/bin:/bin \
      DISTRIBRUTE_BACKEND_URL="$BACKEND_URL" \
      DISTRIBRUTE_DEVICE_ID="$device_id" \
      DISTRIBRUTE_ENROLL_TOKEN="$TOKEN" \
      DISTRIBRUTE_STATE_DIR="$state" \
      "$bin" register || die "enroll failed — check the backend URL + token and retry."
  fi

  info "starting the agent in the FOREGROUND (Ctrl-C to stop) ..."
  # exec => this process BECOMES the daemon; the EXIT trap is replaced, so the verified package
  # tree in $TMP survives for the running agent. Escalate (sudo) only if we aren't already root.
  local fg=(env -i PATH=/usr/bin:/bin \
    DISTRIBRUTE_BACKEND_URL="$BACKEND_URL" \
    DISTRIBRUTE_VERIFY_KEYRING="$VERIFY_KEYRING" \
    DISTRIBRUTE_TOOL_CATALOG="$PKG/tools/tool_catalog.json" \
    DISTRIBRUTE_TOOLS_DIR="$PKG/tools" \
    DISTRIBRUTE_STATE_DIR="$state" \
    DISTRIBRUTE_WORK_DIR="$workd" \
    DISTRIBRUTE_IDLE_MODE="$IDLE_MODE" \
    DISTRIBRUTE_DAEMON=1 \
    DISTRIBRUTE_POLL_INTERVAL="${DISTRIBRUTE_POLL_INTERVAL:-30}" \
    "$bin" work)
  if [ "$(id -u)" -eq 0 ] || test_mode; then
    exec "${fg[@]}"
  elif command -v sudo >/dev/null 2>&1; then
    exec sudo "${fg[@]}"
  else
    die "need root to run the foreground daemon (state dir $state), but sudo is unavailable — re-run as root."
  fi
}

if systemd_usable; then
  run_systemd_install
else
  run_foreground
fi
