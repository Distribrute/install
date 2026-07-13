# Distribrute agent installer

This repository is the **independent trust anchor** for installing the Distribrute operator
agent. It contains only the installer scripts and the Release **public** key — no application
source. Its job is to be a trust domain (GitHub) separate from the release CDN, so that a
compromise of the CDN alone cannot make you install a forged agent.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Distribrute/install/v1/bootstrap.sh | bash
```

You'll be prompted for a one-time enrollment token (mint one in the admin panel). To run
non-interactively:

```sh
curl -fsSL https://raw.githubusercontent.com/Distribrute/install/v1/bootstrap.sh \
  | DISTRIBRUTE_ENROLL_TOKEN=<token> bash
```

The script escalates with `sudo` **only** for the final system-service install — the download
and all verification run as your normal user first.

## Why fetch the script from here (and not the CDN)

`bootstrap.sh` has the Release public key **baked in** (`RELEASE_PUB.pem` / `RELEASE_PUB.hex`,
`f135e3a5…f713eff0`). Before it trusts anything, it verifies the release manifest's detached
Ed25519 signature against that key. The manifest carries `AGENT_SHA256`, and `install.sh`
checks the downloaded binary against it **before executing it**.

That means the chain of trust is:

```
this repo (GitHub TLS)  ─▶  baked Release pubkey
        │
        ▼  verifies signature of
   manifest.env  (from the release CDN)  ─▶  AGENT_SHA256
        │
        ▼  checked before exec
   agent binary  (from the release CDN)  ─▶  its own signed release.json (rest of the package)
```

Forging a release requires the **offline Release secret key**, not merely control of the CDN
(CloudFront/S3). The one thing that must reach you untampered is *this script + baked key* — so
fetch it from GitHub (a trust domain independent of the release CDN), **not** from the CDN.

- The bulk artifacts (`manifest.env`, `manifest.env.sig`, the agent tarball) are served from the
  release CDN (`get.distribrute.com`) — trusted only for **availability**, not authenticity.
- A host without OpenSSL 3.0+ cannot verify the signature; the installer then **fails closed**
  (bypassable only with an explicit, loudly-warned `DISTRIBRUTE_INSECURE_SKIP_MANIFEST_SIG=1`).

## Verifying a release yourself

The agent build is **byte-for-byte reproducible**. You can rebuild it from source in the pinned
container and confirm its `sha256` equals the signed `AGENT_SHA256` — no trust in the build box
required. See [`VERIFYING.md`](./VERIFYING.md).

## Contents

| File | What |
|---|---|
| `bootstrap.sh` | One-command entrypoint: fetch + verify the signed release, then install. |
| `install.sh` | Systemd installer + the fail-closed supply-chain gate (binary auth + package signature). |
| `RELEASE_PUB.pem` / `RELEASE_PUB.hex` | The Release public key releases are signed with. |

---

© Distribrute. These installer scripts are published so operators can install and independently
verify the agent; the agent application source is not part of this repository.
