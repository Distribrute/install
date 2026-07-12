# Verifying a Distribrute agent release

Two independent things you can check. The **signature** check works for anyone, right now, with
nothing but OpenSSL. The **reproducible-build** check additionally proves the signed bytes were
built from the published source.

## 1. Verify the release signature (anyone, now)

Every release manifest is signed with the offline **Release** key, and the installer verifies it
against the public key in this repo (`RELEASE_PUB.pem`) before trusting anything. To check by hand:

```sh
base=https://get.distribrute.com

# fetch the manifest and its detached signature
curl -fsSL "$base/latest/manifest.env"     -o manifest.env
curl -fsSL "$base/latest/manifest.env.sig" -o manifest.env.sig

# verify against the Release public key from THIS repo (independent of the CDN)
curl -fsSL https://raw.githubusercontent.com/Distribrute/install/main/RELEASE_PUB.pem -o RELEASE_PUB.pem
openssl pkeyutl -verify -pubin -inkey RELEASE_PUB.pem -rawin \
  -in manifest.env -sigfile manifest.env.sig
# => "Signature Verified Successfully"
```

`manifest.env` contains `AGENT_SHA256`. The installer checks the downloaded agent binary against
that hash **before executing it**, and the binary's own signed `release.json` covers every
remaining file in the package. So a valid manifest signature roots the entire install in the
offline Release key — a compromised CDN (CloudFront/S3) cannot forge it.

Confirm the public key's fingerprint out-of-band if you can:

```
sha256(RELEASE_PUB raw 32 bytes) — compare against a copy you trust
raw hex: f135e3a509faf27595586c646c2bed2b1616d8250a30c36671a0c900f713eff0
```

## 2. Reproduce the build (byte-for-byte)

The agent binary and the bundled hashcat are built **deterministically**: identical declared
inputs (source at a pinned ref, the public pins, and `SOURCE_DATE_EPOCH`, all recorded in the
release's `provenance.json`) reproduce identical bytes. Rebuilding them in the pinned container
and confirming the `sha256` equals the signed `AGENT_SHA256` removes any need to trust the build
machine.

The reproducible build runs entirely from source. The Distribrute agent/core source is **not yet
public** — until it is, end-to-end reproduction is available to the team and design partners with
source access; the signature check in §1 is the guarantee available publicly today. When the
source is published, this section will link the `reproduce.sh` harness and the exact
`--provenance` invocation.

---

Questions about a specific release's provenance: contact the Distribrute team.
