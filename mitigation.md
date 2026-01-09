# Mitigation and Defensive Guidance

This document lists practical steps to reduce risk from protocol-level issues involving compression framing, size metadata, and parser robustness.

## 1) Patch recommendations

- **Upgrade MongoDB** to the latest vendor-supported patch release for your major version.
- If a vendor advisory exists for your environment, follow it and prioritize updates for:
  - `mongod` server packages
  - client drivers used in applications (they also parse server responses)

Why it helps:
- Most size/length vulnerabilities are fixed by tightening bounds checks, validating size fields, and hardening decompression paths.

### Determining “vulnerable” vs “patched” versions (reporting guidance)

This repo intentionally does not claim which specific MongoDB versions are vulnerable or fixed for a given CVE.

For accurate reporting:

- Use an official **vendor advisory** and/or **release notes** for the CVE.
- Record both:
  - the earliest version listed as **fixed** for each supported major/minor line
  - any versions explicitly listed as **affected**

To identify the exact version you’re running:

- Docker container:
  - `docker compose exec mongodb mongod --version`
  - or `docker compose exec mongodb mongosh --quiet --eval "db.version()"`
- Host install:
  - `mongod --version`
  - `mongosh --quiet --eval "db.version()"`

## 2) Secure configuration guidance

### Consider disabling network compression where not needed

If compression does not provide meaningful benefit (e.g., low-latency local networks), you can reduce exposure by disabling it.

- Server-side: remove or avoid enabling `--networkMessageCompressors`.
- Client-side: configure drivers to avoid requesting compressors.

Trade-off:
- Increased bandwidth usage versus reduced attack surface.

### Enforce network segmentation and least exposure

- Bind MongoDB to private interfaces only.
- Restrict inbound access to trusted application subnets.
- Avoid exposing MongoDB directly to the public Internet.

This lab’s Docker config uses **localhost-only** publishing (`127.0.0.1:27017`).

### Use authentication and authorization

Even though protocol bugs can occur before auth, strong access controls still reduce overall risk.

- Enable authentication and enforce least-privilege roles.
- Rotate credentials and use secrets management.

## 3) Network-level detection ideas (defensive monitoring)

Compression-related issues often manifest as *abnormal framing*. Detection opportunities include:

- **Unexpected `OP_COMPRESSED` usage**:
  - clients that do not normally use compression suddenly sending compressed messages
  - compressed traffic to servers that typically see only uncompressed traffic

- **Length anomalies** (best-effort, depends on visibility):
  - outer `messageLength` values that are unusually large
  - repeated connection resets around compression negotiation

- **Handshake oddities**:
  - `hello` commands advertising unusual compressor lists
  - rapid sequences of failed handshakes

Where to implement:
- Network sensors (IDS/IPS) with MongoDB protocol awareness
- Proxy-based inspection (where TLS is not used, or after TLS termination)
- Server logs and connection telemetry

Limitations:
- If MongoDB traffic is protected by TLS end-to-end, deep packet inspection may not be possible without termination.

## 4) Application / driver hygiene

- Keep MongoDB drivers up to date.
- Avoid custom protocol implementations in production.
- Prefer well-tested libraries for BSON handling.

## 5) Incident response notes

If you suspect exploitation of a protocol bug:

- Isolate the affected host(s) and capture:
  - MongoDB logs
  - connection metadata (source IPs, rates)
  - process crash dumps (if any)
- Compare traffic patterns before/after the suspected window.
- Apply patches and rotate credentials.

---

This repo intentionally provides **no exploitation path**; it is designed to support defense-focused learning.