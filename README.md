# MongoDB Compression Leak Lab (Safe, Educational)

Reference CVE : **CVE-2025-14847**

This repository is an **educational lab** that demonstrates the *concept* behind a class of issues often described as “compression framing / size-metadata memory disclosure” in database wire protocols.

It is written to support defensive understanding: **how MongoDB network compression is negotiated and framed**, why **size fields matter**, and how robust parsers prevent unintended memory exposure.

> Note on CVE reference: This lab is framed around the idea referenced as **CVE-2025-14847** . This repo does **not** validate, reproduce, or exploit a specific vendor bug or claim that any particular MongoDB version is affected. It focuses on the general failure mode (mismatched size metadata around compressed payloads) and the mitigations.

## Version status (vulnerable vs patched)

This repository **does not** include (and should not be used as) evidence of which MongoDB versions are vulnerable or patched for any specific CVE.

To document “vulnerable” vs “patched” versions correctly for a report, use an **official vendor advisory / release notes** for the CVE and cite it.

Practical steps to verify what you are running:

- Docker container version:
  - `docker compose exec mongodb mongod --version`
  - or `docker compose exec mongodb mongosh --quiet --eval "db.version()"`
- Host installation version:
  - `mongod --version`
  - `mongosh --quiet --eval "db.version()"`

If you share the advisory link you’re using, I can format a clean “Affected / Fixed” table in the README without guessing.

## What the vulnerability is (conceptually)

This lab illustrates a **compression framing / size-metadata mismatch** failure mode:

- MongoDB messages are length-prefixed. With network compression, an `OP_COMPRESSED` envelope adds *more* size fields (outer message length, declared uncompressed size, and the inner message’s own length).
- If an implementation **trusts** any of these size fields without strict validation, it can mis-handle buffers during decompression or parsing.
- In buggy implementations, that can lead to **out-of-bounds reads** or returning **uninitialized buffer bytes**, which is one way “memory disclosure” can occur.

See `protocol_overview.md` for the detailed framing walkthrough.

## Ethical disclaimer

- This project is **non-exploitable by design**.
- It does **not** include weaponized logic, exploit code, or techniques intended to compromise systems.
- It should only be run against the **local Docker container** provided here.
- Do not point this code at systems you do not own or lack explicit permission to test.

## Learning objectives

By the end of the lab, you should be able to:

- Explain how MongoDB’s **wire protocol framing** works at a high level.
- Describe how **zlib network compression** is negotiated and applied.
- Understand how **malformed length / size metadata** could *conceptually* lead to memory exposure in a buggy implementation.
- Identify practical mitigations: patching, configuration hardening, and network detection.

## What this repo does (and does not do)

**It does:**
- Start MongoDB in Docker with **zlib compression enabled**.
- Use a tiny, original Python client to:
  - Send an uncompressed `hello` including `compression: ["zlib"]`
  - Send a **correctly framed** `OP_COMPRESSED` message using zlib
  - Log **uncompressed vs compressed sizes** and a summary of server responses
- Include a local “toy parser” demonstration that shows how a defensive parser rejects mismatched size metadata.

**It does NOT:**
- Craft malicious packets for real-world exploitation.
- Attempt authentication bypass.
- Attempt to read arbitrary memory.

## Repository contents

- `docker-compose.yml` – Runs a MongoDB container with zlib compression enabled and **localhost-only** exposure.
- `protocol_overview.md` – Wire protocol + BSON + compression workflow + conceptual vulnerability explanation.
- `mitigation.md` – Defense guidance: patching, config, and detection ideas.
- `lab_probe.py` – Original probe that negotiates compression and logs message sizes safely.

## How to run the lab safely

### 1) Prerequisites

- Docker Desktop (or compatible Docker engine)
- Python 3.10+ (recommended)

### 2) Start MongoDB

From this repo directory:

```powershell
docker compose up -d
```

Confirm it’s running:

```powershell
docker compose ps
```

### 3) Run the probe

```powershell
python .\lab_probe.py
```

Expected output:
- Prints negotiated compressors from the first `hello`
- Prints request/response sizes
- Sends a compressed `hello` and logs both compressed and decompressed message sizes

### 4) Run the toy demo (no network)

```powershell
python .\lab_probe.py --toy-demo
```

This runs only local parsing checks to illustrate why **size validation** matters.

### 5) Shut down

```powershell
docker compose down
```

## Safety notes

- The container is bound to `127.0.0.1:27017` on the host.
- No exploit behavior is present.
- The probe enforces conservative limits (e.g., maximum message size) and validates all length fields.

---

If you want, I can add a short `REPORT.md` template suitable for academic submission (without adding new functionality).