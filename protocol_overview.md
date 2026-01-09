# Protocol Overview: MongoDB Wire Protocol + Compression (Educational)

This document describes, in defensive research terms, how MongoDB’s network protocol frames messages and how optional network compression is applied.

The goal is to make it clear *why* incorrect size metadata is dangerous and *how* robust implementations prevent memory disclosure.

## 1) MongoDB wire protocol basics (framing)

MongoDB clients and servers exchange binary messages over TCP. Each message begins with a fixed-size header that lets the receiver know how many bytes to read.

At a high level:

- A **message header** indicates total message length and what kind of message follows.
- The receiver uses the length to read exactly the right number of bytes from the socket.
- The message body is then parsed based on the operation code.

### Message header (conceptual)

A typical message header contains:

- `messageLength` (int32 LE): total bytes in the message, including the header
- `requestID` (int32 LE): identifier set by the sender
- `responseTo` (int32 LE): requestID being answered (0 for client requests)
- `opCode` (int32 LE): message type

This lab uses `OP_MSG` (modern command messages) and `OP_COMPRESSED` (a wrapper for compression).

## 2) BSON structure (what commands look like)

MongoDB commands are typically encoded as **BSON** documents.

BSON is a binary encoding for JSON-like objects. A BSON document is:

- a 32-bit little-endian length (including the terminator)
- a sequence of typed elements
- a single `0x00` terminator byte

Elements are encoded as:

- one type byte
- a null-terminated string key
- the value bytes (format depends on type)

For example, the `hello` command is represented (conceptually) as a document with keys such as:

- `hello: 1`
- `client: { ... }`
- `compression: ["zlib", ...]`

## 3) zlib compression workflow in MongoDB

MongoDB supports network-level compression to reduce bandwidth. The workflow is:

1) Client sends an initial handshake command (commonly `hello`) and includes a list of supported compressors, e.g. `compression: ["zlib"]`.
2) Server replies with the subset it supports.
3) After negotiation, either side may wrap subsequent messages in an `OP_COMPRESSED` envelope.

### OP_COMPRESSED (conceptual envelope)

`OP_COMPRESSED` is a wrapper message that contains:

- the original opcode being wrapped (e.g., `OP_MSG`)
- the expected **uncompressed size**
- an identifier for which compressor is used (e.g., zlib)
- the compressed bytes of the original message

So on the wire, the receiver:

1) Parses the outer `messageLength` to read the full compressed envelope.
2) Reads `uncompressedSize` from the envelope.
3) Decompresses the payload.
4) Validates that the decompressed payload is a valid message (including internal length checks).

## 4) Conceptual vulnerability: malformed size metadata and memory exposure

This lab focuses on a common failure mode seen in binary protocols:

- A receiver trusts a size field (outer length, declared uncompressed size, or inner message length) without strong validation.
- The receiver then allocates buffers, copies bytes, or returns data using incorrect bounds.

### Where the mismatch can occur

Conceptually, these size fields must agree:

- Outer `messageLength`: how many bytes arrive on the wire for the compressed envelope
- Envelope `uncompressedSize`: how large the decompressed message *should* be
- Inner message’s own `messageLength`: how large the decompressed message *claims* to be

If any of these are inconsistent and code does not carefully validate them, the implementation might:

- read past the end of a buffer
- include uninitialized bytes in a response
- copy too many bytes from a heap buffer into an output

Any of those can produce an effect researchers describe as “memory disclosure” (leaking prior heap contents).

### Important: what this lab does

- The included Python probe **does not** send malformed packets to MongoDB.
- Instead, it demonstrates the *correct* framing and shows a **toy local parser** that rejects mismatches.

This is intentionally non-exploitable and suitable for academic settings.

## 5) Defensive takeaways

- Length fields are an attack surface: every boundary crossing (network → buffer → decompressor → parser) must be validated.
- Defensive parsers should enforce:
  - conservative maximum message sizes
  - exact size equality where required (e.g., decompressed length vs declared uncompressed length)
  - inner message self-consistency (inner `messageLength` must match actual bytes)

For patching and detection guidance, see `mitigation.md`.