"""mongo-compression-leak-lab: Safe probe for MongoDB network compression.

This script is intentionally defensive and non-exploitable:
- Sends only well-formed messages.
- Negotiates zlib compression via `hello` and then sends a correctly framed `OP_COMPRESSED` message.
- Logs sizes and server responses.
- Includes a LOCAL-ONLY "toy demo" showing how mismatched size metadata should be rejected.

It does NOT:
- attempt authentication bypass
- craft malicious packets
- attempt to read server memory

Tested target: the Docker container defined in docker-compose.yml (localhost-only).
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time
import zlib
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


# MongoDB opcodes used in this lab
OP_COMPRESSED = 2012
OP_MSG = 2013

# Compressor IDs in OP_COMPRESSED envelope
COMPRESSOR_ZLIB = 2

# Conservative limits: educational probe, not a full driver
MAX_WIRE_MESSAGE_BYTES = 16 * 1024 * 1024  # 16 MiB
SOCKET_TIMEOUT_SECONDS = 5


class ProtocolError(RuntimeError):
    pass


# -------------------------
# Minimal BSON (subset)
# -------------------------

# BSON type codes used here (not exhaustive)
BSON_DOUBLE = 0x01
BSON_STRING = 0x02
BSON_DOCUMENT = 0x03
BSON_ARRAY = 0x04
BSON_BINARY = 0x05
BSON_BOOL = 0x08
BSON_NULL = 0x0A
BSON_INT32 = 0x10
BSON_INT64 = 0x12


def _encode_cstring(value: str) -> bytes:
    if "\x00" in value:
        raise ValueError("CString cannot contain NUL")
    return value.encode("utf-8") + b"\x00"


def bson_encode(document: Dict[str, Any]) -> bytes:
    """Encode a limited subset of Python types to BSON.

    Supported:
    - int (int32/int64 selection)
    - float
    - str
    - bool
    - None
    - dict (embedded doc)
    - list (array)
    """

    elements = bytearray()
    for key, value in document.items():
        elements += bson_encode_element(key, value)

    total_len = 4 + len(elements) + 1
    return struct.pack("<i", total_len) + bytes(elements) + b"\x00"


def bson_encode_element(key: str, value: Any) -> bytes:
    key_bytes = _encode_cstring(key)

    if value is None:
        return bytes([BSON_NULL]) + key_bytes

    if isinstance(value, bool):
        return bytes([BSON_BOOL]) + key_bytes + (b"\x01" if value else b"\x00")

    if isinstance(value, int):
        # Choose int32 when safe; otherwise int64.
        if -(2**31) <= value <= (2**31 - 1):
            return bytes([BSON_INT32]) + key_bytes + struct.pack("<i", value)
        return bytes([BSON_INT64]) + key_bytes + struct.pack("<q", value)

    if isinstance(value, float):
        return bytes([BSON_DOUBLE]) + key_bytes + struct.pack("<d", value)

    if isinstance(value, str):
        raw = value.encode("utf-8")
        # BSON string includes int32 byte length INCLUDING trailing NUL
        return bytes([BSON_STRING]) + key_bytes + struct.pack("<i", len(raw) + 1) + raw + b"\x00"

    if isinstance(value, dict):
        encoded = bson_encode(value)
        return bytes([BSON_DOCUMENT]) + key_bytes + encoded

    if isinstance(value, list):
        as_doc = {str(i): value[i] for i in range(len(value))}
        encoded = bson_encode(as_doc)
        return bytes([BSON_ARRAY]) + key_bytes + encoded

    raise TypeError(f"Unsupported BSON type for key={key!r}: {type(value).__name__}")


def bson_decode(data: bytes, *, max_depth: int = 20) -> Dict[str, Any]:
    """Decode a limited subset of BSON into Python objects."""
    if max_depth <= 0:
        raise ProtocolError("BSON max depth exceeded")

    if len(data) < 5:
        raise ProtocolError("BSON document too short")

    declared_len = struct.unpack_from("<i", data, 0)[0]
    if declared_len < 5 or declared_len > len(data):
        raise ProtocolError("BSON length mismatch")
    if data[declared_len - 1] != 0:
        raise ProtocolError("BSON missing terminator")

    offset = 4
    out: Dict[str, Any] = {}

    while offset < declared_len - 1:
        element_type = data[offset]
        offset += 1

        key_end = data.find(b"\x00", offset)
        if key_end == -1:
            raise ProtocolError("BSON cstring key not terminated")
        key = data[offset:key_end].decode("utf-8", errors="replace")
        offset = key_end + 1

        value, offset = bson_decode_value(element_type, data, offset, declared_len, max_depth=max_depth)
        out[key] = value

    return out


def bson_decode_value(
    element_type: int,
    data: bytes,
    offset: int,
    declared_doc_len: int,
    *,
    max_depth: int,
) -> Tuple[Any, int]:
    """Decode a single BSON element value."""

    def need(n: int) -> None:
        if offset + n > declared_doc_len:
            raise ProtocolError("BSON value out of bounds")

    if element_type == BSON_NULL:
        return None, offset

    if element_type == BSON_BOOL:
        need(1)
        return data[offset] == 1, offset + 1

    if element_type == BSON_INT32:
        need(4)
        return struct.unpack_from("<i", data, offset)[0], offset + 4

    if element_type == BSON_INT64:
        need(8)
        return struct.unpack_from("<q", data, offset)[0], offset + 8

    if element_type == BSON_DOUBLE:
        need(8)
        return struct.unpack_from("<d", data, offset)[0], offset + 8

    if element_type == BSON_STRING:
        need(4)
        n = struct.unpack_from("<i", data, offset)[0]
        if n <= 0:
            raise ProtocolError("Invalid BSON string length")
        need(4 + n)
        raw = data[offset + 4 : offset + 4 + n]
        if raw[-1] != 0:
            raise ProtocolError("BSON string missing terminator")
        return raw[:-1].decode("utf-8", errors="replace"), offset + 4 + n

    if element_type in (BSON_DOCUMENT, BSON_ARRAY):
        # Embedded document begins with its own length
        need(4)
        embedded_len = struct.unpack_from("<i", data, offset)[0]
        if embedded_len < 5:
            raise ProtocolError("Embedded BSON too short")
        need(embedded_len)
        embedded_bytes = data[offset : offset + embedded_len]
        decoded = bson_decode(embedded_bytes, max_depth=max_depth - 1)
        if element_type == BSON_ARRAY:
            # Convert numeric keys to a list where possible
            items: List[Tuple[int, Any]] = []
            for k, v in decoded.items():
                try:
                    idx = int(k)
                except ValueError:
                    idx = None
                if idx is None:
                    continue
                items.append((idx, v))
            if not items:
                return [], offset + embedded_len
            max_index = max(i for i, _ in items)
            arr: List[Any] = [None] * (max_index + 1)
            for i, v in items:
                if 0 <= i < len(arr):
                    arr[i] = v
            return arr, offset + embedded_len

        return decoded, offset + embedded_len

    if element_type == BSON_BINARY:
        need(5)
        n = struct.unpack_from("<i", data, offset)[0]
        subtype = data[offset + 4]
        need(5 + n)
        blob = data[offset + 5 : offset + 5 + n]
        # Return a descriptive tuple rather than raw bytes to keep output readable.
        return {"binary_subtype": subtype, "length": n}, offset + 5 + n

    # Unknown type: defensive skip is not generally safe without knowing length.
    raise ProtocolError(f"Unsupported BSON element type: 0x{element_type:02x}")


# -------------------------
# MongoDB message framing
# -------------------------


@dataclass
class MongoMessage:
    op_code: int
    request_id: int
    response_to: int
    body: bytes


def pack_message(op_code: int, request_id: int, response_to: int, body: bytes) -> bytes:
    total_len = 16 + len(body)
    if total_len > MAX_WIRE_MESSAGE_BYTES:
        raise ProtocolError("Refusing to build oversized message")
    header = struct.pack("<iiii", total_len, request_id, response_to, op_code)
    return header + body


def pack_op_msg(command_doc: Dict[str, Any], *, request_id: int) -> bytes:
    # OP_MSG body:
    # int32 flagBits
    # byte 0x00 (section kind = 0)
    # BSON document
    flags = 0
    section_kind = b"\x00"
    bson = bson_encode(command_doc)
    body = struct.pack("<i", flags) + section_kind + bson
    return pack_message(OP_MSG, request_id=request_id, response_to=0, body=body)


def pack_op_compressed(
    original_message: bytes,
    *,
    request_id: int,
    compressor_id: int = COMPRESSOR_ZLIB,
) -> bytes:
    # OP_COMPRESSED body:
    # int32 originalOpcode
    # int32 uncompressedSize
    # uint8 compressorId
    # bytes compressedMessage

    if len(original_message) < 16:
        raise ProtocolError("Original message too short")

    original_opcode = struct.unpack_from("<i", original_message, 12)[0]
    uncompressed_size = len(original_message)

    if compressor_id != COMPRESSOR_ZLIB:
        raise ProtocolError("This lab probe only supports zlib")

    compressed_payload = zlib.compress(original_message, level=6)

    body = (
        struct.pack("<i", original_opcode)
        + struct.pack("<i", uncompressed_size)
        + struct.pack("<B", compressor_id)
        + compressed_payload
    )
    return pack_message(OP_COMPRESSED, request_id=request_id, response_to=0, body=body)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError("Connection closed while reading")
        buf += chunk
    return bytes(buf)


def recv_message(sock: socket.socket) -> MongoMessage:
    header = recv_exact(sock, 16)
    message_length, request_id, response_to, op_code = struct.unpack("<iiii", header)

    if message_length < 16:
        raise ProtocolError("Invalid messageLength < 16")
    if message_length > MAX_WIRE_MESSAGE_BYTES:
        raise ProtocolError("Refusing oversized message from server")

    body = recv_exact(sock, message_length - 16)
    return MongoMessage(op_code=op_code, request_id=request_id, response_to=response_to, body=body)


def unpack_op_msg_body(body: bytes) -> Dict[str, Any]:
    if len(body) < 5:
        raise ProtocolError("OP_MSG body too short")
    flags = struct.unpack_from("<i", body, 0)[0]
    _ = flags  # flags are not used by this lab

    section_kind = body[4]
    if section_kind != 0:
        raise ProtocolError("Only OP_MSG section kind 0 is supported in this lab")

    doc_bytes = body[5:]
    return bson_decode(doc_bytes)


def unpack_op_compressed_body(body: bytes) -> Tuple[int, int, int, bytes]:
    if len(body) < 9:
        raise ProtocolError("OP_COMPRESSED body too short")

    original_opcode = struct.unpack_from("<i", body, 0)[0]
    uncompressed_size = struct.unpack_from("<i", body, 4)[0]
    compressor_id = body[8]
    compressed_payload = body[9:]

    return original_opcode, uncompressed_size, compressor_id, compressed_payload


def decode_server_reply(msg: MongoMessage) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Return (decoded_document, size_metrics)."""

    metrics: Dict[str, int] = {
        "wire_message_bytes": 16 + len(msg.body),
        "compressed_payload_bytes": 0,
        "decompressed_message_bytes": 0,
    }

    if msg.op_code == OP_MSG:
        doc = unpack_op_msg_body(msg.body)
        metrics["decompressed_message_bytes"] = metrics["wire_message_bytes"]
        return doc, metrics

    if msg.op_code == OP_COMPRESSED:
        original_opcode, declared_uncompressed, compressor_id, compressed_payload = unpack_op_compressed_body(msg.body)
        metrics["compressed_payload_bytes"] = len(compressed_payload)

        if compressor_id != COMPRESSOR_ZLIB:
            raise ProtocolError(f"Unsupported compressorId from server: {compressor_id}")
        if declared_uncompressed <= 0 or declared_uncompressed > MAX_WIRE_MESSAGE_BYTES:
            raise ProtocolError("Declared uncompressedSize is unreasonable")

        decompressed = zlib.decompress(compressed_payload)

        # Defensive invariants: these are the types of checks that prevent disclosure bugs.
        if len(decompressed) != declared_uncompressed:
            raise ProtocolError(
                "Decompressed size mismatch (defensive abort): "
                f"declared={declared_uncompressed} actual={len(decompressed)}"
            )

        # The decompressed bytes must themselves be a valid MongoDB message.
        if len(decompressed) < 16:
            raise ProtocolError("Inner message too short")
        inner_len, inner_req, inner_resp_to, inner_op = struct.unpack_from("<iiii", decompressed, 0)
        if inner_len != len(decompressed):
            raise ProtocolError("Inner messageLength mismatch")
        if inner_op != original_opcode:
            raise ProtocolError("Inner opcode mismatch")

        metrics["decompressed_message_bytes"] = len(decompressed)

        if inner_op != OP_MSG:
            raise ProtocolError("Inner opcode not supported in this lab")

        inner_body = decompressed[16:]
        doc = unpack_op_msg_body(inner_body)
        return doc, metrics

    raise ProtocolError(f"Unsupported server opcode: {msg.op_code}")


# -------------------------
# Lab logic
# -------------------------


def build_hello_doc() -> Dict[str, Any]:
    # Keep the command minimal: we want safe negotiation only.
    return {
        "hello": 1,
        "client": {"application": {"name": "mongo-compression-leak-lab"}},
        "compression": ["zlib"],
    }


def summarize_hello(doc: Dict[str, Any]) -> Dict[str, Any]:
    # Print a small, readable subset.
    keys_of_interest = [
        "ok",
        "isWritablePrimary",
        "msg",
        "maxWireVersion",
        "minWireVersion",
        "compression",
        "connectionId",
        "localTime",
    ]
    out: Dict[str, Any] = {}
    for k in keys_of_interest:
        if k in doc:
            out[k] = doc[k]
    return out


def run_probe(host: str, port: int) -> int:
    print(f"[+] Connecting to {host}:{port} (timeout={SOCKET_TIMEOUT_SECONDS}s)")

    with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT_SECONDS) as sock:
        sock.settimeout(SOCKET_TIMEOUT_SECONDS)

        # 1) Uncompressed hello with compression negotiation
        req_id_1 = int.from_bytes(os.urandom(4), "little", signed=False)
        hello_msg = pack_op_msg(build_hello_doc(), request_id=req_id_1)

        print("\n[>] Sending uncompressed hello")
        print(f"    request_bytes={len(hello_msg)}")
        sock.sendall(hello_msg)

        reply_1 = recv_message(sock)
        doc_1, metrics_1 = decode_server_reply(reply_1)

        print("[<] Server replied to hello")
        print(f"    wire_bytes={metrics_1['wire_message_bytes']} opcode={reply_1.op_code}")
        print(f"    summary={summarize_hello(doc_1)}")

        server_compressors = doc_1.get("compression", [])
        if not isinstance(server_compressors, list):
            server_compressors = []

        if "zlib" not in server_compressors:
            print("\n[!] Server did not advertise zlib; skipping compressed request.")
            return 0

        # 2) Compressed hello (correctly framed)
        req_id_2 = (req_id_1 + 1) & 0x7FFFFFFF
        inner = pack_op_msg({"hello": 1}, request_id=req_id_2)
        compressed = pack_op_compressed(inner, request_id=req_id_2, compressor_id=COMPRESSOR_ZLIB)

        print("\n[>] Sending compressed hello (well-formed)")
        print(f"    inner_uncompressed_bytes={len(inner)}")
        print(f"    outer_wire_bytes={len(compressed)}")

        sock.sendall(compressed)

        reply_2 = recv_message(sock)
        doc_2, metrics_2 = decode_server_reply(reply_2)

        print("[<] Server replied to compressed hello")
        print(f"    wire_bytes={metrics_2['wire_message_bytes']} opcode={reply_2.op_code}")
        if reply_2.op_code == OP_COMPRESSED:
            print(f"    compressed_payload_bytes={metrics_2['compressed_payload_bytes']}")
            print(f"    decompressed_message_bytes={metrics_2['decompressed_message_bytes']}")
        print(f"    summary={summarize_hello(doc_2)}")

    print("\n[+] Done. No malformed packets were sent.")
    return 0


# -------------------------
# Toy demo (local only)
# -------------------------


def toy_demo_size_mismatch() -> None:
    """Local-only demonstration of defensive size validation.

    This does NOT send anything to MongoDB.

    It builds a well-formed inner message, compresses it, then shows how a
    defensive parser rejects a mismatch between declared and actual sizes.

    Conceptually, if a buggy implementation *trusted* the declared size and
    then copied bytes beyond the true decompressed buffer, it might disclose
    unrelated memory contents.
    """

    print("[toy] Building a well-formed inner OP_MSG")
    inner = pack_op_msg({"hello": 1}, request_id=1234)
    compressed_payload = zlib.compress(inner, level=6)

    declared_uncompressed = len(inner) + 32  # intentionally incorrect metadata

    print("[toy] Simulating OP_COMPRESSED parsing with mismatched size metadata")
    print(f"      declared_uncompressed={declared_uncompressed}")
    print(f"      actual_uncompressed={len(inner)}")
    print(f"      compressed_payload_bytes={len(compressed_payload)}")

    decompressed = zlib.decompress(compressed_payload)

    try:
        if len(decompressed) != declared_uncompressed:
            raise ProtocolError(
                "Defensive abort: declared uncompressedSize does not match actual decompressed size. "
                "A robust implementation should stop here."
            )
    except ProtocolError as exc:
        print(f"[toy] PASS (rejected mismatch): {exc}")
        return

    print("[toy] Unexpected: mismatch was not detected (this should not happen).")


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Safe MongoDB compression probe (educational)")
    parser.add_argument("--host", default="127.0.0.1", help="MongoDB host (default: 127.0.0.1)")
    parser.add_argument("--port", default=27017, type=int, help="MongoDB port (default: 27017)")
    parser.add_argument(
        "--toy-demo",
        action="store_true",
        help="Run local-only toy size-mismatch demo (no network)",
    )

    args = parser.parse_args(argv)

    if args.toy_demo:
        toy_demo_size_mismatch()
        return 0

    try:
        return run_probe(args.host, args.port)
    except (ProtocolError, socket.timeout, ConnectionError, OSError) as exc:
        print(f"[!] Error: {exc}")
        print("[!] Ensure Docker is running and `docker compose up -d` was executed in this repo.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
