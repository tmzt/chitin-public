# Chitin Public Crates

This repository contains a subset of the Chitin project's networking crates, extracted for public use.

> [!WARNING]
> **Pre-release / Subject to Change**: This is an early extraction of the Chitin networking stack. The API and wire format are subject to breaking changes.
>
> **Security & Fuzzing**: These crates have **not** undergone a formal security audit or exhaustive fuzzing. While they are built on top of well-maintained and widely used libraries like `yamux` and `smol`, the custom framing and protocol logic should be considered experimental. Use at your own risk in production environments.

## Included Crates

- **network_transport**: The foundational layer. Defines the unified 16-byte frame header, endpoint addressing (node/service/resource), and the binary message envelope. It includes a priority-based `OutboundHeap` for message queuing.
- **network_mux**: A high-level session manager built on `yamux` and `smol`. It provides `MuxSession`, which handles background polling, reading, and writing of frames over TCP.

## Architectural Overview

The Chitin networking stack is designed for a distributed system of "nodes" and "services". It provides a lightweight, prioritized message-passing interface over multiplexed TCP streams.

### 1. Unified Framing (`network_transport`)

All communication uses a 16-byte header followed by an optional payload (up to 256KB).

```text
[version: u16 LE]  - Protocol version (currently 1)
[checksum: u16 LE] - Internet checksum of header and payload
[mesh_key: u32 LE] - Packed source and destination endpoints
[ext: u32 LE]      - Extended field (obo/on-behalf-of and in-reply-to)
[flags: u16 LE]    - Format (JSONL/Bincode/Raw), TTL, and TCP-like flags (SYN/FIN/RST/ACK)
[len: u16 LE]      - Payload length in 4-byte words (padded)
[payload...]       - Variable length data
```

### 2. Endpoint Addressing

Endpoints are packed `u16` values consisting of:
- **Node ID (6 bits)**: Identifies the physical or virtual machine (0=Concentrator, 63=Broadcast).
- **Resource Type (4 bits)**: Service, Project, Task, Process, etc.
- **Resource ID (6 bits)**: The specific instance (e.g., Service ID).

This allows for efficient routing and filtering of messages at the edge without full packet inspection.

### 3. Priority Queuing

The `OutboundHeap` in `network_transport` implements a three-tier priority system:
- **Realtime**: For low-latency control signals (e.g., audio start/stop).
- **Normal**: For standard request/response traffic (e.g., LLM inference).
- **Bulk**: For background data transfers (e.g., file syncing).

### 4. Multiplexing (`network_mux`)

`network_mux` uses the `yamux` protocol to multiplex multiple logical streams over a single TCP connection.
- **Stream 0**: Reserved for the control plane (node registration, service discovery, heartbeats).
- **Additional Streams**: Opened dynamically for high-bandwidth or long-lived tasks like terminal sessions (PTY) or raw audio streaming.

Each `MuxSession` spawns three background tasks (using `smol`):
1. **Poller**: Drives the `yamux` connection state.
2. **Reader**: Decodes frames from Stream 0 and dispatches them to a callback.
3. **Writer**: Drains the `OutboundHeap` and writes frames to the wire.

## License

These crates are dual-licensed under:

- **MIT license** ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

Copyright © 2026 Timothy Meade
