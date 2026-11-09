# Adversary review 0001: framing (Phase 1)

**Surface:** `zt_proto::FrameDecoder::decode`, the only point where untrusted bytes
become domain types.
**Attacker:** peer authenticated at the Noise level but malicious (compromised agent, stolen
client), or a compromised relay that rewrites frames.

| # | Attack hypothesis | Outcome |
| :-: | :- | :- |
| 1 | Declare `length = 0xFFFF` to force 64 KiB of buffering per connection | **Mitigated.** Rejected from the header alone, before waiting for the payload (`rejects_oversized_length_from_the_header_alone`, property `oversized_lengths_rejected_before_buffering`). |
| 2 | Unknown version or kind to reach untested paths | **Mitigated.** Closed set, fatal error (`rejects_unsupported_versions`, `rejects_unknown_kinds`, all 247 undefined codes). |
| 3 | `Data` frame on stream 0 or `Ping` on a stream to confuse the demultiplexer | **Mitigated.** Stream scope validated in the header (`rejects_stream_frames_on_the_control_stream`, `rejects_control_frames_on_a_data_stream`). |
| 4 | After an error, keep sending in the hope of a resynchronisation | **Mitigated.** Poisoned decoder (`decoder_is_poisoned_after_the_first_error`). |
| 5 | Alternative encodings of the same frame to evade future filters or signatures | **Mitigated.** Canonical encoding verified on arbitrary and structured bytes (`arbitrary_bytes_never_panic_and_accepted_frames_are_canonical`, `structured_fuzz_never_panics`). |
| 6 | `NodeId` with uppercase, Unicode, NUL, newline for homographs, log injection or path traversal | **Mitigated.** Alphabet `[a-z0-9-]` (`rejects_invalid_node_ids`, domain tests). |
| 7 | Errors that echo the sent bytes into the relay logs | **Mitigated.** Errors carry metadata only (`errors_never_echo_attacker_bytes`). |
| 8 | Panic on fuzzed input (overflow, indexing) to bring the process down | **Mitigated.** `deny` lints on indexing and arithmetic, ~10 000 proptest cases per run, `panic = "abort"` in release limits the effect to one process. |
| 9 | Cut the connection mid-frame to leave partial state | **Mitigated.** EOF mid-frame is `DecodeError::Io` (`truncated_stream_is_an_error_not_a_silent_eof`). |
| 10 | Send many 1-byte `Data` frames: each returned `Bytes` shares the read buffer and can keep its allocation alive while it waits in a queue | **Open → Phase 2.** Bounded channels must be sized in **bytes**, not in number of frames, or small payloads must be copied before being queued. |
| 11 | Flood of `Ping`, unsolicited `Pong`, `WindowUpdate` that pushes the credit beyond `u32::MAX` | **Open → Phase 2.** The framing accepts them because they are well formed; rate limiting, `Pong` only in response, and summing credit with `checked_add` are the use cases' job. |
| 12 | Slowloris: send the header and then one byte a minute | **Open → Phase 2.** Per-frame and idle timeouts in the network adapter (`tokio::time::timeout`). |

**Verdict:** the decoder meets the guarantees of the specification. Findings 10–12 are input
requirements for Phase 2 and must be covered by attack tests before the implementation.
