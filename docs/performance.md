# Transport performance, backpressure and measurement

The goal is bounded resource use and predictable behavior when a route or consumer slows down, not a claim that one protocol is always faster than another.

## Behavior

- Receiving a complete early response on H2 or H3 can end upload production. H3 `STOP_SENDING(H3_NO_ERROR)` stops further pulls from files/iterators and prevents submitting the remaining bytes of a partially accepted chunk. The client still waits for a valid final response; cancellation, missing headers and truncation remain errors. A producer callback already executing cannot be preempted.
- Alt-Svc competes on connection readiness, **not by sending a request twice**. A healthy warm TCP connection can be leased as the fallback. At a short budget (100 ms or less), an eligible warm TCP lease can be returned synchronously, without launching a QUIC attempt or penalizing the hint. Otherwise fallback start is bounded by the remaining connect budget. Repeated hints for the same recently failed alternate have a short cooldown; a new endpoint and an expired cooldown may probe again. HTTPS identity and certificate checks are unchanged. Expired Alt-Svc records and QUIC resumption tokens are pruned; limits are 256 alternatives, 256 cooldowns and 128 resumption-token entries, at most 16 KiB per token and 512 KiB in total. Both advertised lifetime and token lifetime are capped at 24 hours; the cooldown is 5 seconds.
- H2 stream admission, memory reservations, and adaptive polling are documented in [H2 flow control](h2-flow-control.md). These limits intentionally change the previous per-stream window boost; the initial Firefox SETTINGS values are retained. Neither a blocked consumer nor an idle connection should force a busy loop.
- Native H1/H2 reads copy only the used prefix into a new `bytes`. They avoid materializing a Python list of integers. The returned bytes do not reference a C buffer that can later change; out-of-bounds native lengths are rejected.
- Verified TLS connections reuse a **read-only parsed trust store**, not peer-verification decisions. The process-wide LRU is limited to 8 snapshots and 4 MiB of represented source material (not a bound on total cryptography/RSS overhead). Root source, exact contents and applicable root constraints participate in the identity. A file replacement with identical size/mtime, a directory membership change or a changed constraints file produces a different snapshot. Missing/malformed inputs fail rather than falling back to a cached good version. DNS names, leaf chains, client keys, client certificates and mutable per-connection state remain outside this cache. Rotation takes effect on new handshakes; close existing sessions if existing TLS connections must be retired immediately.
- H3 controls remain JSON. When the library advertises compatible binary body ABI v1 with all required exports, the connection uses bounded pointer/count operations on its owning thread. A wheel without those exports uses the existing JSON/Base64 body ABI. This capability check is per loaded runtime, not inferred from OS name. In the compatibility path the worker avoids repeated Python encoding and mitigates no-progress retries. See the native slot provenance for source patches and target qualifications.

## Reproducible performance trend

The [performance workflow](../.github/workflows/transport-performance.yml) runs weekly (Monday 03:17 UTC), on manual dispatch, and on relevant same-repository PRs. Compare installed wheels with the same runner, CPU affinity, Python and dependencies. Weekly trends retain the pre-optimization `ea44f8f` reference. For the selective Firefox 161 upgrade, PRs compare with the previous fork `0.9.1` (`fae13b0`); manual runs can select either fixed reference. Both use fresh temporary certificates and actual loopback H1/TLS, hyper-h2 and aioquic peers, served by a separate process. It does not require a public network origin. Wheel downloads and dependency installation happen during setup.

To reproduce on Linux using the actual target wheel, from outside the source tree:

```bash
python -m venv .venv
.venv/bin/python -m pip install -r /path/to/ruyihttp/benchmarks/requirements.txt /path/to/ruyihttp-wheel.whl
.venv/bin/python /path/to/ruyihttp/benchmarks/transport.py --wheel /path/to/ruyihttp-wheel.whl --commit <wheel-source-commit> --output candidate.json
.venv/bin/python /path/to/ruyihttp/benchmarks/summary.py candidate.json --reference baseline.json
```

The harness checks every package member against the specified wheel, the HTTP version/ALPN and the SHA-256 of each timed response. Warm samples require the same connection ID. The JSON artifact includes source/wheel identity, dependency versions, CPU affinity, load, warm and fresh-request latency, client process CPU per MiB, throughput, idle H2 polls/CPU, local H3 bridge bytes, and fast-stream latency/RSS while a large stream is left unread. The RSS counters include Python/runtime allocations; body ABI byte counts are local handoffs, not UDP traffic. Empty sample sets and timeout outcomes are recorded for the intentionally slow-consumer comparison, not counted as fast successes.

Shared runner timings are descriptive. No absolute millisecond threshold blocks a release; protocol behavior, byte equality and trust checks are hard gates. For production extrapolation, repeat at realistic concurrency, RTT, loss and CA configuration on fixed hardware. Keep raw performance artifacts and compare like-for-like CPU/Python/native versions.

### Measured checkpoint: 0.9.1 transport against `ea44f8f`

[Paired hosted ARM64 run](https://github.com/Facetomyself/ruyihttp/actions/runs/45667328076), 2026-11-26: the installed `b067d6b` transport and baseline were exercised sequentially on the same CPU affinity, CPython 3.12.16, with an independent loopback origin. Hot 256 KiB downloads in 64 KiB application chunks returned the same bytes. Median wall times were H1 **11.80 → 1.77 ms**, H2 **10.35 → 3.47 ms**, H3 **14.41 → 14.01 ms** (18 samples each, per wheel). H2 requests that created a fresh session with the full test trust bundle were slightly slower in this sample (**52.32 → 54.95 ms**), despite lower client CPU. No blanket speedup is claimed.

Default trust construction p50 fell from **3.74 to 0.18 ms**. On the unread 12 MiB H2 stream test, small requests completing before reading the large response rose from **0/32 to 32/32 on the same connection**; candidate p95 was 2.15 ms. Four quiet H2 connections produced about **397 → 99 pending probes/s**. A verified 1 MiB H3 upload took **1,716,752 → 0 JSON body-frame bytes**; the latter transferred the payload using the binary data ABI. This is a local encoding measure, not network compression.
