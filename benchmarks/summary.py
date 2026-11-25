"""Render comparable, descriptive measurements. No absolute latency gate on shared runners."""

import argparse
import json
from pathlib import Path


def render(report, reference=None):
    env = report["environment"]
    lines = [
        "# Installed-wheel loopback trend",
        "",
        f"`{env['commit']}` — {env['arch']}, {env['affinity']} CPUs, {env['libc']}, Python {env['python']}",
        f"Wheel `{env['wheel']}` · SHA-256 `{env['sha256']}`",
        "",
    ]
    if reference:
        prev = reference["environment"]
        lines.append(
            f"Reference: `{prev['commit']}`, SHA-256 `{prev['sha256']}`. Ratio is candidate / reference; it is descriptive, not a release cutoff."
        )
    lines.extend(
        [
            "",
            "| Scenario | n | p50 ms | p95 ms | client CPU ms/MiB | MiB/s | p50 ratio |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for name, row in sorted(report["scenarios"].items()):
        median = row["elapsed_ms"]["p50"]
        old = reference["scenarios"][name]["elapsed_ms"]["p50"] if reference else None
        ratio = f"{median / old:.2f}" if old else "—"
        lines.append(
            f"| {name} | {row['elapsed_ms']['n']} | {median:.2f} | {row['elapsed_ms']['p95']:.2f} | {row['client_cpu_ms_per_MiB']:.2f} | {row['aggregate_MiB_per_s']:.2f} | {ratio} |"
        )
    fair = report["stream_fairness"]
    small = fair["small_latency_ms"] or {}
    h3 = report["h3_upload"]
    lines.extend(
        [
            "",
            f"- Default trust-material construction p50: {report['trust_construction']['default']['elapsed_ms']['p50']:.4f} ms ({report['packaged_roots']} roots).",
            f"- Unread large H2 response: {fair['unread_response_bytes_reported_by_peer']} bytes admitted at the origin; {fair['small_completed']}/32 small responses completed; p95 {small.get('p95', '—')} ms; error: {fair['error'] or 'none'}.",
            f"- Client RSS while holding unread response: {fair['rss_while_unread_kib']} KiB (before {fair['rss_before_kib']} KiB).",
            f"- H3 upload: ABI {h3['body_abi']}, {h3['effective_bytes']} application bytes, {h3['json_bytes_per_effective_byte']:.3f} JSON frame bytes per effective byte. This measures the local bridge, not the network.",
            "- Idle H2 (native checks/s, uninstrumented client CPU fraction): "
            + ", ".join(
                f"{x['connections']} connections → {x['pending_polls_per_sec']:.1f}/s, {x['client_cpu_fraction']:.4f}"
                for x in report["idle_h2"]
            )
            + ".",
            "",
            "Wall time includes OS scheduling, protocol peers share a host. Compare trends on like hardware; these are not WAN QPS figures.",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("report", type=Path)
    ap.add_argument("--reference", type=Path)
    args = ap.parse_args()
    print(
        render(
            json.loads(args.report.read_text()),
            json.loads(args.reference.read_text()) if args.reference else None,
        )
    )
