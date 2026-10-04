"""Render recorded firewall execution without inferring which layers ran."""

import json

import streamlit as st


LABELS = {
    "parse": "Input parsing / OCR",
    "decode": "Decode hidden instructions",
    "segment": "Segments & trust boundaries",
    "rules": "Injection rules",
    "tool": "Tool abuse",
    "context": "Context poisoning",
    "jailbreak": "Jailbreak patterns",
    "indirect": "Indirect injection",
    "ml": "ML classifier",
    "sequence": "Multi-step attacks",
    "risk": "Risk engine",
    "llm": "LLM review (advisory)",
    "decision": "Final decision",
}

COLORS = {
    "completed": ("#122c23", "#3fb950"),
    "findings": ("#332710", "#e3b341"),
    "running": ("#102d4b", "#58a6ff"),
    "skipped": ("#20252d", "#8b949e"),
    "pending": ("#161b22", "#6e7681"),
    "error": ("#381a21", "#ff7b72"),
}


def stage_status(stage):
    status = stage.get("status", "pending")
    if status == "completed" and stage.get("detection_count", 0):
        return "Findings"
    return {
        "completed": "Completed", "running": "Running",
        "skipped": "Skipped", "pending": "Not run", "error": "Error",
    }.get(status, "Not run")


def workflow_dot(stages):
    """Use fixed node IDs and quoted labels; scan content cannot inject DOT."""
    recorded = {stage["id"]: stage for stage in stages if stage.get("id") in LABELS}
    lines = [
        'digraph workflow {',
        'graph [rankdir=TB, bgcolor="transparent", pad="0.15", nodesep="0.3", ranksep="0.5"];',
        'node [shape=box, style="rounded,filled", fontname="Arial", fontsize=14, fontcolor="#f0f6fc", margin="0.16,0.12", penwidth=1.4];',
        'edge [color="#63758c", arrowsize=0.7, penwidth=1.3];',
    ]
    for stage_id, stage in recorded.items():
        status = stage.get("status", "pending")
        color_key = "findings" if stage_status(stage) == "Findings" else status
        if stage_id == "decision" and status == "completed":
            color_key = {"BLOCK": "error", "SANITIZE": "findings", "PASS": "completed"}.get(
                stage.get("decision"), color_key
            )
        fill, border = COLORS.get(color_key, COLORS["pending"])
        label = LABELS[stage_id] + "\n" + stage_status(stage)
        if status not in ("pending", "running"):
            label += f" | {stage.get('duration_ms', 0):.2f} ms"
        findings = stage.get("detection_count", 0)
        if findings:
            label += f"\n{findings} finding{'s' if findings != 1 else ''}"
        if stage_id == "decision" and status == "completed":
            label += "\n" + stage.get("detail", "")
        if stage_id == "risk" and "risk_score" in stage:
            label += f"\nRisk score: {stage['risk_score']:.2f}"
        style = "rounded,filled,dashed" if status in ("pending", "skipped") else "rounded,filled"
        lines.append(
            f'{stage_id} [label={json.dumps(label)}, fillcolor="{fill}", '
            f'color="{border}", style="{style}", tooltip={json.dumps(stage.get("detail", ""))}];'
        )

    def row(ids, *, reverse=False):
        visible = [stage_id for stage_id in ids if stage_id in recorded]
        if reverse:
            visible.reverse()
        if visible:
            lines.append('{ rank=same; ' + '; '.join(visible) + '; }')
        for left, right in zip(visible, visible[1:]):
            direction = 'back' if reverse else 'forward'
            lines.append(f'{left} -> {right} [weight=10, dir={direction}];')

    row(["parse", "decode", "segment"])
    lines.extend([
        'subgraph cluster_detectors {',
        'label="Security checks - repeated for each segment";',
        'fontname="Arial"; fontsize=12; fontcolor="#8b949e"; color="#63758c"; style="rounded"; margin=16;',
    ])
    row(["rules", "tool", "context"], reverse=True)
    row(["jailbreak", "indirect", "ml"])
    if "context" in recorded and "jailbreak" in recorded:
        lines.append('context -> jailbreak;')
    lines.append('}')
    row(["sequence", "risk", "llm", "decision"], reverse=True)
    for left, right in [("segment", "rules"), ("ml", "sequence")]:
        if left in recorded and right in recorded:
            lines.append(f'{left} -> {right};')
    lines.append('}')
    return "\n".join(lines)


def render_workflow_graph(stages, *, source=None, running=False, failed=False):
    st.markdown("#### Scan workflow")
    if not stages:
        st.caption("Run a firewall scan to see the security layers executed for your input.")
        return

    if failed:
        failed_layers = [LABELS.get(s["id"], s["label"]) for s in stages if s["status"] == "error"]
        summary = "Scan stopped" + (": " + ", ".join(failed_layers) if failed_layers else "")
    elif running:
        active = [LABELS.get(s["id"], s["label"]) for s in stages if s["status"] == "running"]
        summary = "Scanning" + (": " + ", ".join(active) if active else "")
    else:
        complete = sum(s["status"] == "completed" for s in stages)
        skipped = sum(s["status"] == "skipped" for s in stages)
        summary = f"Last scan: {source or 'unknown'} | {complete} completed | {skipped} skipped"
    st.caption(summary)
    legend = []
    for label, key in [("Completed", "completed"), ("Findings", "findings"), ("Running", "running"), ("Skipped", "skipped"), ("Not run", "pending"), ("Error", "error")]:
        legend.append(f'<span style="white-space:nowrap"><span style="color:{COLORS[key][1]}">&#9679;</span> {label}</span>')
    st.markdown('<div style="display:flex;flex-wrap:wrap;gap:18px;font-size:13px">' + ''.join(legend) + '</div>', unsafe_allow_html=True)
    st.graphviz_chart(workflow_dot(stages), width="stretch", height=520)
    st.caption(
        "Each detector runs in the shown order for every segment; counts and times are totals across segments. "
        "Completed means the layer ran. The risk engine sets the decision; LLM analysis is advisory."
    )


def render_workflow_details(stages, trace):
    if not stages:
        return
    with st.expander("Layer details"):
        st.dataframe([
            {
                "Layer": LABELS.get(stage["id"], stage["label"]),
                "Status": stage_status(stage),
                "Duration (ms)": round(stage.get("duration_ms", 0), 2),
                "Findings": stage.get("detection_count", 0),
                "Detail": stage.get("detail", ""),
            }
            for stage in stages
        ], hide_index=True, use_container_width=True)
        st.caption("Layer timings measure processing time. Total scan latency also includes orchestration and display updates.")
        st.download_button(
            "Download scan trace",
            data=json.dumps(trace, indent=2, ensure_ascii=False, default=str),
            file_name="firewall_scan_trace.json",
            mime="application/json",
            key="download_scan_trace",
        )
