"""HTML block renderers for standardized report section content."""

from __future__ import annotations

import json
import html as _html
from collections.abc import Mapping
from typing import Any

from blue_tap.core.report_contract import SectionBlock
from blue_tap.report.renderers.registry import (
    BlockRendererRegistry,
    coerce_block,
    get_default_block_renderer_registry,
)


def esc(value: Any) -> str:
    return _html.escape(str(value), quote=True)


def render_table(headers: list[str], rows: list[list[Any] | Mapping[str, Any]]) -> str:
    normalized_headers = list(headers)
    normalized_rows: list[list[Any]] = []
    for row in rows:
        if isinstance(row, Mapping):
            if not normalized_headers:
                normalized_headers = list(row.keys())
            normalized_rows.append([row.get(header, "") for header in normalized_headers])
        elif isinstance(row, (list, tuple)):
            normalized_rows.append(list(row))
        else:
            normalized_rows.append([row])
    parts = ["<table><tr>"]
    parts.extend(f"<th>{esc(header)}</th>" for header in normalized_headers)
    parts.append("</tr>")
    for row in normalized_rows:
        parts.append("<tr>")
        parts.extend(f"<td>{esc(cell)}</td>" for cell in row)
        parts.append("</tr>")
    parts.append("</table>")
    return "".join(parts)


def render_paragraph(text: str) -> str:
    return f"<p>{esc(text)}</p>"


def render_text(text: str) -> str:
    return f"<pre>{esc(text)}</pre>"


def render_card_list(cards: list[dict]) -> str:
    """Render a list of cards with title, status badge, and key-value details."""
    parts = ['<div class="card-list">']
    for card in cards:
        title = esc(card.get("title", ""))
        status = card.get("status", "")
        badge_cls = _badge_class(status)
        parts.append(f'<div class="card">')
        parts.append(f'<div class="card-header"><strong>{title}</strong>')
        if status:
            parts.append(f' <span class="badge {badge_cls}">{esc(status)}</span>')
        parts.append('</div>')
        details = card.get("details", {})
        if isinstance(details, dict) and details:
            parts.append('<dl class="card-details">')
            for k, v in details.items():
                parts.append(f'<dt>{esc(k)}</dt><dd>{esc(v)}</dd>')
            parts.append('</dl>')
        body = card.get("body", "")
        if body:
            parts.append(f'<p class="card-body">{esc(body)}</p>')
        parts.append('</div>')
    parts.append('</div>')
    return "\n".join(parts)


def render_status_summary(data: dict) -> str:
    """Render a status summary bar with labeled counts and optional color badges."""
    items = data.get("items", [])
    if not items:
        return ""
    parts = ['<div class="status-summary">']
    for item in items:
        label = esc(item.get("label", ""))
        count = item.get("count", 0)
        badge_cls = _badge_class(item.get("status", ""))
        parts.append(
            f'<div class="status-item">'
            f'<span class="status-count {badge_cls}">{count}</span>'
            f'<span class="status-label">{label}</span>'
            f'</div>'
        )
    parts.append('</div>')
    return "\n".join(parts)


def render_timeline(events: list[dict]) -> str:
    """Render a vertical timeline of events with timestamps."""
    if not events:
        return ""
    parts = ['<div class="timeline">']
    for event in events:
        ts = esc(event.get("timestamp", ""))
        label = esc(event.get("label", event.get("event_type", "")))
        message = esc(event.get("message", ""))
        badge_cls = _badge_class(event.get("status", ""))
        parts.append(
            f'<div class="timeline-event">'
            f'<span class="timeline-ts">{ts}</span>'
            f'<span class="timeline-label {badge_cls}">{label}</span>'
            f'<span class="timeline-msg">{message}</span>'
            f'</div>'
        )
    parts.append('</div>')
    return "\n".join(parts)


def render_key_value(pairs: list[dict] | dict) -> str:
    """Render key-value pairs as a definition list."""
    if isinstance(pairs, dict):
        pairs = [{"key": k, "value": v} for k, v in pairs.items()]
    if not pairs:
        return ""
    parts = ['<dl class="kv-list">']
    for pair in pairs:
        k = esc(pair.get("key", ""))
        v = esc(str(pair.get("value", "")))
        parts.append(f'<dt>{k}</dt><dd>{v}</dd>')
    parts.append('</dl>')
    return "\n".join(parts)


def render_badge_group(badges: list[dict]) -> str:
    """Render a horizontal group of status badges."""
    if not badges:
        return ""
    parts = ['<div class="badge-group">']
    for badge in badges:
        label = esc(badge.get("label", ""))
        value = esc(str(badge.get("value", "")))
        badge_cls = _badge_class(badge.get("status", ""))
        parts.append(f'<span class="badge {badge_cls}">{label}: {value}</span>')
    parts.append('</div>')
    return "\n".join(parts)


def _badge_class(status: str) -> str:
    """Map a status string to a CSS badge class."""
    status_lower = str(status).lower()
    if status_lower in ("confirmed", "success", "completed", "high"):
        return "badge-danger"
    if status_lower in ("inconclusive", "recovered", "medium", "warning"):
        return "badge-warning"
    if status_lower in ("not_applicable", "skipped", "low", "info"):
        return "badge-info"
    if status_lower in ("failed", "error", "critical", "unresponsive"):
        return "badge-critical"
    if status_lower in ("pairing_required",):
        return "badge-pairing"
    return "badge-default"


def render_unknown_block(block: SectionBlock) -> str:
    try:
        rendered = json.dumps(block.data, indent=2, sort_keys=True, default=str)
    except (TypeError, ValueError):
        rendered = str(block.data)
    return render_text(rendered)


def render_block(
    block: SectionBlock | dict[str, Any] | Any,
    registry: BlockRendererRegistry | None = None,
) -> str:
    renderer_registry = registry or get_default_block_renderer_registry()
    normalized = coerce_block(block)
    block_type = str(normalized.block_type).lower()
    renderer = renderer_registry.get(block_type)
    if renderer is not None:
        return renderer(normalized)
    default_registry = get_default_block_renderer_registry()
    if renderer_registry is not default_registry:
        renderer = default_registry.get(block_type)
        if renderer is not None:
            return renderer(normalized)
    return render_unknown_block(normalized)


def render_blocks(
    blocks: tuple[SectionBlock, ...] | list[SectionBlock],
    registry: BlockRendererRegistry | None = None,
) -> str:
    renderer_registry = registry or get_default_block_renderer_registry()
    return "\n".join(render_block(block, renderer_registry) for block in blocks)
