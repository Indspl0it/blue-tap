"""Section-level renderers for standardized report models."""

from __future__ import annotations

from blue_tap.framework.contracts.report_contract import SectionModel
from blue_tap.framework.reporting.renderers.blocks import esc, render_blocks
from blue_tap.framework.reporting.renderers.registry import (
    BlockRendererRegistry,
    get_default_block_renderer_registry,
)


def render_section_model(
    section: SectionModel,
    registry: BlockRendererRegistry | None = None,
) -> str:
    """Render a single section model into HTML."""
    block_registry = registry or get_default_block_renderer_registry()
    parts = [f'<section class="section" id="{esc(section.section_id)}">', f"<h2>{esc(section.title)}</h2>"]
    if section.summary:
        parts.append(f"<p>{esc(section.summary)}</p>")
    rendered_blocks = render_blocks(section.blocks, block_registry)
    if rendered_blocks:
        parts.append(rendered_blocks)
    parts.append("</section>")
    return "\n".join(parts)


def render_sections(
    sections: list[SectionModel],
    registry: BlockRendererRegistry | None = None,
) -> str:
    """Render multiple section models into a single HTML fragment."""
    block_registry = registry or get_default_block_renderer_registry()
    return "\n".join(render_section_model(section, block_registry) for section in sections)
