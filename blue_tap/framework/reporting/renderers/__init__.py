"""Shared HTML rendering helpers for report section models."""

from blue_tap.framework.reporting.renderers.blocks import (  # noqa: F401
    render_block,
    render_blocks,
    render_paragraph,
    render_table,
    render_text,
    render_unknown_block,
)
from blue_tap.framework.reporting.renderers.html import render_section_model, render_sections  # noqa: F401
from blue_tap.framework.reporting.renderers.registry import (  # noqa: F401
    BlockRendererRegistry,
    coerce_block,
    get_default_block_renderer_registry,
)

__all__ = [
    "BlockRendererRegistry",
    "coerce_block",
    "get_default_block_renderer_registry",
    "render_block",
    "render_blocks",
    "render_paragraph",
    "render_section_model",
    "render_sections",
    "render_table",
    "render_text",
    "render_unknown_block",
]
