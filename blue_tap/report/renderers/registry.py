"""Registry and coercion helpers for standardized report block rendering."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable

from blue_tap.core.report_contract import SectionBlock


BlockRenderer = Callable[[SectionBlock], str]


def coerce_block(block: Any) -> SectionBlock:
    """Normalize block-like input into a SectionBlock instance."""
    if isinstance(block, SectionBlock):
        return block
    if isinstance(block, Mapping):
        block_type = str(block.get("block_type", block.get("type", "text")))
        data = block.get("data", block)
        if isinstance(data, Mapping):
            data = dict(data)
        else:
            data = {"text": str(data)}
        return SectionBlock(block_type=block_type, data=data)
    return SectionBlock(block_type="text", data={"text": str(block)})


class BlockRendererRegistry:
    """Registry for block renderers keyed by block type."""

    def __init__(self, renderers: Mapping[str, BlockRenderer] | None = None):
        self._renderers: dict[str, BlockRenderer] = {}
        for block_type, renderer in dict(renderers or {}).items():
            self.register(block_type, renderer)

    def register(self, block_type: str, renderer: BlockRenderer) -> None:
        self._renderers[str(block_type).lower()] = renderer

    def get(self, block_type: str) -> BlockRenderer | None:
        return self._renderers.get(str(block_type).lower())

    def render(self, block: SectionBlock | dict[str, Any] | Any) -> str:
        normalized = coerce_block(block)
        renderer = self.get(normalized.block_type)
        if renderer is None:
            from blue_tap.report.renderers.blocks import render_unknown_block

            return render_unknown_block(normalized)
        return renderer(normalized)

    def known_block_types(self) -> tuple[str, ...]:
        return tuple(sorted(self._renderers))


_DEFAULT_BLOCK_RENDERER_REGISTRY: BlockRendererRegistry | None = None


def get_default_block_renderer_registry() -> BlockRendererRegistry:
    """Return the shared block renderer registry with built-in renderers."""
    global _DEFAULT_BLOCK_RENDERER_REGISTRY
    if _DEFAULT_BLOCK_RENDERER_REGISTRY is None:
        from blue_tap.report.renderers.blocks import (
            render_badge_group,
            render_card_list,
            render_key_value,
            render_paragraph,
            render_status_summary,
            render_table,
            render_text,
            render_timeline,
        )

        registry = BlockRendererRegistry()

        def render_table_block(block: SectionBlock) -> str:
            return render_table(list(block.data.get("headers", [])), list(block.data.get("rows", [])))

        def render_paragraph_block(block: SectionBlock) -> str:
            return render_paragraph(str(block.data.get("text", "")))

        def render_text_block(block: SectionBlock) -> str:
            return render_text(str(block.data.get("text", "")))

        def render_card_list_block(block: SectionBlock) -> str:
            return render_card_list(list(block.data.get("cards", [])))

        def render_status_summary_block(block: SectionBlock) -> str:
            return render_status_summary(block.data)

        def render_timeline_block(block: SectionBlock) -> str:
            return render_timeline(list(block.data.get("events", [])))

        def render_key_value_block(block: SectionBlock) -> str:
            return render_key_value(block.data.get("pairs", block.data))

        def render_badge_group_block(block: SectionBlock) -> str:
            return render_badge_group(list(block.data.get("badges", [])))

        registry.register("table", render_table_block)
        registry.register("paragraph", render_paragraph_block)
        registry.register("text", render_text_block)
        registry.register("card_list", render_card_list_block)
        registry.register("status_summary", render_status_summary_block)
        registry.register("timeline", render_timeline_block)
        registry.register("key_value", render_key_value_block)
        registry.register("badge_group", render_badge_group_block)
        _DEFAULT_BLOCK_RENDERER_REGISTRY = registry
    return _DEFAULT_BLOCK_RENDERER_REGISTRY
