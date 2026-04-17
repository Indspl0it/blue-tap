"""Shared report adapter contract and section models."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SectionBlock:
    block_type: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SectionModel:
    section_id: str
    title: str
    summary: str = ""
    blocks: tuple[SectionBlock, ...] = field(default_factory=tuple)


class ReportAdapter(ABC):
    module: str = ""

    #: Lower priority runs first. Wildcard fallback adapters should raise priority.
    priority: int = 100

    @abstractmethod
    def accepts(self, envelope: dict[str, Any]) -> bool:
        raise NotImplementedError

    @abstractmethod
    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        raise NotImplementedError

    @abstractmethod
    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError
