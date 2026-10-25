"""Live ``agent-bom db update`` progress: OSV download bytes, NVD window slices, records and rate-limit waits."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rich.console import Console
    from rich.progress import Progress, TaskID

DONE_MARKS = {"complete": "[green]✓[/green]", "partial": "[yellow]![/yellow]"}


def progress_note(selected: set[str], osv_ecosystems: tuple, *, nvd_keyless: bool) -> list[str]:
    """What the run will show while it works, for the sources it will actually sync."""
    notes = []
    if "osv" in selected and not osv_ecosystems:
        notes.append("The OSV all-ecosystems archive can exceed 1 GB and take several minutes; its download progress is shown.")
    if "nvd" in selected:
        pace = "5 requests per 30 seconds without NVD_API_KEY" if nvd_keyless else "50 requests per 30 seconds"
        notes.append(f"NVD is read in day slices at {pace}; slices, records read and rate-limit waits are shown.")
    if selected - {"osv", "nvd"}:
        notes.append(f"{', '.join(sorted(selected - {'osv', 'nvd'}))}: reported when each starts and finishes.")
    return notes


def _format_mb(value: int) -> str:
    return f"{value / (1024 * 1024):.1f} MB"


def _nvd_line(phase: str, current: int, total: int | None, detail: str | None) -> str:
    if phase == "slice":
        return f"nvd: slice {current}/{total} ({detail})"
    if phase == "records":
        return f"nvd: {current:,} records read" + (f" (slice {detail})" if detail else "")
    return f"nvd: rate limit: waiting {current}s"


class SyncProgress:
    """The ``sync_db`` progress callback: a live bar on a terminal, one line per event otherwise."""

    def __init__(self, console: Console, renderer: Progress) -> None:
        self.console = console
        self.renderer = renderer
        self.tasks: dict[str, TaskID] = {}
        self.downloaded: dict[str, int] = {}

    def __call__(self, source: str, phase: str, current: int, total: int | None, detail: str | None = None) -> None:
        if phase == "download":
            self.downloaded[source] = current
        if not self.console.is_terminal:
            self._print(source, phase, current, total, detail)
            return
        task_id = self.tasks.get(source)
        if task_id is None:
            task_id = self.tasks[source] = self.renderer.add_task(f"{source}: starting", total=None)
        if phase == "download":
            self.renderer.update(task_id, description=f"{source}: downloading", completed=current, total=total)
        elif phase in {"slice", "records", "rate_wait"}:
            self.renderer.update(task_id, description=_nvd_line(phase, current, total, detail))
        elif phase in DONE_MARKS:
            byte_count = self.downloaded.get(source, 1)
            self.renderer.update(task_id, description=f"{source}: {phase}", completed=byte_count, total=byte_count)
            self.renderer.stop_task(task_id)

    def _print(self, source: str, phase: str, current: int, total: int | None, detail: str | None) -> None:
        if phase == "start":
            self.console.print(f"  [cyan]→[/cyan] {source}: starting")
        elif phase in {"slice", "records", "rate_wait"}:
            self.console.print(f"    {_nvd_line(phase, current, total, detail)}")
        elif phase in DONE_MARKS:
            size = f"; downloaded {_format_mb(self.downloaded[source])}" if source in self.downloaded else ""
            self.console.print(f"  {DONE_MARKS[phase]} {source}: {phase}{size}")
