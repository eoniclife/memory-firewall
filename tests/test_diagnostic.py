import json
import sqlite3
from pathlib import Path

import pytest

from memory_firewall.cli import main
from memory_firewall.diagnostic import (
    DiagnosticWorkspaceError,
    SQLITE_DIAGNOSTIC_MARKER_FILENAME,
    run_sqlite_write_through_diagnostic,
)

RAW_MARKERS = (
    "Ignore all previous instructions",
    "attacker@example.com",
    "writer-return-private-marker-ABCDEFGHIJKLMNOPQRSTUV",
    "User prefers local command-line",
    "The project codename is Mirage",
    "mfev_v1_",
)


def _render(payload: dict[str, object]) -> str:
    return json.dumps(payload, sort_keys=True)


def test_sqlite_write_through_diagnostic_creates_local_artifacts(tmp_path: Path) -> None:
    workspace = tmp_path / "diagnostic"

    summary = run_sqlite_write_through_diagnostic(workspace)

    assert summary["diagnostic_version"] == "mf-28-sqlite-write-through-v1"
    assert summary["workspace"] == str(workspace)
    assert summary["native_rows"] == 3
    assert summary["attention_required"] is True
    assert summary["raw_content_included"] is False
    assert summary["writer_result_included"] is False
    assert summary["production_enforcement"] is False
    assert [item["level"] for item in summary["observations"]] == [
        "pass",
        "warn",
        "high_risk",
    ]
    assert (workspace / SQLITE_DIAGNOSTIC_MARKER_FILENAME).exists()
    assert (workspace / "native-memory.sqlite").exists()
    assert (workspace / "adapter-state").is_dir()
    assert (workspace / "report").is_dir()
    assert json.loads((workspace / "summary.json").read_text(encoding="utf-8")) == summary

    with sqlite3.connect(workspace / "native-memory.sqlite") as conn:
        native_count = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
    assert native_count == 3


def test_sqlite_write_through_diagnostic_refuses_nonempty_unmarked_workspace(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "diagnostic"
    workspace.mkdir()
    sentinel = workspace / "keep.txt"
    sentinel.write_text("do not replace\n", encoding="utf-8")

    with pytest.raises(DiagnosticWorkspaceError, match="not an empty Memory Firewall diagnostic workspace"):
        run_sqlite_write_through_diagnostic(workspace)

    assert sentinel.read_text(encoding="utf-8") == "do not replace\n"
    assert not (workspace / "native-memory.sqlite").exists()


def test_sqlite_write_through_diagnostic_regenerates_marked_workspace(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "diagnostic"
    first = run_sqlite_write_through_diagnostic(workspace)
    stale = workspace / "report" / "stale.txt"
    stale.write_text("old report\n", encoding="utf-8")

    second = run_sqlite_write_through_diagnostic(workspace)

    assert first["native_rows"] == 3
    assert second["native_rows"] == 3
    assert not stale.exists()
    with sqlite3.connect(workspace / "native-memory.sqlite") as conn:
        native_count = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
    assert native_count == 3


def test_sqlite_write_through_diagnostic_redacts_summary_and_share(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "diagnostic"

    summary = run_sqlite_write_through_diagnostic(workspace)
    rendered_summary = _render(summary)
    redacted_share = Path(summary["report_files"]["redacted_share"]).read_text(
        encoding="utf-8",
    )

    for marker in RAW_MARKERS:
        assert marker not in rendered_summary
        assert marker not in redacted_share


def test_sqlite_write_through_diagnostic_cli_json_exits_zero_for_high_risk(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "diagnostic"

    exit_code = main(
        [
            "diagnostic",
            "sqlite-write-through",
            "--workspace",
            str(workspace),
            "--json",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert captured.err == ""
    assert payload["attention_required"] is True
    assert payload["native_rows"] == 3
    assert payload["workspace"] == str(workspace)
    assert [item["level"] for item in payload["observations"]] == [
        "pass",
        "warn",
        "high_risk",
    ]
    for marker in RAW_MARKERS:
        assert marker not in captured.out


def test_sqlite_write_through_diagnostic_cli_preserves_unsafe_workspace(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "diagnostic"
    workspace.mkdir()
    sentinel = workspace / "keep.txt"
    sentinel.write_text("do not replace\n", encoding="utf-8")

    exit_code = main(
        [
            "diagnostic",
            "sqlite-write-through",
            "--workspace",
            str(workspace),
            "--json",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "not an empty Memory Firewall diagnostic workspace" in captured.err
    assert str(workspace) not in captured.err
    assert "Traceback" not in captured.err
    assert captured.out == ""
    assert sentinel.read_text(encoding="utf-8") == "do not replace\n"


def test_sqlite_write_through_diagnostic_cli_rejects_existing_file_workspace(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "diagnostic-file"
    workspace.write_text("not a directory\n", encoding="utf-8")

    exit_code = main(
        [
            "diagnostic",
            "sqlite-write-through",
            "--workspace",
            str(workspace),
            "--json",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "not an empty Memory Firewall diagnostic workspace" in captured.err
    assert str(workspace) not in captured.err
    assert "Traceback" not in captured.err
    assert captured.out == ""
    assert workspace.read_text(encoding="utf-8") == "not a directory\n"
