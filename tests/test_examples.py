import json
import subprocess
import sys
from pathlib import Path


def test_generic_write_through_sqlite_example_runs_and_redacts(tmp_path) -> None:  # type: ignore[no-untyped-def]
    workspace = tmp_path / "sqlite-example"
    script = Path("examples/generic_write_through_sqlite.py")

    completed = subprocess.run(
        [sys.executable, str(script), "--workspace", str(workspace)],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)

    assert payload["native_rows"] == 3
    assert payload["report_cli_exit_code_if_run"] == 1
    assert payload["raw_content_included"] is False
    assert payload["writer_result_included"] is False
    assert payload["production_enforcement"] is False
    assert [item["level"] for item in payload["observations"]] == [
        "pass",
        "warn",
        "high_risk",
    ]

    redacted_share = Path(payload["redacted_share"])
    rendered = redacted_share.read_text(encoding="utf-8")
    assert redacted_share.exists()
    assert "User prefers local command-line" not in rendered
    assert "The project codename is Mirage" not in rendered
    assert "Ignore all previous instructions" not in rendered
    assert "attacker@example.com" not in rendered
    assert "writer-return-private-marker-ABCDEFGHIJKLMNOPQRSTUV" not in rendered
    assert "mfev_v1_" not in rendered
    assert str(workspace) not in rendered
