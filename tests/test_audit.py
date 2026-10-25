import json
from pathlib import Path

from opnsense_guard.audit import AuditLog, verify
from opnsense_guard.server import main


def filled(tmp_path: Path, n: int = 3) -> Path:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(n):
        log.append("plan_created", plan_id=f"p_{i}", actor="stdio")
    return path


def test_chain_verifies(tmp_path: Path) -> None:
    ok, count, _ = verify(filled(tmp_path))
    assert ok
    assert count == 3


def test_chain_continues_across_instances(tmp_path: Path) -> None:
    path = filled(tmp_path)
    AuditLog(path).append("server_started")
    assert verify(path)[0]


def test_edit_detected(tmp_path: Path) -> None:
    path = filled(tmp_path)
    lines = path.read_text().splitlines()
    lines[1] = lines[1].replace("p_1", "p_X")
    path.write_text("\n".join(lines) + "\n")
    ok, _, message = verify(path)
    assert not ok
    assert "line 2" in message


def test_delete_detected(tmp_path: Path) -> None:
    path = filled(tmp_path)
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    ok, _, message = verify(path)
    assert not ok
    assert "chain broken" in message


def test_reorder_detected(tmp_path: Path) -> None:
    path = filled(tmp_path)
    lines = path.read_text().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    path.write_text("\n".join(lines) + "\n")
    assert not verify(path)[0]


def test_secrets_redacted(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    record = log.append(
        "test",
        token_name="laptop",
        nested={"api_key": "k", "Authorization": "Bearer x", "ok": 1},
        token="ogm_secret",
    )
    text = (tmp_path / "audit.jsonl").read_text()
    assert "ogm_secret" not in text
    assert "Bearer x" not in text
    assert record["token_name"] == "laptop"
    assert record["nested"]["ok"] == 1


def test_tail(tmp_path: Path) -> None:
    log = AuditLog(filled(tmp_path, 5))
    assert [r["plan_id"] for r in log.tail(2)] == ["p_3", "p_4"]


def test_cli_verify(tmp_path: Path, capsys: object) -> None:
    path = filled(tmp_path)
    main(["audit", "--env-file", str(tmp_path / "none.env"), "--file", str(path), "verify"])
    path.write_text(path.read_text().replace("p_0", "p_Z"))
    try:
        main(["audit", "--env-file", str(tmp_path / "none.env"), "--file", str(path), "verify"])
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("tampered log passed verification")


def test_records_are_valid_json_lines(tmp_path: Path) -> None:
    for line in filled(tmp_path).read_text().splitlines():
        record = json.loads(line)
        assert {"ts", "event", "prev_hash", "hash"} <= record.keys()
