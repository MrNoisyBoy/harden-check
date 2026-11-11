import pytest

from hardencheck.checks import FAIL, PASS, SKIP, run_all, score
from hardencheck.demo import _w, make_hardened, make_weak


def by_id(results):
    return {r.id: r for r in results}


@pytest.fixture
def weak(tmp_path):
    make_weak(tmp_path)
    return by_id(run_all(tmp_path))


@pytest.fixture
def hardened(tmp_path):
    make_hardened(tmp_path)
    return run_all(tmp_path)


def test_hardened_server_passes_everything(hardened):
    failed = [(r.id, r.detail) for r in hardened if r.status != PASS]
    assert failed == []
    assert score(hardened) == 100


@pytest.mark.parametrize("check_id", ["SSH-01", "SSH-02", "ACC-01", "ACC-02", "ACC-05", "FS-01", "FS-04",
                                      "FS-05", "KRN-02", "NET-01", "NET-02", "LOG-01"])
def test_weak_server_problems_detected(weak, check_id):
    assert weak[check_id].status == FAIL


def test_weak_details_point_to_the_problem(weak):
    assert "backup" in weak["ACC-01"].detail
    assert "test" in weak["ACC-02"].detail
    assert "/usr/bin/find" in weak["FS-05"].detail and "passwd" not in weak["FS-05"].detail
    assert "FTP" in weak["NET-01"].detail and "Redis" in weak["NET-01"].detail


def test_empty_root_is_skipped_not_failed(tmp_path):
    results = by_id(run_all(tmp_path))
    assert results["SSH-01"].status == SKIP
    assert results["ACC-01"].status == SKIP


def test_sshd_first_value_wins_and_dropins_first(tmp_path):
    _w(tmp_path, "/etc/ssh/sshd_config.d/10.conf", "PermitRootLogin no\n")
    _w(tmp_path, "/etc/ssh/sshd_config", "PermitRootLogin yes\n")
    assert by_id(run_all(tmp_path))["SSH-01"].status == PASS


def test_sshd_match_block_ignored(tmp_path):
    _w(tmp_path, "/etc/ssh/sshd_config", "PermitRootLogin no\nMatch Address 10.0.0.0/8\n  PermitRootLogin yes\n")
    assert by_id(run_all(tmp_path))["SSH-01"].status == PASS


def test_sshd_default_root_login_is_fail(tmp_path):
    _w(tmp_path, "/etc/ssh/sshd_config", "Port 22\n")
    r = by_id(run_all(tmp_path))["SSH-01"]
    assert r.status == FAIL and "по умолчанию" in r.detail


def test_sysctl_conf_applied_last(tmp_path):
    _w(tmp_path, "/etc/sysctl.conf", "net.ipv4.ip_forward = 1\n")
    _w(tmp_path, "/etc/sysctl.d/99-z.conf", "net.ipv4.ip_forward = 0\n")
    # sysctl --system применяет /etc/sysctl.conf последним, поэтому его значение побеждает
    assert by_id(run_all(tmp_path))["KRN-02"].status == FAIL


def test_sudo_specific_nopasswd_command_is_ok(tmp_path):
    _w(tmp_path, "/etc/sudoers", "root ALL=(ALL) ALL\n")
    _w(tmp_path, "/etc/sudoers.d/app", "app ALL=(root) NOPASSWD: /usr/bin/systemctl restart app\n")
    assert by_id(run_all(tmp_path))["ACC-05"].status == PASS


def test_score_weights(weak):
    s = score(list(weak.values()))
    assert 0 < s < 50


def test_audit_is_read_only(tmp_path):
    make_weak(tmp_path)
    before = {p: (p.stat().st_mode, p.stat().st_mtime_ns) for p in tmp_path.rglob("*") if p.is_file()}
    run_all(tmp_path)
    after = {p: (p.stat().st_mode, p.stat().st_mtime_ns) for p in tmp_path.rglob("*") if p.is_file()}
    assert before == after
