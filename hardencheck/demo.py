"""Создание демонстрационных «образов» серверов: слабо настроенного и защищённого.

Права файлов выставляются при создании (git их не хранит), поэтому
демо-образы генерируются скриптом, а не лежат в репозитории.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
deploy:x:1000:1000:Deploy:/home/deploy:/bin/bash
"""


def _w(root: Path, rel: str, text: str = "", mode: int = 0o644) -> None:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    os.chmod(p, mode)


def _proc_tcp(ports: list[int]) -> str:
    head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    rows = [f"   {i}: 00000000:{p:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1{i} 1"
            for i, p in enumerate(ports)]
    return head + "\n".join(rows) + "\n"


def make_weak(root: Path) -> None:
    """Типичный «быстро поднятый» сервер: настройки по умолчанию и пара грубых ошибок."""
    _w(root, "/etc/ssh/sshd_config", "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\n")
    _w(root, "/etc/passwd", PASSWD + "backup:x:0:0:backup:/root:/bin/bash\n")
    _w(root, "/etc/shadow", "root:$6$abc$hash:19700:0:99999:7:::\ndeploy:$6$xyz$hash:19700:0:99999:7:::\ntest::19700:0:99999:7:::\n", 0o644)
    _w(root, "/etc/login.defs", "PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\n")
    _w(root, "/etc/sudoers", "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n#includedir /etc/sudoers.d\n", 0o440)
    _w(root, "/etc/sudoers.d/deploy", "deploy ALL=(ALL) NOPASSWD: ALL\n", 0o440)
    _w(root, "/etc/cron.d/backup", "0 3 * * * root /opt/backup.sh\n", 0o666)
    _w(root, "/etc/sysctl.conf", "net.ipv4.ip_forward=1\n")
    _w(root, "/proc/sys/kernel/randomize_va_space", "2\n")
    _w(root, "/proc/sys/net/ipv4/ip_forward", "1\n")
    _w(root, "/proc/sys/net/ipv4/conf/all/accept_redirects", "1\n")
    _w(root, "/proc/sys/net/ipv4/tcp_syncookies", "1\n")
    _w(root, "/proc/sys/kernel/dmesg_restrict", "0\n")
    _w(root, "/proc/net/tcp", _proc_tcp([22, 21, 80, 6379]))
    _w(root, "/usr/bin/passwd", "", 0o4755)
    _w(root, "/usr/bin/find", "", 0o4755)          # SUID на find — классическое повышение привилегий
    _w(root, "/var/log/auth.log", "")


def make_hardened(root: Path) -> None:
    _w(root, "/etc/ssh/sshd_config.d/50-hardening.conf",
       "PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nMaxAuthTries 3\nX11Forwarding no\n")
    _w(root, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n")
    _w(root, "/etc/passwd", PASSWD)
    _w(root, "/etc/shadow", "root:!:19700:0:90:7:::\ndeploy:$6$xyz$hash:19700:1:90:7:::\n", 0o640)
    _w(root, "/etc/login.defs", "PASS_MAX_DAYS\t90\nPASS_MIN_DAYS\t1\n")
    _w(root, "/etc/security/pwquality.conf", "minlen = 14\ndcredit = -1\n")
    _w(root, "/etc/sudoers", "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n", 0o440)
    _w(root, "/etc/sudoers.d/deploy", "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app\n", 0o440)
    _w(root, "/etc/sysctl.d/90-hardening.conf",
       "kernel.randomize_va_space = 2\nnet.ipv4.ip_forward = 0\nnet.ipv4.conf.all.accept_redirects = 0\n"
       "net.ipv4.tcp_syncookies = 1\nkernel.dmesg_restrict = 1\n")
    _w(root, "/proc/net/tcp", _proc_tcp([22, 443]))
    _w(root, "/etc/ufw/ufw.conf", "ENABLED=yes\nLOGLEVEL=low\n")
    _w(root, "/etc/audit/auditd.conf", "log_file = /var/log/audit/audit.log\n")
    _w(root, "/usr/bin/passwd", "", 0o4755)
    _w(root, "/usr/bin/sudo", "", 0o4755)
    _w(root, "/var/log/auth.log", "")


def main() -> None:
    parser = argparse.ArgumentParser(description="Создать демо-образы серверов")
    parser.add_argument("-o", "--out-dir", default="demo")
    args = parser.parse_args()
    out = Path(args.out_dir)
    make_weak(out / "weak-server")
    make_hardened(out / "hardened-server")
    print(f"Созданы {out}/weak-server и {out}/hardened-server")


if __name__ == "__main__":
    main()
