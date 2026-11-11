"""Проверки защищённости Linux-сервера.

Все проверки читают файлы относительно корня `root` — поэтому можно проверять
и живую систему (root="/"), и смонтированный образ/бэкап, и тестовые фикстуры.
Проверки только читают систему и ничего не меняют.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}


@dataclass
class Result:
    id: str
    category: str
    title: str
    severity: str
    status: str
    detail: str = ""
    remediation: str = ""


@dataclass
class Context:
    root: Path
    _cache: dict = field(default_factory=dict)

    def path(self, p: str) -> Path:
        return self.root / p.lstrip("/")

    def read(self, p: str) -> str | None:
        f = self.path(p)
        try:
            return f.read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, IsADirectoryError, PermissionError):
            return None

    def read_dir_confs(self, main: str, drop_in_dir: str) -> str | None:
        """Основной конфиг + файлы *.conf из каталога drop-in (как у sshd/sysctl)."""
        parts = []
        d = self.path(drop_in_dir)
        if d.is_dir():
            parts += [p.read_text(errors="replace") for p in sorted(d.glob("*.conf"))]
        if (text := self.read(main)) is not None:
            parts.append(text)
        return "\n".join(parts) if parts else None


CHECKS: list[tuple[str, str, str, str, Callable[[Context], tuple[str, str]], str]] = []


def check(check_id: str, category: str, title: str, severity: str, remediation: str):
    def deco(fn):
        CHECKS.append((check_id, category, title, severity, fn, remediation))
        return fn
    return deco


# ---------------- SSH ----------------

def _sshd_options(ctx: Context) -> dict[str, str] | None:
    """Опции sshd. Как и sshd, берём ПЕРВОЕ значение; drop-in файлы читаются раньше основного."""
    text = ctx.read_dir_confs("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d")
    if text is None:
        return None
    opts: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.lower().startswith("match "):
            break  # дальше — условные блоки, глобальные опции закончились
        parts = re.split(r"[\s=]+", line, maxsplit=1)
        if len(parts) == 2:
            opts.setdefault(parts[0].lower(), parts[1].strip().lower())
    return opts


def _ssh_option(ctx, key, ok: Callable[[str], bool], default: str):
    opts = _sshd_options(ctx)
    if opts is None:
        return SKIP, "sshd_config не найден"
    value = opts.get(key.lower(), default)
    src = "" if key.lower() in opts else " (значение по умолчанию)"
    return (PASS if ok(value) else FAIL), f"{key} = {value}{src}"


@check("SSH-01", "SSH", "Вход root по SSH запрещён", "critical",
       "PermitRootLogin no в /etc/ssh/sshd_config, затем systemctl reload ssh")
def ssh_root(ctx):
    return _ssh_option(ctx, "PermitRootLogin", lambda v: v == "no", "prohibit-password")


@check("SSH-02", "SSH", "Вход по паролю отключён (только ключи)", "high",
       "PasswordAuthentication no — предварительно убедитесь, что ваш ключ в ~/.ssh/authorized_keys")
def ssh_password(ctx):
    return _ssh_option(ctx, "PasswordAuthentication", lambda v: v == "no", "yes")


@check("SSH-03", "SSH", "Пустые пароли запрещены", "critical", "PermitEmptyPasswords no")
def ssh_empty(ctx):
    return _ssh_option(ctx, "PermitEmptyPasswords", lambda v: v == "no", "no")


@check("SSH-04", "SSH", "Ограничено число попыток аутентификации (≤ 4)", "medium", "MaxAuthTries 4")
def ssh_tries(ctx):
    return _ssh_option(ctx, "MaxAuthTries", lambda v: v.isdigit() and int(v) <= 4, "6")


@check("SSH-05", "SSH", "X11 forwarding отключён", "low", "X11Forwarding no")
def ssh_x11(ctx):
    return _ssh_option(ctx, "X11Forwarding", lambda v: v == "no", "no")


# ---------------- Учётные записи ----------------

def _passwd(ctx) -> list[list[str]] | None:
    text = ctx.read("/etc/passwd")
    return None if text is None else [l.split(":") for l in text.splitlines() if l.count(":") >= 6]


@check("ACC-01", "Учётные записи", "UID 0 только у root", "critical",
       "Удалите или смените UID у лишних учётных записей с UID 0 (usermod -u)")
def uid0(ctx):
    rows = _passwd(ctx)
    if rows is None:
        return SKIP, "/etc/passwd не найден"
    extra = [r[0] for r in rows if r[2] == "0" and r[0] != "root"]
    return (FAIL, "UID 0: " + ", ".join(extra)) if extra else (PASS, "только root")


@check("ACC-02", "Учётные записи", "Нет учётных записей с пустым паролем", "critical",
       "passwd -l <user> или задайте пароль")
def empty_passwords(ctx):
    text = ctx.read("/etc/shadow")
    if text is None:
        return SKIP, "/etc/shadow недоступен (нужны права root)"
    empty = [l.split(":")[0] for l in text.splitlines() if l.count(":") >= 1 and l.split(":")[1] == ""]
    return (FAIL, "пустой пароль: " + ", ".join(empty)) if empty else (PASS, "пустых паролей нет")


@check("ACC-03", "Учётные записи", "Срок действия пароля ≤ 90 дней", "medium",
       "PASS_MAX_DAYS 90 в /etc/login.defs (для существующих: chage --maxdays 90 <user>)")
def pass_max_days(ctx):
    text = ctx.read("/etc/login.defs")
    if text is None:
        return SKIP, "/etc/login.defs не найден"
    m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", text, re.M)
    days = int(m[1]) if m else 99999
    return (PASS if days <= 90 else FAIL), f"PASS_MAX_DAYS = {days}"


@check("ACC-04", "Учётные записи", "Минимальная длина пароля ≥ 12", "medium",
       "minlen = 12 в /etc/security/pwquality.conf (пакет libpam-pwquality)")
def pw_minlen(ctx):
    text = ctx.read("/etc/security/pwquality.conf")
    if text is None:
        return FAIL, "pwquality не настроен — сложность паролей не проверяется"
    m = re.search(r"^\s*minlen\s*=\s*(\d+)", text, re.M)
    n = int(m[1]) if m else 8
    return (PASS if n >= 12 else FAIL), f"minlen = {n}"


@check("ACC-05", "Учётные записи", "sudo не выдаёт полный доступ без пароля", "high",
       "Уберите NOPASSWD: ALL; разрешайте без пароля только конкретные команды")
def sudo_nopasswd(ctx):
    text = ctx.read_dir_confs("/etc/sudoers", "/etc/sudoers.d") or ""
    d = ctx.path("/etc/sudoers.d")
    if d.is_dir():  # в sudoers.d файлы обычно без расширения .conf
        text += "\n".join(p.read_text(errors="replace") for p in d.iterdir() if p.is_file() and p.suffix != ".conf")
    if not text:
        return SKIP, "sudoers не найден"
    bad = [l.strip() for l in text.splitlines()
           if not l.strip().startswith("#") and re.search(r"NOPASSWD:\s*ALL\s*$", l)]
    return (FAIL, "; ".join(bad)) if bad else (PASS, "NOPASSWD: ALL не найден")


# ---------------- Права на файлы ----------------

def _mode_check(ctx, p: str, max_mode: int):
    f = ctx.path(p)
    if not f.exists():
        return SKIP, f"{p} не найден"
    mode = stat.S_IMODE(f.stat().st_mode)
    ok = mode & ~max_mode == 0
    return (PASS if ok else FAIL), f"{p}: {oct(mode)[2:]} (допустимо не шире {oct(max_mode)[2:]})"


@check("FS-01", "Файлы", "Права /etc/shadow не шире 640", "critical", "chmod 640 /etc/shadow")
def shadow_mode(ctx):
    return _mode_check(ctx, "/etc/shadow", 0o640)


@check("FS-02", "Файлы", "Права /etc/passwd не шире 644", "high", "chmod 644 /etc/passwd")
def passwd_mode(ctx):
    return _mode_check(ctx, "/etc/passwd", 0o644)


@check("FS-03", "Файлы", "Права /etc/sudoers не шире 440", "high", "chmod 440 /etc/sudoers")
def sudoers_mode(ctx):
    return _mode_check(ctx, "/etc/sudoers", 0o440)


@check("FS-04", "Файлы", "Нет файлов в /etc, доступных на запись всем", "high",
       "chmod o-w <файл>; выясните, кто и зачем выставил такие права")
def world_writable_etc(ctx):
    etc = ctx.path("/etc")
    if not etc.is_dir():
        return SKIP, "/etc не найден"
    found = []
    for dirpath, _, files in os.walk(etc):
        for name in files:
            p = Path(dirpath) / name
            try:
                if not p.is_symlink() and p.stat().st_mode & stat.S_IWOTH:
                    found.append("/" + str(p.relative_to(ctx.root)))
            except OSError:
                continue
    return (FAIL, ", ".join(found[:10])) if found else (PASS, "не найдено")


KNOWN_SUID = {"su", "sudo", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount", "umount", "ping",
              "pkexec", "fusermount", "fusermount3", "ssh-keysign", "dbus-daemon-launch-helper",
              "polkit-agent-helper-1", "chage", "expiry", "unix_chkpwd", "crontab", "at", "Xorg.wrap"}


@check("FS-05", "Файлы", "Нет нестандартных SUID-файлов", "high",
       "chmod u-s <файл>, если SUID не нужен; проверьте по GTFOBins возможность повышения привилегий")
def suid(ctx):
    found = []
    for d in ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/tmp", "/home"):
        base = ctx.path(d)
        if not base.is_dir() or base.is_symlink():
            continue
        for dirpath, _, files in os.walk(base):
            for name in files:
                p = Path(dirpath) / name
                try:
                    if not p.is_symlink() and p.stat().st_mode & stat.S_ISUID and name not in KNOWN_SUID:
                        found.append("/" + str(p.relative_to(ctx.root)))
                except OSError:
                    continue
    return (FAIL, ", ".join(sorted(found)[:15])) if found else (PASS, "только стандартные SUID-файлы")


# ---------------- Ядро ----------------

def _sysctl(ctx, key: str) -> str | None:
    live = ctx.read("/proc/sys/" + key.replace(".", "/"))
    if live is not None:
        return live.strip()
    text = ctx.read_dir_confs("/etc/sysctl.conf", "/etc/sysctl.d")
    if text is None:
        return None
    value = None
    for m in re.finditer(rf"^\s*{re.escape(key)}\s*=\s*(\S+)", text, re.M):
        value = m[1]  # в sysctl побеждает последнее значение
    return value


SYSCTL = [
    ("KRN-01", "ASLR включён полностью", "kernel.randomize_va_space", "2", "high"),
    ("KRN-02", "IP forwarding выключен", "net.ipv4.ip_forward", "0", "medium"),
    ("KRN-03", "ICMP redirects не принимаются", "net.ipv4.conf.all.accept_redirects", "0", "medium"),
    ("KRN-04", "SYN cookies включены", "net.ipv4.tcp_syncookies", "1", "medium"),
    ("KRN-05", "Доступ к dmesg ограничен", "kernel.dmesg_restrict", "1", "low"),
]

for _id, _title, _key, _want, _sev in SYSCTL:
    def _make(key=_key, want=_want):
        def fn(ctx):
            v = _sysctl(ctx, key)
            if v is None:
                return SKIP, f"{key} не задан"
            return (PASS if v == want else FAIL), f"{key} = {v} (нужно {want})"
        return fn
    check(_id, "Ядро", _title, _sev, f"echo '{_key} = {_want}' > /etc/sysctl.d/90-hardening.conf && sysctl --system")(_make())


# ---------------- Сеть и сервисы ----------------

INSECURE_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 111: "rpcbind", 512: "rexec", 513: "rlogin", 514: "rsh",
                  2049: "NFS", 6379: "Redis", 11211: "Memcached", 27017: "MongoDB"}


def listening_ports(ctx) -> set[int] | None:
    ports, seen = set(), False
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        text = ctx.read(f)
        if text is None:
            continue
        seen = True
        for line in text.splitlines()[1:]:
            cols = line.split()
            if len(cols) > 3 and cols[3] == "0A":  # 0A = LISTEN
                ports.add(int(cols[1].rsplit(":", 1)[1], 16))
    return ports if seen else None


@check("NET-01", "Сеть", "Не слушаются небезопасные сервисы", "high",
       "Остановите и отключите сервис (systemctl disable --now <svc>) или закройте порт на firewall")
def insecure_services(ctx):
    ports = listening_ports(ctx)
    if ports is None:
        return SKIP, "/proc/net/tcp недоступен"
    bad = [f"{INSECURE_PORTS[p]} ({p})" for p in sorted(ports) if p in INSECURE_PORTS]
    return (FAIL, "слушаются: " + ", ".join(bad)) if bad else (PASS, f"открытых портов: {len(ports)}, небезопасных нет")


@check("NET-02", "Сеть", "Межсетевой экран включён", "high", "ufw default deny incoming && ufw allow OpenSSH && ufw enable")
def firewall(ctx):
    ufw = ctx.read("/etc/ufw/ufw.conf")
    if ufw and re.search(r"^\s*ENABLED\s*=\s*yes", ufw, re.M):
        return PASS, "ufw включён"
    nft = ctx.read("/etc/nftables.conf")
    if nft and re.search(r"policy\s+drop", nft):
        return PASS, "nftables с политикой drop"
    return FAIL, "ни ufw, ни nftables с политикой drop не найдены"


# ---------------- Журналирование ----------------

@check("LOG-01", "Журналирование", "Установлен auditd", "medium", "apt install auditd && systemctl enable --now auditd")
def auditd(ctx):
    return (PASS, "auditd настроен") if ctx.path("/etc/audit/auditd.conf").exists() else (FAIL, "auditd не найден")


@check("LOG-02", "Журналирование", "Журналы аутентификации ведутся", "medium",
       "Убедитесь, что rsyslog/journald запущен и пишет auth.log")
def auth_logs(ctx):
    for p in ("/var/log/auth.log", "/var/log/secure"):
        if ctx.path(p).exists():
            return PASS, f"{p} существует"
    if ctx.path("/var/log/journal").is_dir():
        return PASS, "persistent journald"
    return FAIL, "auth.log/secure не найдены"


def run_all(root: Path | str = "/") -> list[Result]:
    ctx = Context(Path(root))
    results = []
    for check_id, category, title, severity, fn, remediation in CHECKS:
        try:
            status, detail = fn(ctx)
        except Exception as e:  # одна сломанная проверка не должна ронять аудит
            status, detail = SKIP, f"ошибка проверки: {e}"
        results.append(Result(check_id, category, title, severity, status, detail, remediation))
    return results


def score(results: list[Result]) -> int:
    """Взвешенный процент пройденных проверок (SKIP не учитываются)."""
    rated = [r for r in results if r.status in (PASS, FAIL, WARN)]
    total = sum(SEVERITY_WEIGHT[r.severity] for r in rated)
    got = sum(SEVERITY_WEIGHT[r.severity] for r in rated if r.status == PASS)
    return round(100 * got / total) if total else 0
