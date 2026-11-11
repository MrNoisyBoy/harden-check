"""harden-check: python -m hardencheck.cli [--root /]"""
from __future__ import annotations

import argparse
import json
import socket
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from .checks import FAIL, PASS, SEVERITY_WEIGHT, SKIP, run_all, score

STATUS_COLOR = {PASS: "#2b8a3e", FAIL: "#c92a2a", "WARN": "#e67700", SKIP: "#868e96"}
ANSI = {PASS: "\033[32m", FAIL: "\033[31m", "WARN": "\033[33m", SKIP: "\033[90m"}

TEMPLATE = Template("""<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><title>Аудит защищённости {{ target }}</title>
<style>
body{font-family:system-ui,sans-serif;margin:32px;color:#222;max-width:1100px}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:8px 0 22px}
th,td{border:1px solid #ddd;padding:6px 9px;text-align:left;vertical-align:top}th{background:#f3f3f3}
.st{color:#fff;padding:2px 7px;border-radius:4px;font-size:12px;font-weight:600}
.score{font-size:46px;font-weight:700} .sub{color:#666} code{font-size:12px;background:#f6f6f6;padding:1px 4px}
</style></head><body>
<h1>Аудит защищённости Linux</h1>
<p class="sub">Цель: <b>{{ target }}</b> · {{ generated }}</p>
<p><span class="score" style="color:{{ score_color }}">{{ score }}%</span> &nbsp; взвешенная оценка ·
{% for s in ["PASS","FAIL","SKIP"] %}<span class="st" style="background:{{ colors[s] }}">{{ s }} {{ counts.get(s,0) }}</span> {% endfor %}</p>

{% if fails %}<h2>Исправить в первую очередь</h2>
<table><tr><th style="width:70px">ID</th><th>Проблема</th><th>Критичность</th><th>Что найдено</th><th>Как исправить</th></tr>
{% for r in fails %}<tr><td>{{ r.id }}</td><td>{{ r.title }}</td><td>{{ r.severity }}</td><td>{{ r.detail }}</td><td><code>{{ r.remediation }}</code></td></tr>{% endfor %}
</table>{% endif %}

<h2>Все проверки</h2>
{% for cat, items in categories.items() %}<h3>{{ cat }}</h3>
<table><tr><th style="width:70px">ID</th><th>Проверка</th><th style="width:80px">Статус</th><th>Детали</th></tr>
{% for r in items %}<tr><td>{{ r.id }}</td><td>{{ r.title }}</td><td><span class="st" style="background:{{ colors[r.status] }}">{{ r.status }}</span></td><td>{{ r.detail }}</td></tr>{% endfor %}
</table>{% endfor %}
</body></html>""", autoescape=True)


def build_html(results, target: str) -> str:
    sc = score(results)
    categories: dict[str, list] = {}
    for r in results:
        categories.setdefault(r.category, []).append(r)
    fails = sorted([r for r in results if r.status == FAIL], key=lambda r: -SEVERITY_WEIGHT[r.severity])
    return TEMPLATE.render(target=target, generated=datetime.now().strftime("%Y-%m-%d %H:%M"), score=sc,
                           score_color="#2b8a3e" if sc >= 80 else "#e67700" if sc >= 50 else "#c92a2a",
                           counts=Counter(r.status for r in results), colors=STATUS_COLOR,
                           fails=fails, categories=categories)


def main() -> None:
    parser = argparse.ArgumentParser(description="Аудит защищённости Linux-сервера (только чтение)")
    parser.add_argument("--root", default="/", help="корень проверяемой системы (по умолчанию живая система)")
    parser.add_argument("-o", "--out-dir", type=Path, default=Path("out"))
    parser.add_argument("--fail-under", type=int, default=0, help="код возврата 1, если оценка ниже порога (для CI)")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    results = run_all(args.root)
    target = socket.gethostname() if args.root == "/" else args.root
    sc = score(results)

    for r in results:
        color, reset = ("", "") if args.no_color else (ANSI[r.status], "\033[0m")
        print(f"{color}[{r.status}]{reset} {r.id:7} {r.title} — {r.detail}")
    print(f"\nОценка: {sc}%  ({', '.join(f'{k} {v}' for k, v in Counter(r.status for r in results).items())})")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "report.html").write_text(build_html(results, target), encoding="utf-8")
    (args.out_dir / "report.json").write_text(json.dumps({"target": target, "score": sc, "results": [asdict(r) for r in results]},
                                                         ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Отчёт: {args.out_dir / 'report.html'}")
    sys.exit(1 if sc < args.fail_under else 0)


if __name__ == "__main__":
    main()
