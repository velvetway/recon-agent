#!/usr/bin/env python3
"""Собирает HTML-атлас CWE из data/cwe/cwe.json.

Использование:
  python3 tools/cwe/atlas.py [--in data/cwe/cwe.json] [--out build/cwe_atlas.html]

Страница самодостаточна: данные встраиваются прямо в HTML. Ссылка на запись
имеет вид cwe_atlas.html#cwe-79 — на неё будет ссылаться отчёт агента.
"""
import argparse
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def compact(w):
    """Короткие ключи, которые ожидает шаблон (экономит ~20% размера страницы)."""
    en = {
        "n": w["name"], "ab": w["abstraction"], "st": w["status"], "t25": w["top25_rank"] > 0,
        "d": w["description"], "x": w["extended"], "rel": w["relations"],
        "cons": [{"s": c["scope"], "i": c["impact"], "note": c["note"]} for c in w["consequences"]],
        "lik": w["likelihood"], "modes": w["modes"],
        "plat": [{"k": p["kind"], "n": p["name"], "p": p["prevalence"]} for p in w["platforms"]],
        "mit": [{"ph": m["phases"], "st": m["strategy"], "t": m["text"], "ef": m["effectiveness"]} for m in w["mitigations"]],
        "det": [{"m": d["method"], "t": d["text"], "ef": d["effectiveness"]} for d in w["detection"]],
        "obs": [{"r": o["ref"], "t": o["text"]} for o in w["observed"]],
        "capec": w["capec"], "alt": w["alt_names"],
    }
    ru = {"n": w["name_ru"], "d": w["description_ru"]} if w["name_ru"] else None
    return en, ru


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="src", default="data/cwe/cwe.json")
    ap.add_argument("--out", default="build/cwe_atlas.html")
    ap.add_argument("--template", default=os.path.join(HERE, "atlas_template.html"))
    args = ap.parse_args()

    with open(args.src, encoding="utf-8") as f:
        catalog = json.load(f)
    en, ru = {}, {}
    for w in catalog["weaknesses"]:
        e, r = compact(w)
        en[w["id"]] = e
        if r:
            ru[w["id"]] = r

    def dump(obj):
        # "<" экранируем: в описаниях CWE встречаются "<!--" и теги, которые
        # иначе ломают разбор встроенного <script>.
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")

    with open(args.template, encoding="utf-8") as f:
        page = f.read()
    if "/*DATA*/" not in page:
        raise SystemExit(f"{args.template}: нет метки /*DATA*/")
    page = page.replace("/*DATA*/", "const DATA={en:" + dump(en) + ",ru:" + dump(ru) + "};")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"{args.out}: {len(en)} записей, {os.path.getsize(args.out) // 1024} КБ")


if __name__ == "__main__":
    main()
