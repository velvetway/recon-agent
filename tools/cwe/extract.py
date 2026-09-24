#!/usr/bin/env python3
"""Собирает data/cwe/cwe.json из официального XML-каталога MITRE CWE.

Источник XML (любой из):
  - https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
  - PyPI-пакет cwe2 (вендорит каталог: cwe2/database_v*/cwec_v*.xml)

Использование:
  python3 tools/cwe/extract.py --xml cwec_v4.14.xml [--ru data/cwe/cwe_ru.tsv] [--out data/cwe/cwe.json]

Берём только действующие слабости (Status != Deprecated) и иерархию
представления CWE-1000 (Research Concepts). Русский перевод названий и
описаний подмешивается из TSV: id<TAB>название<TAB>описание.
"""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict

# CWE Top 25 Most Dangerous Software Weaknesses (2023), в порядке рейтинга.
TOP25 = ["787", "79", "89", "416", "78", "20", "125", "22", "352", "434", "862", "476", "287",
         "190", "502", "77", "119", "798", "918", "306", "362", "269", "94", "863", "276"]

RESEARCH_VIEW = "1000"


def tag(e):
    return e.tag.split("}")[-1]


def text(e):
    return re.sub(r"\s+", " ", "".join(e.itertext())).strip() if e is not None else ""


def cut(s, n):
    return s if len(s) <= n else s[:n].rsplit(" ", 1)[0] + "…"


def child(e, name):
    if e is None:
        return None
    for c in e:
        if tag(c) == name:
            return c
    return None


def children(e, name):
    return [c for c in e if tag(c) == name] if e is not None else []


def load_root(path):
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            name = next(n for n in z.namelist() if n.endswith(".xml"))
            with z.open(name) as f:
                return ET.parse(f).getroot()
    return ET.parse(path).getroot()


def load_ru(path):
    ru = {}
    if not path:
        return ru
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 3:
                sys.exit(f"{path}: ожидалось 3 колонки, строка: {line[:80]!r}")
            ru[parts[0]] = (parts[1], parts[2])
    return ru


def weakness(w, ru):
    cid = w.get("ID")
    rel = defaultdict(list)
    for r in children(child(w, "Related_Weaknesses"), "Related_Weakness"):
        nature = r.get("Nature")
        # ChildOf берём только из Research view, иначе дерево станет графом с
        # десятком родителей; остальные связи — из любого представления.
        if nature == "ChildOf" and r.get("View_ID") != RESEARCH_VIEW:
            continue
        if r.get("CWE_ID") not in rel[nature]:
            rel[nature].append(r.get("CWE_ID"))

    modes = []
    for m in children(child(w, "Modes_Of_Introduction"), "Introduction"):
        ph = text(child(m, "Phase"))
        if ph and ph not in modes:
            modes.append(ph)

    platforms = []
    ap = child(w, "Applicable_Platforms")
    for p in ap if ap is not None else []:
        name = p.get("Name") or p.get("Class")
        if name:
            platforms.append({"kind": tag(p), "name": name, "prevalence": p.get("Prevalence") or ""})

    name_ru, desc_ru = ru.get(cid, ("", ""))
    return {
        "id": cid,
        "name": w.get("Name"),
        "name_ru": name_ru,
        "abstraction": w.get("Abstraction"),
        "status": w.get("Status"),
        "top25_rank": TOP25.index(cid) + 1 if cid in TOP25 else 0,
        "description": text(child(w, "Description")),
        "description_ru": desc_ru,
        "extended": cut(text(child(w, "Extended_Description")), 1400),
        "relations": dict(rel),
        "consequences": [
            {"scope": [text(s) for s in children(c, "Scope")],
             "impact": [text(s) for s in children(c, "Impact")],
             "note": cut(text(child(c, "Note")), 300)}
            for c in children(child(w, "Common_Consequences"), "Consequence")
        ],
        "likelihood": text(child(w, "Likelihood_Of_Exploit")),
        "modes": modes,
        "platforms": platforms,
        "mitigations": [
            {"phases": [text(p) for p in children(m, "Phase")],
             "strategy": text(child(m, "Strategy")),
             "text": cut(text(child(m, "Description")), 650),
             "effectiveness": text(child(m, "Effectiveness"))}
            for m in children(child(w, "Potential_Mitigations"), "Mitigation")[:6]
        ],
        "detection": [
            {"method": text(child(m, "Method")),
             "text": cut(text(child(m, "Description")), 550),
             "effectiveness": text(child(m, "Effectiveness"))}
            for m in children(child(w, "Detection_Methods"), "Detection_Method")[:6]
        ],
        "observed": [
            {"ref": text(child(o, "Reference")), "text": cut(text(child(o, "Description")), 220)}
            for o in children(child(w, "Observed_Examples"), "Observed_Example")[:8]
        ],
        "capec": [a.get("CAPEC_ID") for a in children(child(w, "Related_Attack_Patterns"), "Related_Attack_Pattern")],
        "alt_names": [text(child(a, "Term")) for a in children(child(w, "Alternate_Terms"), "Alternate_Term")],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xml", required=True, help="cwec_v*.xml или cwec_latest.xml.zip")
    ap.add_argument("--ru", default="data/cwe/cwe_ru.tsv", help="TSV с русским переводом ('' — без перевода)")
    ap.add_argument("--out", default="data/cwe/cwe.json")
    args = ap.parse_args()

    root = load_root(args.xml)
    ru = load_ru(args.ru)
    items = {}
    for w in root.iter():
        if tag(w) == "Weakness" and w.get("Status") != "Deprecated":
            items[w.get("ID")] = weakness(w, ru)

    missing = [i for i in items if i not in ru]
    if ru and missing:
        print(f"предупреждение: нет перевода для {len(missing)} CWE: {', '.join(sorted(missing, key=int)[:20])}",
              file=sys.stderr)

    catalog = {
        "source": "MITRE CWE",
        "version": root.get("Version"),
        "date": root.get("Date"),
        "view": RESEARCH_VIEW,
        "weaknesses": [items[i] for i in sorted(items, key=int)],
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(catalog, f, ensure_ascii=False, separators=(",", ":"))
        f.write("\n")
    print(f"{args.out}: {len(items)} слабостей, каталог v{catalog['version']}")


if __name__ == "__main__":
    main()
