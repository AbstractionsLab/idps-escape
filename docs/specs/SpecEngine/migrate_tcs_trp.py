import re
import shutil
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
SPECS = ROOT / "docs" / "specs"


def read_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def write_yaml(path: Path, data):
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=False), encoding="utf-8")


def parse_item(path: Path):
    text = path.read_text(encoding="utf-8")
    if text.startswith("---\n"):
        parts = text.split("\n---\n", 1)
        if len(parts) == 2:
            fm_text = parts[0][4:]
            body = parts[1]
        else:
            fm_text = text[4:]
            body = ""
    else:
        fm_text = ""
        body = text

    fm = yaml.safe_load(fm_text) if fm_text.strip() else {}
    if fm is None:
        fm = {}
    return fm, body


def dump_item(path: Path, fm: dict, body: str):
    fm_text = yaml.safe_dump(fm, sort_keys=False, allow_unicode=False).strip()
    if not body.endswith("\n"):
        body = body + "\n"
    out = f"---\n{fm_text}\n---\n{body}"
    path.write_text(out, encoding="utf-8")


def item_files(folder: Path):
    files = [p for p in folder.glob("*.md") if p.name != ".doorstop.yml"]

    def sort_key(p: Path):
        uid = p.stem
        suffix = uid.split("-", 1)[1] if "-" in uid else uid
        if suffix.isdigit():
            return (0, int(suffix), suffix)
        m = re.match(r"^(\d+)(.*)$", suffix)
        if m:
            return (1, int(m.group(1)), m.group(2))
        return (2, suffix)

    return sorted(files, key=sort_key)


def ordered_unique(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def merge_doc_configs(cfg_paths, prefix, parent):
    cfgs = [read_yaml(p) for p in cfg_paths]
    defaults = {}
    publish = []
    reviewed = []
    for cfg in cfgs:
        attrs = cfg.get("attributes", {})
        for k, v in (attrs.get("defaults") or {}).items():
            defaults[k] = v
        publish.extend(attrs.get("publish") or [])
        reviewed.extend(attrs.get("reviewed") or [])

    defaults["release"] = "stable"

    return {
        "settings": {
            "digits": 3,
            "itemformat": "markdown",
            "parent": parent,
            "prefix": prefix,
            "sep": "-",
        },
        "attributes": {
            "defaults": defaults,
            "publish": ordered_unique((publish or []) + ["release", "source_prefix", "source_uid"]),
            "reviewed": ordered_unique((reviewed or []) + ["release"]),
        },
    }


def remap_text(text: str, mapping: dict):
    pattern = re.compile(r"\b(?:TST|TSS|TRA|TRB|TRS)-[A-Za-z0-9]+\b")
    return pattern.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)


def remap_links(links, uid_map, null_on_change=False):
    if not isinstance(links, list):
        return links

    out = []
    for entry in links:
        if isinstance(entry, dict) and entry:
            old_uid, fp = next(iter(entry.items()))
            new_uid = uid_map.get(old_uid, old_uid)
            if null_on_change and new_uid != old_uid:
                out.append({new_uid: None})
            else:
                out.append({new_uid: fp})
        elif isinstance(entry, str):
            new_uid = uid_map.get(entry, entry)
            if null_on_change and new_uid != entry:
                out.append({new_uid: None})
            else:
                out.append(new_uid)
        else:
            out.append(entry)

    return out


def copy_assets(src_dirs, dst_dir):
    for src in src_dirs:
        if not src.exists():
            continue
        for child in src.iterdir():
            target = dst_dir / "assets" / child.name
            target.parent.mkdir(parents=True, exist_ok=True)
            if child.is_dir():
                if target.exists():
                    continue
                shutil.copytree(child, target)
            else:
                if not target.exists():
                    shutil.copy2(child, target)


def main():
    # Phase 1: TCS from TST + TSS
    src_tst = SPECS / "tst"
    src_tss = SPECS / "tss"
    dst_tcs = SPECS / "tcs"

    if dst_tcs.exists():
        shutil.rmtree(dst_tcs)
    dst_tcs.mkdir(parents=True)

    cfg_tcs = merge_doc_configs([src_tst / ".doorstop.yml", src_tss / ".doorstop.yml"], "TCS", "SRS")
    write_yaml(dst_tcs / ".doorstop.yml", cfg_tcs)

    uid_map = {}
    index = 1
    for source_prefix, folder in [("TST", src_tst), ("TSS", src_tss)]:
        for p in item_files(folder):
            old_uid = p.stem
            new_uid = f"TCS-{index:03d}"
            uid_map[old_uid] = new_uid
            fm, body = parse_item(p)
            fm["source_prefix"] = source_prefix
            fm["source_uid"] = old_uid
            if "release" not in fm or fm["release"] in (None, ""):
                fm["release"] = "stable" if source_prefix == "TSS" else "beta"
            fm["links"] = remap_links(fm.get("links", []), {}, null_on_change=False)
            body = remap_text(body, uid_map)
            dump_item(dst_tcs / f"{new_uid}.md", fm, body)
            index += 1

    for p in item_files(dst_tcs):
        fm, body = parse_item(p)
        new_body = remap_text(body, uid_map)
        if new_body != body:
            dump_item(p, fm, new_body)

    copy_assets([src_tst / "assets", src_tss / "assets"], dst_tcs)

    # Phase 2: TRP from TRA + TRB + TRS
    src_tra = SPECS / "tra"
    src_trb = SPECS / "trb"
    src_trs = SPECS / "trs"
    dst_trp = SPECS / "trp"

    if dst_trp.exists():
        shutil.rmtree(dst_trp)
    dst_trp.mkdir(parents=True)

    cfg_trp = merge_doc_configs([src_tra / ".doorstop.yml", src_trb / ".doorstop.yml", src_trs / ".doorstop.yml"], "TRP", "TCS")
    write_yaml(dst_trp / ".doorstop.yml", cfg_trp)

    report_map = {}
    index = 1
    for source_prefix, folder in [("TRA", src_tra), ("TRB", src_trb), ("TRS", src_trs)]:
        for p in item_files(folder):
            old_uid = p.stem
            new_uid = f"TRP-{index:03d}"
            report_map[old_uid] = new_uid
            fm, body = parse_item(p)
            fm["source_prefix"] = source_prefix
            fm["source_uid"] = old_uid
            fm["release"] = {"TRA": "alpha", "TRB": "beta", "TRS": "stable"}[source_prefix]
            fm["links"] = remap_links(fm.get("links", []), uid_map, null_on_change=True)
            body = remap_text(body, uid_map)
            body = remap_text(body, report_map)
            dump_item(dst_trp / f"{new_uid}.md", fm, body)
            index += 1

    for p in item_files(dst_trp):
        fm, body = parse_item(p)
        new_body = remap_text(remap_text(body, uid_map), report_map)
        if new_body != body:
            dump_item(p, fm, new_body)

    copy_assets([src_tra / "assets", src_trb / "assets", src_trs / "assets"], dst_trp)

    # Mapping artifacts
    map_dir = SPECS / "_migration_maps"
    if map_dir.exists():
        shutil.rmtree(map_dir)
    map_dir.mkdir(parents=True)

    (map_dir / "tcs_uid_map.csv").write_text(
        "old_uid,new_uid\n" + "\n".join(f"{k},{v}" for k, v in sorted(uid_map.items())),
        encoding="utf-8",
    )
    (map_dir / "trp_uid_map.csv").write_text(
        "old_uid,new_uid\n" + "\n".join(f"{k},{v}" for k, v in sorted(report_map.items())),
        encoding="utf-8",
    )

    # Remove legacy folders
    for old in ["tst", "tss", "tra", "trb", "trs"]:
        old_path = SPECS / old
        if old_path.exists():
            shutil.rmtree(old_path)

    print("Migration complete: created docs/specs/tcs and docs/specs/trp, removed legacy folders.")


if __name__ == "__main__":
    main()
