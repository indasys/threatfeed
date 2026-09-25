#!/usr/bin/env python3
"""Prüft threatfeed.txt gemäß Konzept Kapitel 5.

Lokal:   python3 tools/validate.py
Sortieren: python3 tools/validate.py --sort
CI:      python3 tools/validate.py --base base.txt --changed-files changed.txt --labels '["bulk"]'
"""
import argparse
import ipaddress
import json
import os
import sys

FEED = "threatfeed.txt"
MAX_ENTRIES = 100_000
MAX_ADDED = 256
MAX_REMOVED = 50
MAX_SHRINK = 0.20
V4_NORMAL, V4_MIN = 24, 16   # /24 bis /32 normal, /16 bis /23 nur mit large-net, kürzer abgelehnt
V6_NORMAL, V6_MIN = 48, 32   # /48 bis /128 normal, /32 bis /47 nur mit large-net, kürzer abgelehnt
ALLOWED_PATHS = ("threatfeed.txt", ".gitattributes", "tools/", ".github/")

RESERVED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
    "2001:db8::/32", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
)]


class Report:
    def __init__(self):
        self.errors = []          # (zeile, text)
        self.required_labels = set()
        self.stats = {}

    def error(self, msg, line=None):
        self.errors.append((line, msg))

    @property
    def ok(self):
        return not self.errors


def sort_key(net):
    return (net.version, int(net.network_address), net.prefixlen)


def parse(text, rep, report_errors=True):
    """Liefert [(zeilennummer, netz)]. Fehler nur für den Head Stand melden."""
    err = rep.error if report_errors else (lambda *a, **k: None)
    if text.startswith("\ufeff"):
        err("Datei beginnt mit BOM", 1)
    if "\r" in text:
        err("Windows Zeilenenden (CRLF) sind nicht erlaubt")
    if text and not text.endswith("\n"):
        err("Datei muss mit einem Zeilenumbruch enden", text.count("\n") + 1)
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    nets = []
    for no, line in enumerate(lines, 1):
        line = line.lstrip("\ufeff") if no == 1 else line
        if line == "":
            err("Leerzeile", no)
            continue
        if "/" not in line:
            err(f"Kein CIDR, Präfix fehlt: {line!r} (Einzel IP als /32 bzw. /128)", no)
            continue
        try:
            net = ipaddress.ip_network(line, strict=True)
        except ValueError as e:
            err(f"Ungültig: {line!r} ({e})", no)
            continue
        if str(net) != line:
            err(f"Nicht kanonisch: {line!r}, erwartet {net}", no)
            continue
        nets.append((no, net))
    return nets


def check_entries(nets, rep, existing=frozenset()):
    # Reservierte Netze und Präfixlängen
    for no, net in nets:
        for r in RESERVED:
            if net.version == r.version and net.overlaps(r):
                rep.error(f"{net} überschneidet reserviertes Netz {r}", no)
                break
        normal, minimum = (V4_NORMAL, V4_MIN) if net.version == 4 else (V6_NORMAL, V6_MIN)
        if net.prefixlen < minimum:
            rep.error(f"{net} zu groß, kleinstes erlaubtes Präfix ist /{minimum}", no)
        elif net.prefixlen < normal and net not in existing:
            # Nur neu hinzugefügte große Netze brauchen die erhöhte Freigabe, nicht der Bestand
            rep.required_labels.add("large-net")

    # Duplikate
    seen = {}
    for no, net in nets:
        if net in seen:
            rep.error(f"Duplikat: {net} (bereits in Zeile {seen[net]})", no)
        else:
            seen[net] = no

    # Überlappung: bei sortierten CIDRs steht ein umfassendes Netz vor seinen Teilnetzen
    cover = None
    for net in sorted(seen, key=sort_key):
        if cover is not None and net.version == cover.version and net.subnet_of(cover):
            rep.error(f"{net} ist bereits durch {cover} (Zeile {seen[cover]}) abgedeckt", seen[net])
        else:
            cover = net

    # Sortierung
    keys = [sort_key(n) for _, n in nets]
    for i in range(1, len(keys)):
        if keys[i] < keys[i - 1]:
            rep.error("Datei nicht sortiert (ab hier). Lokal korrigieren: python3 tools/validate.py --sort", nets[i][0])
            break

    if len(nets) > MAX_ENTRIES:
        rep.error(f"{len(nets)} Einträge, Maximum {MAX_ENTRIES}")


def check_diff(base_nets, head_nets, labels, rep):
    base = {n for _, n in base_nets}
    head = {n for _, n in head_nets}
    added, removed = head - base, base - head
    rep.stats.update(base=len(base), head=len(head), added=sorted(added, key=sort_key),
                     removed=sorted(removed, key=sort_key))
    if not head:
        rep.error("Feed ist leer. Das würde den Schutz auf allen FortiGates aufheben.")
    if len(added) > MAX_ADDED or len(removed) > MAX_REMOVED:
        rep.required_labels.add("bulk")
    if base and head and "bulk" not in labels:
        shrink = (len(base) - len(head)) / len(base)
        if shrink > MAX_SHRINK:
            rep.error(f"Feed schrumpft um {shrink:.0%} (Grenze {MAX_SHRINK:.0%}), nur mit Label bulk")


def check_paths(changed, rep):
    for path in changed:
        if not any(path == p or (p.endswith("/") and path.startswith(p)) for p in ALLOWED_PATHS):
            rep.error(f"Datei außerhalb der erlaubten Pfade: {path}")


def run(head_text, base_text="", labels=(), changed=()):
    rep = Report()
    labels = set(labels)
    head = parse(head_text, rep)
    base = parse(base_text, rep, report_errors=False)
    check_entries(head, rep, {n for _, n in base})
    check_diff(base, head, labels, rep)
    check_paths(changed, rep)
    for lab in sorted(rep.required_labels - labels):
        rep.error(f"Label {lab} erforderlich (erhöhte Freigabe mit zwei Approvern)")
    return rep


def gha_escape(msg):
    # Zeileninhalt stammt aus dem PR und darf keine eigenen Workflow Befehle erzeugen
    return msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def emit(rep):
    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    for line, msg in rep.errors:
        if gha:
            loc = f"file={FEED},line={line}" if line else f"file={FEED}"
            print(f"::error {loc}::{gha_escape(msg)}")
        else:
            print(f"FEHLER{f' Zeile {line}' if line else ''}: {msg}")
    s = rep.stats
    if s:
        print(f"Einträge: {s['base']} -> {s['head']} | neu: {len(s['added'])} | entfernt: {len(s['removed'])}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and s:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"### Threatfeed Prüfung: {'bestanden' if rep.ok else 'fehlgeschlagen'}\n\n")
            f.write(f"Einträge {s['base']} auf {s['head']}, neu {len(s['added'])}, entfernt {len(s['removed'])}\n\n")
            if rep.required_labels:
                f.write(f"Erforderliche Labels: {', '.join(sorted(rep.required_labels))}\n\n")
            for title, items in (("Neu", s["added"]), ("Entfernt", s["removed"])):
                if items:
                    f.write(f"**{title}** (max. 100 angezeigt)\n```\n" + "\n".join(map(str, items[:100])) + "\n```\n")
            for line, msg in rep.errors:
                f.write(f"* Zeile {line}: {msg}\n" if line else f"* {msg}\n")


def sort_file(path):
    rep = Report()
    with open(path, encoding="utf-8", newline="") as f:
        nets = parse(f.read(), rep)
    if not rep.ok:
        emit(rep)
        return 1
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("".join(f"{n}\n" for n in sorted({n for _, n in nets}, key=sort_key)))
    print(f"{path} sortiert, exakte Duplikate entfernt")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed", default=FEED)
    ap.add_argument("--base", help="Datei mit dem Stand von main")
    ap.add_argument("--changed-files", help="Datei mit geänderten Pfaden, einer pro Zeile")
    ap.add_argument("--labels", default="[]", help="JSON Liste der PR Labels")
    ap.add_argument("--sort", action="store_true")
    a = ap.parse_args()

    if a.sort:
        return sort_file(a.feed)
    if not os.path.exists(a.feed):
        print(f"FEHLER: {a.feed} fehlt")
        return 1
    read = lambda p: open(p, encoding="utf-8", newline="").read() if p and os.path.exists(p) else ""
    changed = [l for l in read(a.changed_files).splitlines() if l]
    rep = run(read(a.feed), read(a.base), json.loads(a.labels or "[]"), changed)
    emit(rep)
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
