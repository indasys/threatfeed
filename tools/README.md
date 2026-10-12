# tools

Prüflogik für `threatfeed.txt`. Dieselbe Prüfung läuft lokal und im Workflow `validate` (dort immer in der Fassung von `main`).

## Inhalt

- `validate.py` - prüft Format, reservierte Netze, Präfixgrenzen, Duplikate, Überlappungen, Sortierung, Größe und Änderungsumfang des Feeds sowie die im PR geänderten Pfade; meldet erforderliche Labels (`large-net`, `bulk`); `--sort` sortiert die Datei und entfernt exakte Duplikate
- `test_validate.py` - Selbsttests (unittest) für `validate.py`

## Nutzung

Aus dem Repo-Stamm:

```bash
python3 tools/validate.py          # Feed prüfen
python3 tools/validate.py --sort   # sortieren, exakte Duplikate entfernen
python3 -m unittest discover -s tools -p 'test_*.py' -v   # Selbsttests
```

Im Workflow zusätzlich mit `--base` (Stand von `main`), `--changed-files` und `--labels` aufgerufen; Fehler erscheinen dann als Annotationen an der betroffenen Zeile und in der Zusammenfassung des Laufs.

## Pflege

- Nur Python-Standardbibliothek, keine Abhängigkeiten.
- Jede neue oder geänderte Regel mit Test in `test_validate.py` absichern.
- Änderungen wirken für andere PRs erst nach dem Merge auf `main`; Review durch die Code Owner laut `.github/CODEOWNERS`.
