# workflows

GitHub-Actions-Workflows, die bei jedem Pull Request auf `main` laufen.

## Inhalt

- `validate.yml` - Workflow `threatfeed-validate`, Job `validate` (Pflicht-Check im Ruleset): prüft den Merge-Stand mit `tools/validate.py` aus `main` gegen den aktuellen `main`, berücksichtigt die PR-Labels und führt danach die Selbsttests der Prüflogik aus dem PR aus
- `approval-gate.yml` - Workflow `threatfeed-approval-gate`, Job `approval-gate`: zählt gültige Freigaben (Schreibrechte, aktueller Commit, nicht vom Autor) und verlangt bei `bulk` bzw. `large-net` ohne `emergency` zwei Freigaben, davon eine aus der Repo-Variable `ELEVATED_APPROVERS`; ein offener PR schlägt vor, diesen Workflow zu entfernen

## Pflege

- Actions sind auf einen Commit-SHA festgelegt (mit Versionskommentar); Updates kommen über Dependabot.
- Rechte minimal halten (`permissions`), Checkout ohne gespeicherte Zugangsdaten.
- Wird ein Job umbenannt, den Pflicht-Check im Ruleset `main-schutz` anpassen, sonst bleibt jeder PR blockiert.
