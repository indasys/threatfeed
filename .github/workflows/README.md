# workflows

GitHub-Actions-Workflows, die bei jedem Pull Request auf `main` laufen.

## Inhalt

- `validate.yml` - Workflow `threatfeed-validate`, Job `validate` (Pflicht-Check im Ruleset): prüft den Merge-Stand mit `tools/validate.py` aus `main` gegen den aktuellen `main`, berücksichtigt die PR-Labels und führt danach die Selbsttests der Prüflogik aus dem PR aus

## Pflege

- Actions sind auf einen Commit-SHA festgelegt (mit Versionskommentar); Updates kommen über Dependabot.
- Rechte minimal halten (`permissions`), Checkout ohne gespeicherte Zugangsdaten.
- Wird ein Job umbenannt, den Pflicht-Check im Ruleset `main-schutz` anpassen, sonst bleibt jeder PR blockiert.
