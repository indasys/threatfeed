# .github

GitHub-Konfiguration des Repos: Zuständigkeiten, Abhängigkeits-Updates und die Workflows für Prüfung und Freigabe von Änderungen am Feed. Die Beschreibung des Gesamtablaufs steht in der `README.md` im Repo-Stamm.

## Inhalt

- `CODEOWNERS` - Pflicht-Reviewer: `threatfeed.txt` durch das Team `threatfeed-approvers`, `.gitattributes`, `tools/` und `.github/` durch die eingetragenen Maintainer
- `dependabot.yml` - monatliche Update-PRs für die verwendeten GitHub Actions
- `workflows/` - der Workflow `validate`

## Pflege

Änderungen an diesem Ordner brauchen ein Code-Owner-Review. Wer Freigabe-Regeln ändert, prüft auch das Ruleset `main-schutz` in den Repo-Einstellungen, damit beides zusammenpasst.
