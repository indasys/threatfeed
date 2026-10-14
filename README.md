# threatfeed

Sperrliste der indasys für FortiGate-Firewalls: IPv4- und IPv6-Netze in CIDR-Schreibweise, eine Zeile pro Netz. Die FortiGates binden `threatfeed.txt` als externen Threat Feed (IP-Adressliste) ein; maßgeblich ist immer der Stand auf `main`. Jede Änderung, die auf `main` landet, wirkt nach dem nächsten Abruf auf allen angebundenen FortiGates. Deshalb laufen Änderungen ausschließlich über Pull Requests mit automatischer Prüfung und Freigabe nach dem Vier-Augen-Prinzip.

Abruf-URL und Abrufintervall sind auf den FortiGates konfiguriert und nicht Teil dieses Repos. Das Repo ist öffentlich: nichts Internes in Commits, PR-Texten oder Kommentaren.

## Inhalt

- `threatfeed.txt` - der Feed (Ausgangsstand war die frühere Sperrliste, siehe Commit „Altliste als Ausgangsstand übernommen“)
- `tools/` - Prüflogik `validate.py` und ihre Selbsttests
- `.github/` - CODEOWNERS, Dependabot und der Workflow `validate`
- `.gitattributes` - erzwingt LF-Zeilenenden für Feed, Python und YAML

## Format von threatfeed.txt

- Ein Netz pro Zeile, immer mit Präfix (Einzel-IP als `/32` bzw. `/128`), kanonische Schreibweise, keine Host-Bits
- Keine Kommentare, keine Leerzeilen, kein BOM, LF-Zeilenenden, Zeilenumbruch am Dateiende
- Sortiert (IPv4 vor IPv6, aufsteigend), keine Duplikate, keine Netze, die bereits durch ein größeres Netz abgedeckt sind
- Keine reservierten oder privaten Bereiche (RFC 1918, Loopback, Link-Local, Dokumentationsnetze usw.)

## Ablauf einer Änderung

1. Branch anlegen, `threatfeed.txt` bearbeiten.
2. Lokal prüfen: `python3 tools/validate.py`. Sortieren und exakte Duplikate entfernen: `python3 tools/validate.py --sort`.
3. Pull Request auf `main` öffnen und, falls nötig, Labels setzen (siehe unten).
4. Validierung: Der Workflow `validate` prüft den Stand nach dem Merge gegen `main`, und zwar immer mit der Prüflogik aus `main`, damit ein PR seine eigene Prüfung nicht aushebeln kann. Er ist Pflicht-Check.
5. Freigabe (Vier-Augen-Prinzip, per Ruleset auf `main`): Änderungen nur per Pull Request, Review durch einen Code Owner (für `threatfeed.txt` das Team `threatfeed-approvers`), Freigabe des letzten Pushs, veraltete Freigaben werden bei neuem Push verworfen, offene Review-Threads müssen gelöst sein. Löschen von `main` und Force-Push sind gesperrt.
6. Merge nur als Squash.

## Prüfregeln (`tools/validate.py`)

- Format und Inhalt wie oben beschrieben
- Präfixe: IPv4 `/24` bis `/32` normal, `/16` bis `/23` nur mit Label `large-net`, kürzer abgelehnt; IPv6 `/48` bis `/128` normal, `/32` bis `/47` nur mit `large-net`, kürzer abgelehnt (gilt nur für neu hinzugefügte Netze)
- Mehr als 256 neue oder mehr als 50 entfernte Einträge: Label `bulk` erforderlich
- Leerer Feed wird abgelehnt; Schrumpfen um mehr als 20 % nur mit `bulk`
- Höchstens 100.000 Einträge
- Ein PR darf nur `threatfeed.txt`, `.gitattributes`, `tools/` und `.github/` ändern

## Labels

- `large-net` - neues Netz größer `/24` bzw. `/48`
- `bulk` - mehr als 256 neue oder 50 entfernte Einträge
- `emergency` - aktiver Angriff, nachträgliches Review innerhalb eines Werktags
- `false-positive` - Entfernung eines Fehleintrags

## Pflege

- Änderungen an `tools/` und `.github/` brauchen ein Review der dort in `.github/CODEOWNERS` eingetragenen Owner.
- Neue Prüfregeln immer mit Selbsttest in `tools/test_validate.py`. Sie greifen für andere PRs erst, wenn sie auf `main` gemergt sind.
- Die Grenzwerte stehen als Konstanten am Anfang von `tools/validate.py`; bei Änderung diese README mitziehen.
