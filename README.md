# RelayPing

**Live-Latenz zu Mullvad-WireGuard-Servern – gemessen von deinem GL.iNet-Router aus.**

RelayPing ist ein kleines, portables Windows-Tool: eine einzige `.exe`, keine Installation. Es zeigt dir in Echtzeit, wie schnell die Mullvad-Server von deinem Anschluss aus erreichbar sind, misst ganze Länder durch und sagt dir, ob es für deine aktiven Tunnel einen besseren Server gibt.

> **Vorabversion (Beta).** Bisher nur gegen einen nachgebauten GL.iNet-Router getestet, noch nicht auf echter Hardware. Rückmeldungen über die Issues sind willkommen.
>
> **Inoffizielles Community-Tool.** RelayPing steht in keiner Verbindung zu Mullvad VPN AB oder GL.iNet. „Mullvad“ und „GL.iNet“ sind Marken ihrer jeweiligen Inhaber.

![Live-Ansicht (Testdaten)](docs/live.png)

## Warum am Router messen?

Wenn dein VPN auf dem Router läuft, geht jeder Ping vom PC erst durch den aktiven Tunnel. Du würdest also messen, wie schnell *der VPN-Server* die anderen Server erreicht, nicht dein Anschluss. RelayPing lässt deshalb den Router selbst pingen, über die WAN-Leitung am Tunnel vorbei. Der PC zeigt nur an.

## Funktionen

- **Tunnel-Übersicht:** erkennt die aktiven WireGuard-Tunnel des Routers und zeigt deren Server mit Live-Latenz.
- **Live-Graphen:** bis zu 8 Server gleichzeitig, Zeitfenster 1, 5 oder 15 Minuten, Tooltip mit allen Werten, verlorene Pakete als rote Marken.
- **Rangliste:** misst alle Server der gewählten Länder (Standard: 20 Pings pro Server, 30 parallel) und sortiert nach Paketverlust, dann nach Latenz. Mit Jitter, Min/Max, eigener vs. gemieteter Server und Anbieter.
- **Bester Server je Tunnel:** nach einer Messung steht bei jedem Tunnel, welcher Server im selben Land besser wäre und um wie viel.
- **Verlauf als CSV:** Minutenwerte der Live-Messung und jede Rangliste, im deutschen Excel-Format (Semikolon, Dezimalkomma).
- **Wiederverbindung:** fällt der Router weg, verbindet sich RelayPing von selbst neu.

![Rangliste (Testdaten)](docs/rangliste.png)

## Voraussetzungen

- Windows 10 oder 11, 64 Bit
- Ein GL.iNet-Router mit Firmware 4.x (entwickelt für den Flint 4 / GL-BE14000). SSH muss aktiv sein, das ist im Heimnetz Standard.
- Auf dem Router werden die üblichen OpenWrt-Werkzeuge genutzt: `ping` (BusyBox), `ubus`, `jsonfilter`, optional `wg` für die Tunnel-Erkennung
- Mullvad-WireGuard-Tunnel auf dem Router. Für Live-Graphen und Rangliste ist das nicht nötig, nur für die Tunnel-Übersicht.

## Download und Start

1. Unter **[Releases](../../releases)** die neueste `RelayPing.exe` herunterladen. Die zugehörige `.sha256`-Datei enthält die Prüfsumme.
2. Doppelklick. Weil die Datei nicht signiert ist, zeigt Windows SmartScreen eine Warnung: **„Weitere Informationen“ → „Trotzdem ausführen“**.
3. Der Browser öffnet sich. Gib **einmal** das Passwort des GL.iNet-Admin-Panels ein.

Bei dieser ersten Anmeldung erzeugt RelayPing einen eigenen SSH-Schlüssel (RSA 3072) und hinterlegt ihn auf dem Router in `/etc/dropbear/authorized_keys`, markiert mit `relayping`. Das Passwort wird nicht gespeichert. Ab dann verbindet sich das Tool bei jedem Start automatisch.

Das Konsolenfenster muss offen bleiben. Schließen oder „Beenden“ in der Oberfläche beendet das Programm.

## Dateien neben der .exe

RelayPing ist portabel und legt alles in den eigenen Ordner. Ist dieser schreibgeschützt, landet es unter `%APPDATA%\RelayPing`.

| Datei | Inhalt |
|---|---|
| `relayping.json` | Einstellungen, Router-Adresse, gemerkter Router-Fingerabdruck |
| `relayping.key` | **dein privater SSH-Schlüssel für den Router**, wie ein Passwort behandeln |
| `relayping-server.json` | Mullvad-Serverliste, wird höchstens einmal am Tag neu geladen |
| `verlauf/` | CSV-Verlauf (`live-minutenwerte.csv`, `ranglisten.csv`) |

## Sicherheit

- Die Oberfläche lauscht nur auf `127.0.0.1`. Zugriffe sind an einen Schlüssel pro Programmstart gebunden. Anfragen mit fremdem Host-Header und Cross-Site-Anfragen werden abgewiesen.
- Den Router-Fingerabdruck merkt sich RelayPing bei der ersten Verbindung (Trust on first use). Ändert er sich später, verweigert das Tool die Verbindung. Nach einem Router-Reset gibt es in den Einstellungen **„Router-Zugang zurücksetzen“**.
- An den Router gehen nur feste Befehle. Server-IPs und Schnittstellennamen werden vorher streng geprüft.
- Schlüssel auf dem Router wieder entfernen (per SSH):
  ```sh
  sed -i '/ relayping$/d' /etc/dropbear/authorized_keys
  ```

## Grenzen

- Ein Ping misst Strecke und Paketverlust, **nicht die Auslastung** eines Servers. Die Rangliste ist eine Vorauswahl. Die besten zwei oder drei Server danach per Speedtest prüfen.
- RelayPing wechselt den Server **nicht** selbst. Ein Knopf zum Umschalten auf Wunsch ist geplant und in der Oberfläche schon angedeutet.
- Die Serverliste kommt aus der öffentlichen Mullvad-API (`api.mullvad.net`).

## Selbst bauen

Benötigt Go 1.24 oder neuer.

```sh
go test ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o RelayPing.exe .
```

Das Programmsymbol und die Versionsinfos stecken in `rsrc_windows_amd64.syso`, erzeugt aus `app.rc` und `icon.ico`. Releases baut eine GitHub Action automatisch, sobald ein Release veröffentlicht wird.

## Lizenz

MIT, siehe [LICENSE](LICENSE). Enthaltene Fremdbibliotheken: siehe [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

### English summary

RelayPing is a portable Windows tool (single `.exe`) that shows **live latency, jitter and packet loss to Mullvad WireGuard servers, measured from your GL.iNet router** over the WAN link, bypassing the tunnel. That matters because pinging from a PC behind a VPN router would only measure the path through the active tunnel. It detects the router's active WireGuard tunnels, plots up to 8 servers live, ranks whole countries, suggests a better server per tunnel and logs to CSV. On first start it asks once for the router's admin password, installs its own SSH key and never stores the password. The UI is German. **Beta – not yet tested on real hardware.** Unofficial, not affiliated with Mullvad VPN AB or GL.iNet. MIT licensed.
