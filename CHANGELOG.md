# LunaSurfer 0.3.23

## 0.3.23 – 2026-11-01
- Lesezeichenordner in der Symbolleiste korrigiert: QToolBar verwendet jetzt QToolButton + QMenu. 
- Chromium-Lesezeichenimporte bewahren die Ordnerhierarchie und Ordner werden als erweiterbare Menüs angezeigt. 
– Startabsturz behoben, der durch den Aufruf von addMenu() auf QToolBar verursacht wurde.

# Changelog
## 0.3.21 – 2026-10-31
-  Start-URLs korrigiert: Wenn LunaSurfer als Standardbrowser verwendet wird und ein Link von einem anderen Programm geöffnet wird, soll jetzt direkt die übergebene URL geöffnet werden – nicht nur die Startseite.
- Neue Einstellung: Unter Einstellungen gibt es jetzt die Option „LunaSurfer als Standardbrowser verwenden“ mit Ja/Nein.
- Dabei sollte der restliche Stand der funktionierenden Version erhalten bleiben.

## 0.3.20 – 2026-10-31
- Korrektur: Das Rechtsklick-Kontextmenü direkt im URL-/Adressfeld wird jetzt von LunaSurfer selbst bereitgestellt und folgt zuverlässig der ausgewählten Sprache.
- Deutsch: Rückgängig, Wiederholen, Ausschneiden, Kopieren, Einfügen, Löschen, Alles auswählen.
- Englisch: Undo, Redo, Cut, Copy, Paste, Delete, Select All.
- Das normale Rechtsklick-Kontextmenü von Webseiten bleibt unverändert.


## 0.3.16 – 2026-10-31

- Korrektur: Alle sichtbaren Versionsangaben wurden geprüft und auf 0.3.16 aktualisiert.
- Der Über-Dialog zeigt jetzt die korrekte aktuelle Version.
- README und Installationsbeispiel wurden auf die aktuelle Version aktualisiert.

## 0.3.15
- Neue Einstellung: Fenstergröße und Position beim Beenden merken (Ja/Nein).
- Bei aktivierter Einstellung wird die letzte Fensterposition und -größe beim nächsten Start wiederhergestellt.

# LunaSurfer Changelog

## 0.3.14 – 2026-10-31
- Fixed the incomplete English translation in the Settings window.
- All Settings labels, permission choices, buttons, startup options, theme names and privacy options now follow the selected language.
- Font-size values are stored internally while displayed in the selected application language.

## 0.3.13 – 2026-10-31
- Language changes between German and English now take effect immediately without restarting LunaSurfer.
- Updated all visible version information to 0.3.13, including the About dialog and source metadata.
- README and changelog wording updated to match the immediate language switching behavior.

## 0.3.12 – 2026-10-31
- Plus button in the tab bar enlarged and styled for better visibility.
- Added selectable application language: Deutsch or English.
- Core browser controls and new tab labels now follow the selected language.
- English mode keeps the native English web context menu.

## 0.3.11
- Kleines Hinweisfenster ergänzt, das nach einem erfolgreich abgeschlossenen Download angezeigt wird.
- Statusleiste meldet zusätzlich den fertigen Download.
- Versionsangaben in App, VERSION-Datei, README und Debian-Paket auf 0.3.11 aktualisiert.

## 0.3.10
- **+ Schaltfläche in der Tab-Leiste** ergänzt. Ein Klick öffnet einen neuen Browser-Tab mit der eingestellten Startseite.

## 0.3.9
- Lesezeichenverwaltung erweitert: Lesezeichen können im Fenster „Lesezeichen verwalten“ geöffnet, bearbeitet und gelöscht werden.
- Bearbeiten und Löschen von Lesezeichen per rechter Maustaste in der Lesezeichenleiste.
- Adressleiste deutlich verbreitert.
- Versionsangaben in App, README und Changelog vereinheitlicht.
- Widevine- und Pluto-TV-Konfiguration unverändert beibehalten.

## 0.3.2
- Gut sichtbaren Stern (★) zum Hinzufügen der aktuellen Seite als Lesezeichen wieder in die Navigationsleiste eingebaut.
- README um Anleitung für den Widevine-Umgebungsbefehl in `~/.profile` ergänzt.
- Anleitung für Ab- und Anmelden bzw. Neustart ergänzt.

## 0.3.0
- Chromium-ähnliche Lesezeichenleiste ergänzt.

## 0.3.22
- Chromium-kompatibler Import und Export von Lesezeichen im HTML-Format.
