LunaSurfer Chngelog

## 0.3.34 2026–11-04

- Kontextmenü der Webseite: „Ausschneiden“, „Kopieren“ und „Einfügen“ ergänzt (deutsch/englisch); die Aktionen verwenden die expliziten QtWebEngine-Bearbeitungsaktionen.
- Einstellungen: Globale JavaScript-Option unter „Sicherheit und Berechtigungen“ ergänzt (standardmäßig aktiviert); Änderung wird nach dem Speichern auf alle geöffneten Tabs angewendet.
- Kontextmenü: „Entwicklerwerkzeuge öffnen“ zeigt jetzt den Tastaturkurzbefehl F12 an.
- F12-Entwicklerwerkzeuge als rechts angedocktes, tabübergreifend verwendetes DevTools-Fenster.
- Kontextmenü der Webseite erweitert: Seite in neuem Tab öffnen, Seitenadresse kopieren, Cache-umgehendes Neuladen, Quelltext anzeigen und Entwicklerwerkzeuge öffnen.
- Doppelklick in der Adressleiste makiert die Adresse.
- Kontextmenü: „Quelltext anzeigen“ wieder ergänzt; die Aktion verwendet direkt `QWebEnginePage.WebAction.ViewSource` und baut kein natives QtWebEngine-Kontextmenü auf.

## 0.3.33 2026-11-03
- Der Download-Verlauf abgeschlossener Downloads bleibt über Programmneustarts hinweg erhalten.
- Zwei zusätzliche Browser-Designs: Graphit und Ocean.
- Abgeschlossene Downloads werden in `~/.local/share/lunasurfer/downloads.json` gespeichert und beim nächsten Start wiederhergestellt.
- Gespeichert werden Dateipfad, Dateigröße und Abschlusszeitpunkt; laufende Qt-WebEngine-Objekte werden nicht serialisiert.
- Entfernen einzelner Einträge und das Löschen abgeschlossener Downloads aktualisieren die gespeicherte Liste sofort.
- Zwei neue Browser-Design
- **Graphit:** neutrales, elegantes Anthrazit-Design.
- **Ocean:** dunkles Petrol-/Türkis-Design.
- Beide Designs sind direkt in den Einstellungen auswählbar und werden sofort angewendet. Die bisherigen drei Designs bleiben erhalten.
- Versionsnummern in VERSION, Fenstertitel, Über-Dialog, README und Debian-Metadaten auf 0.3.33 aktualisiert.

## 0.3.32 - 2026-11-02

### Einstellungen im Browser-Tab
- Der Einstellungsdialog wurde durch eine integrierte Einstellungsseite in einem eigenen Browser-Tab ersetzt – ähnlich wie `chrome://settings` in Chromium.
- Der Einstellungs-Tab kann wie jeder andere Tab geöffnet und geschlossen werden; ein erneuter Aufruf wechselt zum bereits geöffneten Einstellungs-Tab.
- Die Einstellungsseite ist scrollbar und optisch an das dunkle LunaSurfer-Design angepasst.
- Einstellungen sind in die Bereiche Allgemein, Sicherheit und Berechtigungen sowie Datenschutz und Browserdaten gegliedert.
- Die vorhandene Speicher- und Einstellungslogik bleibt erhalten; Speichern schließt nur den Einstellungs-Tab und kehrt zum vorherigen Browser-Tab zurück.
- Beim Wechsel auf den Einstellungs-Tab werden Navigation und Adressanzeige passend aktualisiert.

### Korrektur des Einstellungsseiten-Layouts
- Abschnittsüberschriften spannen jetzt die gesamte Formularbreite statt nur die schmale Beschriftungsspalte.
- Überschriften erhalten eine ausreichende Höhe und feste Innenabstände; dadurch werden lange Titel nicht mehr abgeschnitten.
- Dezente Trennlinie und einheitliche Abstände verbessern die Gliederung der Einstellungsgruppen.
- Ausschließlich Layoutkorrektur: Einstellungswerte, Speicherlogik und Browserfunktionen bleiben unverändert.

## Designkorrektur Einstellungen

- Hintergrund der Einstellungsseite und des Scrollbereichs vereinheitlicht: kein hellgrauer Qt-Standardhintergrund mehr.
- Dunkle Eingabefelder, klarere Beschriftungen, besser sichtbare Checkboxen und einheitlich abgerundete Bedienelemente.
- Fokus-, Hover- und Auswahlzustände im Luna-Farbton gestaltet; Scrollleiste optisch angepasst.
- Einstellungslogik, gespeicherte Werte und Tab-Verhalten unverändert.

### Versionspflege
- VERSION, Fenstertitel, Über-Dialog, README und Debian-Paketmetadaten auf 0.3.32 aktualisiert.
- Die bestehende Funktionalität aus 0.3.31 bleibt erhalten.

## 0.3.31 - 2026-11-02

### Download-Manager
- Modernes dunkles Design mit übersichtlichen Download-Karten.
- Fortschrittsbalken, Prozentanzeige, Dateigröße, Download-Geschwindigkeit und klare Statusanzeigen.
- Downloads können abgebrochen sowie fertige Dateien oder deren Speicherordner geöffnet werden.
- Einträge können aus der Liste entfernt und Dateien nach Sicherheitsabfrage gelöscht werden.
- Suche nach Dateiname und Speicherpfad sowie Filter für alle, aktive und fertige Downloads.
- Download-Manager-Scrollfix: Die bestehenden Karten werden beim 800-ms-Update aktualisiert, statt die gesamte Liste neu aufzubauen. Dadurch bleiben Scrollposition und Sichtbarkeit des letzten Downloads erhalten.
- Download-Ordner konfigurierbar; optional kann vor jedem Download nach dem Speicherort gefragt werden.

### Lesezeichen
- Chromium-Import ohne Überschreiben korrigiert: Ordner und einzelne Lesezeichen werden getrennt verarbeitet; Ordner ohne URL lösen keinen `'url'`-Fehler mehr aus.
- Die spezielle Lesezeichenleisten-Root wird an ihrer festen Position behandelt und mit einer vorhandenen Lesezeichenleiste zusammengeführt. Fehlt sie, wird sie ganz links eingefügt.
- Der Lesezeichenmanager erhält eine moderne dunkle Oberfläche mit aufklappbarer Ordnerstruktur, Name-/Adressspalten und Live-Suche.
- Doppelklick öffnet ein Lesezeichen oder klappt einen Ordner auf bzw. zu.
- Import und Export berücksichtigen die Ordnerhierarchie; Bearbeiten und Löschen bleiben verfügbar.

### Versions- und Releasepflege
- Versionsanzeige im Fenstertitel und im Dialog „Über LunaSurfer“ auf 0.3.31 vereinheitlicht; beide Anzeigen verwenden dieselbe Versionskonstante.
- README, VERSION und Debian-Paketmetadaten auf 0.3.31 abgestimmt.
- Vorhandene Browserfunktionen und Einstellungen aus Version 0.3.30 bleiben erhalten.


## 0.3.30 - 2026-11-02
- Sprachwechsel-Fix: Der Wechsel zwischen den Sprachen wurde korrigiert, damit die Benutzeroberfläche zuverlässig neu aufgebaut bzw. aktualisiert wird.
- Hauptmenü verbessert: Der Menüpunkt „Beenden / Quit“ befindet sich jetzt zusammen mit: Einstellungen, Über LunaSurfer im selben Hauptmenü.
- Adblocker erweitert: Super stark und Mega stark ergänzt; die fünf Stufen Standard, Stark, Sehr stark, Super stark und Mega stark stehen zur Verfügung.
- Drei Designs zur Auswahl: Dunkel Standard, Hell Klassisch und Luna Modern.
- Chromium-Lesezeichenimport ohne Überschreiben: Die Lesezeichenleisten-Root wird mit der vorhandenen Root zusammengeführt und nicht hinter das letzte Lesezeichen angehängt.

## 0.3.29 - 2026-11-02
- Responsive Lesezeichenleiste mit lesbaren Mindestbreiten. 
- Zusätzliche Lesezeichen werden in ein „» Weitere“-Überlaufmenü verschoben, anstatt gequetscht zu werden. 
- „Lesezeichen verwalten“ bleibt verankert und sichtbar. 
- Beinhaltet alle Funktionen und Updates von 0.3.28.

## 0.3.28 – 2026-11-02
- Download-Manager umfassend erweitert: Fortschritt, Prozent, Dateigröße und Download-Geschwindigkeit.
- Laufende Downloads können abgebrochen werden.
- Fertige Dateien oder ihr Ordner können direkt geöffnet werden.
- Einträge können aus der Liste entfernt werden, ohne die Datei zu löschen.
- Dateien können nach Sicherheitsabfrage direkt von der Festplatte gelöscht werden.
- Download-Verlauf kann aufgeräumt werden, ohne laufende Downloads zu beeinflussen.
- README und Paketversion für GitHub-Release aktualisiert.
- Integrierter, aktivierbarer Adblocker mit den Stufen Standard, Stark und Sehr stark; benutzerdefinierte Blockiermuster und Whitelist.

## 0.3.27 – Clipboard & GitHub graph rendering fixes
– Der QtWebEngine-Zugriff auf die Zwischenablage für vom Benutzer ausgelöste Website-Kopierschaltflächen wurde aktiviert. 
– Verbesserter Kontrast von SVG-Beschriftungen in GitHub-Verkehrsdiagrammen, sodass Werte auf hellen Diagrammfeldern sichtbar bleiben.

## 0.3.26 - 2026-11-01
- Tooltips/Info-Kästchen: deutlich besserer Kontrast und etwas größere, besser lesbare Darstellung.
- Tableiste verbessert

## 0.3.25 - 2026-11-01
- HTML5/Web-Vollbild korrigiert: Vollbildunterstützung und das Vollbildsignal werden jetzt an die tatsächliche Profilseite angehängt, die von jedem Tab verwendet wird. 
- YouTube-, Pluto TV- und Joyn-Vollbildanfragen erreichen jetzt das LunaSurfer-Fenster. 
– Stellt den vorherigen maximierten/normalen Fensterstatus wieder her, wenn das Web im Vollbildmodus verlassen wird.

## 0.3.24 - 2026-11-01
- Lesezeichen-Stern in der Navigationsleiste deutlich vergrößert.
- Schriftgrößen-Fix: Die gewählte Schriftgröße bleibt nach dem vollständigen Laden einer Webseite erhalten und springt nicht mehr auf Mittel zurück.

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

## 0.3.26 – UI-Fix
- Kompaktere Hinweisfenster/Tooltips für Stern und Neuer-Tab-Schaltfläche.
- Plus-Schaltfläche der Tab-Leiste steht direkt hinter dem letzten geöffneten Tab statt am rechten Fensterrand.

- Adblock-Stufen „Super stark“ und „Mega stark“ mit zusätzlichen Werbe-, Analyse-, Tracking- und Telemetrie-Regeln; die Whitelist bleibt verfügbar.
- IMPORT MERGE ROOT FIX: Beim Import ohne Überschreiben wird die Chromium-Lesezeichenleiste mit der vorhandenen Root-Leiste zusammengeführt und nicht hinter das letzte Lesezeichen gesetzt.


## 0.3.34 – Kontextmenü- und Adressleistenkorrekturen
- Kontextmenü öffnet bei Rechtsklick auf einen Link genau dessen Ziel in einem neuen Tab.
- Doppelte Aktion „Seitenquelltext anzeigen“ entfernt; der originale QtWebEngine-Eintrag bleibt erhalten.
- „Seite speichern unter…“ öffnet einen Dateidialog für Dateiname und Speicherpfad.
- Doppelklick in der Adressleiste markiert die gesamte Adresse.
- Entwicklerwerkzeuge bleiben rechts angedockt und mit 590 px Mindestbreite erhalten.


## 0.3.34 – Kontextmenü-Sprach- und Linkzielkorrektur
- Native Kontextmenüeinträge werden passend zur LunaSurfer-Sprache übersetzt.
- Der native Qt-Eintrag „Link in neuem Tab öffnen“ wird durch eine eigene URL-basierte Aktion ersetzt.
- Linkziel wird zuerst aus den Qt-Kontextdaten gelesen und bei Bedarf an der Rechtsklickposition im DOM ermittelt.
- Popup-Sperre beeinflusst das explizite Öffnen eines Links in einem neuen Tab nicht.
