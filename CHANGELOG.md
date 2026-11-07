Changelog

# LunaSurfer 0.3.40
- Unterdrücken Sie nach dem Abbrechen einer automatischen Aufforderung zum Entsperren des Passwort-Managers weitere automatische Aufforderungen für 60 Sekunden. Die manuelle Öffnung bleibt sofort verfügbar.

## 0.3.39 – MASTER-PASSWORT ÄNDERN / DOWNLOAD-MANAGER: NEUESTE DOWNLOADS OBEN
- Download-Manager sortiert die Einträge jetzt so, dass der zuletzt gestartete Download ganz oben steht.
- Gilt für laufende und abgeschlossene Downloads sowie für die wiederhergestellte Download-Historie.
- Die interne Zuordnung der Einträge bleibt unverändert; Aktionen wie Öffnen, Abbrechen und Entfernen bleiben korrekt.
- Im Passwortmanager gibt es jetzt „Master-Passwort ändern…“.
- Vor der Änderung wird das aktuelle Master-Passwort geprüft; das neue Passwort muss mindestens 10 Zeichen haben und bestätigt werden.
- Der vollständige Tresor wird mit einem frischen Salt und einem daraus abgeleiteten Schlüssel neu verschlüsselt. Gespeicherte Website-Logins bleiben erhalten.
- Die Tresordatei wird atomar ersetzt; die Dateiberechtigungen bleiben auf den Benutzer beschränkt.
- Dialoge sind Deutsch/Englisch lokalisiert.

## 0.3.38 – PASSWORTMANAGER / LOGIN-AUTOFILL-VERBESSERUNG / WEBSEITEN-ÜBERSETZUNG + USER-AGENT-VERWALTUNG / Verschlüsselter Export und Import
- Neuer Schlüssel-Button direkt in der Browser-Symbolleiste zum Öffnen und Entsperren des Passwortmanagers.
- Tastenkürzel Strg+Umschalt+L zum schnellen Öffnen des Passwortmanagers.
- Gespeicherte Zugangsdaten werden nach dem Entsperren beim Fokussieren von Benutzername- oder Passwortfeldern angeboten.
- Beim Auswählen eines Kontos werden Benutzername und Passwort mit nativen Eingabe-Events gesetzt, damit auch moderne, kontrollierte Webformulare die Werte übernehmen.
- Mehrstufige Login-Seiten werden unterstützt: Ein zuvor eingegebener Benutzername bleibt sitzungs- und ursprungsgebunden verfügbar; auf der Passwortseite kann das passende gespeicherte Konto ausgewählt werden.
- Zugangsdaten werden weiterhin nur für exakt passende Website-Ursprünge angeboten. Es erfolgt kein stilles automatisches Ausfüllen und keine automatische Anmeldung.
- Bestehende Verschlüsselung, Master-Passwort-Sperre und Speicherfunktion bleiben erhalten.
- Automatische Sperre nach fünf Minuten.
- Neue Übersetzen-Schaltfläche direkt neben der Adressleiste.
- Ganze Webseiten können über Google Übersetzer in Deutsch, Englisch, Französisch, Italienisch, Niederländisch, Spanisch, Portugiesisch, Polnisch, Russisch, Türkisch, Japanisch oder Chinesisch angezeigt werden.
- Die Ausgangsadresse wird pro Tab gemerkt; über „Originalseite anzeigen“ kann zur Originalseite zurückgekehrt werden.
- Die Übersetzung wird über den externen Google-Übersetzungsdienst geladen; dafür ist eine Internetverbindung erforderlich und die Seitenadresse wird an Google übermittelt.
- Neue User-Agent-Verwaltung unter Einstellungen → Sicherheit und Berechtigungen.
- Auswahl zwischen Datenschutz-Standard (bisheriger reduzierter Chrome-122-UA), nativem QtWebEngine-User-Agent und einem eigenen User-Agent.
- Eigener User-Agent wird validiert (kein leerer Wert) und dauerhaft in den Einstellungen gespeichert.
- Vorschau des aktuell ausgewählten User-Agent direkt in den Einstellungen.
- Änderungen werden sofort auf das gemeinsame Browserprofil angewendet; geöffnete Webseiten werden aktualisiert.
- Client Hints der Fingerprint-Schutzfunktion werden passend zur ausgewählten Chromium-User-Agent-Version reduziert; Engine und tatsächliche Browserfunktionen werden nicht vorgetäuscht oder geändert.
- Bestehende Fingerprint-, Canvas-, WebGL- und AudioContext-Schutzfunktionen bleiben ansonsten erhalten.
- Verschlüsselter Export und Import
- Export des Tresors als .lsv.
- Eigenes Export-Passwort.
- Verschlüsselter Export mit PBKDF2 und Fernet.
- Import auf einem anderen Gerät.
- Bestehende Logins werden aktualisiert, neue hinzugefügt.
- Dateiberechtigungen: Verzeichnis 700, Passwortdatei 600.

## 0.3.37 – SCHWARZMODUS
- Neue separate Einstellung „Webseiten-Farbgebung“ mit den Optionen „Original“ und „Schwarzmodus“. Und Webseiten-Lesbarkeit.
- Im Schwarzmodus werden Webseitenflächen schwarz dargestellt und Texte, Links, Eingabefelder sowie Bedienelemente auf eine dunkle Oberfläche abgestimmt.
- Der Schwarzmodus ist unabhängig von „Webseiten-Lesbarkeit“ und den vorhandenen Kontraststufen.
- Bilder, Videos, Canvas-Inhalte, SVG-Grafiken und eingebettete Medien werden nicht durch Farbfilter verändert; vorhandene Bildhintergründe bleiben erhalten.
- Die automatische Chromium-Dunkelfärbung wird im Schwarzmodus deaktiviert, damit die eigene schwarze Farbpalette greift.
- Die Auswahl wird gespeichert und auf bestehende sowie neue Tabs angewendet; Unterframes werden ebenfalls berücksichtigt.
- Fingerprint-, Canvas-, WebGL- und AudioContext-Schutz unverändert übernommen.

## 0.3.37
- Neue Einstellung „Webseiten-Lesbarkeit“ unter Einstellungen → Allgemein.
- Drei alternative Stufen: Sanfter Kontrast, Weicher Kontrast und Entspannter Kontrast.
- Die Text- und Linkfarben werden stufenweise leicht transparent mit dem jeweiligen Webseiten-Hintergrund gemischt, um harte Hell-Dunkel-Unterschiede zu reduzieren.
- Die Original-Farbgestaltung und der jeweilige Webseiten-Hintergrund bleiben erhalten; es wird keine globale Abdunklung oder Aufhellung angewendet.
- Bilder, Videos, Canvas-Inhalte und SVG-Grafiken/Diagramme werden nicht gezielt verändert.
- Die Auswahl wird gespeichert und auf bereits geöffnete Tabs sowie neu geladene Webseiten angewendet.
- Fingerprint-, Canvas-, WebGL- und AudioContext-Schutz unverändert übernommen.

## 0.3.36
- *Webseiten-Berechtigungen*
- Verwaltung gespeicherter Webseiten-Berechtigungen unter Einstellungen → Berechtigungen.
- Unterstützung für Kamera, Mikrofon, Standort und Benachrichtigungen.
- Bei Berechtigungsanfragen kann entschieden werden, ob die Auswahl für die jeweilige Webseite gespeichert werden soll.
- Gespeicherte Berechtigungen können verwaltet werden.
- *Datenschutz und Sicherheit *
- Fingerprint-Schutz deutlich verbessert.
- Canvas-Fingerprinting wird randomisiert.
- WebGL-Fingerprinting wird randomisiert.
- AudioContext-Fingerprinting wird randomisiert.
- Hardware-Fingerprinting verbessert (CPU-Kerne und Gerätespeicher).
- User-Agent angepasst und Browserinformationen besser verschleiert.
- Plattforminformationen angepasst.
- Fingerprint-Schutz kann während des laufenden Betriebs ein- und ausgeschaltet werden, ohne Browserneustart.
- Bereits geöffnete Tabs können nach einer Änderung aktualisiert werden.

## 0.3.35 2026–11-05
- Einstellungen: Neue Funktion „Alles löschen“ ergänzt; die bisherigen Einzelfunktionen für Verlauf, Cache und Cookies bleiben erhalten.
- „Alles löschen“ entfernt Verlauf, Cache, Cookies und Anmeldesitzungen sowie persistente Website-Daten wie Local Storage, IndexedDB und Service-Worker-Daten.
- Die vollständige Profilbereinigung wird sicher beim nächsten Programmstart abgeschlossen.
- Lesezeichen und gespeicherte Passwörter bleiben erhalten.
- Deutsch/Englisch inklusive Sicherheitsabfrage und Neustart-Hinweis.
- Bestätigungsdialoge für Verlauf, Cache und Cookies verwenden jetzt sprachabhängige Texte und Schaltflächen (Deutsch: Ja/Nein, Englisch: Yes/No).
- Auswählbare Cookie-Modi hinzugefügt: Alle zulassen, Drittanbieter blockieren, Alle blockieren oder Nur-Sitzung-Persistenz. 
- Die Cookie-Richtlinie wird in den Einstellungen gespeichert und über den Cookie-Store von Qt WebEngine angewendet.
- Der Passwortmanager ist in den Einstellungen unter „Sicherheit und Berechtigungen“ über „Passwortmanager öffnen…“ erreichbar. Gespeicherte Zugangsdaten werden lokal mit einem Master-Passwort verschlüsselt gespeichert.
- Nachdem eine übermittelte Anmeldung erfolgreich erscheint, fragt LunaSurfer, ob die Anmeldeinformationen gespeichert werden sollen. 
- Wenn das gleiche Konto bereits existiert und sein Passwort geändert wurde, fragt LunaSurfer, ob es aktualisiert werden soll. 
- Durch die Fokussierung auf ein Benutzername- oder Passwortfeld werden gespeicherte Anmeldeinformationen für genau diesen Website-Ursprung angezeigt. Wenn Sie ein Konto auswählen, wird das Formular ausgefüllt. 
- Passwörter bleiben lokal verschlüsselt im LunaSurfer-Datenverzeichnis des Benutzers. 
- Verwalten Sie gespeicherte Konten unter Einstellungen → Sicherheit und Berechtigungen → Passwörter. 
- Erfordert „python3-pyside6.qtwebchannel“ und „python3-cryptography“.

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
## 0.3.35 – Passwortmanager-Korrektur
- Master-Passwort wird beim bloßen Fokussieren eines Login-Feldes nicht mehr abgefragt.
- Option zum Anbieten des Passwortspeicherns nach erfolgreicher Anmeldung in den Einstellungen.
- Mehrstufige Login-Formulare können den zuvor eingegebenen Benutzernamen derselben Website übernehmen.


## 0.3.36 – USER_AGENT_REDUCTION
- Geschützten User-Agent auf das reduzierte, Chromium-kompatible Format `Chrome/122.0.0.0` umgestellt; unnötig detaillierte Build- und Patchnummern entfallen.
- Geschützten User-Agent bereits beim Erstellen des Browserprofils setzen, damit auch der erste Seitenaufruf die reduzierte Kennung verwendet.
- Beim Deaktivieren des Fingerprint-Schutzes wird weiterhin der native QtWebEngine-User-Agent wiederhergestellt.
- Canvas-, WebGL- und AudioContext-Schutz unverändert.

## 0.3.38 – PASSWORD_MANAGER_UNLOCK_OPTION
- Added a privacy setting controlling whether the password manager must already be unlocked before autofill.
- When the requirement is disabled, LunaSurfer asks for the master password only after the user focuses a login field; passive page scans never open an unlock prompt.
- The encrypted vault remains encrypted on disk and the master password is still required to decrypt it.

## 0.3.38 – PASSWORD_MANAGER_RETURN_URL_DETECTION
- Passwortmanager erkennt jetzt allgemeine HTTP(S)-Rücksprungadressen in URL-Query-Parametern von Anmeldediensten (auch URL-kodiert und verschachtelt).
- Die erkannte Ursprungsseite wird mit dem gespeicherten Login abgeglichen; keine fest codierten Joyn-/7Pass-Sonderfälle.
- Fremddomain-Vorschläge bleiben an die fokussierte Login-Eingabe und eine ausdrückliche Auswahl gebunden.

## 0.3.38 - GOOGLE_PASSWORD_SAVE_DIAGNOSTICS
- Added privacy-safe diagnostics for Google password capture, success detection, save prompt decisions, and timeout reasons.
- Diagnostic log: ~/.cache/lunasurfer/password-manager-debug.log (credentials are never written).
- Preserved redirect-aware password matching and Joyn/7Pass support.
## 0.3.38 – JOYN_EMAIL_FIELD_CROSS_FORM_FIX
- Improved username/e-mail field detection when authentication providers render e-mail and password fields in separate forms or containers.
- Search the local password form first, then visible document-wide fields; prioritize autocomplete, semantic names, and email inputs.
- Extended focus detection to aria-label and document-wide password lookup. Existing Google, QRZ, redirect matching, and encrypted vault logic remain unchanged.

## 0.3.38 – JOYN_USERNAME_FIRST_STEP_AUTOFILL_FIX
- Login suggestions are now offered on the username/e-mail step even when the provider has not created a password field yet.
- Selecting a saved credential fills the e-mail/username only on the first step and retains it in sessionStorage for the following password step.
- Recognition includes semantic field hints and generic authentication-host/path detection; no Joyn-specific domain mapping was added.
- Google, QRZ, redirect matching, and encrypted vault handling remain unchanged.

### JOYN_EMAIL_FIRST_STEP_SUGGESTION_FIX
- Show saved login suggestions when the first-step e-mail field receives focus, even when no password field exists yet.
- Include placeholder text in username-field detection and record a privacy-safe focus diagnostic.
- Selecting a suggestion fills the e-mail field only; password filling remains on the later password step.

## 0.3.38 - JOYN_RELYING_PARTY_FILTER_FIX
- Prefer explicit authentication return/continue destinations (including 7Pass `cd10`) when selecting saved credentials.
- Prevent unrelated credentials, such as a Google account, from appearing in Joyn's shared 7Pass login form.
- Preserve multi-step username/password handoff and existing Google/QRZ behavior.


## 0.3.38 – JOYN_AUTH_HOST_CREDENTIAL_MATCH_FIX
- Match saved credentials against both an explicit relying-party URL and the current authentication host.
- Supports Joyn entries saved under signin.7pass.de or joyn.de while excluding unrelated Google credentials.
- Preserves multi-step username/password autofill behavior.

## 0.3.38 - JOYN_EXACT_RELYING_PARTY_SCOPE_FIX
- Treat explicit 7Pass return destinations such as `cd10=https://www.joyn.de` as the exclusive credential scope.
- Do not include the shared `signin.7pass.de` host as a broad fallback when a relying party is present; this prevents unrelated Google credentials saved on the same provider host from appearing in Joyn.
- Keep provider-host credentials eligible only when their saved `related_sites` explicitly associates them with the relying party.
- Preserve first-step email suggestions and the multi-step password handoff.

## 0.3.38 – JOYN_SERVICE_BINDING_FIX
- Persist selected auth-provider credentials against the relying party URL.


## 0.3.38 – PASSWORD SAVE SITE ISOLATION FIX
- Password updates now match the exact canonical website key and username only.
- A shared email address or unrelated/stale related URL can no longer update another site’s saved login.
- Existing cross-site authentication metadata is preserved without using it to select an entry for update.
