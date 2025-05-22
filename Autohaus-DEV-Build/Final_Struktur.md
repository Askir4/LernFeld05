# Struktur des Autohaus-Verwaltungssystems

## Inhaltsverzeichnis
1. [Logging-Konfiguration](#logging-konfiguration)
2. [Datenbankverbindungs-Pool](#datenbankverbindungs-pool)
3. [Datenklassen](#datenklassen)
4. [Passwort-Sicherheit](#passwort-sicherheit)
5. [Datenbankfunktionen](#datenbankfunktionen)
6. [Formatierungsfunktionen](#formatierungsfunktionen)
7. [Login-GUI](#login-gui)
8. [Hauptanwendung-GUI](#hauptanwendung-gui)
9. [Hauptprogramm](#hauptprogramm)

## Logging-Konfiguration

### `setup_logging()`
Richtet das Logging-System ein. Erstellt ein Logverzeichnis falls nicht vorhanden und konfiguriert Logger mit File- und Console-Handlern.
- **Rückgabe**: Logger-Instanz

## Datenbankverbindungs-Pool

### Klasse `DbConnectionPool`
Eine einfache Implementierung eines Datenbankverbindungspools.

#### Attribute
- `_instance`: Singleton-Instanz der Klasse
- `connections`: Liste der verfügbaren Verbindungen
- `max_connections`: Maximale Anzahl an Verbindungen im Pool

#### Methoden
- `get_instance()`: Gibt die Singleton-Instanz des Pools zurück
- `__init__()`: Initialisiert den Pool
- `get_connection()`: Gibt eine Verbindung aus dem Pool zurück oder erstellt eine neue
- `release_connection(connection)`: Gibt eine Verbindung in den Pool zurück

### Hilfsfunktionen
- `get_db_connection()`: Holt eine Verbindung aus dem Pool
- `release_db_connection(connection)`: Gibt eine Verbindung in den Pool zurück

## Datenklassen

### Klasse `Benutzer`
Repräsentiert einen Benutzer im System.

#### Attribute
- `name`: Benutzername
- `passwort`: Passwort (kann ein String oder Bytes sein)

#### Methoden
- `get_passwort_hex()`: Gibt das Passwort als Hexadezimalstring zurück, wenn es binär ist

### Klasse `Fahrzeug`
Repräsentiert ein Fahrzeug im System.

#### Attribute
- `id`: Eindeutige ID
- `marke`: Fahrzeugmarke
- `modell`: Fahrzeugmodell
- `baujahr`: Baujahr
- `wert`: Wert in Euro
- `kilometerstand`: Kilometerstand
- `farbe`: Fahrzeugfarbe

#### Methoden
- `beschreibung()`: Gibt eine Kurzbeschreibung des Fahrzeugs zurück

## Passwort-Sicherheit

### `hash_password(password, salt=None)`
Erzeugt einen sicheren Hash mit Salt für ein Passwort.
- **Parameter**:
  - `password`: Zu hashendes Passwort
  - `salt`: Optional, wenn nicht angegeben wird ein neues Salt generiert
- **Rückgabe**: Salt + Hash als Bytes

### `verify_password(stored_password, provided_password)`
Überprüft ein Passwort gegen den gespeicherten Hash.
- **Parameter**:
  - `stored_password`: Gespeicherter Passwort-Hash
  - `provided_password`: Zu überprüfendes Passwort
- **Rückgabe**: Boolean (True wenn das Passwort übereinstimmt)

### `migriere_bestehende_passwoerter()`
Migriert bestehende Klartext-Passwörter zu sicheren Hashes.

## Datenbankfunktionen

### `init_db()`
Initialisiert die Datenbank und erstellt Tabellen, falls sie nicht existieren.

### `lade_benutzer()`
Lädt alle Benutzer aus der Datenbank.
- **Rückgabe**: Liste von Benutzer-Objekten

### `speichere_benutzer(name, passwort)`
Speichert einen neuen Benutzer mit gehashtem Passwort in der Datenbank.
- **Parameter**:
  - `name`: Benutzername
  - `passwort`: Passwort im Klartext
- **Rückgabe**: Boolean (True bei Erfolg)

### `authentifiziere_benutzer(name, passwort)`
Überprüft, ob der Benutzername und das Passwort korrekt sind.
- **Parameter**:
  - `name`: Benutzername
  - `passwort`: Passwort
- **Rückgabe**: Boolean (True bei erfolgreicher Authentifizierung)

### `lade_fahrzeuge(suchbegriff="")`
Lädt alle Fahrzeuge aus der Datenbank, optional gefiltert nach Suchbegriff.
- **Parameter**:
  - `suchbegriff`: Optionaler Suchbegriff
- **Rückgabe**: Liste von Fahrzeug-Objekten

### `speichere_fahrzeug(fahrzeug)`
Speichert ein neues Fahrzeug in der Datenbank.
- **Parameter**:
  - `fahrzeug`: Fahrzeug-Objekt
- **Rückgabe**: ID des neuen Fahrzeugs

### `aktualisiere_kilometerstand(fahrzeug_id, neuer_kilometerstand)`
Aktualisiert den Kilometerstand eines Fahrzeugs in der Datenbank.
- **Parameter**:
  - `fahrzeug_id`: ID des Fahrzeugs
  - `neuer_kilometerstand`: Neuer Kilometerstand
- **Rückgabe**: Boolean (True bei Erfolg)

### `aktualisiere_fahrzeug(fahrzeug)`
Aktualisiert ein bestehendes Fahrzeug in der Datenbank.
- **Parameter**:
  - `fahrzeug`: Fahrzeug-Objekt
- **Rückgabe**: Boolean (True bei Erfolg)

### `loesche_fahrzeug(fahrzeug_id)`
Löscht ein Fahrzeug aus der Datenbank basierend auf der ID.
- **Parameter**:
  - `fahrzeug_id`: ID des zu löschenden Fahrzeugs
- **Rückgabe**: Boolean (True bei Erfolg)

### `importiere_daten_json(parent=None)`
Importiert Benutzer- und Fahrzeugdaten aus einer JSON-Datei mit Transaktionssteuerung.
- **Parameter**:
  - `parent`: Optionales Eltern-Widget für Dialogfenster
- **Rückgabe**: Tupel (erfolgreich, Meldung)

### `exportiere_daten_json(fahrzeuge=None, parent=None)`
Exportiert Benutzer- und Fahrzeugdaten in eine JSON-Datei.
- **Parameter**:
  - `fahrzeuge`: Optional, Liste der zu exportierenden Fahrzeuge
  - `parent`: Optionales Eltern-Widget für Dialogfenster
- **Rückgabe**: Tupel (erfolgreich, Meldung)

## Formatierungsfunktionen

### `format_currency(value)`
Formatiert einen Wert als Währung mit Tausendertrennzeichen.
- **Parameter**:
  - `value`: Zu formatierender Wert
- **Rückgabe**: Formatierter String

### `format_number(value)`
Formatiert eine Zahl mit Tausendertrennzeichen.
- **Parameter**:
  - `value`: Zu formatierender Wert
- **Rückgabe**: Formatierter String

## Login-GUI

### Klasse `LoginApp`
Implementiert die Login-Benutzeroberfläche.

#### Attribute
- `root`: Tkinter-Root-Widget
- `colors`: Farbschema
- `failed_attempts`: Zähler für fehlgeschlagene Anmeldeversuche
- Diverse UI-Elemente

#### Methoden
- `__init__(root)`: Initialisiert die Login-Anwendung
- `zeige_fehler(nachricht)`: Zeigt eine Fehlermeldung an
- `login()`: Überprüft die Anmeldedaten und öffnet die Hauptanwendung
- `reset_login_attempts()`: Setzt den Zähler für fehlgeschlagene Anmeldeversuche zurück
- `oeffne_hauptanwendung(benutzername)`: Öffnet die Hauptanwendung

## Hauptanwendung-GUI

### Klasse `AutohausApp`
Implementiert die Hauptanwendung zur Fahrzeugverwaltung.

#### Attribute
- `root`: Tkinter-Root-Widget
- `benutzername`: Aktuell angemeldeter Benutzer
- `colors`: Farbschema
- `fahrzeuge`: Liste der Fahrzeuge
- `edit_mode`: Flag für Bearbeitungsmodus
- `current_edit_id`: ID des aktuell bearbeiteten Fahrzeugs
- Diverse UI-Elemente

#### Methoden
- `__init__(root, benutzername)`: Initialisiert die Hauptanwendung
- `setup_shortcuts()`: Einrichten von Tastatur-Shortcuts
- `focus_search(event=None)`: Setzt den Fokus auf das Suchfeld
- `create_search_bar()`: Erstellt eine Suchleiste zum Filtern der Fahrzeuge
- `on_search_change(*args)`: Reagiert auf Änderungen im Suchfeld
- `suche_fahrzeuge(suchbegriff)`: Führt die Suche nach Fahrzeugen durch
- `clear_search()`: Leert das Suchfeld
- `create_topbar()`: Erstellt die Top-Bar mit Benutzerinfo und Logout-Button
- `exportiere_daten_json(event=None)`: Exportiert Daten in eine JSON-Datei
- `lade_daten(suchbegriff="")`: Lädt die Fahrzeugdaten und aktualisiert die Anzeige
- `create_treeview()`: Erstellt die Treeview zur Anzeige der Fahrzeuge
- `sort_treeview(column, numeric=False, reverse=False)`: Sortiert die Treeview
- `create_summary_frame()`: Erstellt das Frame für die Zusammenfassung
- `create_button_frame()`: Erstellt das Frame für die Aktionsbuttons
- `get_hover_color(color)`: Berechnet eine dunklere Farbe für Hover-Effekte
- `create_input_frame()`: Erstellt das Frame für die Fahrzeugeingabe
- `ist_gueltige_farbe(farbe)`: Überprüft, ob eine Farbe in der Liste der gültigen Farben ist
- `normalisiere_farbe(farbe)`: Normalisiert die Schreibweise einer Farbe
- `zeige_farbliste()`: Zeigt eine Liste der verfügbaren Fahrzeugfarben an
- `waehle_farbe(farbe, fenster)`: Übernimmt die ausgewählte Farbe
- `create_input_field(parent, label_text, field_name, suffix="", tooltip="")`: Erstellt ein Eingabefeld
- `create_tooltip(widget, text)`: Erstellt einen Tooltip für ein Widget
- `on_entry_focus_in(entry)`: Ändert die Darstellung eines Entry-Widgets bei Fokus
- `on_entry_focus_out(entry)`: Stellt die ursprüngliche Darstellung wieder her
- `create_statusbar()`: Erstellt eine Statusleiste
- `update_status(message)`: Aktualisiert die Statusleiste mit einer Nachricht
- `on_tree_select(event)`: Event-Handler für die Auswahl in der Treeview
- `on_tree_doubleclick(event)`: Event-Handler für Doppelklick auf ein Fahrzeug
- `set_edit_mode(fahrzeug=None)`: Setzt den Bearbeitungsmodus
- `fahrzeug_bearbeiten()`: Beginnt die Bearbeitung eines ausgewählten Fahrzeugs
- `cancel_edit(event=None)`: Bricht die Bearbeitung eines Fahrzeugs ab
- `speichern_bearbeiten(event=None)`: Speichert die Änderungen an einem Fahrzeug
- `logout()`: Meldet den Benutzer ab
- `configure_styles()`: Konfiguriert die ttk-Styles
- `toggle_dark_mode()`: Wechselt zwischen Dark Mode und Light Mode
- `update_colors()`: Aktualisiert die Farben aller Elemente
- `validate_input()`: Validiert die Eingabefelder
- `fahrzeug_hinzufuegen(event=None)`: Fügt ein neues Fahrzeug hinzu
- `fahrzeug_loeschen(event=None)`: Löscht ein ausgewähltes Fahrzeug
- `probefahrt_eintragen()`: Ermöglicht das Eintragen einer Probefahrt
- `benutzer_hinzufuegen()`: Öffnet einen Dialog zum Hinzufügen eines Benutzers

## Hauptprogramm

Das Hauptprogramm (`if __name__ == "__main__"`) führt folgende Schritte aus:
1. Initialisiert die Datenbank
2. Migriert bestehende Passwörter zu sicheren Hashes
3. Startet die GUI
4. Enthält eine globale Ausnahmebehandlung für unerwartete Fehler
