# Autohaus-Verwaltungssystem

## Überblick
Das Autohaus-Verwaltungssystem ist eine Desktop-Anwendung, die entwickelt wurde, um die Fahrzeug- und Benutzerverwaltung in einem Autohaus zu erleichtern. Die Anwendung bietet eine benutzerfreundliche Oberfläche zur Verwaltung von Fahrzeugen, Benutzerkonten und Datenimporten/-exporten.

## Funktionen
- Benutzerauthentifizierung mit sicherer Passwortspeicherung
- Fahrzeugverwaltung (Hinzufügen, Bearbeiten, Löschen)
- Suche und Filterung von Fahrzeugen
- Datenimport und -export im JSON-Format
- Dunkler und heller Modus für die Benutzeroberfläche
- Detaillierte Protokollierung für Systemereignisse
- Responsive Benutzeroberfläche mit Tooltips und Statusmeldungen

## Technische Details
Die Anwendung verwendet folgende Technologien:
- Python für die Programmierlogik
- Tkinter für die grafische Benutzeroberfläche
- SQLite für die Datenbankfunktionalität
- JSON für Datenimport und -export
- Hashing (SHA-256) für sichere Passwortspeicherung

## Projektstruktur
- **Hauptklassen**:
  - `DbConnectionPool`: Implementierung eines Datenbankverbindungspools
  - `Benutzer`: Datenklasse für Benutzerinformationen
  - `Fahrzeug`: Datenklasse für Fahrzeuginformationen
  - `LoginApp`: GUI für den Login-Prozess
  - `AutohausApp`: Hauptanwendungs-GUI

## UML-Diagramme
Das Projekt enthält folgende UML-Diagramme (im PlantUML-Format):
- `klassendiagramm.puml`: Klassendiagramm des Projekts
- `sequenzdiagramm_login.puml`: Sequenzdiagramm für den Login-Prozess
- `aktivitaetsdiagramm.puml`: Aktivitätsdiagramm der Anwendungsfunktionen
- `zustandsdiagramm.puml`: Zustandsdiagramm der Anwendung

## Inbetriebnahme
1. Stellen Sie sicher, dass Python 3.6 oder höher installiert ist
2. Installieren Sie die erforderlichen Abhängigkeiten
3. Führen Sie `Final.py` aus, um die Anwendung zu starten

Bei erstmaligem Start wird automatisch eine Datenbank erstellt und die nötigen Tabellen werden angelegt.

## Hinweise zur Entwicklung
- Das Projekt verwendet moderne Python-Typisierung
- Die Passwortspeicherung erfolgt mit Salt und Hash für maximale Sicherheit
- Die Anwendung verfolgt ein Singleton-Pattern für die Datenbankverwaltung
