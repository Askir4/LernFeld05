import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog
import json
import os
import sqlite3
import hashlib
import datetime
import logging
from typing import List, Optional, Dict, Any, Tuple

# --- Logging-Konfiguration ---
def setup_logging():
    """Richtet das Logging-System ein"""
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    log_file = os.path.join(log_dir, f"autohaus_{datetime.datetime.now().strftime('%Y%m%d')}.log")
    
    # Logger konfigurieren
    logger = logging.getLogger("autohaus")
    logger.setLevel(logging.DEBUG)
    
    # File Handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    
    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Handler hinzufügen
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# Globaler Logger
logger = setup_logging()

# --- Datenbankverbindungs-Pool ---
class DbConnectionPool:
    """Eine einfache Implementierung eines Datenbankverbindungspools"""
    
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = DbConnectionPool()
        return cls._instance
    
    def __init__(self):
        self.connections = []
        self.max_connections = 5
    
    def get_connection(self):
        """Gibt eine Verbindung aus dem Pool zurück oder erstellt eine neue"""
        if not self.connections:
            return sqlite3.connect("autohaus.db")
        return self.connections.pop()
    
    def release_connection(self, connection):
        """Gibt eine Verbindung in den Pool zurück"""
        if len(self.connections) < self.max_connections:
            self.connections.append(connection)
        else:
            connection.close()

def get_db_connection():
    """Holt eine Verbindung aus dem Pool"""
    return DbConnectionPool.get_instance().get_connection()

def release_db_connection(connection):
    """Gibt eine Verbindung in den Pool zurück"""
    if connection:
        DbConnectionPool.get_instance().release_connection(connection)

# --- Datenklassen ---
class Benutzer:
    def __init__(self, name: str, passwort):
        self.name = name
        self.passwort = passwort
        
    def get_passwort_hex(self) -> str:
        """Gibt das Passwort als Hexadezimalstring zurück, wenn es binär ist"""
        if isinstance(self.passwort, bytes):
            return self.passwort.hex()
        return self.passwort


class Fahrzeug:
    def __init__(self, id: int, marke: str, modell: str, baujahr: int, wert: int, kilometerstand: int, farbe: str):
        self.id = id
        self.marke = marke
        self.modell = modell
        self.baujahr = baujahr
        self.wert = wert
        self.kilometerstand = kilometerstand
        self.farbe = farbe

    def beschreibung(self) -> str:
        return f"{self.marke} {self.modell} ({self.baujahr})"


# --- Passwort-Sicherheit ---
def hash_password(password, salt=None):
    """Erzeugt einen sicheren Hash mit Salt für ein Passwort"""
    if salt is None:
        salt = os.urandom(32)  # 32 Bytes für den Salt
    
    # Passwort mit Salt hashen (SHA-256)
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Anzahl der Iterationen
    )
    
    # Salt und Hash zusammen speichern
    return salt + pw_hash

def verify_password(stored_password, provided_password):
    """Überprüft ein Passwort gegen den gespeicherten Hash"""
    # Wenn es sich um Binärdaten handelt, direkt verwenden, sonst dekodieren
    if isinstance(stored_password, str):
        try:
            stored_password = bytes.fromhex(stored_password)
        except ValueError:
            # Wenn das fehlschlägt, handelt es sich um ein Legacy-Klartext-Passwort
            return stored_password == provided_password
    
    if len(stored_password) < 32:
        # Legacy-Passwort (Klartext)
        return stored_password.decode('utf-8') == provided_password
    
    salt = stored_password[:32]  # Die ersten 32 Bytes sind der Salt
    stored_hash = stored_password[32:]
    
    # Hash des eingegebenen Passworts mit dem gleichen Salt berechnen
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        salt,
        100000  # Gleiche Anzahl an Iterationen
    )
    
    # Vergleich der Hashes
    return pw_hash == stored_hash

def migriere_bestehende_passwoerter():
    """Migriert bestehende Klartext-Passwörter zu sicheren Hashes"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # Beginne eine Transaktion
        conn.execute("BEGIN TRANSACTION")
        
        # Hole alle Benutzer
        c.execute("SELECT id, name, passwort FROM benutzer")
        benutzer = c.fetchall()
        
        for benutzer_id, name, klartext_passwort in benutzer:
            # Prüfe, ob das Passwort bereits ein Hash sein könnte
            if len(klartext_passwort) > 64:  # Hashes sind typischerweise länger
                continue
                
            # Hashe das Klartext-Passwort
            hashed_pw = hash_password(klartext_passwort)
            
            # Aktualisiere den Benutzer
            c.execute("UPDATE benutzer SET passwort = ? WHERE id = ?", (hashed_pw, benutzer_id))
            logger.info(f"Passwort für Benutzer {name} (ID: {benutzer_id}) wurde zu einem sicheren Hash migriert")
        
        # Commit der Transaktion
        conn.commit()
        logger.info("Passwort-Migration abgeschlossen")
        
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Fehler bei der Passwort-Migration: {e}")
    finally:
        if conn:
            release_db_connection(conn)


# --- Datenbankfunktionen ---
def init_db():
    """Initialisiert die Datenbank und erstellt Tabellen, falls sie nicht existieren"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # Erstelle Tabellen mit Transaktionen
        conn.execute("BEGIN TRANSACTION")
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS benutzer (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                passwort BLOB
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS fahrzeuge (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                marke TEXT,
                modell TEXT,
                baujahr INTEGER,
                wert INTEGER,
                kilometerstand INTEGER,
                farbe TEXT
            )
        """)
        
        # Überprüfe die Spalten und füge neue hinzu, falls nötig
        c.execute("PRAGMA table_info(fahrzeuge);")
        spalten = c.fetchall()
        spalten_namen = [spalte[1] for spalte in spalten]
        
        if "kilometerstand" not in spalten_namen:
            c.execute("ALTER TABLE fahrzeuge ADD COLUMN kilometerstand INTEGER DEFAULT 0;")
        
        if "farbe" not in spalten_namen:
            c.execute("ALTER TABLE fahrzeuge ADD COLUMN farbe TEXT DEFAULT '';")

        # Erstelle einen Standard-Benutzer, falls noch keine Benutzer existieren
        c.execute("SELECT COUNT(*) FROM benutzer")
        if c.fetchone()[0] == 0:
            # Erzeuge ein zufälliges sicheres Passwort für den Admin-Benutzer
            default_passwort = "admin"  # In der Praxis wäre ein zufallsgeneriertes Passwort besser
            hashed_password = hash_password(default_passwort)
            c.execute("INSERT INTO benutzer (name, passwort) VALUES (?, ?)", ("admin", hashed_password))
            logger.info(f"Standard-Admin-Benutzer erstellt. Passwort: {default_passwort}")

        conn.commit()
        logger.info("Datenbank erfolgreich initialisiert")
        
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Fehler bei der Datenbankinitialisierung: {e}")
    finally:
        if conn:
            release_db_connection(conn)


def lade_benutzer() -> List[Benutzer]:
    """Lädt alle Benutzer aus der Datenbank"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT name, passwort FROM benutzer")
        benutzer_list = [Benutzer(name, pw) for name, pw in c.fetchall()]
        logger.debug(f"Benutzer geladen: {len(benutzer_list)}")
        return benutzer_list
    except sqlite3.Error as e:
        logger.error(f"Fehler beim Laden der Benutzer: {e}")
        return []
    finally:
        if conn:
            release_db_connection(conn)


def speichere_benutzer(name: str, passwort: str) -> bool:
    """Speichert einen neuen Benutzer mit gehashtem Passwort in der Datenbank"""
    if len(passwort) < 8:
        logger.warning(f"Passwort für Benutzer {name} zu kurz (< 8 Zeichen)")
        return False
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # Passwort hashen
        hashed_password = hash_password(passwort)
        
        c.execute("INSERT INTO benutzer (name, passwort) VALUES (?, ?)", (name, hashed_password))
        conn.commit()
        logger.info(f"Neuer Benutzer erstellt: {name}")
        return True
    except sqlite3.IntegrityError:
        logger.warning(f"Benutzer {name} existiert bereits")
        return False
    except sqlite3.Error as e:
        logger.error(f"Datenbankfehler beim Speichern des Benutzers: {e}")
        return False
    finally:
        if conn:
            release_db_connection(conn)


def authentifiziere_benutzer(name: str, passwort: str) -> bool:
    """Überprüft, ob der Benutzername und das Passwort korrekt sind"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT passwort FROM benutzer WHERE name = ?", (name,))
        ergebnis = c.fetchone()
        
        if ergebnis is None:
            logger.info(f"Anmeldeversuch mit nicht existierendem Benutzer: {name}")
            return False
        
        # Passwort-Verifikation
        is_valid = verify_password(ergebnis[0], passwort)
        if not is_valid:
            logger.warning(f"Fehlgeschlagener Anmeldeversuch für Benutzer: {name}")
        else:
            logger.info(f"Erfolgreiche Anmeldung für Benutzer: {name}")
        
        return is_valid
    except Exception as e:
        logger.error(f"Fehler bei der Benutzerauthentifizierung: {e}")
        return False
    finally:
        if conn:
            release_db_connection(conn)


def lade_fahrzeuge(suchbegriff: str = "") -> List[Fahrzeug]:
    """Lädt alle Fahrzeuge aus der Datenbank, optional gefiltert nach Suchbegriff"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        if suchbegriff:
            # Suche in verschiedenen Spalten
            suchbegriff = f"%{suchbegriff}%"
            c.execute("""
                SELECT id, marke, modell, baujahr, wert, kilometerstand, farbe FROM fahrzeuge
                WHERE marke LIKE ? OR modell LIKE ? OR baujahr LIKE ? OR farbe LIKE ?
                ORDER BY marke, modell
            """, (suchbegriff, suchbegriff, suchbegriff, suchbegriff))
        else:
            c.execute("""
                SELECT id, marke, modell, baujahr, wert, kilometerstand, farbe FROM fahrzeuge
                ORDER BY marke, modell
            """)
        
        daten = [Fahrzeug(id, m, mo, bj, w, km, f) for id, m, mo, bj, w, km, f in c.fetchall()]
        return daten
    except sqlite3.Error as e:
        logger.error(f"Fehler beim Laden der Fahrzeuge: {e}")
        return []
    finally:
        if conn:
            release_db_connection(conn)


def speichere_fahrzeug(fahrzeug: Fahrzeug) -> bool:
    """Speichert ein neues Fahrzeug in der Datenbank"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO fahrzeuge (marke, modell, baujahr, wert, kilometerstand, farbe) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (fahrzeug.marke, fahrzeug.modell, fahrzeug.baujahr, 
              fahrzeug.wert, fahrzeug.kilometerstand, fahrzeug.farbe))
        conn.commit()
        logger.info(f"Neues Fahrzeug gespeichert: {fahrzeug.beschreibung()}")
        return True
    except sqlite3.Error as e:
        logger.error(f"Fehler beim Speichern des Fahrzeugs: {e}")
        return False
    finally:
        if conn:
            release_db_connection(conn)


def aktualisiere_kilometerstand(fahrzeug_id: int, neuer_kilometerstand: int) -> bool:
    """Aktualisiert den Kilometerstand eines Fahrzeugs in der Datenbank"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE fahrzeuge SET kilometerstand = ? WHERE id = ?", (neuer_kilometerstand, fahrzeug_id))
        conn.commit()
        logger.info(f"Kilometerstand aktualisiert für Fahrzeug ID {fahrzeug_id}: {neuer_kilometerstand} km")
        return True
    except sqlite3.Error as e:
        logger.error(f"Fehler beim Aktualisieren des Kilometerstands: {e}")
        return False
    finally:
        if conn:
            release_db_connection(conn)


def aktualisiere_fahrzeug(fahrzeug: Fahrzeug) -> bool:
    """Aktualisiert ein bestehendes Fahrzeug in der Datenbank"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            UPDATE fahrzeuge 
            SET marke = ?, modell = ?, baujahr = ?, wert = ?, kilometerstand = ?, farbe = ?
            WHERE id = ?
        """, (fahrzeug.marke, fahrzeug.modell, fahrzeug.baujahr, 
              fahrzeug.wert, fahrzeug.kilometerstand, fahrzeug.farbe, fahrzeug.id))
        conn.commit()
        logger.info(f"Fahrzeug aktualisiert: ID {fahrzeug.id}, {fahrzeug.beschreibung()}")
        return True
    except sqlite3.Error as e:
        logger.error(f"Fehler beim Aktualisieren des Fahrzeugs: {e}")
        return False
    finally:
        if conn:
            release_db_connection(conn)


def loesche_fahrzeug(fahrzeug_id: int) -> bool:
    """Löscht ein Fahrzeug aus der Datenbank basierend auf der ID"""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM fahrzeuge WHERE id = ?", (fahrzeug_id,))
        conn.commit()
        logger.info(f"Fahrzeug gelöscht: ID {fahrzeug_id}")
        return True
    except sqlite3.Error as e:
        logger.error(f"Fehler beim Löschen des Fahrzeugs: {e}")
        return False
    finally:
        if conn:
            release_db_connection(conn)


def importiere_daten_json(parent=None) -> Tuple[bool, str]:
    """Importiert Benutzer- und Fahrzeugdaten aus einer JSON-Datei mit Transaktionssteuerung"""
    if not messagebox.askyesno("Importieren", "Möchten Sie Daten aus einer JSON-Datei importieren?"):
        return False, "Import abgebrochen."
    
    # Dateiauswahl-Dialog verwenden statt Texteingabe
    dateipfad = filedialog.askopenfilename(
        title="JSON-Datei auswählen",
        filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*.*")]
    )
    
    if not dateipfad or not os.path.exists(dateipfad):
        messagebox.showerror("Fehler", "Keine gültige Datei ausgewählt.")
        return False, "Keine gültige Datei ausgewählt."
    
    conn = None
    try:
        with open(dateipfad, "r", encoding="utf-8") as f:
            daten = json.load(f)
        
        # Validiere Datenstruktur
        if not isinstance(daten, dict) or not all(k in daten for k in ["benutzer", "fahrzeuge"]):
            messagebox.showerror("Fehler", "Die JSON-Datei hat nicht die erwartete Struktur.")
            return False, "Ungültiges Dateiformat."
            
        # Import-Statistik
        benutzer_count = 0
        fahrzeug_count = 0
        
        # Starte Transaktion
        conn = get_db_connection()
        c = conn.cursor()
        
        # Transaktion beginnen
        conn.execute("BEGIN TRANSACTION")
        
        # Benutzer-Daten importieren
        for eintrag in daten.get("benutzer", []):
            if "name" not in eintrag or "passwort" not in eintrag:
                continue  # Überspringe ungültige Einträge
                
            try:
                # Prüfe, ob Benutzer existiert
                c.execute("SELECT id FROM benutzer WHERE name = ?", (eintrag["name"],))
                if c.fetchone() is None:
                    # Füge Benutzer hinzu, wenn er noch nicht existiert
                    c.execute("INSERT INTO benutzer (name, passwort) VALUES (?, ?)", 
                             (eintrag["name"], eintrag["passwort"]))
                    benutzer_count += 1
            except sqlite3.Error as e:
                logger.error(f"Fehler beim Importieren des Benutzers {eintrag.get('name')}: {e}")
                
        # Fahrzeug-Daten importieren
        for eintrag in daten.get("fahrzeuge", []):
            try:
                # Validiere erforderliche Felder
                if not all(k in eintrag for k in ["marke", "modell", "baujahr", "wert"]):
                    logger.warning(f"Überspringe ungültigen Fahrzeug-Eintrag: {eintrag}")
                    continue
                    
                # Nutze Standardwerte für optionale Felder
                kilometerstand = eintrag.get("kilometerstand", 0)
                farbe = eintrag.get("farbe", "")
                
                # Validiere Datentypen
                try:
                    baujahr = int(eintrag["baujahr"])
                    wert = int(eintrag["wert"])
                    kilometerstand = int(kilometerstand)
                except (ValueError, TypeError):
                    logger.warning(f"Ungültige Zahlenwerte beim Fahrzeug: {eintrag}")
                    continue
                
                c.execute("""
                    INSERT INTO fahrzeuge (marke, modell, baujahr, wert, kilometerstand, farbe) 
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (str(eintrag["marke"]), str(eintrag["modell"]), baujahr, 
                     wert, kilometerstand, str(farbe)))
                fahrzeug_count += 1
            except sqlite3.Error as e:
                logger.error(f"Fehler beim Importieren eines Fahrzeugs: {e}")
        
        # Transaktion abschließen
        conn.commit()
        
        erfolgstext = f"Daten erfolgreich importiert:\n\n{benutzer_count} Benutzer\n{fahrzeug_count} Fahrzeuge"
        messagebox.showinfo("Import erfolgreich", erfolgstext)
        
        # Refresh der Anzeige
        if parent and hasattr(parent, 'lade_daten'):
            parent.lade_daten()
            
        logger.info(f"Datenimport erfolgreich: {benutzer_count} Benutzer, {fahrzeug_count} Fahrzeuge")
        return True, erfolgstext
            
    except json.JSONDecodeError:
        messagebox.showerror("Fehler", "Die Datei enthält kein gültiges JSON-Format.")
        return False, "Ungültiges JSON-Format."
    except Exception as e:
        if conn:
            conn.rollback()  # Rollback bei Fehler
        fehlermeldung = f"Fehler beim Importieren der Daten: {str(e)}"
        messagebox.showerror("Fehler", fehlermeldung)
        logger.error(fehlermeldung)
        return False, fehlermeldung
    finally:
        if conn:
            release_db_connection(conn)


def exportiere_daten_json(fahrzeuge=None, parent=None) -> Tuple[bool, str]:
    """Exportiert Benutzer- und Fahrzeugdaten in eine JSON-Datei"""
    if not messagebox.askyesno("Exportieren", "Möchten Sie alle Daten in eine JSON-Datei exportieren?"):
        return False, "Export abgebrochen."
    
    # Dateiauswahl-Dialog verwenden
    dateipfad = filedialog.asksaveasfilename(
        title="JSON-Datei speichern",
        defaultextension=".json",
        filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*.*")]
    )
    
    if not dateipfad:
        return False, "Kein Speicherziel ausgewählt."
        
    try:
        # Daten sammeln
        benutzer_daten = lade_benutzer()
        fahrzeug_daten = fahrzeuge if fahrzeuge is not None else lade_fahrzeuge()
        
        # In JSON-Format konvertieren
        export_daten = {
            "benutzer": [
                {
                    "name": b.name, 
                    "passwort": b.get_passwort_hex()
                } for b in benutzer_daten
            ],
            "fahrzeuge": [
                {
                    "marke": f.marke,
                    "modell": f.modell,
                    "baujahr": f.baujahr,
                    "wert": f.wert,
                    "kilometerstand": f.kilometerstand,
                    "farbe": f.farbe
                } for f in fahrzeug_daten
            ]
        }
        
        # In Datei schreiben
        with open(dateipfad, "w", encoding="utf-8") as f:
            json.dump(export_daten, f, indent=4, ensure_ascii=False)
            
        erfolgstext = f"Daten erfolgreich exportiert:\n\n{len(benutzer_daten)} Benutzer\n{len(fahrzeug_daten)} Fahrzeuge"
        messagebox.showinfo("Export erfolgreich", erfolgstext)
        
        # Statusmeldung, wenn Parent-Objekt vorhanden
        if parent and hasattr(parent, 'update_status'):
            parent.update_status(f"Daten wurden erfolgreich nach {os.path.basename(dateipfad)} exportiert.")
            
        logger.info(f"Datenexport erfolgreich: {len(benutzer_daten)} Benutzer, {len(fahrzeug_daten)} Fahrzeuge nach {dateipfad}")
        return True, erfolgstext
            
    except Exception as e:
        fehlermeldung = f"Fehler beim Exportieren der Daten: {str(e)}"
        messagebox.showerror("Fehler", fehlermeldung)
        logger.error(fehlermeldung, exc_info=True)
        return False, fehlermeldung


def format_currency(value):
    """Formatiert einen Wert als Währung mit Tausendertrennzeichen"""
    try:
        return f"{int(value):,} €".replace(",", ".")
    except (ValueError, TypeError):
        return f"{value} €"


def format_number(value):
    """Formatiert eine Zahl mit Tausendertrennzeichen"""
    try:
        return f"{int(value):,}".replace(",", ".")
    except (ValueError, TypeError):
        return str(value)


# --- Login GUI ---
class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Autohaus Login")
        self.root.geometry("500x600")
        self.root.resizable(False, False)
        
        # Farbschema definieren
        self.colors = {
            "bg": "#f9f9f9",
            "panel_bg": "#ffffff",
            "fg": "#333333",
            "accent": "#4682B4",  # Blauton
            "accent_dark": "#3a7ebf",
            "button_bg": "#4682B4",
            "button_fg": "white",
            "button_hover": "#3a7ebf",
            "error": "#e74c3c",
            "success": "#2ecc71",
            "border": "#e0e0e0",
            "input_bg": "white",
            "hint": "#999999"
        }
        
        # Anmeldeversuche zählen (für mögliche Sicherheitsfunktionen)
        self.login_attempts = 0
        self.max_login_attempts = 5
        
        # Hintergrund für das gesamte Fenster
        self.root.configure(bg=self.colors["bg"])
        
        # Login-Panel
        self.login_panel = tk.Frame(root, bg=self.colors["panel_bg"], bd=1, relief="solid")
        self.login_panel.place(relx=0.5, rely=0.5, anchor="center", width=400, height=420)
        
        # Auto-Icon als Text-Symbol
        self.icon_label = tk.Label(
            self.login_panel, 
            text="🚗", 
            font=("Arial", 72), 
            bg=self.colors["panel_bg"],
            fg=self.colors["accent"]
        )
        self.icon_label.pack(pady=(40, 10))
        
        # Titel
        self.titel_label = tk.Label(
            self.login_panel, 
            text="Autohaus Verwaltung", 
            font=("Arial", 24, "bold"), 
            bg=self.colors["panel_bg"],
            fg=self.colors["fg"]
        )
        self.titel_label.pack(pady=(0, 30))
        
        # Fehlertext (zunächst ausgeblendet)
        self.error_label = tk.Label(
            self.login_panel,
            text="",
            font=("Arial", 10),
            bg=self.colors["panel_bg"],
            fg=self.colors["error"]
        )
        
        # Eingabebereich
        self.input_frame = tk.Frame(self.login_panel, bg=self.colors["panel_bg"], bd=0)
        self.input_frame.pack(fill="x", padx=40)
        
        # Benutzername
        self.benutzer_label = tk.Label(
            self.input_frame, 
            text="Benutzername", 
            bg=self.colors["panel_bg"], 
            fg=self.colors["fg"],
            font=("Arial", 12),
            anchor="w"
        )
        self.benutzer_label.pack(anchor="w", pady=(0, 5))
        
        self.benutzer_entry = tk.Entry(
            self.input_frame, 
            font=("Arial", 14), 
            width=25, 
            bd=2,
            relief="groove",
            bg=self.colors["input_bg"],
            fg=self.colors["fg"],
            insertbackground=self.colors["fg"]
        )
        self.benutzer_entry.pack(fill="x", pady=(0, 15))
        
        # Passwort
        self.passwort_label = tk.Label(
            self.input_frame, 
            text="Passwort", 
            bg=self.colors["panel_bg"], 
            fg=self.colors["fg"],
            font=("Arial", 12),
            anchor="w"
        )
        self.passwort_label.pack(anchor="w", pady=(0, 5))
        
        self.passwort_entry = tk.Entry(
            self.input_frame, 
            font=("Arial", 14), 
            width=25, 
            show="•", 
            bd=2,
            relief="groove",
            bg=self.colors["input_bg"],
            fg=self.colors["fg"],
            insertbackground=self.colors["fg"]
        )
        self.passwort_entry.pack(fill="x", pady=(0, 25))
        
        # Login Button
        self.login_button = tk.Button(
            self.input_frame, 
            text="Anmelden", 
            command=self.login, 
            bg=self.colors["button_bg"], 
            fg=self.colors["button_fg"], 
            font=("Arial", 14, "bold"),
            relief="flat",
            bd=0,
            padx=20,
            pady=8,
            cursor="hand2",
            activebackground=self.colors["button_hover"],
            activeforeground=self.colors["button_fg"]
        )
        self.login_button.pack(pady=10)
        
        # Hover-Effekte für den Button
        self.login_button.bind("<Enter>", lambda e: self.login_button.config(bg=self.colors["button_hover"]))
        self.login_button.bind("<Leave>", lambda e: self.login_button.config(bg=self.colors["button_bg"]))
        
        # Bindet die Enter-Taste für Login
        self.benutzer_entry.bind("<Return>", lambda event: self.passwort_entry.focus())
        self.passwort_entry.bind("<Return>", lambda event: self.login())
        
        # Setze den Fokus auf das Benutzernamen-Feld
        self.benutzer_entry.focus()
        
        # Hinweis auf Standard-Benutzer beim ersten Start
        self.info_label = tk.Label(
            root, 
            text="Wir sind die Borg", 
            bg=self.colors["bg"], 
            fg=self.colors["hint"],
            font=("Arial", 10)
        )
        self.info_label.place(relx=0.5, rely=0.92, anchor="center")
        
        # Version anzeigen
        self.version_label = tk.Label(
            root, 
            text="Version 2.0.0", 
            bg=self.colors["bg"], 
            fg=self.colors["hint"],
            font=("Arial", 8)
        )
        self.version_label.place(relx=0.95, rely=0.97, anchor="se")
    
    def zeige_fehler(self, nachricht):
        """Zeigt eine Fehlermeldung an"""
        self.error_label.config(text=nachricht)
        self.error_label.pack(pady=(0, 15))
        
        # Schüttel-Animation für den Panel
        original_x = self.login_panel.winfo_x()
        for i in range(6):
            offset = 5 if i % 2 == 0 else -5
            self.login_panel.place_configure(x=original_x + offset)
            self.login_panel.update()
            self.login_panel.after(50)
        self.login_panel.place_configure(x=original_x)
        
        # Fehler nach 3 Sekunden ausblenden
        self.root.after(3000, lambda: self.error_label.pack_forget())

    def login(self):
        """Überprüft die Anmeldedaten und öffnet die Hauptanwendung, wenn sie korrekt sind"""
        benutzername = self.benutzer_entry.get().strip()
        passwort = self.passwort_entry.get().strip()
        
        if not benutzername or not passwort:
            self.zeige_fehler("Bitte geben Sie Benutzername und Passwort ein.")
            return
        
        # Prüfen, ob zu viele fehlgeschlagene Anmeldeversuche vorliegen
        if self.login_attempts >= self.max_login_attempts:
            self.zeige_fehler(f"Zu viele fehlgeschlagene Anmeldeversuche. Bitte warten Sie 30 Sekunden.")
            self.login_button.config(state="disabled")
            self.root.after(30000, self.reset_login_attempts)  # Nach 30 Sekunden zurücksetzen
            return
        
        if authentifiziere_benutzer(benutzername, passwort):
            self.root.withdraw()  # Verstecke das Login-Fenster
            self.oeffne_hauptanwendung(benutzername)
        else:
            self.login_attempts += 1
            verbleibend = self.max_login_attempts - self.login_attempts
            self.zeige_fehler(f"Ungültiger Benutzername oder Passwort. Noch {verbleibend} Versuche übrig.")
            self.passwort_entry.delete(0, tk.END)
            self.passwort_entry.focus()
    
    def reset_login_attempts(self):
        """Setzt den Zähler für fehlgeschlagene Anmeldeversuche zurück"""
        self.login_attempts = 0
        self.login_button.config(state="normal")
        self.zeige_fehler("Sie können sich jetzt wieder anmelden.")

    def oeffne_hauptanwendung(self, benutzername):
        """Öffnet die Hauptanwendung"""
        hauptfenster = tk.Toplevel(self.root)
        hauptfenster.title("Autohaus Verwaltung")
        
        # Wenn das Hauptfenster geschlossen wird, wird die gesamte Anwendung beendet
        hauptfenster.protocol("WM_DELETE_WINDOW", self.root.destroy)
        
        app = AutohausApp(hauptfenster, benutzername)


# --- GUI Hauptanwendung ---
class AutohausApp:
    def __init__(self, root, benutzername):
        self.root = root
        self.root.title(f"Autohaus Verwaltung - Angemeldet als: {benutzername}")
        self.root.geometry("1200x1000")  # Größeres Fenster für besseres Layout
        self.root.minsize(800, 600)     # Minimale Fenstergröße
        
        # Speichere den Benutzernamen
        self.benutzername = benutzername
        
        # Status für Bearbeitungsmodus
        self.bearbeiten_modus = False
        self.aktuelles_fahrzeug = None
        
        # Liste gültiger Autofarben
        self.gueltige_farben = [
            "schwarz", "silber", "grau", "weiß", "rot", "blau", "grün", "gelb", 
            "braun", "beige", "orange", "lila", "violett", "gold", "bronze", 
            "bordeaux", "türkis", "magenta", "champagner", "anthrazit",
            "schwarz metallic", "silber metallic", "grau metallic", "blau metallic",
            "rot metallic", "grün metallic", "braun metallic", "beige metallic",
            "perlweiß", "perlschwarz", "perlblau", "nachtblau", "dunkelrot", 
            "hellgrün", "dunkelgrün", "hellblau", "navyblau", "kirschrot", 
            "weinrot", "racing grün", "racing rot", "racing blau", "carbon",
            "matt schwarz", "matt grau", "matt weiß", "matt blau", "matt rot"
        ]
        
        # Farbschema definieren
        self.dark_mode = False
        self.light_colors = {
            "bg": "#f5f5f5",
            "panel_bg": "#ffffff",
            "button_bg": "#4682B4",
            "button_fg": "white",
            "delete_button_bg": "#FF6347",
            "add_button_bg": "#3CB371",
            "toggle_button_bg": "#FFD700",
            "probefahrt_button_bg": "#FF8C00",  # Orange für Probefahrt-Button
            "text_color": "#333333",
            "secondary_text": "#666666",
            "accent_color": "#3a7ebf",
            "border_color": "#dddddd",
            "hover_color": "#3a7ebf",
            "input_bg": "white",
            "highlight_bg": "#f0f7ff",
            "statusbar_bg": "#e0e0e0",
            "statusbar_fg": "#555555",
            "search_bg": "#f9f9f9",
            "tooltip_bg": "#fffbe6",
            "tooltip_fg": "#333333",
            "header_bg": "#e9e9e9",
            "row_alt_bg": "#f9f9f9",
            "error_color": "#ff6b6b"
        }
        self.dark_colors = {
            "bg": "#2c2f38",
            "panel_bg": "#383c44",
            "button_bg": "#3a7ebf",
            "button_fg": "white",
            "delete_button_bg": "#c74634",
            "add_button_bg": "#2da65b",
            "toggle_button_bg": "#c8a900",
            "probefahrt_button_bg": "#d17100",  # Dunkleres Orange für Probefahrt-Button im Dark Mode
            "text_color": "#e0e0e0",
            "secondary_text": "#aaaaaa",
            "accent_color": "#5a97d1",
            "border_color": "#444a57",
            "hover_color": "#5a97d1",
            "input_bg": "#454952",
            "highlight_bg": "#364256",
            "statusbar_bg": "#252830",
            "statusbar_fg": "#bbbbbb",
            "search_bg": "#323642",
            "tooltip_bg": "#4a4a3f",
            "tooltip_fg": "#dddddd",
            "header_bg": "#323642",
            "row_alt_bg": "#32353e",
            "error_color": "#ff8a8a"
        }
        self.colors = self.light_colors

        # Input-Felder als Dictionary, um später leichter darauf zugreifen zu können
        self.input_fields = {}
        
        # Liste für Fahrzeuge
        self.fahrzeuge = []
        
        # Letzter Suchbegriff
        self.letzter_suchbegriff = ""

        # Gesamtes Layout in einem Container-Frame
        self.container = tk.Frame(root, bg=self.colors["bg"])
        self.container.pack(fill="both", expand=True, padx=0, pady=0)
        
        # --- TopBar mit Benutzerinfo ---
        self.create_topbar()
        
        # --- Hauptbereich in zwei Spalten teilen ---
        self.content_frame = tk.Frame(self.container, bg=self.colors["bg"])
        self.content_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Linke Spalte für Fahrzeugliste
        self.left_column = tk.Frame(self.content_frame, bg=self.colors["bg"])
        self.left_column.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        # Rechte Spalte für Eingabefelder
        self.right_column = tk.Frame(self.content_frame, bg=self.colors["bg"])
        self.right_column.pack(side="right", fill="both", expand=False, padx=(10, 0), pady=10, ipadx=10, ipady=10)

        # --- Suchleiste erstellen ---
        self.create_search_bar()
        
        # --- Baumansicht für Fahrzeuge ---
        self.create_treeview()
        
        # -- Gesamtwert und Anzahl Label ---
        self.create_summary_frame()
        
        # --- Buttonbereich ---
        self.create_button_frame()
        
        # --- Fahrzeug Eingabebereich ---
        self.create_input_frame()
        
        # --- Statusleiste ---
        self.create_statusbar()
        
        # --- Style-Konfiguration für ttk-Elemente ---
        self.style = ttk.Style()
        self.configure_styles()
        
        # --- Tastatur-Shortcuts ---
        self.setup_shortcuts()
        
        # --- Daten laden ---
        self.lade_daten()
        
        # Zeige Willkommensnachricht
        self.update_status(f"Willkommen, {self.benutzername}! Sie haben {len(self.fahrzeuge)} Fahrzeuge im Bestand.")

    def setup_shortcuts(self):
        """Einrichten von Tastatur-Shortcuts"""
        self.root.bind("<Control-n>", lambda e: self.fahrzeug_hinzufuegen())  # Strg+N: Neues Fahrzeug
        self.root.bind("<Delete>", lambda e: self.fahrzeug_loeschen())  # Entf: Fahrzeug löschen
        self.root.bind("<F5>", lambda e: self.lade_daten())  # F5: Daten neu laden
        self.root.bind("<Control-s>", lambda e: self.speichern_bearbeiten())  # Strg+S: Speichern
        self.root.bind("<Control-f>", lambda e: self.focus_search())  # Strg+F: Suchen
        self.root.bind("<Escape>", lambda e: self.cancel_edit())  # Escape: Bearbeiten abbrechen
        self.root.bind("<Control-e>", lambda e: self.exportiere_daten_json())  # Strg+E: Exportieren

    def focus_search(self, event=None):
        """Setzt den Fokus auf das Suchfeld"""
        if hasattr(self, 'search_entry'):
            self.search_entry.focus_set()

    def create_search_bar(self):
        """Erstellt eine Suchleiste zum Filtern der Fahrzeuge"""
        self.search_frame = tk.Frame(self.left_column, bg=self.colors["panel_bg"], bd=1, relief="groove", padx=10, pady=5)
        self.search_frame.pack(fill="x", pady=(0, 10))
        
        # Suchsymbol
        self.search_icon = tk.Label(
            self.search_frame,
            text="🔍",
            font=("Arial", 12),
            bg=self.colors["panel_bg"],
            fg=self.colors["text_color"]
        )
        self.search_icon.pack(side="left", padx=(0, 5))
        
        # Suchtextfeld
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.on_search_change)
        
        self.search_entry = tk.Entry(
            self.search_frame, 
            textvariable=self.search_var,
            font=("Arial", 11),
            bg=self.colors["search_bg"],
            fg=self.colors["text_color"],
            relief="flat",
            bd=0,
            width=30,
            insertbackground=self.colors["text_color"]
        )
        self.search_entry.pack(side="left", fill="x", expand=True, ipady=5)
        
        # Löschen-Button
        self.clear_button = tk.Button(
            self.search_frame,
            text="✕",
            font=("Arial", 10),
            bg=self.colors["panel_bg"],
            fg=self.colors["text_color"],
            relief="flat",
            bd=0,
            cursor="hand2",
            command=self.clear_search
        )
        self.clear_button.pack(side="right", padx=5)

    def on_search_change(self, *args):
        """Reagiert auf Änderungen im Suchfeld"""
        suchbegriff = self.search_var.get().strip()
        
        # Verzögerte Suche (300ms nach letzter Eingabe)
        if hasattr(self, '_search_after_id'):
            self.root.after_cancel(self._search_after_id)
        
        self._search_after_id = self.root.after(300, lambda: self.suche_fahrzeuge(suchbegriff))

    def suche_fahrzeuge(self, suchbegriff):
        """Führt die Suche nach Fahrzeugen durch"""
        if suchbegriff != self.letzter_suchbegriff:
            self.letzter_suchbegriff = suchbegriff
            self.lade_daten(suchbegriff)
            
            # Status aktualisieren
            if suchbegriff:
                self.update_status(f"Suche nach '{suchbegriff}': {len(self.fahrzeuge)} Ergebnisse gefunden.")
            else:
                self.update_status(f"{len(self.fahrzeuge)} Fahrzeuge im Bestand.")

    def clear_search(self):
        """Leert das Suchfeld"""
        self.search_var.set("")
        self.search_entry.focus_set()

    def create_topbar(self):
        """Erstellt die Top-Bar mit Benutzerinfo und Logout-Button"""
        self.topbar = tk.Frame(self.container, bg=self.colors["panel_bg"], height=60, relief="ridge", bd=1)
        self.topbar.pack(fill="x", pady=(0, 20))
        
        # Logo/Icon
        self.logo_label = tk.Label(
            self.topbar, 
            text="🚗", 
            font=("Arial", 24), 
            bg=self.colors["panel_bg"],
            fg=self.colors["accent_color"]
        )
        self.logo_label.pack(side="left", padx=(20, 5), pady=10)
        
        # Titel
        self.app_title = tk.Label(
            self.topbar, 
            text="Autohaus Verwaltung", 
            font=("Arial", 16, "bold"), 
            bg=self.colors["panel_bg"],
            fg=self.colors["text_color"]
        )
        self.app_title.pack(side="left", padx=5, pady=10)
        
        # Dark/Light Mode Button auf der rechten Seite
        self.theme_button = tk.Button(
            self.topbar, 
            text="🌙" if not self.dark_mode else "☀️", 
            command=self.toggle_dark_mode, 
            bg=self.colors["toggle_button_bg"], 
            fg=self.colors["text_color"], 
            font=("Arial", 12),
            width=4,
            height=1,
            bd=0,
            relief="flat",
            cursor="hand2"
        )
        self.theme_button.pack(side="right", padx=20, pady=10)
        
        # Export-Button
        self.export_button = tk.Button(
            self.topbar, 
            text="Exportieren", 
            command=self.exportiere_daten_json, 
            bg=self.colors["button_bg"], 
            fg=self.colors["button_fg"], 
            font=("Arial", 10),
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=8
        )
        self.export_button.pack(side="right", padx=5, pady=10)
        
        # Abmelden-Button
        self.logout_button = tk.Button(
            self.topbar, 
            text="Abmelden", 
            command=self.logout, 
            bg=self.colors["button_bg"], 
            fg=self.colors["button_fg"], 
            font=("Arial", 10),
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=8
        )
        self.logout_button.pack(side="right", padx=5, pady=10)
        
        # Benutzerinfo
        self.benutzerinfo_label = tk.Label(
            self.topbar, 
            text=f"Angemeldet als: {self.benutzername}", 
            bg=self.colors["panel_bg"], 
            fg=self.colors["text_color"],
            font=("Arial", 10)
        )
        self.benutzerinfo_label.pack(side="right", padx=10, pady=10)
        
        # Hover-Effekte
        self.theme_button.bind("<Enter>", lambda e: self.theme_button.config(bg=self.colors["hover_color"]))
        self.theme_button.bind("<Leave>", lambda e: self.theme_button.config(bg=self.colors["toggle_button_bg"]))
        
        self.export_button.bind("<Enter>", lambda e: self.export_button.config(bg=self.colors["hover_color"]))
        self.export_button.bind("<Leave>", lambda e: self.export_button.config(bg=self.colors["button_bg"]))
        
        self.logout_button.bind("<Enter>", lambda e: self.logout_button.config(bg=self.colors["hover_color"]))
        self.logout_button.bind("<Leave>", lambda e: self.logout_button.config(bg=self.colors["button_bg"]))

    def exportiere_daten_json(self, event=None):
        """Exportiert Benutzer- und Fahrzeugdaten in eine JSON-Datei"""
        success, message = exportiere_daten_json(self.fahrzeuge, self)
        if success:
            self.update_status(message)

    def lade_daten(self, suchbegriff=""):
        """Lädt die Fahrzeugdaten aus der Datenbank und aktualisiert die Anzeige"""
        # Fahrzeuge laden
        self.fahrzeuge = lade_fahrzeuge(suchbegriff)
        
        # TreeView leeren
        for i in self.tree.get_children():
            self.tree.delete(i)
            
        # Daten einfügen
        gesamtwert = 0
        for fahrzeug in self.fahrzeuge:
            self.tree.insert("", "end", values=(
                fahrzeug.beschreibung(),
                format_currency(fahrzeug.wert),
                format_number(fahrzeug.kilometerstand),
                fahrzeug.farbe
            ))
            gesamtwert += fahrzeug.wert
            
        # Zusammenfassung aktualisieren
        self.gesamtwert_label.config(text=f"Gesamtwert: {format_currency(gesamtwert)}")
        self.anzahl_label.config(text=f"Anzahl Fahrzeuge: {len(self.fahrzeuge)}")
        
        # Wenn Bearbeitungsmodus aktiv ist, diesen beenden
        if self.bearbeiten_modus:
            self.set_edit_mode(None)

    def create_treeview(self):
        """Erstellt die Treeview zur Anzeige der Fahrzeuge"""
        # Panel für Treeview
        self.tree_panel = tk.Frame(
            self.left_column, 
            bg=self.colors["panel_bg"], 
            bd=1, 
            relief="groove",
            padx=10,
            pady=10
        )
        self.tree_panel.pack(fill="both", expand=True, pady=(0, 10))
        
        # Label für die Überschrift
        self.tree_header = tk.Label(
            self.tree_panel,
            text="Fahrzeugbestand",
            font=("Arial", 14, "bold"),
            bg=self.colors["panel_bg"],
            fg=self.colors["text_color"]
        )
        self.tree_header.pack(anchor="w", pady=(0, 10))
        
        # Container für die Treeview und Scrollbar
        tree_container = tk.Frame(self.tree_panel, bg=self.colors["panel_bg"])
        tree_container.pack(fill="both", expand=True)
        
        # Spalten definieren
        columns = ("Beschreibung", "Wert", "KM", "Farbe")
        self.tree = ttk.Treeview(tree_container, columns=columns, show="headings", height=15)
        
        # Spaltenüberschriften und -breiten mit detaillierteren Beschreibungen
        self.tree.heading("Beschreibung", text="Fahrzeug-Beschreibung", command=lambda: self.sort_treeview("Beschreibung"))
        self.tree.heading("Wert", text="Fahrzeugwert (€)", command=lambda: self.sort_treeview("Wert", numeric=True))
        self.tree.heading("KM", text="Kilometerstand (km)", command=lambda: self.sort_treeview("KM", numeric=True))
        self.tree.heading("Farbe", text="Fahrzeugfarbe", command=lambda: self.sort_treeview("Farbe"))
        
        self.tree.column("Beschreibung", width=300, anchor="w")
        self.tree.column("Wert", width=120, anchor="e")
        self.tree.column("KM", width=120, anchor="e")
        self.tree.column("Farbe", width=120, anchor="center")
        
        # Scrollbar hinzufügen
        self.scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.tree.pack(fill="both", expand=True)
        
        # Event-Binding für Zeilenauswahl und Doppelklick
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<Double-1>", self.on_tree_doubleclick)

    def sort_treeview(self, column, numeric=False, reverse=False):
        """Sortiert die Treeview nach einer bestimmten Spalte"""
        # Aktuelle Sortierung überprüfen
        if hasattr(self, 'sort_column') and self.sort_column == column:
            reverse = not self.sort_reverse
        
        # Sortierparameter speichern
        self.sort_column = column
        self.sort_reverse = reverse
        
        # Daten holen und sortieren
        data = []
        for item_id in self.tree.get_children():
            item_values = self.tree.item(item_id, 'values')
            # Speichert Werte und Original-Item-ID
            data.append((item_values, item_id))
        
        # Sortierindex bestimmen
        col_idx = {
            "Beschreibung": 0,
            "Wert": 1,
            "KM": 2,
            "Farbe": 3
        }[column]
        
        # Sortieren
        if numeric:
            # Numerische Sortierung (entfernt Tausendertrennzeichen und Währungssymbole)
            data.sort(key=lambda x: int(x[0][col_idx].replace(".", "").replace(",", "").replace(" €", "")), 
                     reverse=reverse)
        else:
            # Alphabetische Sortierung
            data.sort(key=lambda x: x[0][col_idx], reverse=reverse)
        
        # Treeview neu aufbauen
        for idx, item in enumerate(data):
            self.tree.move(item[1], '', idx)
            
        # Überschriften aktualisieren
        for col in ["Beschreibung", "Wert", "KM", "Farbe"]:
            if col == column:
                direction = " ▼" if reverse else " ▲"
                self.tree.heading(col, text=f"{col}{' (€)' if col == 'Wert' else ''}{direction}", 
                                command=lambda c=col, n=(col in ["Wert", "KM"]): self.sort_treeview(c, numeric=n))
            else:
                # Ursprünglichen Text wiederherstellen
                original_text = col
                if col == "Wert":
                    original_text += " (€)"
                elif col == "KM":
                    original_text = "Kilometerstand"
                self.tree.heading(col, text=original_text, 
                                command=lambda c=col, n=(col in ["Wert", "KM"]): self.sort_treeview(c, numeric=n))

    def create_summary_frame(self):
        """Erstellt das Frame für die Zusammenfassung (Gesamtwert und Anzahl der Fahrzeuge)"""
        self.summary_frame = tk.Frame(self.left_column, bg=self.colors["panel_bg"], bd=1, relief="groove", padx=15, pady=15)
        self.summary_frame.pack(fill="x", pady=(0, 10))
        
        # Gesamtwert-Label
        self.gesamtwert_label = tk.Label(
            self.summary_frame, 
            text="Gesamtwert: 0 €", 
            bg=self.colors["panel_bg"], 
            fg=self.colors["text_color"],
            font=("Arial", 12, "bold")
        )
        self.gesamtwert_label.pack(side="left")
        
        # Anzahl-Label
        self.anzahl_label = tk.Label(
            self.summary_frame, 
            text="Anzahl Fahrzeuge: 0", 
            bg=self.colors["panel_bg"], 
            fg=self.colors["text_color"],
            font=("Arial", 12)
        )
        self.anzahl_label.pack(side="right")

    def create_button_frame(self):
        """Erstellt das Frame für die Aktionsbuttons"""
        self.btn_panel = tk.Frame(self.left_column, bg=self.colors["panel_bg"], bd=1, relief="groove", padx=15, pady=15)
        self.btn_panel.pack(fill="x")
        
        # Buttons erstellen
        buttons = [
            ("Fahrzeug bearbeiten", self.fahrzeug_bearbeiten, self.colors["button_bg"], "Strg+E"),
            ("Fahrzeug löschen", self.fahrzeug_loeschen, self.colors["delete_button_bg"], "Entf"),
            ("Probefahrt eintragen", self.probefahrt_eintragen, self.colors["probefahrt_button_bg"], ""),
            ("Benutzer hinzufügen", self.benutzer_hinzufuegen, self.colors["button_bg"], ""),
            ("Daten importieren", lambda: importiere_daten_json(self), self.colors["button_bg"], "")
        ]
        
        # Button-Container für bessere Anordnung
        self.button_container = tk.Frame(self.btn_panel, bg=self.colors["panel_bg"])
        self.button_container.pack(fill="x")
        
        # Konfigurieren der Spalten im Grid-Layout, um gleiche Breitenverteilung zu gewährleisten
        self.button_container.columnconfigure(0, weight=1)
        self.button_container.columnconfigure(1, weight=1)
        
        # Buttons in das Layout einfügen
        for i, (text, command, bg, shortcut) in enumerate(buttons):
            btn = tk.Button(
                self.button_container, 
                text=text, 
                command=command, 
                width=18,  # Etwas schmaler, um in beide Spalten zu passen
                bg=bg, 
                fg=self.colors["button_fg"], 
                relief="flat",
                bd=0,
                font=("Arial", 10, "bold"),
                cursor="hand2",
                padx=5,  # Reduzieren des horizontalen Polsters
                pady=5
            )
            btn.grid(row=i//2, column=i%2, padx=5, pady=7, sticky="ew")
            
            # Hilfereicher Tooltip für Buttons mit Shortcut
            if shortcut:
                self.create_tooltip(btn, f"Shortcut: {shortcut}")
            
            # Hover-Effekt hinzufügen
            btn.bind("<Enter>", lambda e, b=btn, orig_bg=bg: b.config(bg=self.get_hover_color(orig_bg)))
            btn.bind("<Leave>", lambda e, b=btn, orig_bg=bg: b.config(bg=orig_bg))

    def get_hover_color(self, color):
        """Berechnet eine dunklere Farbe für Hover-Effekte"""
        # Einfache Implementierung: 10% dunklere Farbe
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        
        r = max(0, r - 25)
        g = max(0, g - 25)
        b = max(0, b - 25)
        
        return f"#{r:02x}{g:02x}{b:02x}"

    def create_input_frame(self):
        """Erstellt das Frame für die Fahrzeugeingabe"""
        # Panel für die Eingabefelder
        self.input_panel = tk.Frame(
            self.right_column, 
            bg=self.colors["panel_bg"], 
            bd=1, 
            relief="groove",
            padx=20,
            pady=20
        )
        self.input_panel.pack(fill="both", expand=True)
        
        # Überschrift (wird je nach Modus geändert)
        self.input_header = tk.Label(
            self.input_panel,
            text="Neues Fahrzeug hinzufügen",
            font=("Arial", 14, "bold"),
            bg=self.colors["panel_bg"],
            fg=self.colors["text_color"]
        )
        self.input_header.pack(anchor="w", pady=(0, 20))
        
        # Eingabefelder erstellen
        fields = [
            ("Marke:", "marke", "", "Bitte geben Sie die Marke des Fahrzeugs ein"),
            ("Modell:", "modell", "", "Bitte geben Sie das Modell des Fahrzeugs ein"),
            ("Baujahr:", "baujahr", "Jahr", "Bitte geben Sie das Baujahr ein (1870-2100)"),
            ("Wert (€):", "wert", "EUR", "Bitte geben Sie den Wert in Euro ein (> 500)"),
            ("Kilometerstand:", "kilometerstand", "km", "Bitte geben Sie den Kilometerstand ein (> 0)"),
            ("Farbe:", "farbe", "", "Bitte geben Sie eine reale Farbe des Fahrzeugs ein")
        ]
        
        for label_text, field_name, suffix, tooltip in fields:
            self.create_input_field(self.input_panel, label_text, field_name, suffix, tooltip)

        # Button-Container für die Steuerung
        self.input_button_frame = tk.Frame(self.input_panel, bg=self.colors["panel_bg"])
        self.input_button_frame.pack(pady=20, fill="x")
        
        # Button zum Hinzufügen/Speichern
        self.add_button = tk.Button(
            self.input_button_frame, 
            text="Fahrzeug hinzufügen", 
            command=self.fahrzeug_hinzufuegen, 
            bg=self.colors["add_button_bg"], 
            fg=self.colors["button_fg"], 
            font=("Arial", 12, "bold"),
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=10,
            pady=8,
            width=20
        )
        self.add_button.pack(side="left", padx=(0, 10))
        
        # Abbrechen-Button (zunächst ausgeblendet)
        self.cancel_button = tk.Button(
            self.input_button_frame, 
            text="Abbrechen", 
            command=self.cancel_edit, 
            bg=self.colors["delete_button_bg"], 
            fg=self.colors["button_fg"], 
            font=("Arial", 12),
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=10,
            pady=8,
            width=10
        )
        
        # Hover-Effekte
        self.add_button.bind("<Enter>", lambda e: self.add_button.config(bg=self.get_hover_color(self.colors["add_button_bg"])))
        self.add_button.bind("<Leave>", lambda e: self.add_button.config(bg=self.colors["add_button_bg"]))
        
        self.cancel_button.bind("<Enter>", lambda e: self.cancel_button.config(bg=self.get_hover_color(self.colors["delete_button_bg"])))
        self.cancel_button.bind("<Leave>", lambda e: self.cancel_button.config(bg=self.colors["delete_button_bg"]))

        # Farbhilfe-Button hinzufügen
        self.farb_hilfe_button = tk.Button(
            self.input_panel,
            text="Verfügbare Farben anzeigen",
            command=self.zeige_farbliste,
            bg=self.colors["button_bg"],
            fg=self.colors["button_fg"],
            font=("Arial", 10),
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=8,
            pady=3
        )
        self.farb_hilfe_button.place(relx=0.95, rely=0.59, anchor="e")
        
        # Hover-Effekt
        self.farb_hilfe_button.bind("<Enter>", lambda e: self.farb_hilfe_button.config(bg=self.colors["hover_color"]))
        self.farb_hilfe_button.bind("<Leave>", lambda e: self.farb_hilfe_button.config(bg=self.colors["button_bg"]))

    def ist_gueltige_farbe(self, farbe):
        """Überprüft, ob eine Farbe in der Liste der gültigen Farben ist"""
        return any(gueltige_farbe.lower() == farbe.lower() for gueltige_farbe in self.gueltige_farben)
    
    def normalisiere_farbe(self, farbe):
        """Normalisiert die Schreibweise einer Farbe"""
        for gueltige_farbe in self.gueltige_farben:
            if gueltige_farbe.lower() == farbe.lower():
                return gueltige_farbe
        return farbe  # Fallback

    def zeige_farbliste(self):
        """Zeigt eine Liste der verfügbaren Fahrzeugfarben an"""
        farb_fenster = tk.Toplevel(self.root)
        farb_fenster.title("Verfügbare Fahrzeugfarben")
        farb_fenster.geometry("400x500")
        farb_fenster.configure(bg=self.colors["panel_bg"])
        
        # Überschrift
        header = tk.Label(
            farb_fenster,
            text="Verfügbare Fahrzeugfarben",
            font=("Arial", 14, "bold"),
            bg=self.colors["panel_bg"],
            fg=self.colors["text_color"]
        )
        header.pack(pady=(20, 10))
        
        # Info-Text
        info = tk.Label(
            farb_fenster,
            text="Bitte wählen Sie eine dieser Farben für Ihr Fahrzeug:",
            bg=self.colors["panel_bg"],
            fg=self.colors["text_color"],
            font=("Arial", 10)
        )
        info.pack(pady=(0, 10))
        
        # Scrollbarer Frame für die Farbliste
        frame_container = tk.Frame(farb_fenster, bg=self.colors["panel_bg"])
        frame_container.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(frame_container)
        scrollbar.pack(side="right", fill="y")
        
        # Canvas mit Scrollbar
        canvas = tk.Canvas(
            frame_container, 
            bg=self.colors["panel_bg"],
            yscrollcommand=scrollbar.set,
            highlightthickness=0
        )
        canvas.pack(side="left", fill="both", expand=True)
        
        scrollbar.config(command=canvas.yview)
        
        # Frame für Inhalte
        content_frame = tk.Frame(canvas, bg=self.colors["panel_bg"])
        canvas.create_window((0, 0), window=content_frame, anchor="nw")
        
        # Farben hinzufügen
        for i, farbe in enumerate(sorted(self.gueltige_farben)):
            btn = tk.Button(
                content_frame,
                text=farbe,
                font=("Arial", 10),
                bg=self.colors["input_bg"],
                fg=self.colors["text_color"],
                relief="flat",
                bd=1,
                padx=10,
                pady=5,
                width=20,
                anchor="w",
                cursor="hand2",
                command=lambda f=farbe: self.waehle_farbe(f, farb_fenster)
            )
            btn.grid(row=i, column=0, sticky="w", pady=2)
            
            # Hover-Effekt
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=self.colors["highlight_bg"]))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=self.colors["input_bg"]))
        
        # Aktualisieren der Scrollregion
        content_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))
        
        # Schließen-Button am unteren Rand
        close_button = tk.Button(
            farb_fenster,
            text="Schließen",
            command=farb_fenster.destroy,
            bg=self.colors["button_bg"],
            fg=self.colors["button_fg"],
            font=("Arial", 10, "bold"),
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=10,
            pady=5
        )
        close_button.pack(pady=10)
        
        # Zentrieren des Fensters
        farb_fenster.update_idletasks()
        width = farb_fenster.winfo_width()
        height = farb_fenster.winfo_height()
        x = (farb_fenster.winfo_screenwidth() // 2) - (width // 2)
        y = (farb_fenster.winfo_screenheight() // 2) - (height // 2)
        farb_fenster.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
        # Escape-Taste zum Schließen
        farb_fenster.bind("<Escape>", lambda e: farb_fenster.destroy())

    def waehle_farbe(self, farbe, fenster):
        """Übernimmt die ausgewählte Farbe ins Eingabefeld und schließt das Farbfenster"""
        self.input_fields["farbe"].delete(0, tk.END)
        self.input_fields["farbe"].insert(0, farbe)
        fenster.destroy()
        self.input_fields["farbe"].focus_set()

    def create_input_field(self, parent, label_text, field_name, suffix="", tooltip=""):
        """Erstellt ein beschriftetes Eingabefeld mit verbesserter Darstellung"""
        # Container für jedes Feld
        field_container = tk.Frame(parent, bg=self.colors["panel_bg"], pady=5)
        field_container.pack(fill="x")
    
        # Label
        label = tk.Label(
            field_container, 
            text=label_text, 
            bg=self.colors["panel_bg"], 
            fg=self.colors["text_color"],
            font=("Arial", 11),
            width=15,
            anchor="w"
        )
        label.pack(side="left", padx=(0, 10))
    
        # Entry mit verbesserter Darstellung
        entry = tk.Entry(
            field_container, 
            font=("Arial", 11), 
            bg=self.colors["input_bg"],
            fg=self.colors["text_color"],
            insertbackground=self.colors["text_color"],  # Cursor-Farbe
            relief="groove",
            bd=2,
            width=25
        )
        entry.pack(side="left", fill="x", expand=True)
    
        # Suffix-Label (optional)
        if suffix:
            suffix_label = tk.Label(
                field_container,
                text=suffix,
                bg=self.colors["panel_bg"],
                fg=self.colors["secondary_text"],
                font=("Arial", 10),
                width=4,
                anchor="w"
            )
            suffix_label.pack(side="left", padx=5)
    
        # Speichere das Entry-Widget im Dictionary
        self.input_fields[field_name] = entry
        
        # Tooltip-Funktion für Hilfe-Texte
        if tooltip:
            self.create_tooltip(entry, tooltip)
        
        # Fokus-Effekt
        entry.bind("<FocusIn>", lambda e, e_widget=entry: self.on_entry_focus_in(e_widget))
        entry.bind("<FocusOut>", lambda e, e_widget=entry: self.on_entry_focus_out(e_widget))
        
        # Tastaturnavigation verbessern
        if field_name == "marke":
            entry.bind("<Return>", lambda e: self.input_fields["modell"].focus())
        elif field_name == "modell":
            entry.bind("<Return>", lambda e: self.input_fields["baujahr"].focus())
        elif field_name == "baujahr":
            entry.bind("<Return>", lambda e: self.input_fields["wert"].focus())
        elif field_name == "wert":
            entry.bind("<Return>", lambda e: self.input_fields["kilometerstand"].focus())
        elif field_name == "kilometerstand":
            entry.bind("<Return>", lambda e: self.input_fields["farbe"].focus())
        elif field_name == "farbe":
            entry.bind("<Return>", lambda e: self.fahrzeug_hinzufuegen() if not self.bearbeiten_modus else self.speichern_bearbeiten())

    def create_tooltip(self, widget, text):
        """Erstellt einen Tooltip für ein Widget"""
        tooltip = tk.Label(
            widget.master, 
            text=text, 
            font=("Arial", 9),
            bg=self.colors["tooltip_bg"], 
            fg=self.colors["tooltip_fg"],
            relief="solid", 
            borderwidth=1,
            padx=5,
            pady=2
        )
        tooltip.place_forget()
        
        def enter(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 25
            tooltip.geometry(f"+{x}+{y}")
            tooltip.place(x=x, y=y)
            
        def leave(event):
            tooltip.place_forget()
            
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)
    
    def on_entry_focus_in(self, entry):
        """Ändert die Darstellung eines Entry-Widgets, wenn es den Fokus erhält"""
        entry.config(bd=2, relief="solid")
    
    def on_entry_focus_out(self, entry):
        """Stellt die ursprüngliche Darstellung eines Entry-Widgets wieder her, wenn es den Fokus verliert"""
        entry.config(bd=2, relief="groove")

    def create_statusbar(self):
        """Erstellt eine Statusleiste am unteren Rand der Anwendung"""
        self.statusbar = tk.Frame(
            self.container, 
            bg=self.colors["statusbar_bg"], 
            height=25, 
            bd=1, 
            relief="sunken"
        )
        self.statusbar.pack(side="bottom", fill="x")
        
        # Status-Text
        self.status_label = tk.Label(
            self.statusbar,
            text="Bereit.",
            bg=self.colors["statusbar_bg"],
            fg=self.colors["statusbar_fg"],
            font=("Arial", 9),
            anchor="w"
        )
        self.status_label.pack(side="left", padx=10, pady=2)
        
        # Shortcut-Hilfe
        shortcuts = "Shortcuts: F5 = Aktualisieren | Strg+F = Suchen | Strg+S = Speichern | Strg+E = Exportieren | Esc = Abbrechen"
        self.shortcut_label = tk.Label(
            self.statusbar,
            text=shortcuts,
            bg=self.colors["statusbar_bg"],
            fg=self.colors["statusbar_fg"],
            font=("Arial", 9),
            anchor="e"
        )
        self.shortcut_label.pack(side="right", padx=10, pady=2)

    def update_status(self, message):
        """Aktualisiert die Statusleiste mit einer Nachricht"""
        if hasattr(self, 'status_label'):
            self.status_label.config(text=message)
            logger.info(f"Statusaktualisierung: {message}")

    def on_tree_select(self, event):
        """Event-Handler für die Auswahl in der Treeview"""
        # Visuellen Effekt auf die Buttons anwenden, wenn ein Eintrag ausgewählt ist
        selected = len(self.tree.selection()) > 0
        
        # Buttons im Button-Container durchgehen und aktivieren/deaktivieren
        for widget in self.button_container.winfo_children():
            if isinstance(widget, tk.Button):
                if widget["text"] in ["Fahrzeug löschen", "Probefahrt eintragen", "Fahrzeug bearbeiten"]:
                    if not selected:
                        widget.config(state="disabled", bg="#aaaaaa" if not self.dark_mode else "#555555")
                    else:
                        orig_bg = self.colors["delete_button_bg"] if widget["text"] == "Fahrzeug löschen" else \
                                 self.colors["probefahrt_button_bg"] if widget["text"] == "Probefahrt eintragen" else \
                                 self.colors["button_bg"]
                        widget.config(state="normal", bg=orig_bg)
                        
        # Status-Update falls ein Fahrzeug ausgewählt wurde
        if selected:
            selection = self.tree.selection()[0]
            index = self.tree.index(selection)
            fahrzeug = self.fahrzeuge[index]
            self.update_status(f"Fahrzeug ausgewählt: {fahrzeug.beschreibung()} - Wert: {format_currency(fahrzeug.wert)}")

    def on_tree_doubleclick(self, event):
        """Event-Handler für Doppelklick auf ein Fahrzeug in der Treeview"""
        selected_item = self.tree.selection()
        if selected_item:
            self.fahrzeug_bearbeiten()

    def set_edit_mode(self, fahrzeug=None):
        """Setzt die Benutzeroberfläche in den Bearbeitungsmodus oder zurück"""
        if fahrzeug:  # Bearbeitungsmodus aktivieren
            self.bearbeiten_modus = True
            self.aktuelles_fahrzeug = fahrzeug
            
            # UI-Komponenten anpassen
            self.input_header.config(text=f"Fahrzeug bearbeiten: {fahrzeug.beschreibung()}")
            self.add_button.config(text="Änderungen speichern")
            self.cancel_button.pack(side="left")
            
            # Felder mit aktuellen Werten füllen
            self.input_fields["marke"].delete(0, tk.END)
            self.input_fields["marke"].insert(0, fahrzeug.marke)
            
            self.input_fields["modell"].delete(0, tk.END)
            self.input_fields["modell"].insert(0, fahrzeug.modell)
            
            self.input_fields["baujahr"].delete(0, tk.END)
            self.input_fields["baujahr"].insert(0, str(fahrzeug.baujahr))
            
            self.input_fields["wert"].delete(0, tk.END)
            self.input_fields["wert"].insert(0, str(fahrzeug.wert))
            
            self.input_fields["kilometerstand"].delete(0, tk.END)
            self.input_fields["kilometerstand"].insert(0, str(fahrzeug.kilometerstand))
            
            self.input_fields["farbe"].delete(0, tk.END)
            self.input_fields["farbe"].insert(0, fahrzeug.farbe)
            
            # Fokus auf erstes Feld setzen
            self.input_fields["marke"].focus_set()
            
        else:  # Bearbeitungsmodus deaktivieren
            self.bearbeiten_modus = False
            self.aktuelles_fahrzeug = None
            
            # UI-Komponenten zurücksetzen
            self.input_header.config(text="Neues Fahrzeug hinzufügen")
            self.add_button.config(text="Fahrzeug hinzufügen")
            self.cancel_button.pack_forget()
            
            # Alle Felder leeren
            for field_name in self.input_fields:
                self.input_fields[field_name].delete(0, tk.END)

    def fahrzeug_bearbeiten(self):
        """Beginnt die Bearbeitung eines ausgewählten Fahrzeugs"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warnung", "Bitte wählen Sie ein Fahrzeug aus, das bearbeitet werden soll.")
            return
            
        index = self.tree.index(selected_item[0])
        fahrzeug = self.fahrzeuge[index]
        
        # Bearbeitungsmodus aktivieren
        self.set_edit_mode(fahrzeug)
        self.update_status(f"Bearbeite Fahrzeug: {fahrzeug.beschreibung()}")

    def cancel_edit(self, event=None):
        """Bricht die Bearbeitung eines Fahrzeugs ab"""
        if self.bearbeiten_modus:
            if messagebox.askyesno("Abbrechen", "Möchten Sie die Bearbeitung wirklich abbrechen? Ungespeicherte Änderungen gehen verloren."):
                self.set_edit_mode(None)
                self.update_status("Bearbeitung abgebrochen.")

    def speichern_bearbeiten(self, event=None):
        """Speichert die Änderungen an einem bearbeiteten Fahrzeug"""
        if not self.bearbeiten_modus:
            return
            
        fahrzeug = self.validate_input()
        if fahrzeug:
            # ID des bestehenden Fahrzeugs übernehmen
            fahrzeug.id = self.aktuelles_fahrzeug.id
            
            # In Datenbank speichern
            if aktualisiere_fahrzeug(fahrzeug):
                # Bearbeitungsmodus beenden
                self.set_edit_mode(None)
                
                # Liste aktualisieren
                self.lade_daten(self.letzter_suchbegriff)
                
                # Status-Update
                self.update_status(f"Fahrzeug '{fahrzeug.beschreibung()}' erfolgreich aktualisiert.")
                messagebox.showinfo("Erfolg", "Fahrzeug erfolgreich aktualisiert.")
            else:
                messagebox.showerror("Fehler", "Beim Speichern des Fahrzeugs ist ein Fehler aufgetreten.")

    def logout(self):
        """Meldet den Benutzer ab und kehrt zum Login-Bildschirm zurück"""
        if messagebox.askyesno("Abmelden", "Möchten Sie sich wirklich abmelden?"):
            self.root.destroy()
            login_root = tk.Tk()
            login_app = LoginApp(login_root)
            login_root.mainloop()

    def configure_styles(self):
        """Konfiguriert die ttk-Styles basierend auf dem aktuellen Farbschema"""
        bg_color = self.colors["panel_bg"]
        text_color = self.colors["text_color"]
        
        # Grundlegende Konfiguration
        self.style.configure(
            "Treeview", 
            background=bg_color,
            foreground=text_color,
            fieldbackground=bg_color,
            borderwidth=0,
            rowheight=25  # Höhere Zeilen für bessere Lesbarkeit
        )
        
        # Konfiguriert die ausgewählten Zeilen
        self.style.map(
            'Treeview', 
            background=[('selected', self.colors["accent_color"])],
            foreground=[('selected', 'white')]
        )
        
        # Überschriften konfigurieren
        self.style.configure(
            "Treeview.Heading",
            background=self.colors["button_bg"],
            foreground="white",
            relief="flat",
            font=('Arial', 10, 'bold')
        )
        
        # Scrollbar konfigurieren
        self.style.configure(
            "TScrollbar",
            background=self.colors["panel_bg"],
            troughcolor=self.colors["bg"],
            arrowcolor=self.colors["text_color"]
        )

    def toggle_dark_mode(self):
        """Wechselt zwischen Dark Mode und Light Mode"""
        self.dark_mode = not self.dark_mode
        self.colors = self.dark_colors if self.dark_mode else self.light_colors
        
        # Ändere das Theme-Button-Icon
        self.theme_button.config(text="☀️" if self.dark_mode else "🌙")
        
        # Aktualisiere alle Farben
        self.update_colors()
        
        # Treeview-Styles aktualisieren
        self.configure_styles()
        
        # Aktualisiere die Daten, um die Farben zu aktualisieren
        self.lade_daten(self.letzter_suchbegriff)
        
        # Aktualisiere den Selektions-Status in der Treeview
        self.on_tree_select(None)
        
        # Status aktualisieren
        mode_name = "Dunkelmodus" if self.dark_mode else "Hellmodus"
        self.update_status(f"{mode_name} aktiviert.")

    def update_colors(self):
        """Aktualisiert die Farben aller Elemente basierend auf dem aktuellen Farbschema"""
        # Container
        self.container.config(bg=self.colors["bg"])
        self.content_frame.config(bg=self.colors["bg"])
        self.left_column.config(bg=self.colors["bg"])
        self.right_column.config(bg=self.colors["bg"])
        
        # TopBar
        self.topbar.config(bg=self.colors["panel_bg"])
        self.logo_label.config(bg=self.colors["panel_bg"], fg=self.colors["accent_color"])
        self.app_title.config(bg=self.colors["panel_bg"], fg=self.colors["text_color"])
        self.benutzerinfo_label.config(bg=self.colors["panel_bg"], fg=self.colors["text_color"])
        
        # Buttons in der TopBar
        self.theme_button.config(bg=self.colors["toggle_button_bg"], fg=self.colors["text_color"])
        self.logout_button.config(bg=self.colors["button_bg"], fg=self.colors["button_fg"])
        self.export_button.config(bg=self.colors["button_bg"], fg=self.colors["button_fg"])
        
        # Suchleiste
        self.search_frame.config(bg=self.colors["panel_bg"])
        self.search_icon.config(bg=self.colors["panel_bg"], fg=self.colors["text_color"])
        self.search_entry.config(
            bg=self.colors["search_bg"], 
            fg=self.colors["text_color"],
            insertbackground=self.colors["text_color"]
        )
        self.clear_button.config(bg=self.colors["panel_bg"], fg=self.colors["text_color"])
        
        # TreeView Panel
        self.tree_panel.config(bg=self.colors["panel_bg"])
        self.tree_header.config(bg=self.colors["panel_bg"], fg=self.colors["text_color"])
        
        # Summary Frame
        self.summary_frame.config(bg=self.colors["panel_bg"])
        self.gesamtwert_label.config(bg=self.colors["panel_bg"], fg=self.colors["text_color"])
        self.anzahl_label.config(bg=self.colors["panel_bg"], fg=self.colors["text_color"])
        
        # Button Panel
        self.btn_panel.config(bg=self.colors["panel_bg"])
        self.button_container.config(bg=self.colors["panel_bg"])
        
        # Aktualisiere alle Action-Buttons
        for widget in self.button_container.winfo_children():
            if isinstance(widget, tk.Button):
                if widget["text"] == "Fahrzeug löschen":
                    widget.config(bg=self.colors["delete_button_bg"])
                elif widget["text"] == "Probefahrt eintragen":
                    widget.config(bg=self.colors["probefahrt_button_bg"])
                elif widget["text"] == "Fahrzeug bearbeiten":
                    widget.config(bg=self.colors["button_bg"])
                else:
                    widget.config(bg=self.colors["button_bg"])
                
                # Textfarbe aktualisieren
                widget.config(fg=self.colors["button_fg"])
        
        # Input Panel
        self.input_panel.config(bg=self.colors["panel_bg"])
        self.input_header.config(bg=self.colors["panel_bg"], fg=self.colors["text_color"])
        self.input_button_frame.config(bg=self.colors["panel_bg"])
        
        # Aktualisiere alle Eingabefelder
        for container in self.input_panel.winfo_children():
            if isinstance(container, tk.Frame) and container != self.input_button_frame:
                container.config(bg=self.colors["panel_bg"])
                for widget in container.winfo_children():
                    if isinstance(widget, tk.Label):
                        widget.config(bg=self.colors["panel_bg"], fg=self.colors["text_color"])
                    elif isinstance(widget, tk.Entry):
                        widget.config(
                            bg=self.colors["input_bg"], 
                            fg=self.colors["text_color"],
                            insertbackground=self.colors["text_color"]
                        )
        
        # Buttons für Eingabe/Bearbeitung
        self.add_button.config(bg=self.colors["add_button_bg"], fg=self.colors["button_fg"])
        if hasattr(self, 'cancel_button'):
            self.cancel_button.config(bg=self.colors["delete_button_bg"], fg=self.colors["button_fg"])
        
        # Farbhilfe-Button
        if hasattr(self, 'farb_hilfe_button'):
            self.farb_hilfe_button.config(bg=self.colors["button_bg"], fg=self.colors["button_fg"])
            
        # Statusleiste
        self.statusbar.config(bg=self.colors["statusbar_bg"])
        self.status_label.config(bg=self.colors["statusbar_bg"], fg=self.colors["statusbar_fg"])
        self.shortcut_label.config(bg=self.colors["statusbar_bg"], fg=self.colors["statusbar_fg"])

    def validate_input(self) -> Optional[Fahrzeug]:
        """Validiert die Eingabefelder und gibt ein Fahrzeug-Objekt zurück, wenn alle Felder gültig sind"""
        marke = self.input_fields["marke"].get().strip()
        modell = self.input_fields["modell"].get().strip()
        baujahr_str = self.input_fields["baujahr"].get().strip()
        wert_str = self.input_fields["wert"].get().strip()
        km_str = self.input_fields["kilometerstand"].get().strip()
        farbe = self.input_fields["farbe"].get().strip().lower()

        fehler_felder = []
        fehler_meldungen = []

        # Prüfe leere Felder
        for feld, wert in [
            ("marke", marke), 
            ("modell", modell), 
            ("baujahr", baujahr_str), 
            ("wert", wert_str), 
            ("kilometerstand", km_str), 
            ("farbe", farbe)
        ]:
            if not wert:
                fehler_felder.append(feld)
        
        if fehler_felder:
            messagebox.showerror("Fehler", f"Bitte füllen Sie alle erforderlichen Felder aus: {', '.join(fehler_felder)}")
            self.input_fields[fehler_felder[0]].focus_set()
            return None

        # Konvertiere und validiere Zahlen
        try:
            baujahr = int(baujahr_str)
            current_year = datetime.datetime.now().year
            
            if baujahr < 1870 or baujahr > current_year + 1:
                fehler_meldungen.append(f"Das Baujahr muss zwischen 1870 und {current_year + 1} liegen")
                fehler_felder.append("baujahr")
        except ValueError:
            fehler_meldungen.append("Das Baujahr muss eine ganze Zahl sein")
            fehler_felder.append("baujahr")

        try:
            wert = int(wert_str.replace(".", "").replace(",", ""))
            if wert <= 500:
                fehler_meldungen.append("Der Wert muss größer als 500€ sein")
                fehler_felder.append("wert")
        except ValueError:
            fehler_meldungen.append("Der Wert muss eine Zahl sein")
            fehler_felder.append("wert")

        try:
            kilometerstand = int(km_str.replace(".", "").replace(",", ""))
            if kilometerstand <= 0:
                fehler_meldungen.append("Der Kilometerstand muss größer als 0 sein")
                fehler_felder.append("kilometerstand")
        except ValueError:
            fehler_meldungen.append("Der Kilometerstand muss eine Zahl sein")
            fehler_felder.append("kilometerstand")

        # Validiere Farbe
        if not self.ist_gueltige_farbe(farbe):
            fehler_meldungen.append(f"'{farbe}' ist keine gültige Fahrzeugfarbe")
            fehler_felder.append("farbe")
        else:
            # Normalisiere die Farbe mit korrekter Schreibweise
            farbe = self.normalisiere_farbe(farbe)

        # Zeige Fehler an, wenn welche vorhanden sind
        if fehler_meldungen:
            messagebox.showerror("Validierungsfehler", "\n".join(fehler_meldungen))
            if fehler_felder:
                self.input_fields[fehler_felder[0]].focus_set()
                self.input_fields[fehler_felder[0]].select_range(0, tk.END)
            return None

        return Fahrzeug(None, marke, modell, baujahr, wert, kilometerstand, farbe)

    def fahrzeug_hinzufuegen(self, event=None):
        """Fügt ein neues Fahrzeug zur Datenbank hinzu oder speichert Änderungen"""
        if self.bearbeiten_modus:
            self.speichern_bearbeiten()
            return
            
        fahrzeug = self.validate_input()
        if fahrzeug:
            if speichere_fahrzeug(fahrzeug):
                self.lade_daten(self.letzter_suchbegriff)
                
                # Eingabefelder leeren
                for field_name in self.input_fields:
                    self.input_fields[field_name].delete(0, tk.END)
                    
                self.update_status(f"Fahrzeug '{fahrzeug.beschreibung()}' erfolgreich hinzugefügt.")
                messagebox.showinfo("Erfolg", "Fahrzeug erfolgreich hinzugefügt!")
                
                # Fokus auf das erste Feld setzen
                self.input_fields["marke"].focus_set()
            else:
                messagebox.showerror("Fehler", "Beim Hinzufügen des Fahrzeugs ist ein Fehler aufgetreten.")

    def fahrzeug_loeschen(self, event=None):
        """Löscht ein ausgewähltes Fahrzeug aus der Datenbank"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warnung", "Bitte wählen Sie ein Fahrzeug aus, das gelöscht werden soll.")
            return
            
        index = self.tree.index(selected_item[0])
        fahrzeug = self.fahrzeuge[index]
        
        if messagebox.askyesno("Bestätigung", f"Möchten Sie das Fahrzeug '{fahrzeug.beschreibung()}' wirklich löschen?"):
            if loesche_fahrzeug(fahrzeug.id):
                self.lade_daten(self.letzter_suchbegriff)
                self.update_status(f"Fahrzeug '{fahrzeug.beschreibung()}' wurde gelöscht.")
                messagebox.showinfo("Erfolg", "Fahrzeug erfolgreich gelöscht.")
                
                # Falls im Bearbeitungsmodus, diesen beenden
                if self.bearbeiten_modus and self.aktuelles_fahrzeug and self.aktuelles_fahrzeug.id == fahrzeug.id:
                    self.set_edit_mode(None)
            else:
                messagebox.showerror("Fehler", "Beim Löschen des Fahrzeugs ist ein Fehler aufgetreten.")

    def probefahrt_eintragen(self):
        """Ermöglicht das Eintragen einer Probefahrt für ein ausgewähltes Fahrzeug"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warnung", "Bitte wählen Sie ein Fahrzeug für die Probefahrt aus.")
            return
            
        index = self.tree.index(selected_item[0])
        fahrzeug = self.fahrzeuge[index]
        
        # Dialog zur Eingabe der gefahrenen Kilometer
        probefahrt_km = simpledialog.askinteger(
            "Probefahrt", 
            f"Wie viele Kilometer wurden mit dem {fahrzeug.beschreibung()} gefahren?",
            minvalue=1
        )
        
        if probefahrt_km is None:
            return  # Dialog wurde abgebrochen
            
        # Kilometerstand aktualisieren
        neuer_kilometerstand = fahrzeug.kilometerstand + probefahrt_km
        if aktualisiere_kilometerstand(fahrzeug.id, neuer_kilometerstand):
            self.lade_daten(self.letzter_suchbegriff)
            messagebox.showinfo(
                "Erfolg", 
                f"Probefahrt mit {format_number(probefahrt_km)} km erfolgreich eingetragen.\n"
                f"Neuer Kilometerstand: {format_number(neuer_kilometerstand)} km"
            )
            
            self.update_status(f"Probefahrt für '{fahrzeug.beschreibung()}' eingetragen. Neuer Kilometerstand: {format_number(neuer_kilometerstand)} km")
        else:
            messagebox.showerror("Fehler", "Beim Aktualisieren des Kilometerstands ist ein Fehler aufgetreten.")

    def benutzer_hinzufuegen(self):
        """Öffnet einen Dialog zum Hinzufügen eines neuen Benutzers"""
        # Erstelle ein Toplevel-Fenster für den Dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Neuen Benutzer hinzufügen")
        dialog.geometry("400x300")  # Größer für neue Passwort-Anforderungen
        dialog.resizable(False, False)
        dialog.configure(bg=self.colors["bg"])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Zentriere das Dialogfenster
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
        # Inhalt des Dialogs
        content_panel = tk.Frame(dialog, bg=self.colors["panel_bg"], bd=1, relief="groove")
        content_panel.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Überschrift
        header = tk.Label(
            content_panel, 
            text="Neuen Benutzer erstellen", 
            font=("Arial", 14, "bold"),
            bg=self.colors["panel_bg"],
            fg=self.colors["text_color"]
        )
        header.pack(anchor="w", pady=(10, 20))
        
        # Fehlertext (zunächst ausgeblendet)
        error_label = tk.Label(
            content_panel,
            text="",
            font=("Arial", 10),
            bg=self.colors["panel_bg"],
            fg=self.colors["error_color"]
        )
        
        # Information zu Passwortanforderungen
        info_label = tk.Label(
            content_panel,
            text="Passwort muss mindestens 8 Zeichen lang sein",
            font=("Arial", 9),
            bg=self.colors["panel_bg"],
            fg=self.colors["secondary_text"]
        )
        info_label.pack(pady=(0, 10))
        
        # Benutzername und Passwort Eingabefelder
        input_frame = tk.Frame(content_panel, bg=self.colors["panel_bg"], padx=10)
        input_frame.pack(fill="x", expand=True)
        
        # Benutzername
        user_frame = tk.Frame(input_frame, bg=self.colors["panel_bg"])
        user_frame.pack(fill="x", pady=5)
        
        user_label = tk.Label(
            user_frame, 
            text="Benutzername:", 
            bg=self.colors["panel_bg"], 
            fg=self.colors["text_color"],
            font=("Arial", 10),
            width=12,
            anchor="w"
        )
        user_label.pack(side="left")
        
        user_entry = tk.Entry(
            user_frame, 
            font=("Arial", 11), 
            bg=self.colors["input_bg"],
            fg=self.colors["text_color"],
            insertbackground=self.colors["text_color"],
            width=25
        )
        user_entry.pack(side="left", padx=5)
        
        # Passwort
        pass_frame = tk.Frame(input_frame, bg=self.colors["panel_bg"])
        pass_frame.pack(fill="x", pady=5)
        
        pass_label = tk.Label(
            pass_frame, 
            text="Passwort:", 
            bg=self.colors["panel_bg"], 
            fg=self.colors["text_color"],
            font=("Arial", 10),
            width=12,
            anchor="w"
        )
        pass_label.pack(side="left")
        
        pass_entry = tk.Entry(
            pass_frame, 
            font=("Arial", 11), 
            bg=self.colors["input_bg"],
            fg=self.colors["text_color"],
            insertbackground=self.colors["text_color"],
            width=25,
            show="*"
        )
        pass_entry.pack(side="left", padx=5)
        
        # Passwort-Bestätigung
        pass_confirm_frame = tk.Frame(input_frame, bg=self.colors["panel_bg"])
        pass_confirm_frame.pack(fill="x", pady=5)
        
        pass_confirm_label = tk.Label(
            pass_confirm_frame, 
            text="Bestätigung:", 
            bg=self.colors["panel_bg"], 
            fg=self.colors["text_color"],
            font=("Arial", 10),
            width=12,
            anchor="w"
        )
        pass_confirm_label.pack(side="left")
        
        pass_confirm_entry = tk.Entry(
            pass_confirm_frame, 
            font=("Arial", 11), 
            bg=self.colors["input_bg"],
            fg=self.colors["text_color"],
            insertbackground=self.colors["text_color"],
            width=25,
            show="*"
        )
        pass_confirm_entry.pack(side="left", padx=5)
        
        # Zeige Fehlermeldung und schüttle das Fenster leicht
        def show_error(message):
            error_label.config(text=message)
            error_label.pack(pady=(5, 10))
            
            # Schüttel-Animation
            original_x = dialog.winfo_x()
            for i in range(10):
                offset = 5 if i % 2 == 0 else -5
                dialog.geometry(f"+{original_x + offset}+{dialog.winfo_y()}")
                dialog.update()
                dialog.after(50)
            dialog.geometry(f"+{original_x}+{dialog.winfo_y()}")
            
            # Fehler nach 3 Sekunden ausblenden
            dialog.after(3000, lambda: error_label.pack_forget())
        
        # Button-Frame
        button_frame = tk.Frame(content_panel, bg=self.colors["panel_bg"])
        button_frame.pack(pady=20)
        
        # Abbrechen-Button
        cancel_button = tk.Button(
            button_frame,
            text="Abbrechen",
            command=dialog.destroy,
            bg=self.colors["delete_button_bg"],
            fg=self.colors["button_fg"],
            font=("Arial", 10),
            relief="flat",
            padx=10,
            pady=5,
            cursor="hand2"
        )
        cancel_button.pack(side="left", padx=10)
        
        # Speichern-Button
        def save_user():
            name = user_entry.get().strip()
            password = pass_entry.get().strip()
            confirm = pass_confirm_entry.get().strip()
            
            # Validierung
            if not name:
                show_error("Bitte geben Sie einen Benutzernamen ein.")
                user_entry.focus_set()
                return
                
            if not password:
                show_error("Bitte geben Sie ein Passwort ein.")
                pass_entry.focus_set()
                return
                
            if password != confirm:
                show_error("Die Passwörter stimmen nicht überein.")
                pass_confirm_entry.delete(0, tk.END)
                pass_confirm_entry.focus_set()
                return
                
            if len(password) < 8:
                show_error("Das Passwort sollte mindestens 8 Zeichen lang sein.")
                pass_entry.delete(0, tk.END)
                pass_confirm_entry.delete(0, tk.END)
                pass_entry.focus_set()
                return
                
            # In Datenbank speichern
            if speichere_benutzer(name, password):
                dialog.destroy()
                messagebox.showinfo("Erfolg", f"Benutzer '{name}' erfolgreich erstellt.")
                self.update_status(f"Neuer Benutzer '{name}' wurde angelegt.")
            else:
                show_error(f"Der Benutzername '{name}' ist bereits vergeben oder das Passwort ist nicht sicher genug.")
                user_entry.select_range(0, tk.END)
                user_entry.focus_set()
        
        save_button = tk.Button(
            button_frame,
            text="Benutzer anlegen",
            command=save_user,
            bg=self.colors["add_button_bg"],
            fg=self.colors["button_fg"],
            font=("Arial", 10, "bold"),
            relief="flat",
            padx=10,
            pady=5,
            cursor="hand2"
        )
        save_button.pack(side="left")
        
        # Hover-Effekte
        cancel_button.bind("<Enter>", lambda e: cancel_button.config(bg=self.get_hover_color(self.colors["delete_button_bg"])))
        cancel_button.bind("<Leave>", lambda e: cancel_button.config(bg=self.colors["delete_button_bg"]))
        
        save_button.bind("<Enter>", lambda e: save_button.config(bg=self.get_hover_color(self.colors["add_button_bg"])))
        save_button.bind("<Leave>", lambda e: save_button.config(bg=self.colors["add_button_bg"]))
        
        # Bindings für Tastaturnavigation
        user_entry.bind("<Return>", lambda event: pass_entry.focus_set())
        pass_entry.bind("<Return>", lambda event: pass_confirm_entry.focus_set())
        pass_confirm_entry.bind("<Return>", lambda event: save_user())
        
        # Escape-Taste zum Schließen
        dialog.bind("<Escape>", lambda event: dialog.destroy())
        
        # Fokus auf das erste Feld
        user_entry.focus_set()


# --- Hauptprogramm ---
if __name__ == "__main__":
    try:
        # Datenbank initialisieren
        init_db()
        
        # Passwörter zu sicheren Hashes migrieren
        migriere_bestehende_passwoerter()
        
        # GUI starten
        root = tk.Tk()
        app = LoginApp(root)
        root.mainloop()
    except Exception as e:
        # Globale Ausnahmebehandlung für unerwartete Fehler
        logger.critical(f"Schwerwiegender Fehler in der Anwendung: {e}", exc_info=True)
        
        # Wenn möglich, zeige auch eine Meldung an den Benutzer
        try:
            messagebox.showerror(
                "Kritischer Fehler", 
                f"Ein unerwarteter Fehler ist aufgetreten:\n\n{str(e)}\n\n"
                "Die Anwendung wird beendet. Weitere Details finden Sie in der Logdatei."
            )
        except:
            pass