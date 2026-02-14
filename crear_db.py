import sqlite3
import hashlib

conn = sqlite3.connect("cita_plus.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS pacientes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    cedula TEXT NOT NULL UNIQUE,
    telefono TEXT NOT NULL
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS medicos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    especialidad TEXT NOT NULL,
    telefono TEXT NOT NULL
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS citas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    paciente_id INTEGER NOT NULL,
    medico_id INTEGER NOT NULL,
    fecha TEXT NOT NULL,
    hora TEXT NOT NULL,
    motivo TEXT NOT NULL,
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id),
    FOREIGN KEY (medico_id) REFERENCES medicos(id)
)
""")

# Crear tabla usuarios
# Nota: El comando "usuario TEXT NOT NULL UNIQUE," será el correo
cursor.execute("""
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    usuario TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    rol TEXT NOT NULL CHECK (rol IN ('admin', 'secretaria', 'medico', 'paciente')),
    medico_id INTEGER,
    paciente_id INTEGER,
    FOREIGN KEY (medico_id) REFERENCES medicos(id),
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id)
)
""")

# Crear usuario administrador inicial
cursor.execute("SELECT * FROM usuarios WHERE usuario = 'admin@cita.com'") 
admin = cursor.fetchone()

if not admin:
    password_hash = hashlib.sha256("admin123".encode()).hexdigest()
    cursor.execute(""" 
        INSERT INTO usuarios (nombre, usuario, password, rol) 
        VALUES (?, ?, ?, ?) 
        """, ("Administrador del Sistema", "admin@cita.com", password_hash, "admin"))

'''
cursor.execute("SELECT * FROM usuarios WHERE usuario = 'admin'")
admin = cursor.fetchone()

if not admin:
    import hashlib
    password_hash = hashlib.sha256("admin123".encode()).hexdigest()

    cursor.execute("""
        INSERT INTO usuarios (nombre, usuario, password, rol)
        VALUES (?, ?, ?, ?)
    """, ("Administrador del Sistema", "admin", password_hash, "admin"))
'''

conn.commit()
conn.close()

print("Base de datos creada correctamente.")
