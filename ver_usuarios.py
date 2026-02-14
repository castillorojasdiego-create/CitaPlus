import sqlite3

conn = sqlite3.connect("cita_plus.db")
cursor = conn.cursor()

# Actualizar correo del admin
cursor.execute(""" 
UPDATE usuarios 
SET usuario = 'admin@cita.com' 
WHERE id = 1 
""") 
conn.commit()

# Volver a consultar después del UPDATE
usuarios = cursor.execute("SELECT id, nombre, usuario, rol, password FROM usuarios").fetchall()

for u in usuarios:
    print(u)

conn.close()
