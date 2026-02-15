from flask import Flask, render_template, request, redirect, flash, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = "cita-plus-2025"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"   # ruta a donde redirige si no está logueado

class Usuario(UserMixin):
    def __init__(self, id, nombre, usuario, rol, medico_id, paciente_id):
        self.id = id
        self.nombre = nombre
        self.usuario = usuario  # correo
        self.rol = rol
        self.medico_id = medico_id
        self.paciente_id = paciente_id

# Decoradores por rol
from functools import wraps
from flask import abort

def solo_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.rol != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

def solo_secretaria(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.rol not in ("secretaria", "admin"):
            abort(403)
        return f(*args, **kwargs)
    return wrapper

def solo_medico(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.rol != "medico":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

def solo_paciente(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.rol != "paciente":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# Función para cargar usuario desde BD
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect("cita_plus.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return Usuario(row[0], row[1], row[2], row[4], row[5], row[6])
    return None

# Ruta /login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form["correo"]
        password = request.form["password"]

        conn = sqlite3.connect("cita_plus.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE usuario = ?", (correo,))
        user = cursor.fetchone()
        conn.close()

        if user:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if password_hash == user[3]:  # columna password
                usuario_obj = Usuario(user[0], user[1], user[2], user[4], user[5], user[6])
                login_user(usuario_obj)
                return redirect(url_for("home"))

        flash("Correo o contraseña incorrectos", "danger")

    return render_template("login.html")

# Ruta /logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

def get_db_connection():
    conn = sqlite3.connect("cita_plus.db")
    conn.row_factory = sqlite3.Row
    return conn

# Lista temporal para almacenar pacientes
pacientes = []

@app.route("/")
def home():
    return render_template("home.html")

# LAS RUTAS PARA PACIENTES
@app.route("/pacientes")
@login_required
@solo_secretaria
def pacientes_view():
    conn = get_db_connection()
    pacientes = conn.execute("SELECT * FROM pacientes").fetchall()
    conn.close()
    return render_template("pacientes.html", pacientes=pacientes)

# Registrar un Paciente
@app.route("/pacientes/registrar")
@login_required
@solo_secretaria
def registrar_paciente():
    return render_template("registrar_paciente.html")

# Guardar un Paciente
@app.route("/pacientes/guardar", methods=["POST"])
@login_required
@solo_secretaria
def guardar_paciente():
    nombre = request.form["nombre"].strip()
    cedula = request.form["cedula"].strip()
    telefono = request.form["telefono"].strip()
    
    # Validación de campos vacíos
    if not nombre or not cedula or not telefono:
        return render_template(
            "registrar_paciente.html",
            error="Todos los campos son obligatorios."
        )
    
    # Validación de formato de teléfono (solo números)
    if not telefono.isdigit():
        return render_template(
            "registrar_paciente.html",
            error="El teléfono solo debe contener números."
        )
    
    conn = get_db_connection() 
    
    # Validación de cédula duplicada en SQLite 
    existe = conn.execute("SELECT * FROM pacientes WHERE cedula = ?", (cedula,)).fetchone() 
    if existe: 
        conn.close() 
        return render_template("registrar_paciente.html", error="Ya existe un paciente registrado con esa cédula.") 
    conn.execute( 
        "INSERT INTO pacientes (nombre, cedula, telefono) VALUES (?, ?, ?)", 
        (nombre, cedula, telefono) 
    ) 
    conn.commit() 
    conn.close()

    flash("Paciente registrado correctamente", "success")
    return redirect("/pacientes")

# Eliminar un Paciente
@app.route("/pacientes/eliminar/<int:id>")
@login_required
@solo_secretaria
def eliminar_paciente(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM pacientes WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    flash("Paciente eliminado correctamente", "success")
    return redirect("/pacientes")

# Editar un Paciente
@app.route("/pacientes/editar/<int:id>")
@login_required
@solo_secretaria
def editar_paciente(id):
    conn = get_db_connection()
    paciente = conn.execute("SELECT * FROM pacientes WHERE id = ?", (id,)).fetchone()
    conn.close()

    if paciente is None:
        return redirect("/pacientes")

    return render_template("editar_paciente.html", paciente=paciente)

# Actualizar un Paciente
@app.route("/pacientes/actualizar/<int:id>", methods=["POST"])
@login_required
@solo_secretaria
def actualizar_paciente(id):
    nombre = request.form["nombre"].strip()
    cedula = request.form["cedula"].strip()
    telefono = request.form["telefono"].strip()

    # Validar los campos vacios
    if not nombre or not cedula or not telefono:
        return render_template("editar_paciente.html", paciente={"id": id, "nombre": nombre, "cedula": cedula, "telefono": telefono}, error="Todos los campos son obligatorios.")
    
    # Validar el formato de telefono
    if not telefono.isdigit():
        return render_template("editar_paciente.html", paciente={"id": id, "nombre": nombre, "cedula": cedula, "telefono": telefono}, error="El teléfono solo debe contener números.")

    conn = get_db_connection()

    # Validar cédula duplicada excepto la del mismo paciente
    existe = conn.execute("SELECT * FROM pacientes WHERE cedula = ? AND id != ?", (cedula, id)).fetchone()
    if existe:
        conn.close()
        return render_template("editar_paciente.html", paciente={"id": id, "nombre": nombre, "cedula": cedula, "telefono": telefono}, error="Ya existe un paciente con esa cédula.")

    conn.execute(
        "UPDATE pacientes SET nombre = ?, cedula = ?, telefono = ? WHERE id = ?",
        (nombre, cedula, telefono, id)
    )
    conn.commit()
    conn.close()

    flash("Paciente actualizado correctamente", "success")
    return redirect("/pacientes")


# LAS RUTAS PARA MÉDICOS
@app.route("/medicos")
@login_required
@solo_secretaria
def medicos_view():
    conn = get_db_connection()
    medicos = conn.execute("SELECT * FROM medicos").fetchall()
    conn.close()
    return render_template("medicos.html", medicos=medicos)

# Registrar un Médico
@app.route("/medicos/registrar")
@login_required
@solo_secretaria
def registrar_medico():
    return render_template("registrar_medico.html")

# Guardar un Médico
@app.route("/medicos/guardar", methods=["POST"])
@login_required
@solo_secretaria
def guardar_medico():
    nombre = request.form["nombre"].strip()
    especialidad = request.form["especialidad"].strip()
    telefono = request.form["telefono"].strip()

    # Validaciones
    if not nombre or not especialidad or not telefono:
        return render_template("registrar_medico.html", error="Todos los campos son obligatorios.")

    if not telefono.isdigit():
        return render_template("registrar_medico.html", error="El teléfono solo debe contener números.")

    conn = get_db_connection()

    # Validar que no exista un médico con el mismo nombre y especialidad
    existe = conn.execute(
        "SELECT * FROM medicos WHERE nombre = ? AND especialidad = ?",
        (nombre, especialidad)
    ).fetchone()
    
    if existe:
        conn.close()
        return render_template(
            "registrar_medico.html",
            error="Ya existe un médico registrado con ese nombre y especialidad."
        )

    conn.execute(
        "INSERT INTO medicos (nombre, especialidad, telefono) VALUES (?, ?, ?)",
        (nombre, especialidad, telefono)
    )
    conn.commit()
    conn.close()

    flash("Médico registrado correctamente", "success")
    return redirect("/medicos")

# Editar un Médico
@app.route("/medicos/editar/<int:id>")
@login_required
@solo_secretaria
def editar_medico(id):
    conn = get_db_connection()
    medico = conn.execute("SELECT * FROM medicos WHERE id = ?", (id,)).fetchone()
    conn.close()

    if medico is None:
        return redirect("/medicos")

    return render_template("editar_medico.html", medico=medico)

# Actualizar un Médico
@app.route("/medicos/actualizar/<int:id>", methods=["POST"])
@login_required
@solo_secretaria
def actualizar_medico(id):
    nombre = request.form["nombre"].strip()
    especialidad = request.form["especialidad"].strip()
    telefono = request.form["telefono"].strip()

    if not nombre or not especialidad or not telefono:
        return render_template("editar_medico.html", medico={"id": id, "nombre": nombre, "especialidad": especialidad, "telefono": telefono}, error="Todos los campos son obligatorios.")

    if not telefono.isdigit():
        return render_template("editar_medico.html", medico={"id": id, "nombre": nombre, "especialidad": especialidad, "telefono": telefono}, error="El teléfono solo debe contener números.")

    conn = get_db_connection()

    # Validar que no exista un médico con el mismo nombre y especialidad
    existe = conn.execute(
        "SELECT * FROM medicos WHERE nombre = ? AND especialidad = ? AND id != ?",
        (nombre, especialidad, id)
    ).fetchone()
    
    if existe:
        conn.close()
        return render_template(
            "editar_medico.html",
            medico={"id": id, "nombre": nombre, "especialidad": especialidad, "telefono": telefono},
            error="Ya existe un médico con ese nombre y especialidad."
        )

    conn.execute(
        "UPDATE medicos SET nombre = ?, especialidad = ?, telefono = ? WHERE id = ?",
        (nombre, especialidad, telefono, id)
    )
    conn.commit()
    conn.close()

    flash("Médico actualizado correctamente", "success")
    return redirect("/medicos")

# Eliminar un Médico
@app.route("/medicos/eliminar/<int:id>")
@login_required
@solo_secretaria
def eliminar_medico(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM medicos WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    flash("Médico eliminado correctamente", "success")
    return redirect("/medicos")


# LAS RUTAS PARA CITAS
@app.route("/citas")
@login_required
@solo_secretaria
def citas_view():
    conn = get_db_connection()
    citas = conn.execute("""
        SELECT c.id, c.fecha, c.hora, c.motivo,
               p.nombre AS paciente,
               m.nombre AS medico
        FROM citas c
        JOIN pacientes p ON c.paciente_id = p.id
        JOIN medicos m ON c.medico_id = m.id
        ORDER BY c.fecha, c.hora
    """).fetchall()
    conn.close()

    return render_template("citas.html", citas=citas)

# Registrar una Cita
@app.route("/citas/registrar")
@login_required
@solo_secretaria
def registrar_cita():
    conn = get_db_connection()
    pacientes = conn.execute("SELECT * FROM pacientes").fetchall()
    medicos = conn.execute("SELECT * FROM medicos").fetchall()
    conn.close()

    return render_template("registrar_cita.html", pacientes=pacientes, medicos=medicos)

# Guardar una Cita
@app.route("/citas/guardar", methods=["POST"])
@login_required
@solo_secretaria
def guardar_cita():
    paciente_id = request.form["paciente_id"]
    medico_id = request.form["medico_id"]
    fecha = request.form["fecha"]
    hora = request.form["hora"]
    motivo = request.form["motivo"].strip()

    # Validación de campos vacíos
    if not paciente_id or not medico_id or not fecha or not hora or not motivo:
        conn = get_db_connection()
        pacientes = conn.execute("SELECT * FROM pacientes").fetchall()
        medicos = conn.execute("SELECT * FROM medicos").fetchall()
        conn.close()
        return render_template("registrar_cita.html",
                               pacientes=pacientes,
                               medicos=medicos,
                               error="Todos los campos son obligatorios.")

    conn = get_db_connection()

    # ⭐ VALIDACIÓN DE CHOQUE DE CITAS (AQUÍ VA)
    choque = conn.execute("""
        SELECT id FROM citas
        WHERE medico_id = ?
          AND fecha = ?
          AND hora = ?
    """, (medico_id, fecha, hora)).fetchone()

    if choque:
        pacientes = conn.execute("SELECT * FROM pacientes").fetchall()
        medicos = conn.execute("SELECT * FROM medicos").fetchall()
        conn.close()
        return render_template("registrar_cita.html",
                               pacientes=pacientes,
                               medicos=medicos,
                               error="El médico ya tiene una cita en esa fecha y hora.")

    # Insertar la cita
    conn.execute("""
        INSERT INTO citas (paciente_id, medico_id, fecha, hora, motivo)
        VALUES (?, ?, ?, ?, ?)
    """, (paciente_id, medico_id, fecha, hora, motivo))

    conn.commit()
    conn.close()

    flash("Cita registrada correctamente", "success")
    return redirect("/citas")

'''
@app.route("/citas/guardar", methods=["POST"])
def guardar_cita():
    paciente_id = request.form["paciente_id"]
    medico_id = request.form["medico_id"]
    fecha = request.form["fecha"]
    hora = request.form["hora"]
    motivo = request.form["motivo"].strip()

    if not paciente_id or not medico_id or not fecha or not hora or not motivo:
        return render_template("registrar_cita.html", error="Todos los campos son obligatorios.")

    conn = get_db_connection()

    # Validar choque de citas del mismo médico
    choque = conn.execute("""
        SELECT * FROM citas
        WHERE medico_id = ? AND fecha = ? AND hora = ?
    """, (medico_id, fecha, hora)).fetchone()

    if choque:
        conn.close()
        return render_template("registrar_cita.html", error="El médico ya tiene una cita en esa fecha y hora.")

    conn.execute("""
        INSERT INTO citas (paciente_id, medico_id, fecha, hora, motivo)
        VALUES (?, ?, ?, ?, ?)
    """, (paciente_id, medico_id, fecha, hora, motivo))

    conn.commit()
    conn.close()

    flash("Cita registrada correctamente", "success")
    return redirect("/citas")
'''

# Editar una Cita
@app.route("/citas/editar/<int:id>")
@login_required
@solo_secretaria
def editar_cita(id):
    conn = get_db_connection()
    cita = conn.execute("SELECT * FROM citas WHERE id = ?", (id,)).fetchone()
    pacientes = conn.execute("SELECT * FROM pacientes").fetchall()
    medicos = conn.execute("SELECT * FROM medicos").fetchall()
    conn.close()

    if cita is None:
        return redirect("/citas")

    return render_template("editar_cita.html", cita=cita, pacientes=pacientes, medicos=medicos)

# Actualizar una Citas
@app.route("/citas/actualizar/<int:id>", methods=["POST"])
@login_required
@solo_secretaria
def actualizar_cita(id):
    paciente_id = request.form["paciente_id"]
    medico_id = request.form["medico_id"]
    fecha = request.form["fecha"]
    hora = request.form["hora"]
    motivo = request.form["motivo"].strip()

    # Validación de campos vacíos
    if not paciente_id or not medico_id or not fecha or not hora or not motivo:
        conn = get_db_connection()
        pacientes = conn.execute("SELECT * FROM pacientes").fetchall()
        medicos = conn.execute("SELECT * FROM medicos").fetchall()
        conn.close()

        return render_template(
            "editar_cita.html",
            cita={"id": id, "paciente_id": paciente_id, "medico_id": medico_id,
                  "fecha": fecha, "hora": hora, "motivo": motivo},
            pacientes=pacientes,
            medicos=medicos,
            error="Todos los campos son obligatorios."
        )

    conn = get_db_connection()

    # ⭐ Validación de choque de citas
    choque = conn.execute("""
        SELECT id FROM citas
        WHERE medico_id = ?
          AND fecha = ?
          AND hora = ?
          AND id != ?
    """, (medico_id, fecha, hora, id)).fetchone()

    if choque:
        pacientes = conn.execute("SELECT * FROM pacientes").fetchall()
        medicos = conn.execute("SELECT * FROM medicos").fetchall()
        conn.close()

        return render_template(
            "editar_cita.html",
            cita={"id": id, "paciente_id": paciente_id, "medico_id": medico_id,
                  "fecha": fecha, "hora": hora, "motivo": motivo},
            pacientes=pacientes,
            medicos=medicos,
            error="El médico ya tiene una cita en esa fecha y hora."
        )

    # Actualizar la cita
    conn.execute("""
        UPDATE citas
        SET paciente_id = ?, medico_id = ?, fecha = ?, hora = ?, motivo = ?
        WHERE id = ?
    """, (paciente_id, medico_id, fecha, hora, motivo, id))

    conn.commit()
    conn.close()

    flash("Cita actualizada correctamente", "success")
    return redirect("/citas")

'''
@app.route("/citas/actualizar/<int:id>", methods=["POST"])
def actualizar_cita(id):
    paciente_id = request.form["paciente_id"]
    medico_id = request.form["medico_id"]
    fecha = request.form["fecha"]
    hora = request.form["hora"]
    motivo = request.form["motivo"].strip()

    if not paciente_id or not medico_id or not fecha or not hora or not motivo:
        return render_template("editar_cita.html", error="Todos los campos son obligatorios.")

    conn = get_db_connection()

    choque = conn.execute("""
        SELECT * FROM citas
        WHERE medico_id = ? AND fecha = ? AND hora = ? AND id != ?
    """, (medico_id, fecha, hora, id)).fetchone()

    if choque:
        conn.close()
        return render_template("editar_cita.html", error="El médico ya tiene una cita en esa fecha y hora.")

    conn.execute("""
        UPDATE citas
        SET paciente_id = ?, medico_id = ?, fecha = ?, hora = ?, motivo = ?
        WHERE id = ?
    """, (paciente_id, medico_id, fecha, hora, motivo, id))

    conn.commit()
    conn.close()

    flash("Cita actualizada correctamente", "success")
    return redirect("/citas")
'''

# Eliminar una Cita
@app.route("/citas/eliminar/<int:id>")
@login_required
@solo_secretaria
def eliminar_cita(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM citas WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    flash("Cita eliminada correctamente", "success")
    return redirect("/citas")

@app.route("/mis_citas_medico")
@login_required
@solo_medico
def mis_citas_medico():
    conn = get_db_connection()
    citas = conn.execute("""
        SELECT c.id, c.fecha, c.hora, c.motivo,
               p.nombre AS paciente
        FROM citas c
        JOIN pacientes p ON c.paciente_id = p.id
        WHERE c.medico_id = ?
        ORDER BY c.fecha, c.hora
    """, (current_user.medico_id,)).fetchall()
    conn.close()

    return render_template("mis_citas_medico.html", citas=citas)

@app.route("/mis_citas_paciente")
@login_required
@solo_paciente
def mis_citas_paciente():
    conn = get_db_connection()
    citas = conn.execute("""
        SELECT c.id, c.fecha, c.hora, c.motivo,
               m.nombre AS medico
        FROM citas c
        JOIN medicos m ON c.medico_id = m.id
        WHERE c.paciente_id = ?
        ORDER BY c.fecha, c.hora
    """, (current_user.paciente_id,)).fetchall()
    conn.close()

    return render_template("mis_citas_paciente.html", citas=citas)

# RUTAS PARA EL USUARIO
@app.route("/usuarios")
@login_required
@solo_admin
def usuarios_view():
    conn = get_db_connection()
    usuarios = conn.execute("""
        SELECT u.id, u.nombre, u.usuario, u.rol,
               m.nombre AS medico_nombre,
               p.nombre AS paciente_nombre
        FROM usuarios u
        LEFT JOIN medicos m ON u.medico_id = m.id
        LEFT JOIN pacientes p ON u.paciente_id = p.id
        ORDER BY u.id
    """).fetchall()
    conn.close()

    return render_template("usuarios.html", usuarios=usuarios)

# Registrar un Usuario
@app.route("/usuarios/registrar")
@login_required
@solo_admin
def registrar_usuario():
    conn = get_db_connection()
    medicos = conn.execute("SELECT id, nombre FROM medicos").fetchall()
    pacientes = conn.execute("SELECT id, nombre FROM pacientes").fetchall()
    conn.close()

    return render_template("registrar_usuario.html", medicos=medicos, pacientes=pacientes)

# Guardar un Usuario
@app.route("/usuarios/guardar", methods=["POST"])
@login_required
@solo_admin
def guardar_usuario():
    nombre = request.form["nombre"].strip()
    correo = request.form["correo"].strip()
    password = request.form["password"]
    rol = request.form["rol"]
    medico_id = request.form.get("medico_id") or None
    paciente_id = request.form.get("paciente_id") or None

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = get_db_connection()

    # Validar correo duplicado
    existe = conn.execute("SELECT id FROM usuarios WHERE usuario = ?", (correo,)).fetchone()
    if existe:
        conn.close()
        flash("Ya existe un usuario con ese correo.", "danger")
        return redirect(url_for("registrar_usuario"))

    conn.execute("""
        INSERT INTO usuarios (nombre, usuario, password, rol, medico_id, paciente_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (nombre, correo, password_hash, rol, medico_id, paciente_id))

    conn.commit()
    conn.close()

    flash("Usuario creado correctamente", "success")
    return redirect(url_for("usuarios_view"))

# Editar un Usuario
@app.route("/usuarios/editar/<int:id>")
@login_required
@solo_admin
def editar_usuario(id):
    conn = get_db_connection()

    usuario = conn.execute("""
        SELECT * FROM usuarios WHERE id = ?
    """, (id,)).fetchone()

    medicos = conn.execute("SELECT id, nombre FROM medicos").fetchall()
    pacientes = conn.execute("SELECT id, nombre FROM pacientes").fetchall()

    conn.close()

    if usuario is None:
        flash("El usuario no existe.", "danger")
        return redirect(url_for("usuarios_view"))

    return render_template("editar_usuario.html",
                           usuario=usuario,
                           medicos=medicos,
                           pacientes=pacientes)

# Actualizar un Usuario
@app.route("/usuarios/actualizar/<int:id>", methods=["POST"])
@login_required
@solo_admin
def actualizar_usuario(id):
    nombre = request.form["nombre"].strip()
    correo = request.form["correo"].strip()
    rol = request.form["rol"]
    medico_id = request.form.get("medico_id") or None
    paciente_id = request.form.get("paciente_id") or None

    conn = get_db_connection()

    # Validar correo duplicado (excepto el mismo usuario)
    existe = conn.execute("""
        SELECT id FROM usuarios
        WHERE usuario = ? AND id != ?
    """, (correo, id)).fetchone()

    if existe:
        conn.close()
        flash("Ya existe otro usuario con ese correo.", "danger")
        return redirect(url_for("editar_usuario", id=id))

    conn.execute("""
        UPDATE usuarios
        SET nombre = ?, usuario = ?, rol = ?, medico_id = ?, paciente_id = ?
        WHERE id = ?
    """, (nombre, correo, rol, medico_id, paciente_id, id))

    conn.commit()
    conn.close()

    flash("Usuario actualizado correctamente", "success")
    return redirect(url_for("usuarios_view"))

# Eliminar un Usuario
@app.route("/usuarios/eliminar/<int:id>")
@login_required
@solo_admin
def eliminar_usuario(id):
    conn = get_db_connection()

    # Verificar si el usuario existe
    usuario = conn.execute("SELECT * FROM usuarios WHERE id = ?", (id,)).fetchone()

    if usuario is None:
        conn.close()
        flash("El usuario no existe.", "danger")
        return redirect(url_for("usuarios_view"))

    # Evitar que el admin se elimine a sí mismo
    if id == current_user.id:
        conn.close()
        flash("No puedes eliminar tu propia cuenta.", "danger")
        return redirect(url_for("usuarios_view"))

    # Eliminar usuario
    conn.execute("DELETE FROM usuarios WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    flash("Usuario eliminado correctamente.", "success")
    return redirect(url_for("usuarios_view"))


# RUTAS PARA CAMBIAR LA CONTRASEÑA
@app.route("/cambiar_contrasena")
@login_required
def cambiar_contrasena():
    return render_template("cambiar_contrasena.html")

@app.route("/cambiar_contrasena", methods=["POST"])
@login_required
def cambiar_contrasena_post():
    actual = request.form["actual"]
    nueva = request.form["nueva"]
    confirmar = request.form["confirmar"]

    # Verificar contraseña actual
    hash_actual = hashlib.sha256(actual.encode()).hexdigest()
    if hash_actual != current_user.password:
        flash("La contraseña actual es incorrecta.", "danger")
        return redirect(url_for("cambiar_contrasena"))

    # Verificar coincidencia
    if nueva != confirmar:
        flash("Las contraseñas nuevas no coinciden.", "danger")
        return redirect(url_for("cambiar_contrasena"))

    # Actualizar contraseña
    nuevo_hash = hashlib.sha256(nueva.encode()).hexdigest()

    conn = get_db_connection()
    conn.execute("UPDATE usuarios SET password = ? WHERE id = ?", (nuevo_hash, current_user.id))
    conn.commit()
    conn.close()

    flash("Contraseña actualizada correctamente.", "success")
    return redirect(url_for("home"))


import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
