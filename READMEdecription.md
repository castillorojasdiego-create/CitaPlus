# CitaPlus

CitaPlus es un sistema web para la gestión y reserva de citas médicas.  
Permite administrar usuarios, pacientes, médicos y citas mediante una interfaz intuitiva y un flujo de trabajo optimizado.  
El sistema está desarrollado con **Flask**, **SQLite**, **Bootstrap** y **Jinja2**, siguiendo buenas prácticas de arquitectura y seguridad.

---

## 🚀 Características principales

- **Autenticación de usuarios**
  - Inicio de sesión seguro
  - Recuperación y cambio de contraseña
  - Roles: Administrador, Secretaria, Médico y Paciente

- **Gestión de usuarios**
  - Registro, edición y eliminación de usuarios
  - Control de roles y permisos

- **Módulo de pacientes**
  - Registro, edición y listado de pacientes
  - Información básica y datos clínicos esenciales

- **Módulo de médicos**
  - Registro y administración de médicos
  - Especialidades y datos profesionales

- **Gestión de citas**
  - Registrar, editar y cancelar citas
  - Vista personalizada:
    - **Mis Citas (Médico)**
    - **Mis Citas (Paciente)**

- **Interfaz moderna**
  - Bootstrap 5
  - Plantillas reutilizables con `base.html`
  - Navegación dinámica según el rol del usuario

---

## 🛠️ Tecnologías utilizadas

| Tecnología | Uso |
|-----------|-----|
| **Python 3** | Lógica del servidor |
| **Flask** | Framework web |
| **SQLite** | Base de datos ligera |
| **Jinja2** | Motor de plantillas |
| **Bootstrap 5** | Estilos y diseño responsivo |
| **Git & GitHub** | Control de versiones |

---

## 📂 Estructura del proyecto

CitaPlus/
│── app.py
│── crear_db.py
│── cita_plus.db
│── static/
│   └── css/
│       └── style.css
│── templates/
│   ├── base.html
│   ├── login.html
│   ├── home.html
│   ├── usuarios.html
│   ├── pacientes.html
│   ├── medicos.html
│   ├── citas.html
│   ├── registrar_usuario.html
│   ├── registrar_paciente.html
│   ├── registrar_medico.html
│   ├── registrar_cita.html
│   ├── editar_usuario.html
│   ├── editar_paciente.html
│   ├── editar_medico.html
│   ├── editar_cita.html
│   ├── mis_citas_medico.html
│   └── mis_citas_paciente.html
└── ver_usuarios.py

---

## ⚙️ Instalación y ejecución

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/castillorojasdiego-create/CitaPlus.git

2. Crear y activar un entorno virtual:
   python -m venv venv
   venv\Scripts\activate

3. Instalar dependencias:
   pip install flask

4. Ejecutar la aplicación:
   python app.py

5. Abrir en el navegador:
   http://127.0.0.1:5000

👨‍💻 Autor
Diego Castillo  
Proyecto académico desarrollado para la UNELLEZ, Barinas.
Enfoque en metodologías ágiles, arquitectura de software y desarrollo web profesional.

📄 Licencia
Este proyecto se distribuye bajo la licencia MIT.
Puedes usarlo, modificarlo y distribuirlo libremente.

---

# IMPORTANTE
# Usuario Administrador Inicial:
Correo: admin@cita.com
Contraseña: admin123
