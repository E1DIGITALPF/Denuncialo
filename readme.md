# Denuncialo

**Denuncialo** es una aplicación web desarrollada con Flask que permite a los usuarios enviar denuncias de manera anónima y segura. La plataforma incluye funcionalidades de cifrado, autenticación de usuarios y verificación de CAPTCHA para garantizar la seguridad y confidencialidad de los datos.

## Características

- **Envío de denuncias:** Los usuarios pueden enviar denuncias de manera segura. Cada denuncia puede incluir imágenes adjuntas y un correo electrónico cifrado opcional.
- **Cifrado de correos electrónicos:** Los correos electrónicos proporcionados son cifrados usando `Fernet` para garantizar la privacidad.
- **Gestión de denuncias:** Los administradores pueden visualizar, confirmar, marcar como resueltas y eliminar denuncias desde el panel de administración.
- **Autenticación de usuarios:** Sistema de autenticación con protección por reCAPTCHA para evitar bots.
- **Protección contra abuso:** Límites en la tasa de solicitudes para prevenir el abuso (5 solicitudes por minuto).
- **Carga y almacenamiento de imágenes:** Los usuarios pueden adjuntar imágenes a sus denuncias, las cuales son almacenadas de manera segura en el servidor.
- **Dashboard:** Los usuarios autenticados pueden ver el estado de las denuncias en un panel de control.

## Tecnologías Usadas

- Python (Flask)
- SQLAlchemy (ORM para base de datos)
- Flask-Migrate (Migraciones de base de datos)
- Flask-Limiter (Límite de tasas)
- Flask-Login (Gestión de autenticación)
- Waitress (Servidor WSGI para producción)
- reCAPTCHA de Google

## Configuración

### Requisitos

- Python 3.x
- pip
- Un entorno virtual (opcional, pero recomendado)

### Instalación

1. Clona el repositorio:
    ```bash
    git clone https://github.com/E1DIGITALPF/Denuncialo
    cd denuncialo
    ```

2. Crea y activa un entorno virtual (opcional):
    ```bash
    python -m venv venv
    source venv/bin/activate  # En Windows: venv\Scripts\activate
    ```

3. Instala las dependencias:
    ```bash
    pip install -r requirements.txt
    ```

4. Configura las variables de entorno:
    - `SECRET_KEY`: Clave secreta para la aplicación Flask (se genera corriendo generarKey.py).
    - `DATABASE_URL`: URL de la base de datos (por defecto usa SQLite).
    - `ENCRYPTION_KEY`: Clave para cifrado de correos electrónicos (si no se proporciona, se genera corriendo generarKey.py).
    - `RECAPTCHA_SITE_KEY`: Clave del sitio [reCAPTCHA de Google](https://www.google.com/recaptcha/).
    - `RECAPTCHA_SECRET_KEY`: Clave secreta reCAPTCHA.

    Puedes configurar estas variables en un archivo `.env` o usar el archivo env.example.

5. Inicializa la base de datos:
    ```bash
    flask db upgrade
    ```

6. Crea la carpeta para las imágenes subidas (si no existe):
    ```bash
    mkdir uploads
    ```

### Ejecución en desarrollo

Para ejecutar la aplicación en modo desarrollo:

    ```bash
    flask run
    ```
La aplicación estará disponible en http://127.0.0.1:5000/.

### Ejecución en producción

Para ejecutar la aplicación en un entorno de producción utilizando Waitress:

1. Comenta la línea de desarrollo en `run.py`:

    ```python
    # app.run(debug=True)
    ```

2. Descomenta la línea de producción:

    ```python
    serve(app, host="0.0.0.0", port=8080)
    ```

3. Ejecuta la aplicación:

    ```bash
    python app.py
    ```

La aplicación estará disponible en `http://<TU_DOMINIO>:8080/`.

---

## Funcionalidades clave

### Envío de denuncias

- Los usuarios pueden enviar denuncias de forma anónima o con un correo electrónico cifrado.
- Cada denuncia recibe un código de verificación único para su seguimiento.
- Los administradores pueden revisar y cambiar el estado de las denuncias (pendiente, activa, resuelta).

### Sistema de autenticación

- Los administradores deben iniciar sesión para gestionar las denuncias.
- Los usuarios no autenticados solo tienen acceso al envío de denuncias y al panel público.

### Seguridad

- La aplicación incluye protección contra bots mediante Google reCAPTCHA.
- Los correos electrónicos son cifrados antes de almacenarse en la base de datos.
- Las imágenes subidas se almacenan en un directorio protegido y se gestionan de forma segura.

---

## A futuro

- Cifrar todo el contenido de la denuncia (para aumentar la cuota de recepción de contenido multimedia y que permanezca protegido contra filtraciones)
- Mejor manejo de cuentas (en la actualidad solo es posible crear administradores mediante script. Se piensa en una cuenta SuperAdmin que se pueda crear con scripts solamente pero que maneje subcuentas de administradores desde el dashboard.)
- Mejor seguimiento de denuncias: se piensa utilizar un sistema similar al de empresas de tracking registrando incidencias que generen metadatos en tiempo real.
- Una UI simpática. Por ahora esto es el mero esqueleto. Se busca hacer algo lo suficientemente robusto como para que escale a todo nivel y cueste cero, tanto instalar como mantener.

## ¿Colaboraciones?

En la actualidad no se aceptan colaboraciones externas, pero en todo momento si puedes bifurcar y hacer los cambios que necesite.