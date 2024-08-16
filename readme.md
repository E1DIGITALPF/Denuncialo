# Denuncialo - Plataforma para enviar y monitorear denuncias anonimas

Esta es una aplicación web basada en Flask que permite a los usuarios enviar denuncias anónimas y proporciona una interfaz de administración para ver y administrar estos informes.

## Características
- Envío de Denuncias Anónimas: Permite a los usuarios enviar denuncias de manera segura sin revelar su identidad.
- Cifrado de Correos Electrónicos: Los correos electrónicos opcionales proporcionados por los denunciantes se cifran para proteger la privacidad.
- Verificación con reCAPTCHA: Protege el formulario contra el spam y los envíos automatizados.
- Interfaz de Usuario Intuitiva: Fácil de usar tanto para los denunciantes como para los administradores.
- Dashboard para Administradores: Muestra una lista de denuncias recibidas, con la opción de ver detalles completos en un popup.

## Instalación
Sigue estos pasos para instalar y ejecutar la aplicación en tu entorno local:

### Clonar el Repositorio

### Crear un Entorno Virtual:

`python -m venv venv`

### Activar el Entorno Virtual:

#### En Windows:

`venv\Scripts\activate`

#### En macOS/Linux:

`source venv/bin/activate`

### Instalar las Dependencias:

`pip install -r requirements.txt`

### Configurar Variables de Entorno:

Crea un archivo .env en la raíz del proyecto con las siguientes variables:

`ENCRYPTION_KEY=<tu_clave_de_cifrado>
RECAPTCHA_SITE_KEY=<tu_clave_del_sitio_reCAPTCHA>
RECAPTCHA_SECRET_KEY=<tu_clave_secreta_reCAPTCHA>`

### Inicializar la Base de Datos:

`flask shell`
>>> from run import db
>>> db.create_all()

### Ejecutar la Aplicación:

`flask run`

La aplicación estará disponible en http://localhost:5000.

## Uso

- Los usuarios pueden enviar informes anónimos accediendo a la página principal y haciendo clic en "Enviar tu denuncia"
- Los administradores pueden iniciar sesión haciendo clic en el botón "Inicio de sesión de administrador" y usando sus credenciales
- Una vez que hayan iniciado sesión, los administradores pueden ver todos los informes enviados, incluidas las direcciones de correo electrónico descifradas.