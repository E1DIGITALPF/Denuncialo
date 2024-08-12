# Denuncialo
Denuncialo es una aplicación web para la recepción de denuncias anónimas, creada para proporcionar una plataforma segura y privada para reportar incidentes sin comprometer la identidad del denunciante. La aplicación está diseñada para ciudadanos que necesitan reportar irregularidades de manera confidencial.

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

`ENCRYPTION_KEY=<tu_clave_de_cifrado>`
`RECAPTCHA_SITE_KEY=<tu_clave_del_sitio_reCAPTCHA>`
`RECAPTCHA_SECRET_KEY=<tu_clave_secreta_reCAPTCHA>`

### Inicializar la Base de Datos:

`flask shell`
`>>> from run import db`
`>>> db.create_all()`

### Ejecutar la Aplicación:

`flask run`

La aplicación estará disponible en http://localhost:5000.

## Uso
- Enviar una Denuncia: Accede a la página principal y completa el formulario para enviar una denuncia. Los correos electrónicos opcionales se cifrarán para garantizar la privacidad.
- Ver Denuncias: Los administradores pueden acceder al dashboard para ver una lista de todas las denuncias recibidas. Al hacer clic en una denuncia, se mostrará un popup con los detalles completos.

