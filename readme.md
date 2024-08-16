# Denuncialo - Plataforma para enviar y monitorear denuncias anonimas

Esta es una aplicación web basada en Flask que permite a los usuarios enviar denuncias anónimas y proporciona una interfaz de administración para ver y administrar estos informes.

## Características

- Envío de informes anónimos
- Soporte para carga de archivos de imágenes
- Integración de reCAPTCHA para prevención de spam
- Almacenamiento de correo electrónico cifrado
- Panel de administración para ver los informes enviados
- Autenticación de usuario para acceso de administrador

## Requisitos previos

- Python 3.7+
- pip
- virtualenv (recomendado fervientemente)

## Configuración inicial

1. Clone el repositorio:
```
git clone https://github.com/E1DIGITALPF/Denuncialo.git
```
```
cd Denuncialo
```

2. Cree y active un entorno virtual:
```
python -m venv venv
```
```
source venv/bin/activate # En Windows, use venv\Scripts\activate
```

3. Instale los paquetes necesarios:
```
pip install -r requirements.txt
```

4. Configure las variables de entorno:
Descomente el archivo .env.example dejando solo .env y llenando con las variables:
- ```ENCRYPTION_KEY=AFTER_RUNNING_GENERATE_KEY_PY```: Corre el script ```generateKey.py``` y pega aqui la cadena recibida.
- ```RECAPTCHA_SITE_KEY=GOOGLE_RECAPTCHA_SITE_KEY```: Debes crear tus credenciales aca en la [consola de Google](https://www.google.com/recaptcha) y copiar aca la clave de tu sitio.
- ```RECAPTCHA_SECRET_KEY=GOOGLE?RECAPTCHA_SECRET_KEY```: en la misma plataforma anterior copia la llave secreta del sitio y ponla aca. 

5. Inicializando la base de datos
El script inicial crea la base de datos al arrancar por pruimera vez con el nombre ```denuncias.db``` en la carpeta /instance.

6. Cree un usuario administrador:
```
python create_admin.py
```
Siga las indicaciones para configurar un nombre de usuario y una contraseña de administrador.

7. Ejecute el servidor de desarrollo:
```
flask run
```

8. Acceda a la aplicación en `http://localhost:5000`

## Implementación de producción

Para la implementación de producción, considere los siguientes pasos:

1. Use un servidor WSGI de nivel de producción como Gunicorn:
```
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 "run:create_app()"
```

2. Configure un proxy inverso (por ejemplo, Nginx) para manejar archivos estáticos y terminación SSL.

3. Utilice una base de datos de nivel de producción como PostgreSQL:
- Instale PostgreSQL y el paquete psycopg2
- Actualice `SQLALCHEMY_DATABASE_URI` en la clase Config para utilizar PostgreSQL

4. Configure el registro adecuado:
- Configure el registro de la aplicación para escribir en archivos
- Configure la rotación de registros

5. Utilice variables de entorno para toda la información confidencial (claves, URI de la base de datos, etc.)

6. Asegúrese de que el modo DEBUG esté desactivado en producción:
```python
app.run(debug=False)
```

7. Realice copias de seguridad periódicas de su base de datos y de los archivos cargados.

8. Configure la supervisión y las alertas para su aplicación.

9. Implemente medidas de seguridad adicionales:
- Use HTTPS
- Implemente límites de velocidad
- Establezca políticas CORS adecuadas
- Actualice las dependencias con regularidad

## Uso

- Los usuarios pueden enviar informes anónimos accediendo a la página principal y haciendo clic en "Enviar tu denuncia"
- Los administradores pueden iniciar sesión haciendo clic en el botón "Inicio de sesión de administrador" y usando sus credenciales
- Una vez que hayan iniciado sesión, los administradores pueden ver todos los informes enviados, incluidas las direcciones de correo electrónico descifradas.