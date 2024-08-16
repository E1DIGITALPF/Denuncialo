import os
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import requests
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import random
import string

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///denuncias.db'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY') or Fernet.generate_key()
    RECAPTCHA_SITE_KEY = os.environ.get('RECAPTCHA_SITE_KEY')
    RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Denuncia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=True)
    denuncia = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    encrypted_email = db.Column(db.LargeBinary, nullable=True)
    verification_code = db.Column(db.String(10), unique=True, nullable=False)
    image_filenames = db.Column(db.Text, nullable=True)

    def get_decrypted_email(self, cipher_suite):
        if self.encrypted_email:
            return cipher_suite.decrypt(self.encrypted_email).decode()
        return None

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = 'login'

    cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.route('/')
    def index():
        return redirect(url_for('dashboard'))

    @app.route('/dashboard')
    def dashboard():
        denuncias = Denuncia.query.order_by(Denuncia.timestamp.desc()).all()
        verification_message = session.pop('verification_message', None)
        return render_template('dashboard.html', denuncias=denuncias, verification_message=verification_message)

    @app.route('/submit', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def submit_denuncia():
        if request.method == 'POST':
            try:
                name = request.form.get('name', '')
                email = request.form.get('email', '')
                denuncia = request.form['denuncia']
                
                uploaded_files = request.files.getlist("images")
                image_filenames = []
                for file in uploaded_files:
                    if file and allowed_file(file.filename, app.config['ALLOWED_EXTENSIONS']):
                        filename = secure_filename(file.filename)
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)
                        image_filenames.append(filename)

                recaptcha_response = request.form['g-recaptcha-response']
                if not verify_recaptcha(recaptcha_response, app.config['RECAPTCHA_SECRET_KEY']):
                    flash('Verificación de reCAPTCHA fallida. Por favor, inténtelo de nuevo.', 'error')
                    return redirect(url_for('submit_denuncia'))

                if not denuncia:
                    flash('La denuncia no puede estar vacía.', 'error')
                    return redirect(url_for('submit_denuncia'))

                encrypted_email = cipher_suite.encrypt(email.encode()) if email else None
                verification_code = generate_verification_code()

                new_denuncia = Denuncia(
                    name=name, 
                    denuncia=denuncia, 
                    encrypted_email=encrypted_email,
                    verification_code=verification_code,
                    image_filenames=','.join(image_filenames)
                )
                db.session.add(new_denuncia)
                db.session.commit()

                session['verification_message'] = f'Denuncia enviada de manera segura. Su código de verificación es: {verification_code}'
                return redirect(url_for('dashboard'))

            except Exception as e:
                app.logger.error(f"Error submitting denuncia: {str(e)}")
                flash('Ocurrió un error al enviar la denuncia. Por favor, inténtelo de nuevo.', 'error')
                return redirect(url_for('submit_denuncia'))

        return render_template('denuncia_form.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

    @app.route('/uploads/<filename>')
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('view_denuncias'))
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            recaptcha_response = request.form['g-recaptcha-response']
            
            if not verify_recaptcha(recaptcha_response, app.config['RECAPTCHA_SECRET_KEY']):
                flash('reCAPTCHA verification failed. Please try again.', 'error')
                return redirect(url_for('login'))
            
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('view_denuncias'))
            flash('Invalid username or password', 'error')
        return render_template('login.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))

    @app.route('/view_denuncias')
    @login_required
    def view_denuncias():
        denuncias = Denuncia.query.all()
        decrypted_emails = {denuncia.id: denuncia.get_decrypted_email(cipher_suite) for denuncia in denuncias}
        return render_template('view_denuncias.html', denuncias=denuncias, decrypted_emails=decrypted_emails)

    return app

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def verify_recaptcha(recaptcha_response, secret_key):
    recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {
        'secret': secret_key,
        'response': recaptcha_response
    }
    response = requests.post(recaptcha_url, data=payload)
    result = response.json()
    return result.get('success', False)

def generate_verification_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

def init_app():
    app = create_app()
    with app.app_context():
        db.create_all()
    
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.mkdir(app.config['UPLOAD_FOLDER'])

    return app

if __name__ == "__main__":
    app = init_app()
    app.run(debug=True)