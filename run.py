from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import os
import requests
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///denuncias.db'
db = SQLAlchemy(app)

ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', 'default_encryption_key')
cipher_suite = Fernet(ENCRYPTION_KEY.encode())

class Denuncia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=True)
    denuncia = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    encrypted_email = db.Column(db.LargeBinary, nullable=True)

    def get_encrypted_email(self):
        if self.encrypted_email:
            return cipher_suite.decrypt(self.encrypted_email).decode()
        return None

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    denuncias = Denuncia.query.order_by(Denuncia.timestamp.desc()).all()
    for denuncia in denuncias:
        denuncia.encrypted_email = denuncia.encrypted_email.decode('utf-8')
    return render_template('dashboard.html', denuncias=denuncias)

@app.route('/submit', methods=['GET', 'POST'])
def submit_denuncia():
    if request.method == 'POST':
        try:
            name = request.form.get('name', '')
            email = request.form.get('email', '')
            denuncia = request.form['denuncia']
        except KeyError as e:
            flash(f'Campo faltante: {e}', 'error')
            return redirect(url_for('submit_denuncia'))

        recaptcha_response = request.form['g-recaptcha-response']
        secret_key = os.getenv('RECAPTCHA_SECRET_KEY')

        recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
        payload = {
            'secret': secret_key,
            'response': recaptcha_response
        }
        response = requests.post(recaptcha_url, data=payload)
        result = response.json()

        if not result.get('success'):
            flash('Verificación de reCAPTCHA fallida. Por favor, inténtelo de nuevo.', 'error')
            return redirect(url_for('submit_denuncia'))

        if not denuncia:
            flash('La denuncia no puede estar vacía.', 'error')
            return redirect(url_for('submit_denuncia'))

        encrypted_email = cipher_suite.encrypt(email.encode()) if email else None

        new_denuncia = Denuncia(name=name, denuncia=denuncia, encrypted_email=encrypted_email)
        db.session.add(new_denuncia)
        db.session.commit()

        flash('Denuncia enviada de manera segura.', 'success')
        return redirect(url_for('dashboard'))

    site_key = os.getenv('RECAPTCHA_SITE_KEY')
    return render_template('denuncia_form.html', site_key=site_key)

if __name__ == "__main__":
    app.run(debug=True)