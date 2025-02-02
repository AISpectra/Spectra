from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_session import Session
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import openai
from dotenv import load_dotenv
import os
from flask_cors import CORS

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# Configuración de Flask
app = Flask(__name__)
CORS(app)


# Configuración de la sesión
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"  # Se almacenará en archivos temporales
Session(app)

import logging
from logging import StreamHandler

mail_handler = StreamHandler()
mail_handler.setLevel(logging.DEBUG)
app.logger.addHandler(mail_handler)

app.secret_key = os.getenv("SECRET_KEY", "1999")  # Cambia esto por una clave secreta real
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de Flask-Mail usando variables de entorno
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Leer desde el archivo .env
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Leer desde el archivo .env
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')  # Usar el mismo correo para el remitente
app.config['MAIL_ASCII_ATTACHMENTS'] = False

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Base de datos
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Memoria a corto plazo
short_term_memory = {}

# Modelo de usuario
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)  # Nombre de usuario único
    email = db.Column(db.String(150), unique=True, nullable=False)  # Correo único
    password = db.Column(db.String(150), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)  # Verificación de correo
    privacy_accepted = db.Column(db.Boolean, default=False)
    subscription = db.Column(db.String(10), default="free")

# Cargar usuario para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rutas

@app.route('/inicio')
def inicio():
    return render_template('inicio.html')  # Página de inicio

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Verificar si el nombre de usuario ya está en uso
        if User.query.filter_by(username=username).first():
            flash("El nombre de usuario ya está en uso", "danger")
        # Verificar si el correo ya está registrado
        elif User.query.filter_by(email=email).first():
            existing_user = User.query.filter_by(email=email).first()
            # Si el correo está registrado pero no verificado, reenviar el correo de confirmación
            if not existing_user.is_verified:
                # Enviar correo de verificación
                token = serializer.dumps(email, salt="email-confirm")
                confirm_url = url_for('confirm_email', token=token, _external=True)
                msg = Message('Confirma tu correo electrónico', recipients=[email])
                msg.body = f'Haz clic en el siguiente enlace para confirmar tu correo electrónico: {confirm_url}'
                mail.send(msg)

                flash("Este correo ya está registrado. Hemos reenviado el correo de confirmación.", "info")
                return redirect(url_for('login'))
        else:
            # Registrar un nuevo usuario
            new_user = User(username=username, email=email, password=password)  # Hash la contraseña para producción
            db.session.add(new_user)
            db.session.commit()

            # Enviar correo de verificación
            token = serializer.dumps(email, salt="email-confirm")
            confirm_url = url_for('confirm_email', token=token, _external=True)
            msg = Message('Confirma tu correo electrónico', recipients=[email])
            msg.body = f'Haz clic en el siguiente enlace para confirmar tu correo electrónico: {confirm_url}'
            mail.send(msg)

            flash("Registro exitoso. Revisa tu correo para confirmar tu cuenta.", "success")
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt="email-confirm", max_age=3600)  # 1 hora de validez
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            db.session.commit()
            flash("¡Correo confirmado exitosamente! Ahora puedes iniciar sesión.", "success")
            return redirect(url_for('login'))
    except SignatureExpired:
        flash("El enlace de confirmación ha expirado. Regístrate nuevamente.", "danger")
        return redirect(url_for('register'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # Generar token de recuperación
            token = serializer.dumps(email, salt='recover-password')

            # Crear enlace de recuperación de contraseña
            reset_url = url_for('reset_password', token=token, _external=True)

            # Enviar el correo de recuperación
            msg = Message('Recuperación de contraseña',
                          recipients=[email],
                          body=f'Para cambiar tu contraseña, haz clic en el siguiente enlace: {reset_url}')
            mail.send(msg)

            flash('Te hemos enviado un enlace para recuperar tu contraseña.', 'info')
            return redirect(url_for('login'))
        else:
            flash('No encontramos una cuenta con ese correo electrónico.', 'danger')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Verificar el token
        email = serializer.loads(token, salt='recover-password', max_age=3600)  # El token caduca en 1 hora
    except SignatureExpired:
        flash('El enlace de recuperación ha caducado.', 'danger')
        return redirect(url_for('forgot_password'))  # Redirige a la página de solicitud de recuperación

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_new_password']
        user = User.query.filter_by(email=email).first()

        # Verificar que las contraseñas coinciden
        if new_password != confirm_password:
            flash('Las contraseñas no coinciden. Intenta de nuevo.', 'danger')
            return render_template('reset_password.html', token=token)

        if user:
            # Si no quieres encriptar la contraseña, simplemente actualiza el campo sin encriptar
            user.password = new_password  # No encriptamos la contraseña en este caso
            db.session.commit()  # Guardar los cambios
            flash('Tu contraseña ha sido actualizada exitosamente.', 'success')
            return redirect(url_for('login'))  # Redirigir a la página de login después de la actualización
        else:
            flash('No se pudo encontrar un usuario con ese correo electrónico.', 'danger')
    
    return render_template('reset_password.html', token=token)

@app.route('/select_subscription', methods=['POST'])
@login_required
def select_subscription():
    plan = request.form.get('plan')  # 'free' o 'premium'

    if plan not in ['free', 'premium']:
        flash("Selección inválida.", "danger")
        return redirect(url_for('suscripcion'))

    current_user.subscription = plan
    db.session.commit()

    return redirect(url_for('chat'))  # Lleva al usuario al chat después de elegir el plan


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']  # Puede ser username o email
        password = request.form['password']
        
        # Buscar por username o email
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        
        if user and user.password == password:  # Para producción, usa un hash seguro
            if not user.is_verified:
                flash("Debes confirmar tu correo antes de iniciar sesión.", "danger")
                return redirect(url_for('login'))
            
            login_user(user)

            # Si el usuario no tiene un plan guardado, enviarlo a suscripción
            if not user.subscription or user.subscription == "free":
                return redirect(url_for('suscripcion'))

            # Si el usuario tiene el plan premium, enviarlo directamente al chat
            return redirect(url_for('chat'))
        
        flash("Nombre de usuario/correo o contraseña incorrectos", "danger")

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('inicio')) 

@app.route('/privacy')
@login_required
def privacy():
    return render_template('privacy.html')

@app.route('/accept_privacy', methods=['POST'])
@login_required
def accept_privacy():
    current_user.privacy_accepted = True
    db.session.commit()
    flash("Has aceptado la política de privacidad", "success")
    return redirect(url_for('index'))
    return render_template('privacy.html', show_accept=not current_user.privacy_accepted)

@app.route('/suscripcion', methods=['GET', 'POST'])
def suscripcion():
    if request.method == 'POST':
        plan = request.form.get('plan')  # Obtener el plan seleccionado (free o premium)
        
        if plan == 'free':
            current_user.subscription = 'free'  # Guardamos el plan gratuito en la base de datos
        elif plan == 'premium':
            current_user.subscription = 'premium'  # Guardamos el plan premium en la base de datos
        
        db.session.commit()  # Confirmar los cambios en la base de datos
        
        # Redirigir al chat o al lugar correspondiente según el plan
        if plan == 'free':
            return redirect(url_for('chat'))  # O la ruta que corresponde al chat
        else:
            return redirect(url_for('chat'))  # O la ruta que corresponde al chat
       
    return render_template('suscripcion.html', subscription_actual=current_user.subscription)
  # Página de suscripción

@app.route('/weekly')
@login_required
def weekly():
    return render_template('weekly.html')  # Página semanal

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        try:
            user_input = request.json['message']
            user_id = current_user.id

            # Inicializar memoria a corto plazo si no existe
            if user_id not in short_term_memory:
                short_term_memory[user_id] = []

            # Control de interacciones diarias
            if current_user.subscription == 'free':
                today = datetime.now().strftime("%Y-%m-%d")
                if 'chat_interactions' not in session:
                    session['chat_interactions'] = {'count': 0, 'last_date': today}
                
                if session['chat_interactions']['last_date'] != today:
                    session['chat_interactions']['count'] = 0
                    session['chat_interactions']['last_date'] = today
                
                if session['chat_interactions']['count'] >= 10:
                    return jsonify({"response": "Has alcanzado el límite de 10 mensajes diarios. Actualiza tu plan para continuar."})

            # Construir contexto con memoria a corto plazo
            messages = [{"role": "system", "content": "Te llamas Spectra, estas ofreciendo una sesion de apoyo emocional, cuando hagas preguntas realiza solo una pregunta por mensaje, intenta que tus preguntas sean exploratorias, utiliza mensajes cortos y sencillos..."}]
            
            messages.extend(short_term_memory[user_id])  # Agregar historial reciente
            messages.append({"role": "user", "content": user_input})

            # Llamar a la API de OpenAI
            response = openai.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=messages
            )

            # Extraer respuesta del chatbot
            bot_response = response.choices[0].message.content
            print("Respuesta de OpenAI:", bot_response)

            # Actualizar memoria a corto plazo
            short_term_memory[user_id].append({"role": "user", "content": user_input})
            short_term_memory[user_id].append({"role": "assistant", "content": bot_response})

            # Limitar tamaño de memoria
            if len(short_term_memory[user_id]) > 10:
                short_term_memory[user_id] = short_term_memory[user_id][-10:]

            # Incrementar el contador de interacciones para usuarios gratuitos
            if current_user.subscription == 'free':
                session['chat_interactions']['count'] += 1

            return jsonify({"response": bot_response})
        except Exception as e:
            print("Excepción general:", e)
            return jsonify({"error": "Hubo un problema al procesar tu solicitud."}), 500

    # Si es un GET, mostrar la interfaz del chat
    return render_template('chat.html', subscription=current_user.subscription)

# Configurar base de datos antes de la primera ejecución
with app.app_context():
    db.create_all()

# Obtener la clave de API de OpenAI desde las variables de entorno
openai.api_key = os.getenv("OPENAI_API_KEY")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
