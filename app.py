from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from markupsafe import Markup
import re
from flask_session import Session
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import openai
import requests
import os
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client, Client
from datetime import datetime
import pytz
from threading import Thread
import time



PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_SECRET = os.getenv("PAYPAL_SECRET")
PAYPAL_PLAN_ID = os.getenv("PAYPAL_PLAN_ID")
PAYPAL_BASE_URL = "https://api-m.paypal.com"  # Usa "api-m.paypal.com" en producción.

def get_paypal_access_token():
    url = f"{PAYPAL_BASE_URL}/v1/oauth2/token"
    headers = {"Accept": "application/json", "Accept-Language": "en_US"}
    data = {"grant_type": "client_credentials"}
    response = requests.post(url, headers=headers, auth=(PAYPAL_CLIENT_ID, PAYPAL_SECRET), data=data)
    return response.json().get("access_token")


def create_paypal_subscription():
    access_token = get_paypal_access_token()  # Asegúrate de que esta función ya funciona
    if not access_token:
        print("No se pudo obtener el access token")
        return None

    # Verifica que el plan_id esté definido y correcto
    print("Plan ID:", PAYPAL_PLAN_ID)
    url = f"{PAYPAL_BASE_URL}/v1/billing/subscriptions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    data = {
        "plan_id": PAYPAL_PLAN_ID,  
        "subscriber": {
            "name": {
                "given_name": current_user.username,
                "surname": "Apellido"
            },
            "email_address": current_user.email
        },
        "application_context": {
            "brand_name": "Spectra",
            "return_url": url_for('suscripcion_exitosa', _external=True),
            "cancel_url": url_for('suscripcion_cancelada', _external=True)
        }
    }

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 201:
        subscription = response.json()
        print("Suscripción creada:", subscription)
        return subscription
    else:
        print("Error al crear la suscripción:", response.text)
        return None



# Cargar variables de entorno
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise ValueError("Las credenciales de Supabase no están configuradas correctamente.")

# Crear cliente de Supabase
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# Configuración de Flask
app = Flask(__name__)
CORS(app)


# Configuración de la sesión
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"  # Se almacenará en archivos temporales
app.config['SESSION_COOKIE_SECURE'] = True  # Solo en HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Evita acceso por JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Reduce riesgo CSRF

Session(app)

import logging
from logging import StreamHandler

mail_handler = StreamHandler()
mail_handler.setLevel(logging.DEBUG)
app.logger.addHandler(mail_handler)

app.secret_key = os.getenv("SECRET_KEY", "1999")  # Cambia esto por una clave secreta real
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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


# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Memoria a corto plazo
short_term_memory = {}

# Modelo de usuario
class User(UserMixin):
    def __init__(self, id, username, email, is_verified, privacy_accepted, show_accept, subscription, subscription_id):
        self.id = id
        self.username = username
        self.email = email
        self.is_verified = is_verified
        self.privacy_accepted = privacy_accepted
        self.show_accept = show_accept
        self.subscription = subscription
        self.subscription_id = subscription_id





# Cargar usuario para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    response = supabase.table("users").select("*").eq("id", user_id).execute()
    user_data = response.data
    if user_data and len(user_data) > 0:
        # Pasar todos los atributos al crear el objeto User
        return User(
            user_data[0]['id'],
            user_data[0]['username'],
            user_data[0]['email'],
            user_data[0].get('is_verified', False),  # Usar .get() para evitar KeyError
            user_data[0].get('privacy_accepted', False),
            user_data[0].get('show_accept', False),
            user_data[0].get('subscription', 'free'),
            user_data[0].get('subscription_id')  # Agregado
        )
    return None



# Función para registrar usuario en Supabase
def register_user(username, email, password):
    hashed_password = generate_password_hash(password)
    try:
        response = supabase.table("users").insert({
            "username": username,
            "email": email,
            "password_hash": hashed_password,
            "is_verified": False,
            "privacy_accepted": False,
            "show_accept": False,  # Definir como False por defecto
            "subscription": "free"
        }).execute()
        if response.status_code == 201:  # Verifica que la inserción fue exitosa
            return response.data
        return None
    except Exception as e:
        print(f"Error al registrar usuario: {e}")
        return None



# Función para autenticar usuario
def get_user_by_email(email):
    try:
        response = supabase.table("users").select("*").eq("email", email).execute()
        if response.status_code == 200 and len(response.data) > 0:
            user_data = response.data[0]
            # Devuelve un objeto User con todos los atributos
            return User(
                user_data["id"],
                user_data["username"],
                user_data["email"],
                user_data.get("is_verified", False),
                user_data.get("privacy_accepted", False),
                user_data.get("show_accept", False),
                user_data.get("subscription", "free")
            )
        else:
            return None
    except Exception as e:
        print(f"Error al consultar el usuario: {e}")
        return None

def generar_weekly_letter():
    """Genera automáticamente una carta semanal con IA y la guarda en Supabase."""
    
    # Obtener la semana actual del año
    tz = pytz.timezone("UTC")  # Ajusta según tu zona horaria si es necesario
    semana_actual = datetime.now(tz).isocalendar()[1]

    # Verificar si ya existe una carta para esta semana
    response = supabase.table("weekly_letters").select("*").eq("week", semana_actual).execute()
    if response.data:
        print(f"Ya existe una carta para la semana {semana_actual}.")
        return  # No hacer nada si ya hay una carta para esta semana

    # Pedir a OpenAI que genere contenido
    prompt = (
        "Genera un artículo breve sobre bienestar emocional para una newsletter semanal. "
        "Debe incluir: (1) Un título atractivo, (2) Un subtítulo opcional, (3) Un contenido breve y útil. "
        "El tema debe ser relevante para el bienestar mental. "
        "Formato de respuesta:\n"
        "Título: [Aquí va el título]\n"
        "Subtítulo: [Aquí va el subtítulo (puede estar vacío)]\n"
        "Contenido: [Aquí va el texto principal]\n"
    )

    try:
        respuesta = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": "Eres un experto en bienestar emocional."},
                      {"role": "user", "content": prompt}]
        )
        contenido_ia = respuesta.choices[0].message.content

        # Extraer título, subtítulo y contenido
        lineas = contenido_ia.split("\n")
        titulo = lineas[0].replace("Título: ", "").strip()
        subtitulo = lineas[1].replace("Subtítulo: ", "").strip() if "Subtítulo: " in lineas[1] else ""
        contenido = "\n".join(lineas[2:]).replace("Contenido: ", "").strip()

        # Guardar en Supabase
        supabase.table("weekly_letters").insert({
            "week": semana_actual,
            "titulo": titulo,
            "subtitulo": subtitulo,
            "contenido": contenido
        }).execute()

        print(f"✅ Weekly Letter generada para la semana {semana_actual}: {titulo}")

    except Exception as e:
        print(f"❌ Error al generar la Weekly Letter: {e}")

def ejecutar_tarea_semanal():
    """Ejecuta la generación de Weekly Letter cada semana automáticamente."""
    while True:
        generar_weekly_letter()
        time.sleep(604800)  # 7 días en segundos (1 semana)



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
        existing_user_by_username = supabase.table("users").select("*").eq("username", username).execute().data
        if existing_user_by_username:
            flash("El nombre de usuario ya está en uso", "danger")
            return redirect(url_for('register'))

        # Verificar si el correo ya está registrado
        existing_user_by_email = supabase.table("users").select("*").eq("email", email).execute().data
        if existing_user_by_email:
            # Si el correo está registrado pero no verificado, reenviar el correo de confirmación
            if not existing_user_by_email[0]["is_verified"]:
                # Enviar correo de verificación
                token = serializer.dumps(email, salt="email-confirm")
                confirm_url = url_for('confirm_email', token=token, _external=True)
                msg = Message('Confirma tu correo electrónico', recipients=[email])
                msg.body = f'Haz clic en el siguiente enlace para confirmar tu correo electrónico: {confirm_url}'
                mail.send(msg)

                flash("Este correo ya está registrado. Hemos reenviado el correo de confirmación.", "info")
                return redirect(url_for('login'))

            else:
                flash("Este correo ya está registrado y verificado. Puedes iniciar sesión.", "info")
                return redirect(url_for('login'))

        # Registrar un nuevo usuario
        hashed_password = generate_password_hash(password)
        response = supabase.table("users").insert({
            "username": username,
            "email": email,
            "password_hash": hashed_password,
            "is_verified": False,
            "privacy_accepted": False,
            "show_accept": True,
            "subscription": "free"
        }).execute()

        if response.data:
            flash("Registro exitoso. Revisa tu correo para confirmar tu cuenta.", "success")
        else:
            flash("Hubo un problema al registrar tu cuenta.", "danger")
            return redirect(url_for('register'))

        # Enviar correo de verificación
        token = serializer.dumps(email, salt="email-confirm")
        confirm_url = url_for('confirm_email', token=token, _external=True)
        msg = Message('Confirma tu correo electrónico', recipients=[email])
        msg.html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; background: #f4f4f4; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2); }}
                .button {{ background: #00c6ff; color: white; padding: 12px 20px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block; margin-top: 15px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>¡Bienvenido a Spectra!</h2>
                <p>Gracias por registrarte. Para activar tu cuenta, haz clic en el botón de abajo:</p>
                <a href="{confirm_url}" class="button">Confirmar Cuenta</a>
                <p>Si no solicitaste este registro, ignora este mensaje.</p>
                <p>Atentamente,<br>El equipo de Spectra</p>
            </div>
        </body>
        </html>
        """
        mail.send(msg)

        
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt="email-confirm", max_age=3600)  # 1 hora de validez
        
        # Obtener el usuario de Supabase
        user = supabase.table("users").select("*").eq("email", email).execute().data

        if user:
            # Actualizar el estado de verificación
            response = supabase.table("users").update({"is_verified": True}).eq("email", email).execute()
            
            if response.data:  # Verificar si hubo un error en la respuesta
                flash("¡Correo confirmado exitosamente! Ahora puedes iniciar sesión.", "success")
            else:
                flash("Hubo un problema al confirmar tu correo.", "danger")
            return redirect(url_for('login'))
        else:
            flash("Usuario no encontrado.", "danger")
            return redirect(url_for('register'))

    except SignatureExpired:
        flash("El enlace de confirmación ha expirado. Regístrate nuevamente.", "danger")
        return redirect(url_for('register'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        # Obtener el usuario de Supabase
        user = supabase.table("users").select("*").eq("email", email).execute().data

        if user:
            # Generar token de recuperación
            token = serializer.dumps(email, salt='recover-password')

            # Crear enlace de recuperación de contraseña
            reset_url = url_for('reset_password', token=token, _external=True)

            # Enviar el correo de recuperación
            msg = Message('Restablece tu contraseña en Spectra', recipients=[email])
            msg.html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ 
                      font-family: Arial, sans-serif; 
                      text-align: center;
                      background: #f4f4f4; 
                      padding: 20px; 
                    }}
                    .container {{ 
                      max-width: 600px;
                      margin: auto; 
                      background: white; 
                      padding: 20px; 
                      border-radius: 10px;
                      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2); 
                    }}
                    .button {{ 
                      background: #00c6ff; 
                      color: white; 
                      padding: 12px 20px; 
                      text-decoration: none; 
                      border-radius: 5px; 
                      font-weight: bold; 
                      display: inline-block; 
                      margin-top: 15px; 
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Restablece tu contraseña</h2>
                    <p>Parece que solicitaste un cambio de contraseña. Haz clic en el botón de abajo para continuar:</p>
                    <a href="{reset_url}" class="button">Restablecer Contraseña</a>
                    <p>Si no solicitaste este cambio, ignora este mensaje.</p>
                    <p>Atentamente,<br>El equipo de Spectra</p>
                </div>
            </body>
            </html>
            """
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

    # Obtener el usuario desde Supabase
    user = supabase.table("users").select("*").eq("email", email).execute().data

    if not user:
        flash('No se pudo encontrar un usuario con ese correo electrónico.', 'danger')
        return redirect(url_for('forgot_password'))  # Redirigir a la página de solicitud de recuperación

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_new_password']

        # Verificar que las contraseñas coinciden
        if new_password != confirm_password:
            flash('Las contraseñas no coinciden. Intenta de nuevo.', 'danger')
            return render_template('reset_password.html', token=token)

        if user:
            # Actualizar la contraseña en Supabase
            hashed_password = generate_password_hash(new_password)
            response = supabase.table("users").update({"password_hash": hashed_password}).eq("email", email).execute()

            if response.data:
                flash('Tu contraseña ha sido actualizada exitosamente.', 'success')
                return redirect(url_for('login'))  # Redirigir a la página de login después de la actualización
            else:
                flash('Hubo un problema al actualizar tu contraseña.', 'danger')
                return redirect(url_for('forgot_password'))  # Si no se pudo actualizar, redirigir a recuperar contraseña
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

    # Actualizar el plan de suscripción en Supabase
    response = supabase.table("users").update({
        "subscription": plan
    }).eq("email", current_user.email).execute()

    if response.data:
        return redirect(url_for('chat'))  # Lleva al usuario al chat después de elegir el plan
    else:
        flash("Hubo un problema al cambiar el plan de suscripción.", "danger")
        return redirect(url_for('suscripcion'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']  # Puede ser username o email
        password = request.form['password']
        
        # Buscar por username o email
        user_data = supabase.table("users").select("*").eq("email", identifier).execute().data

        if not user_data:  # Si no se encuentra por email, buscar por username
            user_data = supabase.table("users").select("*").eq("username", identifier).execute().data

        if not user_data:  # Si no hay datos, mostrar error
            flash("Usuario no encontrado", "danger")
            return redirect(url_for('login'))
        
        user = user_data[0]  # Obtener el primer resultado de la consulta
        
        # Verificar la contraseña
        if not check_password_hash(user["password_hash"], password):
            flash("Contraseña incorrecta", "danger")
            return redirect(url_for('login'))

        # Verificar si el usuario está verificado
        if not user["is_verified"]:
            flash("Debes confirmar tu correo antes de iniciar sesión.", "danger")
            return redirect(url_for('login'))

        # Eliminar cuentas duplicadas por email
        duplicate_users = supabase.table("users").select("*").eq("email", identifier).execute().data
        if len(duplicate_users) > 1:
            duplicate_users.sort(key=lambda u: u["id"])  # Ordenar por ID
            for duplicate in duplicate_users[1:]:  # Mantener el primero y borrar los demás
                supabase.table("users").delete().eq("id", duplicate["id"]).execute()

        # Crear instancia de usuario
        user_obj = User(
            user["id"], 
            user["username"], 
            user["email"], 
            user.get("is_verified", False), 
            user.get("privacy_accepted", False), 
            user.get("show_accept", False), 
            user.get("subscription", "free"),
            user.get("subscription_id")  # Esto puede ser None si no se ha registrado una suscripción
        )  # Asumo que User toma estos argumentos
        print(f"ID: {user['id']}, Username: {user['username']}, Email: {user['email']}")
        login_user(user_obj)

        # Verificar si ha aceptado la política de privacidad
        if not user["privacy_accepted"]:
            return redirect(url_for('privacy'))

        # Redirigir según el plan de suscripción
        if not user["subscription"] or user["subscription"] == "free":
            return redirect(url_for('suscripcion'))
        else:
            return redirect(url_for('chat'))

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
    # return render_template('privacy.html')
    return render_template('privacy.html', show_accept=current_user.show_accept)

@app.route('/accept_privacy', methods=['GET', 'POST'])
@login_required
def accept_privacy():
    # Actualizar los valores de privacidad en Supabase
    response = supabase.table("users").update({
        "privacy_accepted": True,
        "show_accept": False
    }).eq("email", current_user.email).execute()

    if response.data:
        flash("Has aceptado la política de privacidad", "success")
        return redirect(url_for('suscripcion'))
    else:
        flash("Hubo un problema al aceptar la política de privacidad", "danger")
        return redirect(url_for('suscripcion'))


@app.route('/suscripcion', methods=['GET', 'POST'])
@login_required  # Proteger la vista
def suscripcion():
    paypal_client_id = os.getenv("PAYPAL_CLIENT_ID")  # Obtén el Client ID de PayPal desde las variables de entorno
    
    if request.method == 'POST':
        plan = request.form.get('plan')  # Obtener el plan seleccionado (free o premium)
        
        if plan == 'free':
            current_user.subscription = 'free'  # Guardamos el plan gratuito en la base de datos
        elif plan == 'premium':
            current_user.subscription = 'premium'  # Guardamos el plan premium en la base de datos
        
        response = supabase.table("users").update({"subscription": plan}).eq("id", current_user.id).execute()
        
        # Verificar si la respuesta contiene datos válidos
        if response.data:
            flash("Suscripción actualizada.", "success")
        else:
            flash("Hubo un error al actualizar la suscripción.", "danger")

        # Redirigir al chat o al lugar correspondiente según el plan
        if plan == 'free':
            return redirect(url_for('chat'))  # O la ruta que corresponde al chat
        else:
            return redirect(url_for('chat'))  # O la ruta que corresponde al chat
       
    return render_template('suscripcion.html', subscription_actual=current_user.subscription, paypal_client_id=paypal_client_id)
  # Página de suscripción


@app.route('/suscription2')
def suscription2():
    return render_template('suscripcion2.html') 

@app.route('/respiracion')
@login_required
def respiracion():
    return render_template('respiracion.html')  # Página de respiración guiada

@app.route('/iphone-version')
@login_required
def iphone_version():
    return render_template("iphone.html")  # Crea un archivo iphone.html

@app.route("/android-version")
@login_required
def android_version():
    return render_template("android.html")


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
            messages = [
              {
                "role": "system",
                "content": (
                   "Eres Spectra, una inteligencia artificial diseñada para brindar apoyo emocional. " 
                   "Fuiste creada por Samuel Expósito. Debes escuchar activamente, responder con empatía y validar emociones. "
                   "Utiliza técnicas de clarificación, paráfrasis y reflejo para ayudar al usuario a expresarse mejor. "
                   "Intenta ser breve en tus respuestas y simular una conversación hablada real"
                   "Formula preguntas abiertas (solo una pregunta por cada mensaje) para fomentar la reflexión. Antes de finalizar la conversación, realiza una breve síntesis de la conversación y sugiere un ejercicio de autoayuda. " 
                )
              }
            ]
            
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

@app.route('/actualizar_suscripcion', methods=['POST'])
def actualizar_suscripcion():
    data = request.get_json()
    subscription_id = data.get('subscriptionID')
    # user_id = request.cookies.get('user_id')  
    # Ajusta según cómo identifiques al usuario
    user_id = current_user.id
    if not subscription_id or not user_id:
        return jsonify({"success": False, "error": "Datos insuficientes"}), 400

    # Actualiza la suscripción en Supabase
    try:
        response = supabase.table("users").update({"subscription": "premium", "subscription_id": data.get('subscriptionID')}).eq("id", user_id).execute()
        return jsonify({"success": True})
    except Exception as e:
        print("Error actualizando suscripción:", e)
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/suscripcion_exitosa')
@login_required
def suscripcion_exitosa():
    # Aquí puedes verificar el estado de la suscripción y actualizar en Supabase
    supabase.table("users").update({"subscription": "premium"}).eq("id", current_user.id).execute()
    flash("¡Suscripción exitosa!", "success")
    return redirect(url_for('chat'))

@app.route('/suscripcion_cancelada')
@login_required
def suscripcion_cancelada():
    flash("La suscripción fue cancelada.", "danger")
    return redirect(url_for('suscripcion'))

@app.route('/popit')
@login_required
def popit():
    return render_template('popit.html')

@app.route('/cancelar_suscripcion', methods=['POST'])
@login_required
def cancelar_suscripcion():
    # Suponiendo que almacenas el ID de suscripción en el usuario, por ejemplo en current_user.subscription_id
    subscription_id = current_user.subscription_id  
    if not subscription_id:
        return jsonify({"success": False, "error": "No hay suscripción activa."}), 400

    access_token = get_paypal_access_token()
    url = f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}/cancel"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    data = {
        "reason": "El usuario canceló su suscripción."
    }
    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 204:  # 204 No Content indica éxito
        # Actualiza el estado de la suscripción en Supabase (por ejemplo, a "free" o "canceled")
        supabase.table("users").update({"subscription": "free", "subscription_id": None}).eq("id", current_user.id).execute()
        return jsonify({"success": True})
    else:
        print("Error al cancelar la suscripción:", response.text)
        return jsonify({"success": False, "error": response.text}), 500

@app.route('/weekly')
@login_required
def weekly():
    """Muestra la carta de la semana actual."""
    
    semana_actual = datetime.now(pytz.UTC).isocalendar()[1]
    response = supabase.table("weekly_letters").select("*").eq("week", semana_actual).execute()
    
    if response.data:
        weekly_letter = response.data[0]
        return render_template('weekly.html', titulo=weekly_letter['titulo'], subtitulo=weekly_letter['subtitulo'], contenido=weekly_letter['contenido'])
    else:
        return render_template('weekly.html', titulo="Aún no hay contenido", subtitulo="", contenido="La carta de esta semana aún no ha sido generada.")

with app.app_context():
    print("🔹 Ejecutando Weekly Letter al iniciar la app...")
    generar_weekly_letter()

@app.template_filter('format_weekly')
def format_weekly(text):
    """Reemplaza saltos de línea con <br> y **negritas** con <b>"""
    if not text:
        return ""
    
    # Reemplazar saltos de línea por <br>
    text = text.replace("\n", "<br>")

    # Reemplazar **palabra** por <b>palabra</b>
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)

    return Markup(text)

# Obtener la clave de API de OpenAI desde las variables de entorno
openai.api_key = os.getenv("OPENAI_API_KEY")

if __name__ == '__main__':
    print("🔹 Iniciando ejecución de Weekly Letter en el arranque...")
    Thread(target=ejecutar_tarea_semanal, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
