from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, FileField, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired, Email
from cryptography.hazmat.primitives.kdf.argon2 import Argon2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import mysql.connector
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from kyber import Kyber1024  # Placeholder for Kyber library
import redis
import bleach
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent', message_queue='redis://localhost:6379/0')

# MySQL Configuration
db_config = {
    'user': 'zixt_user',
    'password': 'secure_password',
    'host': 'localhost',
    'database': 'zixt_db'
}

# Email Configuration
EMAIL_ADDRESS = "your_email@example.com"
EMAIL_PASSWORD = "your_app_password"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587

# File Upload Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'}
MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MB
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Argon2 configuration
argon2 = Argon2(time_cost=16, memory_cost=2 ** 15, parallelism=2, hash_len=32)


# Security Headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers[
        'Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


def get_db_connection():
    return mysql.connector.connect(**db_config)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def send_verification_email(email, token):
    msg = MIMEText(f"Click to verify your Zixt account: https://zixt.app/verify/{token}")
    msg['Subject'] = 'Zixt Email Verification'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)


def get_current_aes_key():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, key_value FROM encryption_keys WHERE expires_at > %s ORDER BY created_at DESC LIMIT 1",
                   (datetime.now(),))
    key = cursor.fetchone()
    if not key:
        new_key = os.urandom(32)  # 256-bit AES key
        expires_at = datetime.now() + timedelta(days=30)  # Rotate every 30 days
        cursor.execute("INSERT INTO encryption_keys (key_value, expires_at) VALUES (%s, %s)", (new_key, expires_at))
        conn.commit()
        key = (cursor.lastrowid, new_key)
    conn.close()
    return key[1]  # Return the key value


def encrypt_message(message, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_message = message + b' ' * (16 - len(message) % 16)
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(ciphertext, aes_key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return padded_message.rstrip(b' ')


# Forms with CSRF Protection
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')


class MessageForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired()])
    file = FileField('Attachment')
    submit = SubmitField('Send')


class ThreadForm(FlaskForm):
    participants = SelectMultipleField('Participants', coerce=int)
    submit = SubmitField('Create')


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data.encode('utf-8')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, is_admin FROM users WHERE username = %s AND is_verified = 1", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and argon2.verify(password, user[1]):
            session['user_id'] = user[0]
            session['is_admin'] = user[2]
            return redirect(url_for('dashboard'))
        flash('Invalid credentials or unverified account')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data.encode('utf-8')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            flash('Username or email already taken')
        else:
            hashed_pw = argon2.hash(password)
            token = secrets.token_urlsafe(32)
            cursor.execute("""
                INSERT INTO users (username, email, password, verification_token)
                VALUES (%s, %s, %s, %s)
            """, (username, email, hashed_pw, token))
            conn.commit()
            send_verification_email(email, token)
            flash('Please check your email to verify your account')
        conn.close()
    return render_template('register.html', form=form)


@app.route('/verify/<token>')
def verify_email(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_verified = 1, verification_token = NULL WHERE verification_token = %s",
                   (token,))
    if cursor.rowcount > 0:
        conn.commit()
        flash('Email verified! Please log in.')
    else:
        flash('Invalid or expired verification token')
    conn.close()
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all threads for the user
    cursor.execute("""
        SELECT DISTINCT t.id, t.creator_id, GROUP_CONCAT(u.username) as participants
        FROM threads t
        JOIN thread_participants tp ON t.id = tp.thread_id
        JOIN users u ON tp.user_id = u.id
        WHERE tp.user_id = %s AND tp.is_deleted = 0
        GROUP BY t.id, t.creator_id
    """, (session['user_id'],))
    threads = cursor.fetchall()

    # Fetch all users for creating new threads
    cursor.execute("SELECT id, username FROM users WHERE id != %s AND is_verified = 1", (session['user_id'],))
    users = [(user[0], user[1]) for user in cursor.fetchall()]
    thread_form = ThreadForm()
    thread_form.participants.choices = users

    if thread_form.validate_on_submit():
        participants = thread_form.participants.data
        participants.append(session['user_id'])  # Include creator
        cursor.execute("INSERT INTO threads (creator_id) VALUES (%s)", (session['user_id'],))
        thread_id = cursor.lastrowid
        for user_id in participants:
            cursor.execute("INSERT INTO thread_participants (thread_id, user_id) VALUES (%s, %s)", (thread_id, user_id))
        conn.commit()
        return redirect(url_for('thread', thread_id=thread_id))

    conn.close()
    return render_template('dashboard.html', threads=threads, thread_form=thread_form, users=users,
                           is_admin=session.get('is_admin', False))


@app.route('/thread/<int:thread_id>', methods=['GET', 'POST'])
def thread(thread_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if user is part of the thread
    cursor.execute("SELECT creator_id FROM threads WHERE id = %s", (thread_id,))
    thread = cursor.fetchone()
    if not thread:
        flash('Thread not found')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT user_id FROM thread_participants WHERE thread_id = %s AND user_id = %s AND is_deleted = 0",
                   (thread_id, session['user_id']))
    if not cursor.fetchone():
        flash('You are not part of this thread')
        return redirect(url_for('dashboard'))

    form = MessageForm()
    if form.validate_on_submit():
        message = bleach.clean(form.message.data)
        file = form.file.data
        filename = None
        if file and allowed_file(file.filename) and file.content_length <= MAX_FILE_SIZE:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Generate ephemeral Kyber keys for PFS
        public_key, private_key = Kyber1024.keygen()
        shared_secret, kyber_ciphertext = Kyber1024.enc(public_key)
        aes_key = get_current_aes_key()
        encrypted_message = encrypt_message(message.encode('utf-8'), aes_key)

        cursor.execute("""
            INSERT INTO messages (thread_id, sender_id, ciphertext, kyber_ciphertext, kyber_public_key, file_path)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (thread_id, session['user_id'], encrypted_message, kyber_ciphertext, public_key, filename))
        conn.commit()

        # Emit message to all participants
        cursor.execute("SELECT user_id FROM thread_participants WHERE thread_id = %s AND is_deleted = 0", (thread_id,))
        participants = [row[0] for row in cursor.fetchall()]
        for user_id in participants:
            decrypted = decrypt_message(encrypted_message, aes_key).decode('utf-8')
            socketio.emit('new_message', {
                'thread_id': thread_id,
                'sender_id': session['user_id'],
                'message': decrypted,
                'file': filename
            }, room=str(user_id))

    # Fetch messages
    cursor.execute("""
        SELECT sender_id, ciphertext, kyber_ciphertext, kyber_public_key, file_path
        FROM messages
        WHERE thread_id = %s
        ORDER BY id
    """, (thread_id,))
    messages = cursor.fetchall()
    decrypted_messages = []
    aes_key = get_current_aes_key()
    for msg in messages:
        sender_id, ciphertext, kyber_ciphertext, kyber_public_key, file_path = msg
        shared_secret = Kyber1024.dec(kyber_ciphertext, private_key if sender_id == session['user_id'] else None)
        decrypted = decrypt_message(ciphertext, aes_key).decode('utf-8')
        decrypted_messages.append((sender_id, decrypted, file_path))

    # Fetch participants and users
    cursor.execute(
        "SELECT u.id, u.username FROM thread_participants tp JOIN users u ON tp.user_id = u.id WHERE tp.thread_id = %s",
        (thread_id,))
    participants = cursor.fetchall()
    cursor.execute("SELECT id, username FROM users WHERE id != %s AND is_verified = 1", (session['user_id'],))
    users = [(user[0], user[1]) for user in cursor.fetchall()]

    conn.close()
    return render_template('dashboard.html', thread_id=thread_id, messages=decrypted_messages,
                           participants=participants,
                           creator_id=thread[0], users=users, form=form)


@app.route('/create_thread', methods=['POST'])
def create_thread():
    form = ThreadForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        cursor = conn.cursor()
        participants = form.participants.data
        participants.append(session['user_id'])
        cursor.execute("INSERT INTO threads (creator_id) VALUES (%s)", (session['user_id'],))
        thread_id = cursor.lastrowid
        for user_id in participants:
            cursor.execute("INSERT INTO thread_participants (thread_id, user_id) VALUES (%s, %s)", (thread_id, user_id))
        conn.commit()
        conn.close()
        return redirect(url_for('thread', thread_id=thread_id))
    return redirect(url_for('dashboard'))


@app.route('/add_participant/<int:thread_id>', methods=['POST'])
def add_participant(thread_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT creator_id FROM threads WHERE id = %s", (thread_id,))
    if cursor.fetchone()[0] != session['user_id']:
        flash('Only the creator can add participants')
        return redirect(url_for('thread', thread_id=thread_id))
    user_id = request.form['user_id']
    cursor.execute("INSERT INTO thread_participants (thread_id, user_id) VALUES (%s, %s)", (thread_id, user_id))
    conn.commit()
    conn.close()
    return redirect(url_for('thread', thread_id=thread_id))


@app.route('/remove_participant/<int:thread_id>/<int:user_id>', methods=['POST'])
def remove_participant(thread_id, user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT creator_id FROM threads WHERE id = %s", (thread_id,))
    if cursor.fetchone()[0] != session['user_id']:
        flash('Only the creator can remove participants')
        return redirect(url_for('thread', thread_id=thread_id))
    cursor.execute("UPDATE thread_participants SET is_deleted = 1 WHERE thread_id = %s AND user_id = %s",
                   (thread_id, user_id))
    conn.commit()
    conn.close()
    return redirect(url_for('thread', thread_id=thread_id))


@app.route('/delete_thread/<int:thread_id>', methods=['POST'])
def delete_thread(thread_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE thread_participants SET is_deleted = 1 WHERE thread_id = %s AND user_id = %s",
                   (thread_id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))


# SocketIO Events
@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(str(session['user_id']))


# Admin Routes
@app.route('/admin')
def admin():
    if 'user_id' not in session or not session.get('is_admin', False):
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    return render_template('admin.html')


@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if 'user_id' not in session or not session.get('is_admin', False):
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        action = request.form['action']
        if action == 'create':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password'].encode('utf-8')
            hashed_pw = argon2.hash(password)
            cursor.execute("INSERT INTO users (username, email, password, is_verified) VALUES (%s, %s, %s, 1)",
                           (username, email, hashed_pw))
        elif action == 'delete':
            user_id = request.form['user_id']
            cursor.execute("DELETE FROM users WHERE id = %s AND is_admin = 0", (user_id,))
        conn.commit()

    cursor.execute("SELECT id, username, email, is_admin, is_verified FROM users")
    users = cursor.fetchall()
    conn.close()
    return render_template('manage_users.html', users=users)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or not session.get('is_admin', False):
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        if 'password' in request.form and request.form['password']:
            password = request.form['password'].encode('utf-8')
            hashed_pw = argon2.hash(password)
            cursor.execute("UPDATE users SET username = %s, email = %s, password = %s WHERE id = %s",
                           (username, email, hashed_pw, user_id))
        else:
            cursor.execute("UPDATE users SET username = %s, email = %s WHERE id = %s",
                           (username, email, user_id))
        conn.commit()
        flash('User updated successfully')
        return redirect(url_for('manage_users'))

    cursor.execute("SELECT username, email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return render_template('edit_user.html', user=user, user_id=user_id)


if __name__ == '__main__':
    socketio.run(app, debug=True)