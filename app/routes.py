from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from flask_socketio import emit, join_room
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, FileField
from wtforms.validators import DataRequired
from app import db, socketio, email_service, csrf
from app.crypto import Crypto
from app.blockchain import Blockchain
from app.models import User, UserKeyHistory, UserPublicKeyHash, Thread, ThreadParticipant, Message
import base64
import os
import bleach
from werkzeug.utils import secure_filename
from mimetypes import guess_type
from datetime import datetime
import io
import subprocess
import json
from web3 import Web3

main = Blueprint('main', __name__)
crypto = Crypto()
blockchain = Blockchain()

ALLOWED_IMAGE_TYPES = {'image/png', 'image/jpeg', 'image/gif', 'image/bmp'}
ALLOWED_DOCUMENT_TYPES = {'application/pdf', 'text/plain', 'application/msword', 
                         'application/vnd.openxmlformats-officedocument.wordprocessingml.document'}
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'pdf', 'txt', 'doc', 'docx'}
MAX_FILE_SIZE = 15 * 1024 * 1024

def allowed_file(filename, content_type):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return (ext in ALLOWED_EXTENSIONS and 
            (content_type in ALLOWED_IMAGE_TYPES or content_type in ALLOWED_DOCUMENT_TYPES))

def verify_zkp(circuit_name, proof, public_inputs):
    proof_json = json.dumps(proof)
    public_inputs_json = json.dumps(public_inputs)
    with open(f"/tmp/{circuit_name}_proof.json", "w") as f:
        f.write(proof_json)
    with open(f"/tmp/{circuit_name}_public.json", "w") as f:
        f.write(public_inputs_json)
    result = subprocess.run(
        [
            "node",
            "--experimental-modules",
            f"/home/rhuff/zixt/node_modules/snarkjs/cli.js",
            "groth16",
            "verify",
            f"/home/rhuff/zixt/app/circuits/{circuit_name}_verification_key.json",
            f"/tmp/{circuit_name}_public.json",
            f"/tmp/{circuit_name}_proof.json",
        ],
        capture_output=True,
        text=True
    )
    return "true" in result.stdout.lower()

class MessageForm(FlaskForm):
    content = TextAreaField('Message')
    file = FileField('Attach File')
    submit = SubmitField('Send')

class ThreadForm(FlaskForm):
    name = StringField('Thread Name')
    usernames = StringField('Usernames (comma-separated)', validators=[DataRequired()])
    submit = SubmitField('Create')

class AddUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Add')

@main.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        public_key_hash = request.form['public_key_hash']
        zkp_proof = json.loads(request.form['zkp_proof'])
        user = UserPublicKeyHash.query.filter_by(public_key_hash=public_key_hash).first()
        if not user:
            flash('User not found', 'danger')
        elif not user.user.is_verified:
            flash('Email not verified', 'danger')
        elif verify_zkp('auth', zkp_proof, [public_key_hash]):
            session['user_id'] = user.user_id
            session['username'] = user.user.username
            session['is_admin'] = user.user.is_admin
            session['private_key'] = request.form.get('private_key', '')
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid proof', 'danger')
    return render_template('login.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        public_key = base64.b64decode(request.form['public_key'])
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
        else:
            password_hash = crypto.hash_password(password)
            public_key_hash = hashlib.sha3_512(public_key).hexdigest()
            token = email_service.generate_verification_token(email)
            user = User(
                username=username,
                email=email,
                public_key=public_key,
                password_hash=password_hash,
                verification_token=token
            )
            db.session.add(user)
            db.session.flush()
            user_hash = UserPublicKeyHash(
                user_id=user.id,
                public_key_hash=public_key_hash
            )
            db.session.add(user_hash)
            db.session.commit()
            
            if email_service.send_verification_email(email, username, token):
                flash('Registration successful! Please verify your email.', 'success')
            else:
                flash('Failed to send verification email. Try again later.', 'danger')
                db.session.delete(user)
                db.session.commit()
            return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/verify_email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        flash('Email verified! You can now log in.', 'success')
        return redirect(url_for('main.login'))
    flash('Invalid or expired token', 'danger')
    return render_template('verify_email.html')

@main.route('/rotate_key', methods=['POST'])
def rotate_key():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    user = User.query.get(session['user_id'])
    new_public_key, new_private_key, key_history = crypto.rotate_user_key(user)
    public_key_hash = hashlib.sha3_512(new_public_key).hexdigest()
    user_hash = UserPublicKeyHash(
        user_id=user.id,
        public_key_hash=public_key_hash
    )
    db.session.add(user_hash)
    db.session.add(key_history)
    db.session.commit()
    session['private_key'] = base64.b64encode(new_private_key).decode()
    flash('Key rotated successfully', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('main.login'))

@main.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    threads = Thread.query.join(ThreadParticipant).filter(
        ThreadParticipant.user_id == session['user_id'],
        ThreadParticipant.deleted == False
    ).all()
    thread_form = ThreadForm()
    return render_template('dashboard.html', threads=threads, thread_form=thread_form)

@main.route('/thread/<int:thread_id>')
def thread(thread_id):
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    thread = Thread.query.get_or_404(thread_id)
    participant = ThreadParticipant.query.filter_by(
        thread_id=thread_id, user_id=session['user_id'], deleted=False
    ).first()
    if not participant:
        flash('You are not part of this thread', 'danger')
        return redirect(url_for('main.dashboard'))
    
    messages = Message.query.filter_by(thread_id=thread_id).order_by(Message.id.asc()).all()
    decrypted_messages = []
    for msg in messages:
        try:
            shared_secret = crypto.decapsulate_key(base64.b64decode(msg.ciphertext), base64.b64decode(session['private_key']))
            content = crypto.decrypt_data(msg.content, shared_secret).decode()
            decrypted_messages.append({
                "content": content,
                "file_path": msg.file_path,
                "file_name": msg.file_name,
                "file_type": msg.file_type
            })
        except:
            continue
    
    participants = User.query.join(ThreadParticipant).filter(
        ThreadParticipant.thread_id == thread_id, ThreadParticipant.deleted == False
    ).all()
    thread_form = ThreadForm()
    add_user_form = AddUserForm()
    message_form = MessageForm()
    return render_template(
        'dashboard.html',
        threads=Thread.query.join(ThreadParticipant).filter(
            ThreadParticipant.user_id == session['user_id'],
            ThreadParticipant.deleted == False
        ).all(),
        current_thread=thread,
        messages=decrypted_messages,
        participants=participants,
        thread_form=thread_form,
        add_user_form=add_user_form,
        message_form=message_form
    )

@main.route('/create_thread', methods=['POST'])
@csrf.exempt
def create_thread():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    form = ThreadForm()
    if form.validate_on_submit():
        name = form.name.data
        usernames = form.usernames.data.split(',')
        
        thread = Thread(creator_id=session['user_id'], name=name.strip() or f"Thread {session['username']}")
        db.session.add(thread)
        db.session.flush()
        
        creator_participant = ThreadParticipant(thread_id=thread.id, user_id=session['user_id'])
        db.session.add(creator_participant)
        
        for username in usernames:
            username = username.strip()
            if username and username != session['username']:
                user = User.query.filter_by(username=username).first()
                if user:
                    participant = ThreadParticipant(thread_id=thread.id, user_id=user.id)
                    db.session.add(participant)
                else:
                    flash(f"User {username} not found", 'danger')
        
        db.session.commit()
        socketio.emit('thread_update', {'thread_id': thread.id, 'name': thread.name}, room=f"user_{session['user_id']}")
        return redirect(url_for('main.thread', thread_id=thread.id))
    flash('Invalid input', 'danger')
    return redirect(url_for('main.dashboard'))

@main.route('/add_user/<int:thread_id>', methods=['POST'])
@csrf.exempt
def add_user(thread_id):
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    form = AddUserForm()
    if form.validate_on_submit():
        thread = Thread.query.get_or_404(thread_id)
        if thread.creator_id != session['user_id']:
            flash('Only the creator can add users', 'danger')
            return redirect(url_for('main.thread', thread_id=thread_id))
        
        username = form.username.data.strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('User not found', 'danger')
        elif ThreadParticipant.query.filter_by(thread_id=thread_id, user_id=user.id, deleted=False).first():
            flash('User already in thread', 'danger')
        else:
            participant = ThreadParticipant(thread_id=thread_id, user_id=user.id)
            db.session.add(participant)
            db.session.commit()
            socketio.emit('thread_update', {'thread_id': thread_id, 'name': thread.name}, room=f"user_{user.id}")
            flash('User added', 'success')
    
    return redirect(url_for('main.thread', thread_id=thread_id))

@main.route('/remove_user/<int:thread_id>/<int:user_id>', methods=['POST'])
@csrf.exempt
def remove_user(thread_id, user_id):
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    thread = Thread.query.get_or_404(thread_id)
    if thread.creator_id != session['user_id']:
        flash('Only the creator can remove users', 'danger')
        return redirect(url_for('main.thread', thread_id=thread_id))
    
    participant = ThreadParticipant.query.filter_by(thread_id=thread_id, user_id=user_id, deleted=False).first()
    if participant:
        participant.deleted = True
        db.session.commit()
        socketio.emit('thread_update', {'thread_id': thread_id, 'name': thread.name}, room=f"user_{user_id}")
        flash('User removed', 'success')
    return redirect(url_for('main.thread', thread_id=thread_id))

@main.route('/delete_thread/<int:thread_id>', methods=['POST'])
@csrf.exempt
def delete_thread(thread_id):
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    participant = ThreadParticipant.query.filter_by(
        thread_id=thread_id, user_id=session['user_id'], deleted=False
    ).first()
    if participant:
        participant.deleted = True
        db.session.commit()
        socketio.emit('thread_update', {'thread_id': thread_id, 'deleted': True}, room=f"user_{session['user_id']}")
        flash('Thread deleted', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/download/<path:filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    file_path = os.path.join('app/uploads', filename)
    message = Message.query.filter_by(file_path=filename).first()
    if not message:
        flash('File not found', 'danger')
        return redirect(url_for('main.dashboard'))
    
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        shared_secret = crypto.decapsulate_key(
            base64.b64decode(message.ciphertext), 
            base64.b64decode(session['private_key'])
        )
        decrypted_data = crypto.decrypt_data(encrypted_data, shared_secret)
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=message.file_name,
            mimetype=message.file_type
        )
    except:
        flash('Unable to decrypt file', 'danger')
        return redirect(url_for('main.dashboard'))

@main.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        user = User.query.get(user_id) if user_id else None
        
        if action == 'create':
            username = request.form['username']
            email = request.form['email']
            password = crypto.hash_password(request.form['password'])
            public_key = base64.b64decode(request.form['public_key'])
            is_admin = 'is_admin' in request.form
            
            if User.query.filter_by(username=username).first():
                flash('Username already taken', 'danger')
            elif User.query.filter_by(email=email).first():
                flash('Email already registered', 'danger')
            else:
                new_user = User(
                    username=username,
                    email=email,
                    public_key=public_key,
                    password_hash=password,
                    is_admin=is_admin,
                    is_verified=True
                )
                db.session.add(new_user)
                db.session.flush()
                public_key_hash = hashlib.sha3_512(public_key).hexdigest()
                user_hash = UserPublicKeyHash(
                    user_id=new_user.id,
                    public_key_hash=public_key_hash
                )
                db.session.add(user_hash)
                db.session.commit()
                flash('User created', 'success')
        
        elif action == 'edit' and user:
            username = request.form['username']
            email = request.form['email']
            public_key = request.form.get('public_key')
            is_admin = 'is_admin' in request.form
            
            if username != user.username and User.query.filter_by(username=username).first():
                flash('Username already taken', 'danger')
            elif email != user.email and User.query.filter_by(email=email).first():
                flash('Email already registered', 'danger')
            else:
                user.username = username
                user.email = email
                if public_key:
                    user.public_key = base64.b64decode(public_key)
                    public_key_hash = hashlib.sha3_512(user.public_key).hexdigest()
                    user_hash = UserPublicKeyHash(
                        user_id=user.id,
                        public_key_hash=public_key_hash
                    )
                    db.session.add(user_hash)
                user.is_admin = is_admin
                db.session.commit()
                flash('User updated', 'success')
        
        elif action == 'delete' and user:
            if user.id == session['user_id']:
                flash('Cannot delete yourself', 'danger')
            else:
                db.session.delete(user)
                db.session.commit()
                flash('User deleted', 'success')
    
    users = User.query.all()
    return render_template('admin.html', users=users)

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(f"user_{session['user_id']}")

@socketio.on('send_message')
def handle_message(data):
    if 'user_id' not in session:
        return
    
    thread_id = data['thread_id']
    content = bleach.clean(data['content'].strip())
    zkp_proof = json.loads(data['zkp_proof'])
    file = request.files.get('file') if 'file' in request.files else None
    
    if not content and not file:
        return
    
    thread = Thread.query.get_or_404(thread_id)
    participants = User.query.join(ThreadParticipant).filter(
        ThreadParticipant.thread_id == thread_id, ThreadParticipant.deleted == False
    ).all()
    
    if not ThreadParticipant.query.filter_by(
        thread_id=thread_id, user_id=session['user_id'], deleted=False
    ).first():
        return
    
    if not verify_zkp('message', zkp_proof, [thread_id]):
        emit('message_error', {'error': 'Invalid proof'}, to=f"user_{session['user_id']}")
        return
    
    file_path = None
    file_name = None
    file_type = None
    if file:
        if file.content_length > MAX_FILE_SIZE:
            emit('message_error', {'error': 'File too large'}, to=f"user_{session['user_id']}")
            return
        content_type = file.mimetype
        if not allowed_file(file.filename, content_type):
            emit('message_error', {'error': 'Invalid file type'}, to=f"user_{session['user_id']}")
            return
        file_name = secure_filename(file.filename)
        file_type = content_type
        file_data = file.read()
    
    sender_public_key, sender_private_key = crypto.encapsulate_key()
    
    for user in participants:
        ciphertext, shared_secret = crypto.encapsulate_shared_secret(user.public_key)
        encrypted_content = crypto.encrypt_data(content.encode(), shared_secret) if content else ""
        
        if file:
            encrypted_file = crypto.encrypt_data(file_data, shared_secret)
            file_path = os.path.join('app/uploads', f"{thread_id}_{user.id}_{hashlib.sha3_256(file_name.encode()).hexdigest()}")
            with open(file_path, 'wb') as f:
                f.write(base64.b64decode(encrypted_file))
        
        message = Message(
            thread_id=thread_id,
            content=encrypted_content,
            ciphertext=base64.b64encode(ciphertext).decode(),
            zkp_proof=json.dumps(zkp_proof).encode(),
            file_path=file_path,
            file_name=file_name,
            file_type=file_type
        )
        db.session.add(message)
    
    db.session.commit()
    
    block_data = {
        "thread_id": thread_id,
        "content": encrypted_content,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "zkp_proof": json.dumps(zkp_proof),
        "file_path": file_path,
        "file_name": file_name,
        "file_type": file_type
    }
    blockchain.add_block(block_data, base64.b64decode(session['private_key']))
    
    for user in participants:
        try:
            shared_secret = crypto.decapsulate_key(ciphertext, base64.b64decode(session['private_key']))
            decrypted_content = crypto.decrypt_data(encrypted_content, shared_secret).decode() if encrypted_content else ""
            emit('new_message', {
                'thread_id': thread_id,
                'content': decrypted_content,
                'file_path': file_path,
                'file_name': file_name,
                'file_type': file_type
            }, room=f"user_{user.id}")
        except:
            continue
