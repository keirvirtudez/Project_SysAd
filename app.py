from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect 
from functools import wraps
from dotenv import load_dotenv
import os
import jwt
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta

load_dotenv('project.env')
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cloud.db'

# Security configurations
csrf = CSRFProtect(app)
db = SQLAlchemy(app)

# Rate limiting (DDoS protection)
from flask_limiter import Limiter
limiter = Limiter(
    app=app,
    key_func=lambda: request.remote_addr,
    default_limits=["100 per 15 minute"]
)

# SQL Injection filter
@app.before_request
def sql_injection_filter():
    """Block SQL injection attempts"""
    sql_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|SCRIPT)\b)",
        r"(--|\/\*|\*\/|';|\"|;|--|\/\*)",
        r"(\bOR\b\s+\b1\b\s*=\s*\b1\b)",
        r"(\bAND\b\s+\b1\b\s*=\s*\b1\b)"
    ]
    
    if request.is_json:
        data = str(request.get_json())
        for pattern in sql_patterns:
            import re
            if re.search(pattern, data, re.IGNORECASE):
                return jsonify({'error': 'SQL Injection detected - Request blocked'}), 403

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True)
    role = db.Column(db.String(50), default='member')  # member, network-operator, sec-auditor, admin
    project = db.Column(db.String(100))
    mfa_secret = db.Column(db.String(32))
    mfa_enabled = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255))
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)
    encryption_key = db.Column(db.String(255))  # AES-256 key reference
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    project = db.Column(db.String(100))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    checksum = db.Column(db.String(64))  # SHA-256 for integrity

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100))
    resource = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    success = db.Column(db.Boolean)

# Authentication utilities
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256:100000')

def verify_password(stored, provided):
    return check_password_hash(stored, provided)

def generate_mfa_secret():
    return pyotp.random_base32()

def verify_mfa_token(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=2)

def generate_jwt(user_id, mfa_verified=False):
    payload = {
        'user_id': user_id,
        'mfa_verified': mfa_verified,
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_jwt(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if not token:
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        
        decoded = decode_jwt(token)
        if not decoded:
            session.clear()
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
        
        g.user_id = decoded['user_id']
        g.mfa_verified = decoded['mfa_verified']
        g.user = User.query.get(decoded['user_id'])
        
        return f(*args, **kwargs)
    return decorated_function

def mfa_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.get('mfa_verified'):
            flash('MFA verification required', 'warning')
            return redirect(url_for('mfa_verify'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user.role != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# app.py - OpenStack Configuration for Remote VM

import os
from openstack import connection

class OpenStackManager:
    def __init__(self):
        # Connect to OpenStack on Ubuntu VM
        # Change this IP to your Ubuntu VM's IP!
        self.auth_url = os.getenv('OS_AUTH_URL', 'http://192.168.56.200:5000/v3')
        self.username = os.getenv('OS_USERNAME', 'admin')
        self.password = os.getenv('OS_PASSWORD', 'group5po')
        self.project_name = os.getenv('OS_PROJECT_NAME', 'admin')
        self.user_domain = os.getenv('OS_USER_DOMAIN_NAME', 'Default')
        self.project_domain = os.getenv('OS_PROJECT_DOMAIN_NAME', 'Default')
    
    def get_connection(self):
        """Create connection to OpenStack"""
        try:
            conn = connection.Connection(
                auth_url=self.auth_url,
                username=self.username,
                password=self.password,
                project_name=self.project_name,
                user_domain_name=self.user_domain,
                project_domain_name=self.project_domain,
                identity_api_version='3'
            )
            return conn
        except Exception as e:
            print(f"OpenStack connection error: {e}")
            return None
    
    def create_keystone_user(self, username, password, project_name, role_name):
        """Create user in OpenStack Keystone"""
        conn = self.get_connection()
        if not conn:
            return {'error': 'Cannot connect to OpenStack'}
        
        try:
            # Create project if not exists
            try:
                proj = conn.identity.find_project(project_name)
                if not proj:
                    proj = conn.identity.create_project(name=project_name)
            except Exception as e:
                print(f"Project error: {e}")
                proj = None
            
            # Create user
            user = conn.identity.create_user(
                name=username,
                password=password,
                default_project_id=proj.id if proj else None
            )
            
            # Find or create role
            try:
                role = conn.identity.find_role(role_name)
                if not role:
                    role = conn.identity.create_role(name=role_name)
            except:
                role = conn.identity.create_role(name=role_name)
            
            # Assign role
            if proj and role:
                conn.identity.assign_project_role_to_user(proj, user, role)
            
            return {
                'success': True,
                'keystone_user_id': user.id,
                'project_id': proj.id if proj else None,
                'role_id': role.id
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def list_servers(self):
        """List all servers/instances"""
        conn = self.get_connection()
        if not conn:
            return []
        
        servers = []
        for server in conn.compute.servers():
            servers.append({
                'id': server.id,
                'name': server.name,
                'status': server.status,
                'flavor': server.flavor['original_name'] if 'original_name' in server.flavor else 'unknown'
            })
        return servers
    
    def create_server(self, name, image, flavor, network):
        """Create a new server instance"""
        conn = self.get_connection()
        if not conn:
            return {'error': 'Cannot connect to OpenStack'}
        
        try:
            server = conn.compute.create_server(
                name=name,
                image_id=image,
                flavor_id=flavor,
                networks=[{"uuid": network}]
            )
            return {'success': True, 'server_id': server.id}
        except Exception as e:
            return {'error': str(e)}
    
    def create_network(self, name, subnet_cidr):
        """Create network and subnet"""
        conn = self.get_connection()
        if not conn:
            return {'error': 'Cannot connect to OpenStack'}
        
        try:
            # Create network
            network = conn.network.create_network(name=name)
            
            # Create subnet
            subnet = conn.network.create_subnet(
                network_id=network.id,
                cidr=subnet_cidr,
                ip_version=4
            )
            
            return {
                'success': True,
                'network_id': network.id,
                'subnet_id': subnet.id
            }
        except Exception as e:
            return {'error': str(e)}
    
    def create_volume(self, size, name):
        """Create encrypted volume"""
        conn = self.get_connection()
        if not conn:
            return {'error': 'Cannot connect to OpenStack'}
        
        try:
            volume = conn.block_storage.create_volume(
                size=size,
                name=name
            )
            return {'success': True, 'volume_id': volume.id}
        except Exception as e:
            return {'error': str(e)}

# Routes

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Prevent brute force
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Log attempt
        log = AccessLog(
            action='LOGIN_ATTEMPT',
            resource=username,
            ip_address=request.remote_addr,
            success=False
        )
        db.session.add(log)
        
        user = User.query.filter_by(username=username).first()
        
        if user and verify_password(user.password_hash, password):
            if user.mfa_enabled:
                # Store temp session, require MFA
                session['temp_user_id'] = user.id
                session['pending_mfa'] = True
                log.success = True
                db.session.commit()
                return redirect(url_for('mfa_verify'))
            else:
                # Generate JWT and log in
                token = generate_jwt(user.id, mfa_verified=True)
                session['token'] = token
                user.last_login = datetime.utcnow()
                log.user_id = user.id
                log.success = True
                db.session.commit()
                flash(f'Welcome, {user.username}!', 'success')
                return redirect(url_for('dashboard'))
        else:
            db.session.commit()
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    if not session.get('pending_mfa') or not session.get('temp_user_id'):
        return redirect(url_for('login'))
    
    user = User.query.get(session['temp_user_id'])
    
    if request.method == 'POST':
        mfa_code = request.form.get('mfa_code')
        
        if verify_mfa_token(user.mfa_secret, mfa_code):
            # MFA passed, generate full JWT
            token = generate_jwt(user.id, mfa_verified=True)
            session['token'] = token
            session.pop('temp_user_id', None)
            session.pop('pending_mfa', None)
            
            # Log success
            log = AccessLog(
                user_id=user.id,
                action='MFA_SUCCESS',
                resource='MFA Verification',
                ip_address=request.remote_addr,
                success=True
            )
            db.session.add(log)
            db.session.commit()
            
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash('MFA verified successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid MFA code. Please try again.', 'danger')
    
    return render_template('mfa_verify.html', username=user.username)

@app.route('/dashboard')
@login_required
@mfa_required
def dashboard():
    # Get user's files count
    file_count = File.query.filter_by(owner_id=g.user_id).count()
    
    # Get recent access logs
    logs = AccessLog.query.filter_by(user_id=g.user_id).order_by(
        AccessLog.timestamp.desc()
    ).limit(10).all()
    
    return render_template('dashboard.html', 
                         user=g.user,
                         file_count=file_count,
                         logs=logs)

@app.route('/files', methods=['GET', 'POST'])
@login_required
@mfa_required
def file_manager():
    if request.method == 'POST':
        # Handle file upload with encryption
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        # Encrypt file (AES-256)
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        f = Fernet(key)
        
        file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        
        # Save to storage (local or OpenStack Swift)
        filename = f"{g.user_id}_{datetime.utcnow().timestamp()}_{file.filename}"
        filepath = os.path.join('uploads', filename)
        
        with open(filepath, 'wb') as f_out:
            f_out.write(encrypted_data)
        
        # Save to database
        new_file = File(
            filename=filename,
            original_name=file.filename,
            file_path=filepath,
            file_size=len(file_data),
            encryption_key=key.decode(),  # Store key securely in production!
            owner_id=g.user_id,
            project=g.user.project
        )
        db.session.add(new_file)
        
        # Log
        log = AccessLog(
            user_id=g.user_id,
            action='FILE_UPLOAD',
            resource=file.filename,
            ip_address=request.remote_addr,
            success=True
        )
        db.session.add(log)
        db.session.commit()
        
        flash('File uploaded and encrypted successfully!', 'success')
        return redirect(url_for('file_manager'))
    
    # GET - list files
    files = File.query.filter_by(owner_id=g.user_id).all()
    return render_template('file_manager.html', files=files, user=g.user)

@app.route('/download/<int:file_id>')
@login_required
@mfa_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check ownership
    if file.owner_id != g.user_id and g.user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('file_manager'))
    
    # Decrypt and serve
    from cryptography.fernet import Fernet
    f = Fernet(file.encryption_key.encode())
    
    with open(file.file_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    
    decrypted_data = f.decrypt(encrypted_data)
    
    # Log
    log = AccessLog(
        user_id=g.user_id,
        action='FILE_DOWNLOAD',
        resource=file.original_name,
        ip_address=request.remote_addr,
        success=True
    )
    db.session.add(log)
    db.session.commit()
    
    from flask import send_file
    return send_file(
        BytesIO(decrypted_data),
        download_name=file.original_name,
        as_attachment=True
    )

@app.route('/admin')
@login_required
@mfa_required
@admin_required
def admin_panel():
    users = User.query.all()
    projects = db.session.query(User.project).distinct().all()
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(50).all()
    
    return render_template('admin_panel.html', 
                         users=users, 
                         projects=[p[0] for p in projects if p[0]],
                         logs=logs,
                         user=g.user)

@app.route('/admin/create-user', methods=['POST'])
@login_required
@mfa_required
@admin_required
def create_user():
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    role = request.form.get('role', 'member')
    project = request.form.get('project')
    
    # Check if user exists
    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'danger')
        return redirect(url_for('admin_panel'))
    
    # Create local user
    new_user = User(
        username=username,
        password_hash=hash_password(password),
        email=email,
        role=role,
        project=project
    )
    db.session.add(new_user)
    db.session.commit()
    
    # Sync with OpenStack Keystone
    try:
        os_manager = OpenStackManager()
        keystone_result = os_manager.create_keystone_user(
            username=username,
            password=password,
            project_name=project or 'default',
            role_name=role
        )
        flash(f'User created and synced with OpenStack! Keystone ID: {keystone_result["keystone_user_id"]}', 'success')
    except Exception as e:
        flash(f'Local user created but OpenStack sync failed: {str(e)}', 'warning')
    
    # Log
    log = AccessLog(
        user_id=g.user_id,
        action='CREATE_USER',
        resource=username,
        ip_address=request.remote_addr,
        success=True
    )
    db.session.add(log)
    db.session.commit()
    
    return redirect(url_for('admin_panel'))

@app.route('/admin/setup-mfa/<int:user_id>')
@login_required
@mfa_required
def setup_mfa(user_id):
    """Setup MFA for current user"""
    if user_id != g.user_id and g.user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if not user.mfa_secret:
        user.mfa_secret = generate_mfa_secret()
        db.session.commit()
    
    # Generate QR code
    totp = pyotp.TOTP(user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.username,
        issuer_name='Group5-Cloud-Security'
    )
    
   # Replace the QR code generation in app.py with this:

def generate_mfa_qr(username, secret):
    """Generate QR code - works with or without Pillow"""
    import qrcode
    import io
    import base64
    
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name='Group5-Cloud-Security')
    
    # Create QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    
    # Try to use PIL for image, fallback to SVG
    try:
        from PIL import Image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode()
    except ImportError:
        # Fallback: Return SVG string instead
        import qrcode.image.svg
        factory = qrcode.image.svg.SvgImage
        svg_img = qr.make_image(image_factory=factory)
        buffer = io.BytesIO()
        svg_img.save(buffer)
        return base64.b64encode(buffer.getvalue()).decode()

@app.route('/admin/enable-mfa/<int:user_id>', methods=['POST'])
@login_required
@mfa_required
def enable_mfa(user_id):
    if user_id != g.user_id and g.user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    user = User.query.get_or_404(user_id)
    mfa_code = request.form.get('mfa_code')
    
    if verify_mfa_token(user.mfa_secret, mfa_code):
        user.mfa_enabled = True
        db.session.commit()
        flash('MFA enabled successfully!', 'success')
    else:
        flash('Invalid MFA code', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# API endpoints for AJAX/JavaScript
@app.route('/api/user/info')
@login_required
def user_info():
    return jsonify({
        'username': g.user.username,
        'role': g.user.role,
        'project': g.user.project,
        'mfa_enabled': g.user.mfa_enabled
    })

@app.route('/api/system/status')
@login_required
@mfa_required
def system_status():
    """Get OpenStack system status"""
    # This would query OpenStack APIs
    return jsonify({
        'multi_az': True,
        'auto_scaling_status': 'active',
        'encryption_enabled': True,
        'waf_status': 'active',
        'backup_status': 'synced'
    })
@app.route('/test-openstack')
def test_openstack():
    """Test OpenStack connection - REMOVE THIS IN PRODUCTION"""
    try:
        os_manager = OpenStackManager()
        conn = os_manager.get_connection()
        
        if not conn:
            return jsonify({'status': 'FAILED', 'error': 'Cannot connect to OpenStack'}), 500
        
        # Test by listing projects
        projects = list(conn.identity.projects())
        servers = list(conn.compute.servers())
        networks = list(conn.network.networks())
        
        return jsonify({
            'status': 'SUCCESS',
            'auth_url': os_manager.auth_url,
            'projects': [p.name for p in projects],
            'servers': [s.name for s in servers],
            'networks': [n.name for n in networks]
        })
    
    except Exception as e:
        return jsonify({'status': 'FAILED', 'error': str(e)}), 500
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=False)