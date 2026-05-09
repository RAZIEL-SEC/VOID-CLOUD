import os
import uuid
import time
import json
import threading
from datetime import datetime, timedelta
from flask import Flask, request, render_template, send_from_directory, redirect, url_for, flash, jsonify, abort
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6')

UPLOAD_FOLDER = 'uploads'
DATA_FILE = 'data.json'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ── Data persistence ──────────────────────────────────────────────────────────
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {"files": {}, "share_tokens": {}, "activity_log": []}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

# ── Flask-Login ───────────────────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')
admin_pass_hash = generate_password_hash(ADMIN_PASSWORD)

class AdminUser(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    if user_id == ADMIN_USERNAME:
        return AdminUser(user_id)
    return None

# ── Helpers ───────────────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {
    'image': ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'],
    'pdf':   ['pdf'],
    'video': ['mp4', 'webm', 'ogg'],
    'audio': ['mp3', 'wav', 'ogg'],
    'doc':   ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'md'],
    'archive': ['zip', 'rar', '7z', 'tar', 'gz'],
}

def get_file_category(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    for cat, exts in ALLOWED_EXTENSIONS.items():
        if ext in exts:
            return cat
    return 'other'

def get_preview_type(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext in ALLOWED_EXTENSIONS['image']:
        return 'image'
    if ext in ALLOWED_EXTENSIONS['pdf']:
        return 'pdf'
    return None

def log_activity(action, filename, ip=None):
    data = load_data()
    entry = {
        "action": action,
        "filename": filename,
        "ip": ip or request.remote_addr,
        "timestamp": datetime.now().isoformat()
    }
    data['activity_log'].insert(0, entry)
    data['activity_log'] = data['activity_log'][:500]  # keep last 500
    save_data(data)

def get_folder_for_file(filename):
    data = load_data()
    return data['files'].get(filename, {}).get('folder', 'geral')

def human_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

# ── Cleanup expired share tokens ──────────────────────────────────────────────
def cleanup_tokens():
    while True:
        time.sleep(60)
        data = load_data()
        now = datetime.now()
        expired = [t for t, v in data['share_tokens'].items()
                   if datetime.fromisoformat(v['expires_at']) < now]
        for t in expired:
            data['share_tokens'].pop(t, None)
        if expired:
            save_data(data)

threading.Thread(target=cleanup_tokens, daemon=True).start()

# ── Routes: Public ────────────────────────────────────────────────────────────
@app.route('/')
def index():
    data = load_data()
    files_info = []
    folder_filter = request.args.get('folder', '')
    search = request.args.get('q', '').lower()

    for fname in os.listdir(UPLOAD_FOLDER):
        fpath = os.path.join(UPLOAD_FOLDER, fname)
        meta = data['files'].get(fname, {})
        folder = meta.get('folder', 'geral')

        if folder_filter and folder != folder_filter:
            continue
        if search and search not in fname.lower():
            continue

        files_info.append({
            'name': fname,
            'size': human_size(os.path.getsize(fpath)),
            'category': get_file_category(fname),
            'preview_type': get_preview_type(fname),
            'folder': folder,
            'downloads': meta.get('downloads', 0),
            'uploaded_at': meta.get('uploaded_at', ''),
        })

    folders = sorted(set(
        data['files'].get(f, {}).get('folder', 'geral')
        for f in os.listdir(UPLOAD_FOLDER)
    ))

    return render_template('index.html',
                           files=files_info,
                           folders=folders,
                           current_folder=folder_filter,
                           search=search)

@app.route('/upload', methods=['POST'])
def upload_file():
    uploaded_files = request.files.getlist('file')
    folder = request.form.get('folder', 'geral').strip() or 'geral'

    if not uploaded_files or all(f.filename == '' for f in uploaded_files):
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400

    saved = []
    data = load_data()
    for file in uploaded_files:
        if file.filename == '':
            continue
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        data['files'][filename] = {
            'folder': folder,
            'downloads': 0,
            'uploaded_at': datetime.now().isoformat(),
            'size': os.path.getsize(filepath),
        }
        saved.append(filename)
        log_activity('upload', filename)

    save_data(data)
    return jsonify({'success': True, 'files': saved})

@app.route('/download/<filename>')
def download_file(filename):
    data = load_data()
    if filename in data['files']:
        data['files'][filename]['downloads'] = data['files'][filename].get('downloads', 0) + 1
        save_data(data)
    log_activity('download', filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/preview/<filename>')
def preview_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ── Share links ───────────────────────────────────────────────────────────────
@app.route('/share/create/<filename>', methods=['POST'])
def create_share_link(filename):
    hours = int(request.form.get('hours', 24))
    token = str(uuid.uuid4())
    data = load_data()
    data['share_tokens'][token] = {
        'filename': filename,
        'expires_at': (datetime.now() + timedelta(hours=hours)).isoformat(),
        'created_at': datetime.now().isoformat(),
    }
    save_data(data)
    link = url_for('share_download', token=token, _external=True)
    return jsonify({'link': link, 'expires_in': f'{hours}h'})

@app.route('/s/<token>')
def share_download(token):
    data = load_data()
    entry = data['share_tokens'].get(token)
    if not entry:
        abort(404)
    if datetime.fromisoformat(entry['expires_at']) < datetime.now():
        abort(410)  # Gone
    filename = entry['filename']
    data['files'].get(filename, {})
    log_activity('share_download', filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# ── Admin routes ──────────────────────────────────────────────────────────────
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and check_password_hash(admin_pass_hash, password):
            login_user(AdminUser(username))
            return redirect(url_for('admin_dashboard'))
        flash('Credenciais inválidas')
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_dashboard():
    data = load_data()
    files = os.listdir(UPLOAD_FOLDER)
    total_size = sum(os.path.getsize(os.path.join(UPLOAD_FOLDER, f)) for f in files)
    total_downloads = sum(data['files'].get(f, {}).get('downloads', 0) for f in files)
    folders = {}
    for f in files:
        folder = data['files'].get(f, {}).get('folder', 'geral')
        folders[folder] = folders.get(folder, 0) + 1

    return render_template('admin_dashboard.html',
                           total_files=len(files),
                           total_size=human_size(total_size),
                           total_downloads=total_downloads,
                           folders=folders,
                           activity_log=data['activity_log'][:50])

@app.route('/admin/files')
@login_required
def admin_files():
    data = load_data()
    files_info = []
    for fname in os.listdir(UPLOAD_FOLDER):
        fpath = os.path.join(UPLOAD_FOLDER, fname)
        meta = data['files'].get(fname, {})
        files_info.append({
            'name': fname,
            'size': human_size(os.path.getsize(fpath)),
            'category': get_file_category(fname),
            'folder': meta.get('folder', 'geral'),
            'downloads': meta.get('downloads', 0),
            'uploaded_at': meta.get('uploaded_at', ''),
        })
    return render_template('admin_files.html', files=files_info)

@app.route('/admin/delete/<filename>')
@login_required
def admin_delete(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        data = load_data()
        data['files'].pop(filename, None)
        save_data(data)
        log_activity('delete', filename)
        flash('Arquivo apagado com sucesso')
    else:
        flash('Arquivo não encontrado')
    return redirect(url_for('admin_files'))

@app.route('/admin/move/<filename>', methods=['POST'])
@login_required
def admin_move(filename):
    new_folder = request.form.get('folder', 'geral').strip() or 'geral'
    data = load_data()
    if filename not in data['files']:
        data['files'][filename] = {}
    data['files'][filename]['folder'] = new_folder
    save_data(data)
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)