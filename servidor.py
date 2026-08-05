import os
import re
import uuid
import time
import json
import threading
from functools import wraps
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
PUBLIC_DIR = 'public'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
os.makedirs(os.path.join(UPLOAD_FOLDER, PUBLIC_DIR), exist_ok=True)

USERNAME_RE = re.compile(r'^[a-z0-9_]{3,20}$')


def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
    else:
        data = {}
    data.setdefault('files', {})
    data.setdefault('share_tokens', {})
    data.setdefault('activity_log', [])
    data.setdefault('folders', {})   # { owner_dir: [nomes de pasta] }
    data.setdefault('users', {})     # { username: {password_hash, created_at} }
    return data


def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)


login_manager = LoginManager()
login_manager.init_app(app)

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')
admin_pass_hash = generate_password_hash(ADMIN_PASSWORD)


class AdminUser(UserMixin):
    def __init__(self, username):
        self.id = f'admin:{username}'
        self.username = username
        self.is_admin = True


class RegularUser(UserMixin):
    def __init__(self, username):
        self.id = f'user:{username}'
        self.username = username
        self.is_admin = False


@login_manager.user_loader
def load_user(user_id):
    if ':' not in user_id:
        return None
    kind, username = user_id.split(':', 1)
    if kind == 'admin':
        return AdminUser(username) if username == ADMIN_USERNAME else None
    if kind == 'user':
        data = load_data()
        return RegularUser(username) if username in data['users'] else None
    return None


@login_manager.unauthorized_handler
def unauthorized():
    # manda pra tela de login certa dependendo de onde a pessoa tentou entrar
    if request.path.startswith('/admin'):
        return redirect(url_for('admin_login', next=request.path))
    return redirect(url_for('user_login', next=request.path))


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            return unauthorized()
        return f(*args, **kwargs)
    return wrapper


def is_regular_user():
    return current_user.is_authenticated and not getattr(current_user, 'is_admin', False)


def owner_dir_of_current_user():
    return f'user_{current_user.username}'


def can_access(owner_dir):
    """True se o usuário atual (ou visitante) pode ver/baixar o que está em owner_dir."""
    if owner_dir == PUBLIC_DIR:
        return True
    if current_user.is_authenticated:
        if getattr(current_user, 'is_admin', False):
            return True
        if owner_dir == owner_dir_of_current_user():
            return True
    return False


def can_manage(owner_dir):
    """True se pode apagar/mover/organizar (mais estrito que can_access: público só admin gerencia)."""
    if current_user.is_authenticated and getattr(current_user, 'is_admin', False):
        return True
    if owner_dir == PUBLIC_DIR:
        return False
    return current_user.is_authenticated and owner_dir == owner_dir_of_current_user()


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


def get_real_ip():
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr


def log_activity(action, filename, owner_dir=None, ip=None):
    data = load_data()
    entry = {
        "action": action,
        "filename": filename,
        "owner": owner_dir or PUBLIC_DIR,
        "ip": ip or get_real_ip(),
        "timestamp": datetime.now().isoformat()
    }
    data['activity_log'].insert(0, entry)
    data['activity_log'] = data['activity_log'][:500]
    save_data(data)


def human_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def dedupe_filename(directory, filename):
    """Evita sobrescrever arquivo existente com o mesmo nome."""
    base, ext = os.path.splitext(filename)
    candidate = filename
    i = 1
    while os.path.exists(os.path.join(directory, candidate)):
        candidate = f"{base}_{i}{ext}"
        i += 1
    return candidate


def get_all_owner_dirs():
    return sorted(
        d for d in os.listdir(UPLOAD_FOLDER)
        if os.path.isdir(os.path.join(UPLOAD_FOLDER, d))
    )


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


# ── Página principal ──────────────────────────────────────────────────────────
@app.route('/')
def index():
    data = load_data()
    folder_filter = request.args.get('folder', '')
    search = request.args.get('q', '').lower()

    logged_in = is_regular_user()
    view = request.args.get('view', 'private' if logged_in else 'public')
    if view == 'private' and not logged_in:
        view = 'public'

    owner_dir = owner_dir_of_current_user() if view == 'private' else PUBLIC_DIR
    owner_path = os.path.join(UPLOAD_FOLDER, owner_dir)
    os.makedirs(owner_path, exist_ok=True)

    files_info = []
    for fname in os.listdir(owner_path):
        fpath = os.path.join(owner_path, fname)
        if not os.path.isfile(fpath):
            continue
        key = f"{owner_dir}/{fname}"
        meta = data['files'].get(key, {})
        folder = meta.get('folder', 'geral') if view == 'private' else None

        if view == 'private' and folder_filter and folder != folder_filter:
            continue
        if search and search not in fname.lower():
            continue

        files_info.append({
            'name': fname,
            'owner_dir': owner_dir,
            'size': human_size(os.path.getsize(fpath)),
            'category': get_file_category(fname),
            'preview_type': get_preview_type(fname),
            'folder': folder,
            'downloads': meta.get('downloads', 0),
            'uploaded_at': meta.get('uploaded_at', ''),
            'can_manage': can_manage(owner_dir),
        })

    folders = []
    if view == 'private':
        stored = set(data.get('folders', {}).get(owner_dir, []))
        used = set(f['folder'] for f in files_info if f['folder'])
        folders = sorted(stored | used)

    return render_template('index.html',
                           files=files_info,
                           folders=folders,
                           current_folder=folder_filter,
                           search=search,
                           view=view,
                           is_logged_in=logged_in,
                           username=current_user.username if current_user.is_authenticated else None)


# ── Registro / login de usuário ───────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_regular_user():
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if not USERNAME_RE.match(username):
            flash('Usuário inválido: use 3-20 caracteres (letras minúsculas, números ou _).')
            return render_template('register.html')
        if username == ADMIN_USERNAME:
            flash('Esse nome de usuário não está disponível.')
            return render_template('register.html')
        if len(password) < 6:
            flash('A senha precisa ter pelo menos 6 caracteres.')
            return render_template('register.html')
        if password != confirm:
            flash('As senhas não coincidem.')
            return render_template('register.html')

        data = load_data()
        if username in data['users']:
            flash('Esse nome de usuário já existe.')
            return render_template('register.html')

        data['users'][username] = {
            'password_hash': generate_password_hash(password),
            'created_at': datetime.now().isoformat(),
        }
        save_data(data)
        os.makedirs(os.path.join(UPLOAD_FOLDER, f'user_{username}'), exist_ok=True)

        flash('Conta criada! Agora é só entrar.')
        return redirect(url_for('user_login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if is_regular_user():
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        data = load_data()
        rec = data['users'].get(username)
        if rec and check_password_hash(rec['password_hash'], password):
            login_user(RegularUser(username), remember=remember)
            os.makedirs(os.path.join(UPLOAD_FOLDER, f'user_{username}'), exist_ok=True)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Usuário ou senha inválidos.')
    return render_template('login.html')


@app.route('/logout')
@login_required
def user_logout():
    logout_user()
    return redirect(url_for('index'))


# ── Upload ────────────────────────────────────────────────────────────────────
@app.route('/upload', methods=['POST'])
def upload_file():
    uploaded_files = request.files.getlist('file')

    if is_regular_user():
        owner_dir = owner_dir_of_current_user()
        folder = request.form.get('folder', 'geral').strip() or 'geral'
    else:
        owner_dir = PUBLIC_DIR
        folder = None
        # Sem login não existe como provar dono do arquivo, então exigimos
        # confirmação explícita de que a pessoa sabe que isso fica público.
        if request.form.get('public_consent') != 'yes':
            return jsonify({'error': 'É preciso confirmar que entende que o arquivo ficará público antes de enviar.'}), 400

    if not uploaded_files or all(f.filename == '' for f in uploaded_files):
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400

    owner_path = os.path.join(UPLOAD_FOLDER, owner_dir)
    os.makedirs(owner_path, exist_ok=True)

    saved = []
    data = load_data()
    for file in uploaded_files:
        if file.filename == '':
            continue
        filename = secure_filename(file.filename)
        if not filename:
            continue
        filename = dedupe_filename(owner_path, filename)
        filepath = os.path.join(owner_path, filename)
        file.save(filepath)

        key = f"{owner_dir}/{filename}"
        data['files'][key] = {
            'folder': folder or 'geral',
            'downloads': 0,
            'uploaded_at': datetime.now().isoformat(),
            'size': os.path.getsize(filepath),
            'owner': owner_dir,
        }
        saved.append(filename)
        log_activity('upload', filename, owner_dir=owner_dir)

    if owner_dir != PUBLIC_DIR and folder:
        data['folders'].setdefault(owner_dir, [])
        if folder not in data['folders'][owner_dir]:
            data['folders'][owner_dir].append(folder)

    save_data(data)
    return jsonify({'success': True, 'files': saved})


# ── Download / preview ────────────────────────────────────────────────────────
@app.route('/download/<owner_dir>/<path:filename>')
def download_file(owner_dir, filename):
    if not can_access(owner_dir):
        abort(403)
    data = load_data()
    key = f"{owner_dir}/{filename}"
    if key in data['files']:
        data['files'][key]['downloads'] = data['files'][key].get('downloads', 0) + 1
        save_data(data)
    log_activity('download', filename, owner_dir=owner_dir)
    return send_from_directory(os.path.join(UPLOAD_FOLDER, owner_dir), filename, as_attachment=True)


@app.route('/preview/<owner_dir>/<path:filename>')
def preview_file(owner_dir, filename):
    if not can_access(owner_dir):
        abort(403)
    return send_from_directory(os.path.join(UPLOAD_FOLDER, owner_dir), filename)


@app.route('/delete/<owner_dir>/<path:filename>', methods=['POST'])
def delete_file(owner_dir, filename):
    if not can_manage(owner_dir):
        abort(403)
    file_path = os.path.join(UPLOAD_FOLDER, owner_dir, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        data = load_data()
        data['files'].pop(f"{owner_dir}/{filename}", None)
        save_data(data)
        log_activity('delete', filename, owner_dir=owner_dir)
        return jsonify({'success': True})
    return jsonify({'error': 'Arquivo não encontrado'}), 404


# ── Share links ───────────────────────────────────────────────────────────────
@app.route('/share/create/<owner_dir>/<path:filename>', methods=['POST'])
def create_share_link(owner_dir, filename):
    if not can_access(owner_dir):
        abort(403)
    hours = int(request.form.get('hours', 24))
    token = str(uuid.uuid4())
    data = load_data()
    data['share_tokens'][token] = {
        'owner_dir': owner_dir,
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
        abort(410)
    owner_dir = entry['owner_dir']
    filename = entry['filename']
    file_path = os.path.join(UPLOAD_FOLDER, owner_dir, filename)
    if not os.path.exists(file_path):
        abort(404)
    log_activity('share_download', filename, owner_dir=owner_dir)
    return send_from_directory(os.path.join(UPLOAD_FOLDER, owner_dir), filename, as_attachment=True)


# ── Pastas (organização dentro do espaço privado do usuário) ────────────────
@app.route('/folder/create', methods=['POST'])
@login_required
def folder_create():
    if getattr(current_user, 'is_admin', False):
        abort(403)
    owner_dir = owner_dir_of_current_user()
    body = request.get_json() or {}
    name = (body.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Nome inválido'}), 400
    data = load_data()
    data['folders'].setdefault(owner_dir, [])
    if name not in data['folders'][owner_dir]:
        data['folders'][owner_dir].append(name)
        save_data(data)
    return jsonify({'success': True, 'name': name})


@app.route('/folder/rename', methods=['POST'])
@login_required
def folder_rename():
    if getattr(current_user, 'is_admin', False):
        abort(403)
    owner_dir = owner_dir_of_current_user()
    body = request.get_json() or {}
    old = (body.get('old') or '').strip()
    new = (body.get('new') or '').strip()
    if not old or not new:
        return jsonify({'error': 'Nomes inválidos'}), 400

    data = load_data()
    folders = data['folders'].setdefault(owner_dir, [])
    if old in folders:
        folders[folders.index(old)] = new
    elif new not in folders:
        folders.append(new)

    for key, meta in data['files'].items():
        if key.startswith(owner_dir + '/') and meta.get('folder') == old:
            meta['folder'] = new

    save_data(data)
    return jsonify({'success': True})


@app.route('/file/move', methods=['POST'])
@login_required
def file_move():
    if getattr(current_user, 'is_admin', False):
        abort(403)
    owner_dir = owner_dir_of_current_user()
    body = request.get_json() or {}
    filename = body.get('filename')
    dst_folder = (body.get('dst_folder') or 'geral').strip() or 'geral'

    key = f"{owner_dir}/{filename}"
    data = load_data()
    if key not in data['files']:
        return jsonify({'error': 'Arquivo não encontrado'}), 404

    data['files'][key]['folder'] = dst_folder
    data['folders'].setdefault(owner_dir, [])
    if dst_folder not in data['folders'][owner_dir]:
        data['folders'][owner_dir].append(dst_folder)

    save_data(data)
    return jsonify({'success': True})


# ── Admin ──────────────────────────────────────────────────────────────────────
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember') == 'on'
        if username == ADMIN_USERNAME and check_password_hash(admin_pass_hash, password):
            login_user(AdminUser(username), remember=remember)
            return redirect(request.args.get('next') or url_for('admin_dashboard'))
        flash('Credenciais inválidas')
    return render_template('admin_login.html')


@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    data = load_data()
    total_files = 0
    total_size = 0
    total_downloads = 0
    owners = {}

    for owner_dir in get_all_owner_dirs():
        owner_path = os.path.join(UPLOAD_FOLDER, owner_dir)
        files = [f for f in os.listdir(owner_path) if os.path.isfile(os.path.join(owner_path, f))]
        owners[owner_dir] = len(files)
        total_files += len(files)
        for f in files:
            total_size += os.path.getsize(os.path.join(owner_path, f))
            total_downloads += data['files'].get(f"{owner_dir}/{f}", {}).get('downloads', 0)

    return render_template('admin_dashboard.html',
                           total_files=total_files,
                           total_size=human_size(total_size),
                           total_downloads=total_downloads,
                           total_users=len(data['users']),
                           owners=owners,
                           activity_log=data['activity_log'][:50])


@app.route('/admin/files')
@admin_required
def admin_files():
    data = load_data()
    files_info = []
    for owner_dir in get_all_owner_dirs():
        owner_path = os.path.join(UPLOAD_FOLDER, owner_dir)
        for fname in os.listdir(owner_path):
            fpath = os.path.join(owner_path, fname)
            if not os.path.isfile(fpath):
                continue
            meta = data['files'].get(f"{owner_dir}/{fname}", {})
            files_info.append({
                'name': fname,
                'owner_dir': owner_dir,
                'owner_label': 'Público (sem login)' if owner_dir == PUBLIC_DIR else owner_dir.replace('user_', '', 1),
                'size': human_size(os.path.getsize(fpath)),
                'category': get_file_category(fname),
                'folder': meta.get('folder', '—') if owner_dir != PUBLIC_DIR else '—',
                'downloads': meta.get('downloads', 0),
                'uploaded_at': meta.get('uploaded_at', ''),
            })
    return render_template('admin_files.html', files=files_info)


@app.route('/admin/users')
@admin_required
def admin_users():
    data = load_data()
    users_info = []
    for username, rec in data['users'].items():
        owner_dir = f'user_{username}'
        owner_path = os.path.join(UPLOAD_FOLDER, owner_dir)
        count = 0
        if os.path.isdir(owner_path):
            count = len([f for f in os.listdir(owner_path) if os.path.isfile(os.path.join(owner_path, f))])
        users_info.append({
            'username': username,
            'created_at': rec.get('created_at', ''),
            'file_count': count,
        })
    users_info.sort(key=lambda u: u['created_at'], reverse=True)
    return render_template('admin_users.html', users=users_info)


@app.route('/admin/delete/<owner_dir>/<path:filename>')
@admin_required
def admin_delete(owner_dir, filename):
    file_path = os.path.join(UPLOAD_FOLDER, owner_dir, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        data = load_data()
        data['files'].pop(f"{owner_dir}/{filename}", None)
        save_data(data)
        log_activity('delete', filename, owner_dir=owner_dir)
        flash('Arquivo apagado com sucesso')
    else:
        flash('Arquivo não encontrado')
    return redirect(url_for('admin_files'))


@app.route('/admin/move/<owner_dir>/<path:filename>', methods=['POST'])
@admin_required
def admin_move(owner_dir, filename):
    new_folder = request.form.get('folder', 'geral').strip() or 'geral'
    data = load_data()
    key = f"{owner_dir}/{filename}"
    data['files'].setdefault(key, {})['folder'] = new_folder
    data['folders'].setdefault(owner_dir, [])
    if new_folder not in data['folders'][owner_dir]:
        data['folders'][owner_dir].append(new_folder)
    save_data(data)
    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
