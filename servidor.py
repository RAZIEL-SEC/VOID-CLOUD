import os
from flask import Flask, request, render_template, send_from_directory, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'sua-chave-secreta-aqui'  # Mude para algo seguro e único
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Inicializar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

# Classe simples para usuário admin
class AdminUser(UserMixin):
    def __init__(self, username):
        self.id = username

# Credenciais de admin (ALTERE AQUI: edite esses valores diretamente no código)
ADMIN_USERNAME = 'admin'  # Altere para o usuário desejado
ADMIN_PASSWORD = 'senhafoda'  # Altere para a senha desejada (será hasheada automaticamente)

# Hash da senha (feito automaticamente)
admin_pass_hash = generate_password_hash(ADMIN_PASSWORD)

@login_manager.user_loader
def load_user(user_id):
    if user_id == ADMIN_USERNAME:
        return AdminUser(user_id)
    return None

@app.route('/')
def index():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'Erro: Nenhum arquivo enviado', 400
    file = request.files['file']
    if file.filename == '':
        return 'Erro: Nenhum arquivo selecionado', 400
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# Rotas admin
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and check_password_hash(admin_pass_hash, password):
            user = AdminUser(username)
            login_user(user)
            return redirect(url_for('admin_files'))
        flash('Credenciais inválidas')
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/files')
@login_required
def admin_files():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('admin_files.html', files=files)

@app.route('/admin/delete/<filename>')
@login_required
def admin_delete(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash('Arquivo apagado com sucesso')
    else:
        flash('Arquivo não encontrado')
    return redirect(url_for('admin_files'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))