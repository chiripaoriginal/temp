import sqlite3
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import functools
import os
import shutil
import base64

# --- 1. CONFIGURACIÓN ---
DATABASE = 'visitors.db'
SECRET_KEY = '5a44a95681c7e6c3e387249a8f278f2e2a8c3d98a6b72d9e'
BACKUP_DIR = 'backups'
LAST_BACKUP_FILE = 'last_auto_backup.txt'
UPLOAD_FOLDER_VISITORS = 'static/uploads/visitors'
UPLOAD_FOLDER_USERS = 'static/uploads/users'

# --- 2. INICIALIZACIÓN DE LA APLICACIÓN ---
app = Flask(__name__)
app.config.from_object(__name__)

os.makedirs(app.config['UPLOAD_FOLDER_VISITORS'], exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER_USERS'], exist_ok=True)
os.makedirs(app.config['BACKUP_DIR'], exist_ok=True)

# --- 3. FUNCIONES DE BASE DE DATOS Y SESIÓN ---
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db_connection()
        conn.execute('CREATE TABLE IF NOT EXISTS visitors (id INTEGER PRIMARY KEY, name TEXT NOT NULL, id_number TEXT NOT NULL, purpose TEXT NOT NULL, entry_time DATETIME NOT NULL, exit_time DATETIME, registered_by TEXT NOT NULL, photo_path TEXT);')
        conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, photo_path TEXT);')
        conn.execute('CREATE TABLE IF NOT EXISTS flagged_visitors (id_number TEXT PRIMARY KEY, reason TEXT NOT NULL, flagged_by TEXT NOT NULL, timestamp DATETIME NOT NULL);')
        if conn.execute('SELECT id FROM users WHERE role = ?', ('administrador',)).fetchone() is None:
            conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ('admin', generate_password_hash('admin'), 'administrador'))
        conn.commit()
        conn.close()

@app.cli.command('init-db')
def init_db_command():
    init_db()
    print('Base de datos inicializada.')

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None
    if user_id:
        conn = get_db_connection()
        g.user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash('Debes iniciar sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def role_required(*roles):
    def wrapper(view_func):
        @functools.wraps(view_func)
        def decorated_view(*args, **kwargs):
            if g.user is None: return redirect(url_for('login'))
            if g.user['role'] not in roles:
                flash('No tienes permiso para acceder a esta página.', 'danger')
                return redirect(url_for('index'))
            return view_func(*args, **kwargs)
        return decorated_view
    return wrapper

# --- 4. RUTAS PRINCIPALES ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = get_db_connection().execute('SELECT * FROM users WHERE username = ?', (request.form['username'],)).fetchone()
        if user and check_password_hash(user['password'], request.form['password']):
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        flash('Usuario o contraseña incorrectos.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    auto_backup()
    visitors = get_db_connection().execute('SELECT v.*, f.reason as flag_reason FROM visitors v LEFT JOIN flagged_visitors f ON v.id_number = f.id_number WHERE v.exit_time IS NULL ORDER BY v.entry_time DESC').fetchall()
    return render_template('index.html', visitors=visitors, current_user=g.user)

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    visitor_data = request.args.to_dict() if request.method == 'GET' else {}
    error_msg = None
    if request.method == 'POST':
        id_number = request.form.get('id_number', '').strip()
        if not re.match(r'^[a-zA-Z0-9-]{3,}$', id_number):
            error_msg = "El número de identificación es inválido. Mínimo 3 caracteres (letras, números, guiones)."
            return render_template('register.html', current_user=g.user, visitor=request.form, error=error_msg)

        name, purpose = request.form['name'], request.form['purpose']
        conn = get_db_connection()
        active_visitor = conn.execute('SELECT * FROM visitors WHERE id_number = ? AND exit_time IS NULL', (id_number,)).fetchone()
        if active_visitor:
            error_msg = f"Error: El visitante con identificación '{id_number}' ya se encuentra dentro de las instalaciones."
            conn.close()
            return render_template('register.html', current_user=g.user, visitor=request.form, error=error_msg)
        
        photo_path = None
        photo_data_url = request.form.get('photo_data_url')
        if photo_data_url and 'base64' in photo_data_url:
            try:
                img_data = base64.b64decode(photo_data_url.split(',')[1])
                filename = f"visitor_{secure_filename(id_number)}_{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
                full_path = os.path.join(app.config['UPLOAD_FOLDER_VISITORS'], filename)
                with open(full_path, 'wb') as f: f.write(img_data)
                photo_path = os.path.join('uploads/visitors', filename).replace('\\', '/')
            except Exception as e:
                flash(f"Hubo un error al guardar la foto: {e}", "danger")
        
        conn.execute('INSERT INTO visitors (name, id_number, purpose, entry_time, registered_by, photo_path) VALUES (?, ?, ?, ?, ?, ?)',
                     (name, id_number, purpose, datetime.now(), g.user['username'], photo_path))
        conn.commit()
        conn.close()
        flash('Visitante registrado con éxito!', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', current_user=g.user, visitor=visitor_data, error=error_msg)

@app.route('/exit/<int:visitor_id>')
@login_required
def mark_exit(visitor_id):
    conn = get_db_connection()
    conn.execute('UPDATE visitors SET exit_time = ? WHERE id = ?', (datetime.now(), visitor_id))
    conn.commit()
    conn.close()
    flash('Salida registrada con éxito.', 'success')
    return redirect(url_for('index'))

@app.route('/all_visitors')
@login_required
def view_all_visitors():
    all_visitors = get_db_connection().execute('SELECT v.*, f.reason as flag_reason FROM visitors v LEFT JOIN flagged_visitors f ON v.id_number = f.id_number ORDER BY v.entry_time DESC').fetchall()
    return render_template('index.html', visitors=all_visitors, current_user=g.user, all_visitors=True)

@app.route('/search_visitor', methods=['GET', 'POST'])
@login_required
def search_visitor():
    if request.method == 'POST':
        id_number = request.form['id_number']
        last_visit = get_db_connection().execute('SELECT * FROM visitors WHERE id_number = ? ORDER BY entry_time DESC LIMIT 1', (id_number,)).fetchone()
        if last_visit:
            flash('Visitante encontrado. Por favor, confirma los datos.', 'info')
            return redirect(url_for('register', **dict(last_visit)))
        else:
            flash('Visitante no encontrado.', 'warning')
            return redirect(url_for('register', id_number=id_number))
    return render_template('search_visitor.html', current_user=g.user)

@app.route('/api/visitor/<string:id_number>')
@login_required
def get_visitor_data(id_number):
    last_visit = get_db_connection().execute('SELECT v.name, v.purpose, f.reason as flag_reason, f.flagged_by, f.timestamp FROM visitors v LEFT JOIN flagged_visitors f ON v.id_number = f.id_number WHERE v.id_number = ? ORDER BY v.entry_time DESC LIMIT 1', (id_number,)).fetchone()
    if last_visit:
        return jsonify(dict(last_visit))
    else:
        return jsonify({'error': 'Not found'}), 404

# --- 5. RUTA PARA GESTIONAR ALERTAS ---
@app.route('/manage_alert/<string:id_number>', methods=['GET', 'POST'])
@login_required
def manage_visitor_alert(id_number):
    conn = get_db_connection()
    visitor = conn.execute('SELECT name, id_number FROM visitors WHERE id_number = ? LIMIT 1', (id_number,)).fetchone()
    if not visitor:
        flash("No se encontró ningún visitante con esa identificación.", "danger")
        conn.close()
        return redirect(url_for('view_all_visitors'))

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'save':
            reason = request.form.get('reason', '').strip()
            if not reason:
                flash("El motivo de la alerta no puede estar vacío.", "danger")
            else:
                conn.execute('INSERT OR REPLACE INTO flagged_visitors (id_number, reason, flagged_by, timestamp) VALUES (?, ?, ?, ?)',
                             (id_number, reason, g.user['username'], datetime.now()))
                conn.commit()
                flash("Alerta guardada correctamente.", "success")
                conn.close()
                return redirect(url_for('view_all_visitors'))
        elif action == 'remove' and (g.user['role'] in ['supervisor', 'administrador']):
            conn.execute('DELETE FROM flagged_visitors WHERE id_number = ?', (id_number,))
            conn.commit()
            flash("La alerta ha sido eliminada.", "info")
            conn.close()
            return redirect(url_for('view_all_visitors'))

    alert = conn.execute('SELECT * FROM flagged_visitors WHERE id_number = ?', (id_number,)).fetchone()
    conn.close()
    return render_template('manage_alert.html', visitor=visitor, alert=alert, current_user=g.user)

# --- 6. RUTAS DE ADMINISTRACIÓN (COMPLETAS) ---
def auto_backup():
    try:
        with open(app.config['LAST_BACKUP_FILE'], 'r') as f: last_backup_time = datetime.fromisoformat(f.read())
    except (FileNotFoundError, ValueError): last_backup_time = datetime.min
    if datetime.now() - last_backup_time > timedelta(hours=24):
        backup_filename = f"visitors_auto_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        try:
            shutil.copy2(app.config['DATABASE'], os.path.join(app.config['BACKUP_DIR'], backup_filename))
            with open(app.config['LAST_BACKUP_FILE'], 'w') as f: f.write(datetime.now().isoformat())
            print(f"Backup automático realizado: {backup_filename}")
        except Exception as e: print(f"Error en el backup automático: {e}")

def get_backup_files():
    if not os.path.exists(app.config['BACKUP_DIR']): return []
    files = [f for f in os.listdir(app.config['BACKUP_DIR']) if f.endswith('.db')]
    backups = [{'filename': f, 'modified_time': datetime.fromtimestamp(os.path.getmtime(os.path.join(app.config['BACKUP_DIR'], f))).strftime('%Y-%m-%d %H:%M:%S')} for f in files]
    return sorted(backups, key=lambda x: x['modified_time'], reverse=True)

@app.route('/admin/backup/create')
@login_required
@role_required('administrador')
def create_backup():
    backup_filename = f"visitors_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    try:
        shutil.copy2(app.config['DATABASE'], os.path.join(app.config['BACKUP_DIR'], backup_filename))
        flash(f'Copia de seguridad creada con éxito: {backup_filename}', 'success')
    except Exception as e:
        flash(f'Error al crear la copia de seguridad: {e}', 'danger')
    return redirect(url_for('index'))

@app.route('/admin/backup/restore')
@login_required
@role_required('administrador')
def restore_backup_options():
    backups = get_backup_files()
    return render_template('admin/restore_backup.html', backups=backups, current_user=g.user)

@app.route('/admin/backup/view/<path:filename>')
@login_required
@role_required('administrador')
def view_backup_data(filename):
    backup_path = os.path.join(app.config['BACKUP_DIR'], filename)
    if not os.path.exists(backup_path):
        flash("El archivo de backup no existe.", "danger")
        return redirect(url_for('restore_backup_options'))
    try:
        conn_backup = sqlite3.connect(backup_path)
        conn_backup.row_factory = sqlite3.Row
        visitors = conn_backup.execute('SELECT * FROM visitors ORDER BY entry_time DESC').fetchall()
        conn_backup.close()
        flash(f"Mostrando datos del backup '{filename}'. Esto es solo una vista.", "info")
        return render_template('index.html', visitors=visitors, current_user=g.user, is_backup_view=True, backup_filename=filename)
    except Exception as e:
        flash(f"Error al leer el archivo de backup: {e}", "danger")
        return redirect(url_for('restore_backup_options'))

@app.route('/admin/backup/merge', methods=['GET', 'POST'])
@login_required
@role_required('administrador')
def merge_backup():
    if request.method == 'POST':
        backup_filename = request.form['backup_file_to_merge']
        backup_path = os.path.join(app.config['BACKUP_DIR'], backup_filename)
        if not os.path.exists(backup_path):
            flash("El archivo de backup seleccionado no existe.", "danger")
            return redirect(url_for('merge_backup'))
        
        try:
            conn_main = get_db_connection()
            conn_backup = sqlite3.connect(backup_path)
            conn_backup.row_factory = sqlite3.Row
            backup_visitors = conn_backup.execute('SELECT * FROM visitors').fetchall()
            
            new_visitors_count = 0
            updated_exit_times_count = 0
            for visitor_b in backup_visitors:
                entry_time_b = datetime.fromisoformat(visitor_b['entry_time'])
                main_visitor = conn_main.execute('SELECT * FROM visitors WHERE id_number = ? AND abs(julianday(entry_time) - julianday(?)) * 86400 < 60', (visitor_b['id_number'], entry_time_b)).fetchone()

                if main_visitor:
                    if main_visitor['exit_time'] is None and visitor_b['exit_time'] is not None:
                        conn_main.execute('UPDATE visitors SET exit_time = ? WHERE id = ?', (visitor_b['exit_time'], main_visitor['id']))
                        updated_exit_times_count += 1
                else:
                    conn_main.execute('INSERT INTO visitors (name, id_number, purpose, entry_time, exit_time, registered_by, photo_path) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                      (visitor_b['name'], visitor_b['id_number'], visitor_b['purpose'], visitor_b['entry_time'], visitor_b['exit_time'], visitor_b['registered_by'], visitor_b.get('photo_path')))
                    new_visitors_count += 1
            
            conn_main.commit()
            flash(f'Fusión completada. {new_visitors_count} nuevos visitantes añadidos y {updated_exit_times_count} salidas actualizadas.', 'success')
        except sqlite3.Error as e:
            flash(f'Error de base de datos durante la fusión: {e}', 'danger')
        finally:
            if 'conn_main' in locals() and conn_main: conn_main.close()
            if 'conn_backup' in locals() and conn_backup: conn_backup.close()
        return redirect(url_for('index'))
    return render_template('admin/merge_backup.html', backups=get_backup_files(), current_user=g.user)

@app.route('/admin/users')
@login_required
@role_required('administrador')
def manage_users():
    users = get_db_connection().execute('SELECT * FROM users ORDER BY username').fetchall()
    return render_template('admin/users.html', users=users, current_user=g.user)

@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@role_required('administrador')
def create_user():
    if request.method == 'POST':
        username, password, role = request.form['username'], request.form['password'], request.form['role']
        conn = get_db_connection()
        if conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            flash('El nombre de usuario ya existe.', 'danger')
        else:
            photo_path = None
            photo_data_url = request.form.get('photo_data_url')
            if photo_data_url and 'base64' in photo_data_url:
                try:
                    img_data = base64.b64decode(photo_data_url.split(',')[1])
                    filename = f"user_{secure_filename(username)}.png"
                    full_path = os.path.join(app.config['UPLOAD_FOLDER_USERS'], filename)
                    with open(full_path, 'wb') as f: f.write(img_data)
                    photo_path = os.path.join('uploads/users', filename).replace('\\', '/')
                except Exception as e:
                    flash(f"Hubo un error al guardar la foto: {e}", "danger")
            conn.execute('INSERT INTO users (username, password, role, photo_path) VALUES (?, ?, ?, ?)',
                         (username, generate_password_hash(password), role, photo_path))
            conn.commit()
            flash('Usuario creado con éxito.', 'success')
        conn.close()
        return redirect(url_for('manage_users'))
    return render_template('admin/create_user.html', current_user=g.user)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('administrador')
def edit_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        new_username, new_role, new_password = request.form['username'], request.form['role'], request.form.get('password')
        photo_data_url = request.form.get('photo_data_url')
        
        conn = get_db_connection()
        photo_path = user['photo_path']
        if photo_data_url and 'base64' in photo_data_url:
            try:
                img_data = base64.b64decode(photo_data_url.split(',')[1])
                filename = f"user_{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
                full_path = os.path.join(app.config['UPLOAD_FOLDER_USERS'], filename)
                with open(full_path, 'wb') as f: f.write(img_data)
                photo_path = os.path.join('uploads/users', filename).replace('\\', '/')
            except Exception as e:
                flash(f"Hubo un error al guardar la nueva foto: {e}", "danger")
        
        if new_password:
            conn.execute('UPDATE users SET username = ?, password = ?, role = ?, photo_path = ? WHERE id = ?',
                         (new_username, generate_password_hash(new_password), new_role, photo_path, user_id))
        else:
            conn.execute('UPDATE users SET username = ?, role = ?, photo_path = ? WHERE id = ?',
                         (new_username, new_role, photo_path, user_id))
        conn.commit()
        conn.close()
        flash('Usuario actualizado con éxito.', 'success')
        return redirect(url_for('manage_users'))
    return render_template('admin/edit_user.html', user=user, current_user=g.user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required('administrador')
def delete_user(user_id):
    if user_id == g.user['id']:
        flash('No puedes eliminar tu propia cuenta de administrador.', 'danger')
    else:
        conn = get_db_connection()
        user = conn.execute('SELECT photo_path FROM users WHERE id = ?', (user_id,)).fetchone()
        if user and user['photo_path']:
            try: os.remove(os.path.join('static', user['photo_path']))
            except OSError: pass
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        flash('Usuario eliminado con éxito.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/clean_database', methods=['GET', 'POST'])
@login_required
@role_required('administrador')
def clean_database():
    if request.method == 'POST':
        if check_password_hash(g.user['password'], request.form['admin_password']):
            conn = get_db_connection()
            deleted_rows = conn.execute('DELETE FROM visitors').rowcount
            conn.commit()
            conn.close()
            flash(f'Base de datos de visitantes limpiada. Se eliminaron {deleted_rows} registros.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Contraseña de administrador incorrecta.', 'danger')
    return render_template('admin/clean_database.html', current_user=g.user)

# --- 7. PUNTO DE ENTRADA ---
if __name__ == '__main__':
    if not os.path.exists(app.config['DATABASE']):
        with app.app_context():
            init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)