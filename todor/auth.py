# Importando Blueprint
from flask import Blueprint, render_template, request, url_for, flash, session, g

# Creando instancia
bp = Blueprint('auth', __name__, url_prefix='/auth')

#Creado ruta y función
@bp.route('/register')
def register():
    return render_template('auth/register.html')

# Manejo de Inicio de Sesión
@bp.route('/login', methods = ('GET', 'POST'))
def login():
    #Validación de datos
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Manejo de errores
        error = None

        # Consultado a la base de datos
        user = User.query.filter_by(username = username).first()
        if user == None:
            error = "Nombre de usuario incorrecto"
        elif not check_password_hash(user.password, password):
            error = "Contraseña incorrecta"

        # Iniciar sesión
        if error == None:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('todo.index'))

        flash(error)

    return render_template('auth/login.html')

# cerrar session
@bp.route('/loguot')
def logout():
    session.clear()
    return render_template(url_for(índex))

# Agregando verificación de inicio de  sesión
import functools

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view

# Manteniendo la sesión
@bp.before_app_request
def load_loggged_in_user():
    user_id = session.get('user_id')

    # Comparando
    if user_id is None:
        g.user = None
    else:
        g.user = User.query.get_or_404(user_id)

