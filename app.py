# app.py (CÓDIGO CORREGIDO Y COMPLETO)

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from os import getenv
from datetime import datetime
import pytz
import bcrypt
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError
import time

load_dotenv()
app = Flask(__name__)

# --- CONFIGURACIÓN ---
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{getenv('DB_USER')}:{getenv('DB_PASSWORD')}@{getenv('DB_HOST')}:{getenv('DB_PORT', '5432')}/{getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = getenv('SECRET_KEY', 'inventario-secreto-final')
app.config['TIMEZONE'] = 'America/Mexico_City'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicia sesión para acceder."
login_manager.login_message_category = "info"

@app.context_processor
def inject_timestamp():
    return dict(timestamp=int(time.time()))

# --- FILTROS Y LOADERS ---

# ***** FUNCIÓN CORREGIDA *****
@app.template_filter('localdatetime')
def format_datetime_local(dt):
    # Esta verificación es ahora más robusta. Si 'dt' está vacío o no es una fecha,
    # simplemente devolverá una cadena vacía en lugar de causar un error.
    if not isinstance(dt, datetime):
        return ""
        
    utc_tz = pytz.utc
    local_tz = pytz.timezone(app.config.get('TIMEZONE', 'UTC'))
    
    if dt.tzinfo is None:
        local_dt = utc_tz.localize(dt).astimezone(local_tz)
    else:
        local_dt = dt.astimezone(local_tz)
        
    return local_dt.strftime('%d/%m/%Y %H:%M')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- MODELOS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    es_admin = db.Column(db.Boolean, default=False)
    ordenes_creadas = db.relationship('Orden', backref='creador', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def check_password(self, password):
        try:
            return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))
        except Exception:
            return False

class Producto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    ubicacion = db.Column(db.String(100))
    estante = db.Column(db.String(50))
    nombre_cana = db.Column(db.String(100))
    nombre_IUPAC = db.Column(db.String(200))
    formula_molecular = db.Column(db.String(100))
    cast_sigmg = db.Column(db.String(100))
    estado_fisico = db.Column(db.String(50))
    cantidad = db.Column(db.Float)
    unidad_medida = db.Column(db.String(50))
    estado = db.Column(db.String(50))
    ubicacion_actual = db.Column(db.String(100))
    otra_ubicacion_actual = db.Column(db.String(200), nullable=True)
    detalles_orden = db.relationship('DetalleOrden', backref='producto', lazy=True)

class Orden(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    solicitado_por = db.Column(db.String(100), nullable=False)
    creado_por_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fecha_solicitud = db.Column(db.DateTime, default=datetime.utcnow)
    fecha_cierre = db.Column(db.DateTime, nullable=True)
    estado = db.Column(db.String(20), default='ABIERTA')
    observaciones = db.Column(db.Text, nullable=True)
    detalles = db.relationship('DetalleOrden', backref='orden', lazy='joined', cascade="all, delete-orphan")

class DetalleOrden(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    orden_id = db.Column(db.Integer, db.ForeignKey('orden.id', ondelete='CASCADE'), nullable=False)
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'), nullable=False)
    cantidad_pedida = db.Column(db.Float, nullable=False)
    cantidad_devuelta = db.Column(db.Float, default=0)

class OrdenHistorial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_orden_id = db.Column(db.Integer, nullable=False)
    solicitante_info = db.Column(db.String(200), nullable=False)
    productos_info = db.Column(db.Text, nullable=False)
    fecha_solicitud = db.Column(db.DateTime, nullable=False)
    fecha_cierre = db.Column(db.DateTime, nullable=True)
    fecha_eliminacion = db.Column(db.DateTime, default=datetime.utcnow)
    eliminado_por_rol = db.Column(db.String(50), nullable=False)
    eliminado_por_info = db.Column(db.String(200), nullable=False)

# --- RUTAS ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=True)
            return redirect(url_for('admin_dashboard'))
        flash('Credenciales incorrectas.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def dashboard_router():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/panel/home')
@login_required
def admin_dashboard():
    productos = Producto.query.order_by(Producto.nombre).all()
    ordenes_abiertas = Orden.query.filter_by(estado='ABIERTA').count()
    return render_template('admin_dashboard.html', 
                           productos=productos, 
                           ordenes_abiertas=ordenes_abiertas)

@app.route('/panel/ordenes')
@login_required
def admin_ordenes():
    ordenes_activas = Orden.query.options(joinedload(Orden.creador)).order_by(Orden.fecha_solicitud.desc()).all()
    return render_template('admin_ordenes.html', ordenes=ordenes_activas)

@app.route('/panel/orden/nueva', methods=['GET', 'POST'])
@login_required
def crear_orden():
    productos = Producto.query.order_by(Producto.nombre).all()
    if request.method == 'POST':
        try:
            solicitado_por = request.form['solicitado_por']
            producto_id = int(request.form['producto_id'])
            cantidad = float(request.form['cantidad'])
            
            if not solicitado_por:
                flash('Debes especificar quién solicita el producto.', 'danger')
                return redirect(url_for('crear_orden'))

            producto = Producto.query.get_or_404(producto_id)

            if producto.cantidad < cantidad:
                flash(f'Stock insuficiente para {producto.nombre}. Cantidad disponible: {producto.cantidad}', 'danger')
                return redirect(url_for('crear_orden'))

            nueva_orden = Orden(
                solicitado_por=solicitado_por,
                creado_por_id=current_user.id,
                estado='ABIERTA'
            )
            detalle = DetalleOrden(orden=nueva_orden, producto_id=producto_id, cantidad_pedida=cantidad)
            
            producto.cantidad -= cantidad

            db.session.add(nueva_orden)
            db.session.add(detalle)
            db.session.commit()
            flash(f'Orden para "{solicitado_por}" creada con éxito por {current_user.nombre}.', 'success')
            return redirect(url_for('admin_ordenes'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear la orden: {e}', 'danger')

    return render_template('crear_orden.html', productos=productos)

@app.route('/panel/historial')
@login_required
def admin_historial():
    historial = OrdenHistorial.query.order_by(OrdenHistorial.fecha_eliminacion.desc()).all()
    return render_template('admin_historial.html', historial=historial)

@app.route('/panel/orden/borrar-historial/<int:orden_id>', methods=['POST'])
@login_required
def admin_borrar_orden_historial(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    try:
        productos = ", ".join([f"{d.producto.nombre} (x{d.cantidad_pedida})" for d in orden.detalles])
        rol = 'admin' if current_user.es_admin else 'gerente'
        nuevo_historial = OrdenHistorial(
            original_orden_id=orden.id,
            solicitante_info=orden.solicitado_por,
            productos_info=productos,
            fecha_solicitud=orden.fecha_solicitud,
            fecha_cierre=orden.fecha_cierre,
            eliminado_por_rol=rol,
            eliminado_por_info=current_user.nombre,
        )
        db.session.add(nuevo_historial)
        db.session.delete(orden)
        db.session.commit()
        flash(f'La orden #{orden.id} ha sido movida al historial.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al mover el registro al historial: {e}', 'danger')
    return redirect(url_for('admin_ordenes'))

@app.route('/panel/producto/gestion/<int:id>', methods=['GET', 'POST'])
@app.route('/panel/producto/nuevo', methods=['GET', 'POST'])
@login_required
def gestionar_producto(id=None):
    producto = Producto.query.get(id) if id else None
    if request.method == 'POST':
        try:
            is_new = producto is None
            if is_new: producto = Producto()
            
            producto.nombre = request.form['nombre']
            producto.ubicacion = request.form.get('ubicacion')
            producto.estante = request.form.get('estante')
            producto.nombre_cana = request.form.get('nombre_cana')
            producto.nombre_IUPAC = request.form.get('nombre_IUPAC')
            producto.formula_molecular = request.form.get('formula_molecular')
            producto.cast_sigmg = request.form.get('cast_sigmg')
            producto.estado_fisico = request.form.get('estado_fisico')
            producto.cantidad = float(request.form['cantidad'])
            producto.unidad_medida = request.form['unidad_medida']
            producto.estado = request.form.get('estado')
            producto.ubicacion_actual = request.form['ubicacion_actual']
            if producto.ubicacion_actual == 'otro':
                producto.otra_ubicacion_actual = request.form.get('otra_ubicacion_actual')
            else:
                producto.otra_ubicacion_actual = None

            if is_new:
                db.session.add(producto)
            db.session.commit()
            flash('Producto guardado con éxito.', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash(f'Error al guardar producto: {e}', 'danger')
            db.session.rollback()
    return render_template('gestion_producto.html', producto=producto)

@app.route('/panel/producto/borrar/<int:producto_id>', methods=['POST'])
@login_required
def admin_borrar_producto(producto_id):
    producto = Producto.query.get_or_404(producto_id)
    try:
        db.session.delete(producto)
        db.session.commit()
        flash(f'Producto "{producto.nombre}" eliminado con éxito.', 'success')
    except IntegrityError:
        db.session.rollback()
        flash(f'Error: El producto "{producto.nombre}" no se puede eliminar porque está en uso en una o más órdenes.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar el producto: {e}.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/panel/orden/cerrar/<int:orden_id>', methods=['GET', 'POST'])
@login_required
def cerrar_orden(orden_id):
    orden = Orden.query.options(joinedload(Orden.detalles).joinedload(DetalleOrden.producto)).get_or_404(orden_id)
    if orden.estado == 'CERRADA':
        flash('Esta orden ya está cerrada.', 'warning')
        return redirect(url_for('admin_ordenes'))
    if request.method == 'POST':
        try:
            observaciones = request.form.get('observaciones', 'Sin observaciones.')
            for detalle in orden.detalles:
                input_name = f'devuelto_{detalle.id}'
                cantidad_devuelta = float(request.form.get(input_name, 0))
                
                if cantidad_devuelta > detalle.cantidad_pedida:
                    flash(f"No se puede devolver más de lo pedido para {detalle.producto.nombre}.", 'danger')
                    return render_template('admin_cerrar_orden.html', orden=orden)

                detalle.cantidad_devuelta = cantidad_devuelta
                producto_a_devolver = Producto.query.get(detalle.producto_id)
                if producto_a_devolver:
                    producto_a_devolver.cantidad += cantidad_devuelta

            orden.estado = 'CERRADA'
            orden.fecha_cierre = datetime.utcnow()
            orden.observaciones = observaciones
            db.session.commit()
            flash('Orden cerrada y stock actualizado.', 'success')
            return redirect(url_for('admin_ordenes'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al cerrar la orden: {e}', 'danger')
            
    return render_template('admin_cerrar_orden.html', orden=orden)

@app.cli.command("create-user")
def create_user_cli():
    """Crea una nueva cuenta de administrador o gerente."""
    nombre = input("Nombre: ")
    email = input("Email: ")
    password = input("Contraseña: ")
    rol = ''
    while rol not in ['admin', 'gerente']:
        rol = input("Rol (admin/gerente): ").lower()
    
    if User.query.filter_by(email=email).first():
        print(f"Error: El correo '{email}' ya está registrado.")
        return

    user = User(
        nombre=nombre, 
        email=email, 
        es_admin=(rol == 'admin')
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print(f"¡Usuario '{nombre}' creado exitosamente con rol de '{rol}'!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)