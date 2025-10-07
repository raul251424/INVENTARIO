# app.py (CÓDIGO COMPLETO Y FINAL CON SOLUCIÓN DE CACHÉ)

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from os import getenv
from datetime import datetime, timedelta
import uuid
import pytz
import bcrypt
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError
import time # <--- IMPORTACIÓN AÑADIDA PARA SOLUCIONAR EL CACHÉ

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

# (NUEVO) ESTA FUNCIÓN INYECTA LA VERSIÓN (TIMESTAMP) EN TODAS LAS PLANTILLAS PARA EVITAR PROBLEMAS DE CACHÉ
@app.context_processor
def inject_timestamp():
    return dict(timestamp=int(time.time()))

# --- FILTROS Y LOADERS ---
@app.template_filter('localdatetime')
def format_datetime_local(dt):
    if dt is None: return ""
    utc_tz = pytz.utc
    local_tz = pytz.timezone(app.config.get('TIMEZONE', 'UTC'))
    local_dt = utc_tz.localize(dt).astimezone(local_tz)
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
    ordenes = db.relationship('Orden', backref='solicitante', lazy=True, cascade="all, delete-orphan")

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
    sku = db.Column(db.String(50), unique=True, nullable=True, index=True)
    stock_actual = db.Column(db.Integer, default=0)
    stock_minimo = db.Column(db.Integer, default=5)
    tipo = db.Column(db.String(1), default='P')
    detalles_orden = db.relationship('DetalleOrden', backref='producto', lazy=True)

class Orden(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    fecha_solicitud = db.Column(db.DateTime, default=datetime.utcnow)
    fecha_cierre = db.Column(db.DateTime, nullable=True)
    estado = db.Column(db.String(20), default='ABIERTA')
    observaciones = db.Column(db.Text, nullable=True)
    detalles = db.relationship('DetalleOrden', backref='orden', lazy='joined', cascade="all, delete-orphan")

class DetalleOrden(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    orden_id = db.Column(db.Integer, db.ForeignKey('orden.id', ondelete='CASCADE'), nullable=False)
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'), nullable=False)
    cantidad_pedida = db.Column(db.Integer, nullable=False)
    cantidad_devuelta = db.Column(db.Integer, default=0)

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
    user_id_afectado = db.Column(db.Integer, nullable=False)

# --- FUNCIONES AUXILIARES ---
def generar_sku(nombre_producto):
    nombre_limpio = ''.join(c for c in nombre_producto if c.isalnum()).upper()
    prefix = nombre_limpio[:4]
    return f"{prefix}-{uuid.uuid4().hex[:6]}"

def gestionar_stock_en_sesion(producto, cantidad, tipo='resta'):
    if producto:
        if tipo == 'resta':
            producto.stock_actual -= cantidad
        elif tipo == 'suma':
            producto.stock_actual += cantidad
        return True
    return False

# --- RUTAS DE AUTENTICACIÓN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_router'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=True)
            return redirect(url_for('dashboard_router'))
        flash('Credenciales incorrectas.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard_router():
    if current_user.es_admin:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_dashboard'))

# --- RUTAS DE ADMINISTRADOR ---
@app.route('/panel/admin/home')
@login_required
def admin_dashboard():
    if not current_user.es_admin: abort(403)
    productos = Producto.query.order_by(Producto.nombre).all()
    ordenes_abiertas = Orden.query.filter_by(estado='ABIERTA').count()
    productos_bajos_stock = [p for p in productos if p.stock_actual <= p.stock_minimo]
    return render_template('admin_dashboard.html', 
                           productos=productos, 
                           ordenes_abiertas=ordenes_abiertas,
                           productos_bajos_stock=productos_bajos_stock)

@app.route('/panel/ordenes')
@login_required
def admin_ordenes():
    if not current_user.es_admin: abort(403)
    ordenes_activas = Orden.query.order_by(Orden.fecha_solicitud.desc()).all()
    return render_template('admin_ordenes.html', ordenes=ordenes_activas)

@app.route('/panel/historial')
@login_required
def admin_historial():
    if not current_user.es_admin: abort(403)
    historial = OrdenHistorial.query.order_by(OrdenHistorial.fecha_eliminacion.desc()).all()
    return render_template('admin_historial.html', historial=historial)

@app.route('/panel/orden/borrar-historial/<int:orden_id>', methods=['POST'])
@login_required
def admin_borrar_orden_historial(orden_id):
    if not current_user.es_admin: abort(403)
    orden = Orden.query.get_or_404(orden_id)
    try:
        productos = ", ".join([f"{d.producto.nombre} (x{d.cantidad_pedida})" for d in orden.detalles])
        nuevo_historial = OrdenHistorial(
            original_orden_id=orden.id,
            solicitante_info=orden.solicitante.nombre,
            productos_info=productos,
            fecha_solicitud=orden.fecha_solicitud,
            fecha_cierre=orden.fecha_cierre,
            eliminado_por_rol='admin',
            eliminado_por_info=current_user.nombre,
            user_id_afectado=orden.user_id
        )
        db.session.add(nuevo_historial)
        db.session.delete(orden)
        db.session.commit()
        flash(f'La orden #{orden.id} ha sido eliminada y registrada en el historial.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar el registro: {e}', 'danger')
    return redirect(url_for('admin_ordenes'))

@app.route('/panel/ordenes/purgar', methods=['POST'])
@login_required
def admin_purgar_ordenes():
    if not current_user.es_admin: abort(403)
    try:
        limite_dias = int(request.form.get('tiempo', 180))
        fecha_limite = datetime.utcnow() - timedelta(days=limite_dias)
        ordenes_a_borrar = Orden.query.filter(
            Orden.estado == 'CERRADA',
            Orden.fecha_cierre < fecha_limite
        )
        cantidad_borrada = ordenes_a_borrar.count()
        if cantidad_borrada > 0:
            ordenes_a_borrar.delete(synchronize_session=False)
            db.session.commit()
            flash(f'Se han eliminado exitosamente {cantidad_borrada} registros antiguos.', 'success')
        else:
            flash('No se encontraron órdenes antiguas para eliminar.', 'info')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error al intentar purgar las órdenes: {e}', 'danger')
    return redirect(url_for('admin_ordenes'))

@app.route('/panel/historial/borrar-seleccionados', methods=['POST'])
@login_required
def admin_borrar_historial_seleccion():
    if not current_user.es_admin: abort(403)
    ids_a_borrar = request.form.getlist('historial_ids')
    if not ids_a_borrar:
        flash('No has seleccionado ningún registro para eliminar.', 'warning')
        return redirect(url_for('admin_historial'))
    try:
        OrdenHistorial.query.filter(OrdenHistorial.id.in_(ids_a_borrar)).delete(synchronize_session=False)
        db.session.commit()
        flash(f'Se han eliminado {len(ids_a_borrar)} registros del historial exitosamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error al eliminar los registros: {e}', 'danger')
    return redirect(url_for('admin_historial'))

@app.route('/panel/historial/borrar-todo', methods=['POST'])
@login_required
def admin_borrar_historial_todo():
    if not current_user.es_admin: abort(403)
    try:
        num_filas_borradas = db.session.query(OrdenHistorial).delete()
        db.session.commit()
        flash(f'Se ha borrado todo el historial ({num_filas_borradas} registros eliminados).', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error al borrar todo el historial: {e}', 'danger')
    return redirect(url_for('admin_historial'))
    
@app.route('/panel/producto/gestion/<int:id>', methods=['GET', 'POST'])
@app.route('/panel/producto/nuevo', methods=['GET', 'POST'])
@login_required
def gestionar_producto_admin(id=None):
    if not current_user.es_admin: abort(403)
    producto = Producto.query.get(id) if id else None
    if request.method == 'POST':
        try:
            is_new = producto is None
            if is_new: producto = Producto()
            producto.nombre = request.form['nombre']
            producto.stock_actual = int(request.form['stock_actual'])
            producto.stock_minimo = int(request.form['stock_minimo'])
            producto.tipo = request.form['tipo']
            if is_new:
                producto.sku = generar_sku(producto.nombre)
                db.session.add(producto)
            db.session.commit()
            flash('Producto guardado con éxito.', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash(f'Error al guardar producto: {e}', 'danger')
            db.session.rollback()
    return render_template('gestion_producto.html', producto=producto)

@app.route('/panel/orden/cerrar/<int:orden_id>', methods=['GET', 'POST'])
@login_required
def cerrar_orden(orden_id):
    if not current_user.es_admin: abort(403)
    orden = Orden.query.options(joinedload(Orden.detalles).joinedload(DetalleOrden.producto)).get_or_404(orden_id)
    if orden.estado == 'CERRADA':
        flash('Esta orden ya está cerrada.', 'warning')
        return redirect(url_for('admin_ordenes'))
    if request.method == 'POST':
        try:
            observaciones = request.form.get('observaciones', 'Sin observaciones.')
            for detalle in orden.detalles:
                input_name = f'devuelto_{detalle.id}'
                cantidad_devuelta = int(request.form.get(input_name, 0))
                detalle.cantidad_devuelta = cantidad_devuelta
                if detalle.producto.tipo == 'P':
                    producto_a_devolver = Producto.query.get(detalle.producto_id)
                    gestionar_stock_en_sesion(producto_a_devolver, cantidad_devuelta, tipo='suma')
                if detalle.cantidad_pedida > cantidad_devuelta:
                    faltante = detalle.cantidad_pedida - cantidad_devuelta
                    flash(f'¡ALERTA! Producto {detalle.producto.nombre}: Faltaron {faltante} unidades.', 'danger')
            orden.estado = 'CERRADA'
            orden.fecha_cierre = datetime.utcnow()
            orden.observaciones = observaciones
            db.session.commit()
            flash('Orden cerrada y stock actualizado.', 'success')
            return redirect(url_for('admin_ordenes'))
        except Exception as e:
            flash(f'Error al cerrar la orden: {e}', 'danger')
            db.session.rollback()
    return render_template('admin_cerrar_orden.html', orden=orden)

@app.route('/panel/usuarios')
@login_required
def admin_usuarios():
    if not current_user.es_admin: abort(403)
    users = User.query.filter(User.id != current_user.id).order_by(User.nombre).all()
    return render_template('admin_usuarios.html', users=users)

@app.route('/panel/usuario/crear', methods=['GET', 'POST'])
@login_required
def admin_crear_usuario():
    if not current_user.es_admin: abort(403)
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        nombre = request.form['nombre']
        rol = request.form['rol']
        if User.query.filter_by(email=email).first():
            flash('Ese correo ya existe.', 'warning')
            return redirect(url_for('admin_crear_usuario'))
        new_user = User(nombre=nombre, email=email, es_admin=(rol == 'admin'))
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash(f'Cuenta creada con rol: {rol}.', 'success')
        return redirect(url_for('admin_usuarios'))
    return render_template('gestion_usuario.html', action='crear')

@app.route('/panel/usuario/editar/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_editar_usuario(user_id):
    if not current_user.es_admin: abort(403)
    user_a_editar = User.query.get_or_404(user_id)
    if request.method == 'POST':
        try:
            user_a_editar.nombre = request.form['nombre']
            user_a_editar.email = request.form['email']
            user_a_editar.es_admin = (request.form['rol'] == 'admin')
            new_password = request.form['password']
            if new_password:
                user_a_editar.set_password(new_password)
            db.session.commit()
            flash(f'Usuario {user_a_editar.nombre} actualizado con éxito.', 'success')
            return redirect(url_for('admin_usuarios'))
        except Exception as e:
            flash(f'Error al actualizar usuario: {e}', 'danger')
            db.session.rollback()
    return render_template('gestion_usuario.html', user_data=user_a_editar, action='editar')

@app.route('/panel/usuario/borrar/<int:user_id>', methods=['POST'])
@login_required
def admin_borrar_usuario(user_id):
    if not current_user.es_admin:
        abort(403)
    user_a_borrar = User.query.get_or_404(user_id)
    if user_a_borrar.id == current_user.id:
        flash('No puedes eliminar tu propia cuenta de administrador.', 'danger')
        return redirect(url_for('admin_usuarios'))
    try:
        db.session.delete(user_a_borrar)
        db.session.commit()
        flash(f'El usuario "{user_a_borrar.nombre}" y todos sus registros han sido eliminados.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error al eliminar el usuario: {e}', 'danger')
    return redirect(url_for('admin_usuarios'))

@app.route('/panel/producto/borrar/<int:producto_id>', methods=['POST'])
@login_required
def admin_borrar_producto(producto_id):
    if not current_user.es_admin: abort(403)
    producto = Producto.query.get_or_404(producto_id)
    try:
        db.session.delete(producto)
        db.session.commit()
        flash(f'Producto "{producto.nombre}" eliminado con éxito.', 'success')
    except IntegrityError:
        flash(f'Error al eliminar el producto. Está en uso en órdenes pendientes.', 'danger')
        db.session.rollback()
    except Exception as e:
        flash(f'Error al eliminar el producto: {e}.', 'danger')
        db.session.rollback()
    return redirect(url_for('admin_dashboard'))

# --- RUTAS DE USUARIO NORMAL ---
@app.route('/user/inventario/prestables')
@login_required
def listar_prestables():
    productos = Producto.query.filter(Producto.stock_actual > 0, Producto.tipo == 'P').order_by(Producto.nombre).all()
    return render_template('lista_productos_filtrada.html', productos=productos, tipo_accion='prestamo', titulo='Artículos Prestables')

@app.route('/user/inventario/consumibles')
@login_required
def listar_consumibles():
    productos = Producto.query.filter(Producto.stock_actual > 0, Producto.tipo == 'C').order_by(Producto.nombre).all()
    return render_template('lista_productos_filtrada.html', productos=productos, tipo_accion='consumible', titulo='Artículos Consumibles')

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    productos_prestables = Producto.query.filter(Producto.stock_actual > 0, Producto.tipo == 'P').order_by(Producto.nombre).all()
    productos_consumibles = Producto.query.filter(Producto.stock_actual > 0, Producto.tipo == 'C').order_by(Producto.nombre).all()
    mis_ordenes_activas = Orden.query.filter_by(user_id=current_user.id).order_by(Orden.fecha_solicitud.desc()).all()
    return render_template('user_dashboard.html',
                           productos_prestables=productos_prestables,
                           productos_consumibles=productos_consumibles,
                           mis_ordenes=mis_ordenes_activas)

@app.route('/user/historial')
@login_required
def user_historial_admin():
    historial = OrdenHistorial.query.filter_by(
        user_id_afectado=current_user.id,
        eliminado_por_rol='admin'
    ).order_by(OrdenHistorial.fecha_eliminacion.desc()).all()
    return render_template('user_historial.html', historial=historial)

@app.route('/user/solicitar/<int:producto_id>', methods=['POST'])
@login_required
def solicitar_producto(producto_id):
    producto = Producto.query.get_or_404(producto_id)
    try:
        cantidad = int(request.form.get('cantidad', 1))
        if cantidad <= 0:
            flash('La cantidad debe ser mayor a cero.', 'danger')
            return redirect(url_for('user_dashboard'))
    except ValueError:
        flash('Cantidad no válida.', 'danger')
        return redirect(url_for('user_dashboard'))
    if producto.stock_actual < cantidad:
        flash(f'Stock insuficiente para {producto.nombre}. Cantidad disponible: {producto.stock_actual}', 'danger')
        return redirect(url_for('user_dashboard'))
    try:
        tipo = request.form.get('tipo', 'prestamo')
        if tipo == 'consumible':
            nueva_orden = Orden(user_id=current_user.id, estado='CERRADA', fecha_cierre=datetime.utcnow(), observaciones='Consumo directo registrado.')
            detalle = DetalleOrden(orden=nueva_orden, producto=producto, cantidad_pedida=cantidad, cantidad_devuelta=0)
            db.session.add(nueva_orden)
            db.session.add(detalle)
            gestionar_stock_en_sesion(producto, cantidad, tipo='resta')
            flash(f'Consumo de {producto.nombre} (x{cantidad}) registrado con éxito.', 'success')
        elif tipo == 'prestamo':
            if producto.tipo == 'C':
                flash('No se puede prestar un consumible.', 'danger')
                return redirect(url_for('user_dashboard'))
            nueva_orden = Orden(user_id=current_user.id, estado='ABIERTA')
            detalle = DetalleOrden(orden=nueva_orden, producto=producto, cantidad_pedida=cantidad)
            db.session.add(nueva_orden)
            db.session.add(detalle)
            gestionar_stock_en_sesion(producto, cantidad, tipo='resta')
            flash(f'Préstamo de {producto.nombre} (x{cantidad}) solicitado. Pendiente de devolución.', 'success')
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'Error en la solicitud: {e}', 'danger')
    return redirect(url_for('user_dashboard'))

@app.route('/user/orden/borrar/<int:orden_id>', methods=['POST'])
@login_required
def user_borrar_orden(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    if orden.user_id != current_user.id or orden.estado != 'ABIERTA':
        flash('No tienes permiso para borrar esta orden o no está Abierta.', 'danger')
        return redirect(url_for('user_dashboard'))
    try:
        if orden.estado == 'ABIERTA':
            for detalle in orden.detalles:
                producto_a_devolver = Producto.query.get(detalle.producto_id)
                gestionar_stock_en_sesion(producto_a_devolver, detalle.cantidad_pedida, tipo='suma')
        db.session.delete(orden)
        db.session.commit()
        flash(f'Orden #{orden_id} eliminada y stock restaurado.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al borrar la orden: {e}', 'danger')
    return redirect(url_for('user_dashboard'))

@app.route('/user/historial/borrar/<int:orden_id>', methods=['POST'])
@login_required
def user_borrar_historial(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    if orden.user_id != current_user.id: abort(403)
    try:
        productos = ", ".join([f"{d.producto.nombre} (x{d.cantidad_pedida})" for d in orden.detalles])
        nuevo_historial = OrdenHistorial(
            original_orden_id=orden.id,
            solicitante_info=orden.solicitante.nombre,
            productos_info=productos,
            fecha_solicitud=orden.fecha_solicitud,
            fecha_cierre=orden.fecha_cierre,
            eliminado_por_rol='usuario',
            eliminado_por_info=current_user.nombre,
            user_id_afectado=orden.user_id
        )
        db.session.add(nuevo_historial)
        db.session.delete(orden)
        db.session.commit()
        flash(f'La orden #{orden.id} ha sido eliminada y registrada en el historial.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar el registro: {e}', 'danger')
    return redirect(url_for('user_dashboard'))

# --- COMANDO CLI PARA CREAR ADMIN ---
@app.cli.command("create-admin")
def create_admin_cli():
    """Crea una nueva cuenta de administrador por consola."""
    nombre = input("Nombre: ")
    email = input("Email: ")
    password = input("Contraseña: ")
    if User.query.filter_by(email=email).first():
        print(f"Error: El correo '{email}' ya está registrado.")
        return
    admin_user = User(nombre=nombre, email=email, es_admin=True)
    admin_user.set_password(password)
    db.session.add(admin_user)
    db.session.commit()
    print(f"¡Administrador '{nombre}' creado exitosamente!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)