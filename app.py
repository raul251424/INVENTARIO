# app.py (CÓDIGO COMPLETO, CORREGIDO Y FINAL)

from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from os import getenv
from datetime import datetime, timedelta
import pytz
import bcrypt
from sqlalchemy.orm import joinedload, selectinload 
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import select, func, text 
import time
import csv
from io import StringIO
from typing import List, Dict, Any
from flask_migrate import Migrate

# --- INICIALIZACIÓN Y CONFIGURACIÓN ---
load_dotenv()
app = Flask(__name__)

# --- SOLUCIÓN AL ERROR 'TemplateSyntaxError: Encountered unknown tag 'do'' ---
# Habilita la extensión 'do' para que Jinja2 reconozca la etiqueta {% do %} en las plantillas.
app.jinja_env.add_extension('jinja2.ext.do')
# -------------------------------------------------------------------------------

# Configuración de la base de datos y clave secreta
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{getenv('DB_USER')}:{getenv('DB_PASSWORD')}@{getenv('DB_HOST')}:{getenv('DB_PORT', '5432')}/{getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = getenv('SECRET_KEY', 'un-secreto-muy-fuerte-y-dificil-de-adivinar')
app.config['TIMEZONE'] = 'America/Mexico_City'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

# --- MEJORAS DE SEGURIDAD: Cookies de Sesión ---
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# -----------------------------------------------

# --- EXTENSIONES ---
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db) 

login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicia sesión para acceder."
login_manager.login_message_category = "info"

# --- HELPERS Y FILTROS DE PLANTILLAS ---
@app.context_processor
def inject_timestamp():
    return dict(timestamp=int(time.time()))

@app.template_filter('localdatetime')
def format_datetime_local(dt):
    if not isinstance(dt, datetime): return ""
    utc_tz = pytz.utc
    local_tz = pytz.timezone(app.config.get('TIMEZONE', 'UTC'))
    if dt.tzinfo is None: dt = utc_tz.localize(dt)
    local_dt = dt.astimezone(local_tz)
    return local_dt.strftime('%d/%m/%Y %H:%M')

@app.template_filter('abreviar_unidad')
def abreviar_unidad_filter(unidad):
    unidad = str(unidad).lower().strip()
    mapa = {
        'gramos': 'g', 'kilogramos': 'kg', 'miligramos': 'mg',
        'mililitros': 'ml', 'litros': 'L', 'microlitros': 'µl',
        'moles': 'mol', 'milimoles': 'mmol', 'unidades': 'u',
        'unidad': 'u', 'paquetes': 'paquetes', 'g': 'g', 'kg': 'kg', 
        'mg': 'mg', 'ml': 'ml', 'l': 'L', 'µl': 'µl', 'mol': 'mol', 
        'mmol': 'mmol', 'u': 'u'
    }
    return mapa.get(unidad, unidad)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- MODELOS DE BASE DE DATOS ---
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    es_admin = db.Column(db.Boolean, default=False)
    ordenes_creadas = db.relationship('Orden', backref='creador', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def check_password(self, password):
        return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))

class Producto(db.Model):
    __tablename__ = 'producto'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(500), nullable=False, unique=True, index=True) 
    ubicacion = db.Column(db.String(255), index=True)
    estante = db.Column(db.String(100))
    nombre_cana = db.Column(db.String(255))
    nombre_IUPAC = db.Column(db.String(500))
    formula_molecular = db.Column(db.String(255))
    cast_sigmg = db.Column(db.String(255))
    estado_fisico = db.Column(db.String(100), index=True)
    cantidad = db.Column(db.Float)
    unidad_medida = db.Column(db.String(100), index=True)
    estado = db.Column(db.String(100), index=True)
    ubicacion_actual = db.Column(db.String(255), index=True)
    otra_ubicacion_actual = db.Column(db.String(500), nullable=True)
    stock_minimo = db.Column(db.Float, default=0) 
    detalles_orden = db.relationship('DetalleOrden', backref='producto', lazy=True, cascade="all, delete-orphan")

class Orden(db.Model):
    __tablename__ = 'orden'
    id = db.Column(db.Integer, primary_key=True)
    solicitado_por = db.Column(db.String(100), nullable=False)
    creado_por_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fecha_solicitud = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    fecha_cierre = db.Column(db.DateTime, nullable=True)
    estado = db.Column(db.String(20), default='ABIERTA', index=True)
    observaciones = db.Column(db.Text, nullable=True)
    detalles = db.relationship('DetalleOrden', backref='orden', lazy='joined', cascade="all, delete-orphan")

class DetalleOrden(db.Model):
    __tablename__ = 'detalle_orden'
    id = db.Column(db.Integer, primary_key=True)
    orden_id = db.Column(db.Integer, db.ForeignKey('orden.id', ondelete='CASCADE'), nullable=False)
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'), nullable=False)
    cantidad_pedida = db.Column(db.Float, nullable=False)
    cantidad_devuelta = db.Column(db.Float, default=0)

class OrdenHistorial(db.Model):
    __tablename__ = 'orden_historial'
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
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            session.permanent = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Correo electrónico o contraseña no válidos.', 'danger')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def dashboard_router():
    return redirect(url_for('admin_dashboard') if current_user.is_authenticated else url_for('login'))

@app.route('/panel/dashboard')
@login_required
def admin_dashboard():
    try:
        # --- CORRECCIÓN: Limpia los mensajes flash de stock bajo al cargar el dashboard ---
        # Esto evita que la alerta persista si el usuario la cierra y navega.
        if '_flashes' in session:
            session['_flashes'] = [f for f in session['_flashes'] if 'Stock bajo' not in f[1]]
            if not session['_flashes']:
                session.pop('_flashes', None)
        # ---------------------------------------------------------------------------------

        total_productos = db.session.query(func.count(Producto.id)).scalar()
        ordenes_abiertas = db.session.query(func.count(Orden.id)).filter(Orden.estado == 'ABIERTA').scalar()
        productos_recientes = Producto.query.order_by(Producto.id.desc()).limit(5).all()
        
        productos_stock_bajo = Producto.query.filter(
            Producto.cantidad.isnot(None),
            Producto.stock_minimo.isnot(None),
            Producto.stock_minimo > 0,
            Producto.cantidad <= Producto.stock_minimo 
        ).order_by(Producto.nombre).all()

        return render_template(
            'admin_dashboard.html', 
            total_productos=total_productos, 
            ordenes_abiertas=ordenes_abiertas, 
            productos_recientes=productos_recientes,
            productos_stock_bajo=productos_stock_bajo
        )
    except Exception as e:
        app.logger.error(f"Error al cargar el dashboard: {e}")
        flash('Ocurrió un error inesperado al cargar la información del panel.', "danger")
        return render_template('admin_dashboard.html', total_productos='N/A', ordenes_abiertas='N/A', productos_recientes=[], productos_stock_bajo=[])

@app.route('/panel/inventario')
@login_required
def inventario_completo():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
    except (ValueError, TypeError):
        page, per_page = 1, 10
        
    if per_page not in [10, 25, 50]: per_page = 10
    if page < 1: page = 1
    
    # Captura de todos los parámetros de filtrado
    search_term = request.args.get('search', '', type=str)
    estado_fisico_filter = request.args.get('estado_fisico', 'todos', type=str)
    unidad_medida_filter = request.args.get('unidad_medida', 'todas', type=str)
    estado_envase_filter = request.args.get('estado_envase', 'todos', type=str)
    ubicacion_actual_filter = request.args.get('ubicacion_actual', 'todas', type=str) 

    query = Producto.query.order_by(Producto.nombre)
    
    if search_term:
        query = query.filter(Producto.nombre.ilike(f'%{search_term}%'))
    if estado_fisico_filter != 'todos':
        query = query.filter(func.upper(Producto.estado_fisico) == estado_fisico_filter.upper())
    if unidad_medida_filter != 'todas':
        query = query.filter(func.upper(Producto.unidad_medida) == unidad_medida_filter.upper())
    if estado_envase_filter != 'todos':
        query = query.filter(func.upper(Producto.estado) == estado_envase_filter.upper()) 
    if ubicacion_actual_filter != 'todas':
        query = query.filter(func.upper(Producto.ubicacion_actual) == ubicacion_actual_filter.upper())

    # Lógica para el filtro de estado físico (sin 'gas', solo DB + base)
    estados_fisicos_unicos_db_raw = db.session.query(Producto.estado_fisico).distinct().filter(Producto.estado_fisico != None).all()
    estados_fisicos_db = {e[0].lower() for e in estados_fisicos_unicos_db_raw}
    # CAMBIO: Lista base sin 'gas'
    estados_fisicos_base = {'líquido', 'sólido'}
    
    estados_fisicos_unicos = sorted(list(estados_fisicos_base.union(estados_fisicos_db)))
    # -------------------------------------------------------------------------

    unidades_medida_unicas_raw = db.session.query(Producto.unidad_medida).distinct().filter(Producto.unidad_medida != None).all()
    unidades_medida_unicas = sorted([u[0] for u in unidades_medida_unicas_raw])
    
    estados_envase_posibles = ['abierto', 'cerrado']
    ubicaciones_actuales_posibles = ['lesqo', 'loefba', 'otro']

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    if page > pagination.pages and pagination.pages > 0:
         return redirect(url_for('inventario_completo', page=pagination.pages, **request.args))
    
    productos_procesados = []
    # --- NUEVA CARACTERÍSTICA: Numeración de Filas ---
    start_index = (pagination.page - 1) * pagination.per_page
    
    for index, producto in enumerate(pagination.items):
        # Asignar el número de fila al objeto producto
        producto.row_number = start_index + index + 1
        # --- FIN NUEVA CARACTERÍSTICA ---
        
        if producto.cantidad is None:
            producto.cantidad = 0.0
        if producto.stock_minimo is None:
            producto.stock_minimo = 0.0
        productos_procesados.append(producto)

    return render_template('inventario_completo.html', 
        productos=productos_procesados,
        pagination=pagination, 
        search_term=search_term, 
        per_page=per_page, 
        estado_fisico_filter=estado_fisico_filter, 
        unidad_medida_filter=unidad_medida_filter, 
        estado_envase_filter=estado_envase_filter, 
        ubicacion_actual_filter=ubicacion_actual_filter, 
        estados_fisicos_unicos=estados_fisicos_unicos, 
        estados_envase_unicos=estados_envase_posibles, 
        unidades_medida_unicas=unidades_medida_unicas, 
        ubicaciones_actuales_posibles=ubicaciones_actuales_posibles
    )

@app.route('/panel/inventario/exportar-csv')
@login_required
def exportar_inventario_csv():
    search_term = request.args.get('search', '', type=str)
    estado_fisico_filter = request.args.get('estado_fisico', 'todos', type=str)
    unidad_medida_filter = request.args.get('unidad_medida', 'todas', type=str)
    estado_envase_filter = request.args.get('estado_envase', 'todos', type=str)
    ubicacion_actual_filter = request.args.get('ubicacion_actual', 'todas', type=str) 

    query = Producto.query.order_by(Producto.nombre)
    
    if search_term:
        query = query.filter(Producto.nombre.ilike(f'%{search_term}%'))
    if estado_fisico_filter != 'todos':
        query = query.filter(func.upper(Producto.estado_fisico) == estado_fisico_filter.upper())
    if unidad_medida_filter != 'todas':
        query = query.filter(func.upper(Producto.unidad_medida) == unidad_medida_filter.upper())
    if estado_envase_filter != 'todos':
        query = query.filter(func.upper(Producto.estado) == estado_envase_filter.upper()) 
    if ubicacion_actual_filter != 'todas':
        query = query.filter(func.upper(Producto.ubicacion_actual) == ubicacion_actual_filter.upper())

    productos_a_exportar = query.all()
    
    si = StringIO()
    cw = csv.writer(si)

    headers = [
        "ID", "Nombre", "Formula Molecular", "Nombre IUPAC", "Nombre Comun (Cana)", 
        "CAS / SIGMG", "Estado Fisico", "Cantidad", "Unidad de Medida", 
        "Stock Minimo", "Estado Envase", "Ubicacion Almacen", "Estante", 
        "Ubicacion Actual (Uso)", "Detalle Ubicacion (Otro)"
    ]
    cw.writerow(headers)

    for p in productos_a_exportar:
        row = [
            p.id, p.nombre, p.formula_molecular, p.nombre_IUPAC, p.nombre_cana,
            p.cast_sigmg, p.estado_fisico, p.cantidad, p.unidad_medida, 
            p.stock_minimo, p.estado, p.ubicacion, p.estante, p.ubicacion_actual, 
            p.otra_ubicacion_actual
        ]
        cw.writerow([str(item) if item is not None else '' for item in row])

    output = si.getvalue()
    fecha_exportacion = datetime.now(pytz.timezone(app.config.get('TIMEZONE', 'UTC'))).strftime('%Y%m%d_%H%M')
    
    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment;filename=inventario_exportado_{fecha_exportacion}.csv",
            "Content-type": "text/csv; charset=utf-8"
        }
    )

@app.route('/panel/ordenes')
@login_required
def admin_ordenes():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    if per_page not in [10, 25, 50]: per_page = 10
    estado_filter = request.args.get('estado', 'todas', type=str)
    
    query = Orden.query.options(
        joinedload(Orden.creador),
        selectinload(Orden.detalles).joinedload(DetalleOrden.producto)
    ).order_by(Orden.fecha_solicitud.desc())
    
    if estado_filter == 'abiertas':
        query = query.filter(Orden.estado == 'ABIERTA')
    elif estado_filter == 'cerradas':
        query = query.filter(Orden.estado == 'CERRADA')
        
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('admin_ordenes.html', ordenes=pagination.items, pagination=pagination, per_page=per_page, estado_filter=estado_filter)

@app.route('/panel/orden/nueva', methods=['GET', 'POST'])
@login_required
def crear_orden():
    productos = Producto.query.filter(Producto.cantidad.isnot(None), Producto.cantidad > 0).order_by(Producto.nombre).all()
    if request.method == 'POST':
        try:
            solicitado_por = request.form.get('solicitado_por')
            producto_id = int(request.form.get('producto_id'))
            cantidad_str = request.form.get('cantidad', '0').replace(',', '.')
            cantidad = float(cantidad_str)

            if not all([solicitado_por, producto_id, cantidad > 0]):
                flash('Todos los campos son obligatorios y la cantidad debe ser mayor a cero.', 'danger')
                return render_template('crear_orden.html', productos=productos)
            
            producto = db.session.get(Producto, producto_id)
            
            if not producto or producto.cantidad is None or producto.cantidad < cantidad:
                flash(f'Stock insuficiente. Disponible: {producto.cantidad if producto else 0}', 'danger')
                return render_template('crear_orden.html', productos=productos)
            
            nueva_orden = Orden(solicitado_por=solicitado_por, creado_por_id=current_user.id)
            detalle = DetalleOrden(orden=nueva_orden, producto_id=producto_id, cantidad_pedida=cantidad)
            
            producto.cantidad -= cantidad
            
            db.session.add_all([nueva_orden, detalle])
            db.session.commit()
            flash(f'Orden para "{solicitado_por}" creada con éxito.', 'success')
            return redirect(url_for('admin_ordenes'))
        
        except (ValueError, TypeError) as e:
            flash('Por favor, introduce valores válidos.', 'danger')
            app.logger.error(f"Error de valor/tipo al crear orden: {e}")
        except Exception as e:
            db.session.rollback()
            flash('Ocurrió un error inesperado al crear la orden.', 'danger')
            app.logger.error(f"Error al crear la orden: {e}")
    return render_template('crear_orden.html', productos=productos)

@app.route('/panel/producto/gestion/', methods=['GET', 'POST'])
@app.route('/panel/producto/gestion/<int:id>', methods=['GET', 'POST'])
@login_required
def gestionar_producto(id=None):
    producto = db.session.get(Producto, id) if id else None
    
    # Capturar el parámetro 'next' de la URL para redirigir después de guardar
    next_url = request.args.get('next', url_for('inventario_completo'))

    if request.method == 'POST':
        try:
            is_new = producto is None
            if is_new:
                producto = Producto()
                db.session.add(producto)
            
            producto.nombre = request.form['nombre'].strip()
            producto.ubicacion = request.form.get('ubicacion', '').strip()
            producto.estante = request.form.get('estante', '').strip()
            producto.nombre_cana = request.form.get('nombre_cana', '').strip()
            producto.nombre_IUPAC = request.form.get('nombre_IUPAC', '').strip()
            producto.formula_molecular = request.form.get('formula_molecular', '').strip()
            producto.cast_sigmg = request.form.get('cast_sigmg', '').strip()
            producto.estado_fisico = request.form.get('estado_fisico', '').strip().lower() 
            
            cantidad_str = request.form.get('cantidad', '0').replace(',', '.')
            producto.cantidad = float(cantidad_str)
            
            stock_minimo_str = request.form.get('stock_minimo', '0').replace(',', '.')
            producto.stock_minimo = float(stock_minimo_str)

            producto.unidad_medida = request.form['unidad_medida'].strip().lower()
            producto.estado = request.form.get('estado', '').strip().lower() 
            producto.ubicacion_actual = request.form['ubicacion_actual'].strip().lower()
            
            if producto.ubicacion_actual == 'otro':
                producto.otra_ubicacion_actual = request.form.get('otra_ubicacion_actual', '').strip()
            else:
                producto.otra_ubicacion_actual = None

            db.session.commit()
            flash('Producto guardado con éxito.', 'success')
            
            # --- Persistencia del Filtro: Redirige usando el valor 'next' ---
            return redirect(request.form.get('next') or url_for('inventario_completo'))
            
        except Exception as e:
            db.session.rollback()
            flash('Ocurrió un error inesperado al guardar el producto.', 'danger')
            app.logger.error(f"Error al guardar el producto: {e}")
            
    # Asegúrate de pasar 'next_url' a la plantilla en el método GET
    return render_template('gestion_producto.html', producto=producto, next_url=next_url)
    
@app.route('/panel/historial')
@login_required
def admin_historial():
    if not current_user.es_admin: abort(403)
    page = request.args.get('page', 1, type=int)
    pagination = OrdenHistorial.query.order_by(OrdenHistorial.fecha_eliminacion.desc()).paginate(page=page, per_page=25, error_out=False)
    return render_template('admin_historial.html', historial=pagination.items, pagination=pagination)

@app.route('/panel/historial/borrar-seleccion', methods=['POST'])
@login_required
def admin_borrar_historial_seleccion():
    if not current_user.es_admin: abort(403)
    historial_ids = request.form.getlist('historial_ids')
    if not historial_ids:
        flash('No se seleccionó ningún registro.', 'warning')
        return redirect(url_for('admin_historial'))

    try:
        OrdenHistorial.query.filter(OrdenHistorial.id.in_(historial_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f'Se eliminaron {len(historial_ids)} registros del historial.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ocurrió un error inesperado al eliminar registros.', 'danger')
        app.logger.error(f"Error al eliminar registros: {e}")
    
    return redirect(url_for('admin_historial'))

@app.route('/panel/historial/borrar-todo', methods=['POST'])
@login_required
def admin_borrar_historial_todo():
    if not current_user.es_admin: abort(403)
    try:
        num_deleted = db.session.query(OrdenHistorial).delete()
        db.session.commit()
        flash(f'¡ADVERTENCIA! Se eliminaron {num_deleted} registros. El historial está vacío.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash('Ocurrió un error inesperado al borrar todo el historial.', 'danger')
        app.logger.error(f"Error al borrar todo el historial: {e}")
    
    return redirect(url_for('admin_historial'))

@app.route('/panel/orden/borrar-historial/<int:orden_id>', methods=['POST'])
@login_required
def admin_borrar_orden_historial(orden_id):
    orden = db.session.get(Orden, orden_id)
    if not orden:
        flash('La orden no existe.', 'danger')
        return redirect(url_for('admin_ordenes'))
    try:
        if orden.estado == 'ABIERTA':
            for detalle in orden.detalles:
                producto = db.session.get(Producto, detalle.producto_id)
                if producto:
                    if producto.cantidad is None: producto.cantidad = 0
                    producto.cantidad += detalle.cantidad_pedida
        productos_info = ", ".join([f"{d.producto.nombre if d.producto else 'N/A'} (x{d.cantidad_pedida})" for d in orden.detalles])
        rol = 'Admin' if current_user.es_admin else 'Usuario'
        
        nuevo_historial = OrdenHistorial(
            original_orden_id=orden.id, solicitante_info=orden.solicitado_por,
            productos_info=productos_info, fecha_solicitud=orden.fecha_solicitud,
            fecha_cierre=orden.fecha_cierre, eliminado_por_rol=rol,
            eliminado_por_info=current_user.nombre,
        )
        db.session.add(nuevo_historial)
        db.session.delete(orden)
        db.session.commit()
        flash(f'La orden #{orden.id} ha sido movida al historial.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ocurrió un error inesperado al mover la orden al historial.', 'danger')
        app.logger.error(f"Error al mover la orden: {e}")
    return redirect(url_for('admin_ordenes'))

@app.route('/panel/producto/borrar/<int:id>', methods=['POST'])
@login_required
def admin_borrar_producto(id):
    producto = db.session.get(Producto, id)
    if not producto:
        return jsonify({'success': False, 'message': 'Producto no encontrado.'}), 404
    try:
        db.session.delete(producto)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Producto eliminado.'})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error: El producto está en uso en una orden.'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Ocurrió un error inesperado.'}), 500

@app.route('/panel/producto/borrar-seleccion', methods=['POST'])
@login_required
def admin_borrar_productos_seleccion():
    if not current_user.es_admin: abort(403)
    producto_ids = request.form.getlist('producto_ids')
    if not producto_ids:
        flash('No se seleccionó ningún producto para eliminar.', 'warning')
        return redirect(url_for('inventario_completo'))

    try:
        # Aquí se realiza el borrado de los productos seleccionados
        num_deleted = db.session.query(Producto).filter(Producto.id.in_(producto_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f'Se eliminaron {num_deleted} productos seleccionados.', 'success')
    except IntegrityError:
        db.session.rollback()
        flash('Error: No se pudieron eliminar algunos productos porque están en uso en órdenes.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash('Ocurrió un error inesperado al eliminar productos.', 'danger')
        app.logger.error(f"Error al eliminar productos: {e}")
    
    return redirect(url_for('inventario_completo'))

# --- RUTA 'BORRAR TODO' RESTAURADA ---
@app.route('/panel/producto/borrar-todo', methods=['POST'])
@login_required
def admin_borrar_productos_todo():
    if not current_user.es_admin: abort(403)
    try:
        num_deleted = db.session.query(Producto).delete(synchronize_session=False)
        db.session.commit()
        flash(f'¡ADVERTENCIA! Se eliminaron {num_deleted} productos. El inventario está vacío.', 'danger')
    except IntegrityError:
        db.session.rollback()
        flash('Error: No se pueden eliminar todos los productos porque algunos están en uso en órdenes.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash('Ocurrió un error inesperado al borrar todo el inventario.', 'danger')
        app.logger.error(f"Error al borrar todo el inventario: {e}")
    
    return redirect(url_for('inventario_completo'))
# -----------------------------------------------

@app.route('/panel/orden/cerrar/<int:orden_id>', methods=['GET', 'POST'])
@login_required
def cerrar_orden(orden_id):
    orden = db.session.get(Orden, orden_id)
    if not orden: abort(404)
    if orden.estado == 'CERRADA':
        flash('Esta orden ya ha sido cerrada.', 'warning')
        return redirect(url_for('admin_ordenes'))
    if request.method == 'POST':
        try:
            for detalle in orden.detalles:
                input_name = f"devuelto_{detalle.id}"
                cantidad_devuelta_str = request.form.get(input_name, '0').replace(',', '.')
                cantidad_devuelta = float(cantidad_devuelta_str) if cantidad_devuelta_str else 0.0
                    
                if not (0 <= cantidad_devuelta <= detalle.cantidad_pedida):
                    flash(f'La cantidad devuelta para "{detalle.producto.nombre}" no es válida.', 'danger')
                    return render_template('admin_cerrar_orden.html', orden=orden)
                
                detalle.cantidad_devuelta = cantidad_devuelta
                producto = db.session.get(Producto, detalle.producto_id)
                if producto:
                    if producto.cantidad is None: producto.cantidad = 0
                    producto.cantidad += cantidad_devuelta 
                    
            orden.estado = 'CERRADA'
            orden.fecha_cierre = datetime.utcnow()
            orden.observaciones = request.form.get('observaciones', '')
            db.session.commit()
            flash('Orden cerrada y stock actualizado.', 'success')
            return redirect(url_for('admin_ordenes'))
        except (ValueError, TypeError):
            flash('Por favor, introduce valores numéricos válidos.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash('Ocurrió un error inesperado al cerrar la orden.', 'danger')
            app.logger.error(f"Error al cerrar la orden: {e}")
    return render_template('admin_cerrar_orden.html', orden=orden)

# app.py - Función Corregida: _update_product_from_row()

def _update_product_from_row(producto: Producto, row: Dict[str, Any]):
    """
    Función auxiliar para actualizar un objeto Producto desde una fila de CSV.
    Incluye manejo de errores robusto para la conversión a float.
    """
    errors = []
    
    for field, value in row.items():
        field = field.strip().lower()
        
        # Asegura que value no sea None y se convierta a string vacío si lo es
        str_value = str(value).strip() if value is not None else '' 
        
        if hasattr(producto, field) and str_value != '':
            if field in ['cantidad', 'stock_minimo']:
                # Manejo de errores de conversión a float: ignora el error y usa 0.0
                try:
                    # Reemplaza comas por puntos antes de la conversión a float
                    numeric_value = str_value.replace(',', '.')
                    setattr(producto, field, float(numeric_value))
                except ValueError:
                    # Si falla la conversión (porque encontró texto), usa 0.0 y registra el error.
                    setattr(producto, field, 0.0)
                    errors.append(f"El campo '{field}' esperaba un número, pero se encontró '{str_value}'. Se estableció en 0.")
            else:
                setattr(producto, field, str_value) 
    
    if errors:
        # Lanza ValueError para que el bloque try/except en importar_inventario
        # pueda capturar estos errores específicos de campo.
        raise ValueError("; ".join(errors))


@app.route('/importar', methods=['GET', 'POST']) 
@login_required
def importar_inventario():
    if request.method == 'POST':
        if 'archivo_csv' not in request.files:
            flash('No se encontró el archivo en la solicitud.', 'danger')
            return redirect(request.url)

        file = request.files['archivo_csv']
        if file.filename == '' or not file.filename.lower().endswith('.csv'):
            flash('No se seleccionó ningún archivo o el formato no es .csv.', 'warning')
            return redirect(request.url)

        errors = []
        try:
            content = file.stream.read().decode('utf-8-sig')
            stream = StringIO(content)

            try:
                dialect = csv.Sniffer().sniff(stream.read(2048))
                stream.seek(0)
            except csv.Error:
                stream.seek(0)
                dialect = 'excel'
            
            csv_reader = csv.DictReader(stream, dialect=dialect)
            
            # Normaliza los nombres de las columnas a minúsculas y sin espacios
            if csv_reader.fieldnames:
                normalized_fieldnames = {}
                for name in csv_reader.fieldnames:
                    if name is not None:
                         normalized_fieldnames[name] = name.strip().lower()

                csv_reader.fieldnames = [normalized_fieldnames.get(name, name) for name in csv_reader.fieldnames if name is not None]

            # Valida que las columnas obligatorias existan
            required_columns = ['nombre', 'cantidad', 'stock_minimo', 'unidad_medida']
            if not csv_reader.fieldnames or not all(col in csv_reader.fieldnames for col in required_columns):
                current_fields = set(csv_reader.fieldnames if csv_reader.fieldnames else [])
                missing = [col for col in required_columns if col not in current_fields]
                flash(f"El archivo CSV debe contener las siguientes columnas obligatorias: {', '.join(missing)}.", 'danger')
                return render_template('importar_inventario.html', errors=errors)
            
            # Inicia una transacción
            with db.session.begin_nested():
                for i, row_original in enumerate(csv_reader, start=2):
                    row = {}
                    for k, v in row_original.items():
                        if k is not None:
                            row[k] = str(v).strip() if v is not None else ''

                    nombre_producto = row.get('nombre', '').strip()
                    if not nombre_producto:
                        errors.append(f"Fila {i}: El 'nombre' del producto no puede estar vacío.")
                        continue
                    
                    producto = db.session.query(Producto).filter(func.lower(Producto.nombre) == func.lower(nombre_producto)).first()
                    
                    try:
                        if producto:  # Actualizar producto existente
                            _update_product_from_row(producto, row)
                        else:  # Crear nuevo producto
                            nuevo_producto = Producto(nombre=nombre_producto)
                            _update_product_from_row(nuevo_producto, row)
                            db.session.add(nuevo_producto)
                    
                    except ValueError as e:
                        # Este bloque captura el error de campo específico lanzado por _update_product_from_row
                        errors.append(f"Fila {i} (Producto: '{nombre_producto}'): {e}")
                    except Exception as e:
                        errors.append(f"Fila {i} (Producto: '{nombre_producto}'): Error inesperado - {e}")
                
                if errors:
                    raise SQLAlchemyError("Errores encontrados durante la importación, revirtiendo cambios.")

            db.session.commit()
            flash('Inventario importado y/o actualizado exitosamente. 🎉', 'success')
            return redirect(url_for('inventario_completo'))

        except SQLAlchemyError:
             db.session.rollback() 
             # Nota: Se mejoró el mensaje aquí, ya que los errores se listan abajo
             flash('Se encontraron errores en el archivo CSV. No se importó ningún dato. Revisa los detalles abajo.', 'danger')
        except (csv.Error, Exception) as e:
            db.session.rollback()
            errors.append(f"Error crítico al leer o procesar el archivo: {e}")
            flash(f"Error crítico al procesar el archivo. Revisa el formato y el delimitador. Detalles: {e}", 'danger')

        return render_template('importar_inventario.html', errors=errors)

    return render_template('importar_inventario.html', errors=[])

@app.route('/panel/usuarios')
@login_required
def admin_usuarios():
    if not current_user.es_admin: abort(403)
    page = request.args.get('page', 1, type=int)
    pagination = User.query.filter(User.id != current_user.id).order_by(User.nombre).paginate(page=page, per_page=10, error_out=False)
    return render_template('admin_usuarios.html', users=pagination.items, pagination=pagination)

@app.route('/panel/usuario/gestion', methods=['GET', 'POST'])
@app.route('/panel/usuario/gestion/<int:id>', methods=['GET', 'POST'])
@login_required
def gestionar_usuario(id=None):
    if not current_user.es_admin: abort(403)
    user = db.session.get(User, id) if id else None
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            nombre = request.form.get('nombre', '').strip()
            rol = request.form.get('rol')
            password = request.form.get('password')

            if not email or not nombre or not rol:
                flash("Nombre, email y rol son campos obligatorios.", 'danger')
                return render_template('gestion_usuario.html', user=user)

            existing_user_by_email = User.query.filter(User.email == email, User.id != id).first()
            if existing_user_by_email:
                flash('El correo electrónico ya está en uso por otro usuario.', 'danger')
                return render_template('gestion_usuario.html', user=user)

            if user is None:
                if not password:
                    flash('La contraseña es obligatoria para nuevos usuarios.', 'danger')
                    return render_template('gestion_usuario.html', user=user)
                user = User(nombre=nombre, email=email, es_admin=(rol == 'admin'))
                user.set_password(password)
                db.session.add(user)
                flash('Usuario creado con éxito.', 'success')
            else:
                user.nombre = nombre
                user.email = email
                user.es_admin = (rol == 'admin')
                if password:
                    user.set_password(password)
                flash('Usuario actualizado con éxito.', 'success')
            
            db.session.commit()
            return redirect(url_for('admin_usuarios'))
        except Exception as e:
            db.session.rollback()
            flash("Ocurrió un error inesperado al gestionar el usuario.", "danger")
            app.logger.error(f"Error al gestionar usuario: {e}")

    return render_template('gestion_usuario.html', user=user)

@app.route('/panel/usuario/borrar/<int:id>', methods=['POST'])
@login_required
def borrar_usuario(id):
    if not current_user.es_admin: abort(403)
    if id == current_user.id:
        flash('No puedes eliminar tu propia cuenta.', 'danger')
        return redirect(url_for('admin_usuarios'))

    user_a_borrar = db.session.get(User, id)
    if user_a_borrar:
        try:
            db.session.delete(user_a_borrar)
            db.session.commit()
            flash(f'Usuario "{user_a_borrar.nombre}" eliminado.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('No se pudo eliminar al usuario. Ocurrió un error inesperado.', 'danger')
            app.logger.error(f"Error al eliminar usuario: {e}")
    else:
        flash("Usuario no encontrado.", "warning")
    return redirect(url_for('admin_usuarios'))

@app.cli.command("init-db")
def init_db_command():
    """Inicializa la base de datos."""
    db.create_all()
    print("Base de datos inicializada.")

@app.cli.command("create-user")
def create_user_cli():
    """Crea un nuevo usuario desde la línea de comandos."""
    nombre = input("Nombre: ")
    email = input("Email: ")
    password = input("Contraseña: ")
    rol = ''
    while rol not in ['admin', 'gerente']:
        rol = input("Rol (admin/gerente): ").lower()
    
    if User.query.filter_by(email=email).first():
        print(f"Error: El correo '{email}' ya existe.")
        return
        
    user = User(nombre=nombre, email=email, es_admin=(rol == 'admin'))
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print(f"¡Usuario '{nombre}' con rol '{rol}' creado exitosamente!")

@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
        "img-src 'self' data:;"
    )
    response.headers['Content-Security-Policy'] = csp
    return response

if __name__ == '__main__':
    app.run(debug=True)
