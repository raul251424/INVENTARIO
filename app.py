# app.py (CÓDIGO COMPLETO CON LA CORRECCIÓN DE PAGINACIÓN)

from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from os import getenv
from datetime import datetime, timedelta
import pytz
import bcrypt
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import select, func, text 
import time
import csv
from io import StringIO
from typing import List, Dict, Any

# --- INICIALIZACIÓN Y CONFIGURACIÓN ---
load_dotenv()
app = Flask(__name__)

# Configuración de la base de datos y clave secreta
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{getenv('DB_USER')}:{getenv('DB_PASSWORD')}@{getenv('DB_HOST')}:{getenv('DB_PORT', '5432')}/{getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = getenv('SECRET_KEY', 'un-secreto-muy-fuerte-y-dificil-de-adivinar')
app.config['TIMEZONE'] = 'America/Mexico_City'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

# --- EXTENSIONES ---
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)

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
    ubicacion = db.Column(db.String(255))
    estante = db.Column(db.String(100))
    nombre_cana = db.Column(db.String(255))
    nombre_IUPAC = db.Column(db.String(500))
    formula_molecular = db.Column(db.String(255))
    cast_sigmg = db.Column(db.String(255))
    estado_fisico = db.Column(db.String(100))
    cantidad = db.Column(db.Float)
    unidad_medida = db.Column(db.String(100))
    estado = db.Column(db.String(100))
    ubicacion_actual = db.Column(db.String(255))
    otra_ubicacion_actual = db.Column(db.String(500), nullable=True)
    detalles_orden = db.relationship('DetalleOrden', backref='producto', lazy=True, cascade="all, delete-orphan")

class Orden(db.Model):
    __tablename__ = 'orden'
    id = db.Column(db.Integer, primary_key=True)
    solicitado_por = db.Column(db.String(100), nullable=False)
    creado_por_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fecha_solicitud = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    fecha_cierre = db.Column(db.DateTime, nullable=True)
    estado = db.Column(db.String(20), default='ABIERTA')
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

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    if request.method == 'POST':
        return '', 204
    return redirect(url_for('login'))

@app.route('/')
def dashboard_router():
    return redirect(url_for('admin_dashboard') if current_user.is_authenticated else url_for('login'))

@app.route('/panel/dashboard')
@login_required
def admin_dashboard():
    try:
        total_productos = db.session.query(func.count(Producto.id)).scalar()
        ordenes_abiertas = db.session.query(func.count(Orden.id)).filter(Orden.estado == 'ABIERTA').scalar()
        productos_recientes = Producto.query.order_by(Producto.id.desc()).limit(5).all()
        return render_template('admin_dashboard.html', total_productos=total_productos, ordenes_abiertas=ordenes_abiertas, productos_recientes=productos_recientes)
    except Exception as e:
        flash(f"No se pudo cargar la información del dashboard: {e}", "danger")
        return render_template('admin_dashboard.html', total_productos='N/A', ordenes_abiertas='N/A', productos_recientes=[])

@app.route('/panel/inventario')
@login_required
def inventario_completo():
    # --- INICIO CORRECCIÓN DE VALIDACIÓN Y PAGINACIÓN ---
    try:
        # Recuperamos 'page' y lo forzamos a ser un entero, por defecto 1
        page = int(request.args.get('page', 1))
        # Recuperamos 'per_page' y lo forzamos a ser un entero, por defecto 10
        per_page = int(request.args.get('per_page', 10))
    except ValueError:
        # Si el valor de 'page' o 'per_page' es inválido (ej. 'abc'), usamos los valores por defecto
        page = 1
        per_page = 10
        
    # Validamos que per_page esté en las opciones permitidas
    if per_page not in [10, 25, 50]: 
        per_page = 10
    # Aseguramos que la página sea al menos 1
    if page < 1:
        page = 1
    
    # Resto de filtros, que ya estaban correctos
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

    estados_fisicos_unicos = db.session.query(Producto.estado_fisico).distinct().filter(Producto.estado_fisico != None).all()
    unidades_medida_unicas = db.session.query(Producto.unidad_medida).distinct().filter(Producto.unidad_medida != None).all()
    
    estados_envase_posibles = ['abierto', 'cerrado']
    ubicaciones_actuales_posibles = ['lesqo', 'loefba', 'otro']

    # La paginación debe usar los valores limpios de page y per_page
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Si la página solicitada es mayor que el número total de páginas, redirigimos a la última página válida
    if page > pagination.pages and pagination.pages > 0:
         return redirect(url_for('inventario_completo', page=pagination.pages, **request.args))
    elif page < 1:
        return redirect(url_for('inventario_completo', page=1, **request.args))

    return render_template('inventario_completo.html', productos=pagination.items, pagination=pagination, search_term=search_term, per_page=per_page, estado_fisico_filter=estado_fisico_filter, unidad_medida_filter=unidad_medida_filter, estado_envase_filter=estado_envase_filter, ubicacion_actual_filter=ubicacion_actual_filter, estados_fisicos_unicos=[e[0] for e in estados_fisicos_unicos], estados_envase_unicos=estados_envase_posibles, unidades_medida_unicas=[u[0] for u in unidades_medida_unicas], ubicaciones_actuales_unicas=ubicaciones_actuales_posibles)
    # --- FIN CORRECCIÓN DE VALIDACIÓN Y PAGINACIÓN ---


@app.route('/panel/ordenes')
@login_required
def admin_ordenes():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    if per_page not in [10, 25, 50]: per_page = 10
    estado_filter = request.args.get('estado', 'todas', type=str)
    query = Orden.query.options(joinedload(Orden.creador)).order_by(Orden.fecha_solicitud.desc())
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
            cantidad_str = request.form.get('cantidad').replace(',', '.')
            cantidad = float(cantidad_str)

            if not all([solicitado_por, producto_id, cantidad]):
                flash('Todos los campos son obligatorios.', 'danger')
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
            flash(f'Por favor, introduce valores válidos. Error: {e}', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear la orden: {e}', 'danger')
    return render_template('crear_orden.html', productos=productos)

@app.route('/panel/producto/gestion/', methods=['GET', 'POST'])
@app.route('/panel/producto/gestion/<int:id>', methods=['GET', 'POST'])
@login_required
def gestionar_producto(id=None):
    producto = db.session.get(Producto, id) if id else None
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
            
            producto.unidad_medida = request.form['unidad_medida'].strip().lower()
            producto.estado = request.form.get('estado', '').strip().lower() 
            producto.ubicacion_actual = request.form['ubicacion_actual'].strip().lower()
            
            if producto.ubicacion_actual == 'otro':
                producto.otra_ubicacion_actual = request.form.get('otra_ubicacion_actual', '').strip()
            else:
                producto.otra_ubicacion_actual = None

            db.session.commit()
            flash('Producto guardado con éxito.', 'success')
            return redirect(url_for('inventario_completo'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al guardar el producto: {e}', 'danger')
    return render_template('gestion_producto.html', producto=producto)
    
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
        OrdenHistorial.query.filter(OrdenHistorial.id.in_(historial_ids)).delete(synchronize_session='fetch')
        db.session.commit()
        flash(f'Se eliminaron {len(historial_ids)} registros del historial.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar registros: {e}', 'danger')
    
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
        flash(f'Error al borrar todo el historial: {e}', 'danger')
    
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
        rol = 'Admin' if current_user.es_admin else 'Gerente'
        
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
        flash(f'Error al mover la orden: {e}', 'danger')
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
        return jsonify({'success': False, 'message': f'Error inesperado: {e}'}), 500

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
            flash(f'Error al cerrar la orden: {e}', 'danger')
    return render_template('admin_cerrar_orden.html', orden=orden)

# --- RUTA DE IMPORTACIÓN CSV CON CORRECCIÓN DE TRANSACCIÓN ---
@app.route('/panel/inventario/importar', methods=['GET', 'POST'])
@login_required
def importar_inventario():
    db.session.close() # <-- LÍNEA DE ÚLTIMO RECURSO
    if not current_user.es_admin:
        abort(403)

    if request.method == 'POST':
        if 'archivo_csv' not in request.files or request.files['archivo_csv'].filename == '':
            flash('No se seleccionó ningún archivo.', 'danger')
            return redirect(request.url)

        file = request.files['archivo_csv']
        if not file.filename.lower().endswith('.csv'):
            flash('Tipo de archivo no permitido. Sube un archivo CSV.', 'danger')
            return redirect(request.url)

        try:
            file_content = file.stream.read().decode("utf-8")
            file_content_clean = file_content.lstrip('\ufeff')
            
            stream = StringIO(file_content_clean)
            try:
                dialect = csv.Sniffer().sniff(stream.read(1024), delimiters=',;\t')
                stream.seek(0)
                delimiter = dialect.delimiter
            except csv.Error:
                stream.seek(0)
                delimiter = ','
            
            reader_for_validation = csv.DictReader(stream, delimiter=delimiter)
            reader_for_validation.fieldnames = [name.strip().lower() for name in reader_for_validation.fieldnames]

            required_fields = ['nombre', 'cantidad', 'unidad_medida']
            if not all(field in reader_for_validation.fieldnames for field in required_fields):
                missing = ", ".join([field for field in required_fields if field not in reader_for_validation.fieldnames])
                raise ValueError(f"Faltan encabezados obligatorios en el archivo CSV: {missing}")

            with db.session.begin():
                existing_products_query = select(Producto.id, func.upper(Producto.nombre).label('nombre_upper'))
                result = db.session.execute(existing_products_query).all()
                existing_products_map = {row.nombre_upper: row.id for row in result}

                stream.seek(0)
                reader = csv.DictReader(stream, delimiter=delimiter)
                reader.fieldnames = [name.strip().lower() for name in reader.fieldnames]
                
                data_to_insert, data_to_update = [], []
                
                field_mapping = {
                    'nombre': 'nombre', 'ubicacion': 'ubicacion', 'estante': 'estante',
                    'nombre_cana': 'nombre_cana', 'nombre_IUPAC': 'nombre_IUPAC',
                    'formula_molecular': 'formula_molecular', 'cast_sigmg': 'cast_sigmg',
                    'estado_fisico': 'estado_fisico', 'cantidad': 'cantidad',
                    'unidad_medida': 'unidad_medida', 'estado': 'estado',
                    'ubicacion_actual': 'ubicacion_actual', 'otra_ubicacion_actual': 'otra_ubicacion_actual',
                }

                for row_number, row in enumerate(reader, 2):
                    nombre_raw = row.get('nombre', '').strip()
                    if not nombre_raw:
                        raise ValueError(f"Fila {row_number}: El campo 'nombre' no puede estar vacío.")

                    processed_row = {}
                    for csv_key, model_attr in field_mapping.items():
                        csv_value = row.get(csv_key, '').strip()
                        if model_attr == 'cantidad':
                            processed_row[model_attr] = float(csv_value.replace(',', '.')) if csv_value else 0.0
                        elif model_attr in ['estado_fisico', 'unidad_medida', 'estado', 'ubicacion_actual']:
                            processed_row[model_attr] = csv_value.lower() if csv_value else None
                        else:
                            processed_row[model_attr] = csv_value if csv_value else None
                    
                    if processed_row.get('ubicacion_actual') != 'otro':
                        processed_row['otra_ubicacion_actual'] = None
                    
                    processed_row['nombre'] = nombre_raw
                    nombre_upper = nombre_raw.upper()
                    
                    if nombre_upper in (p['nombre'].upper() for p in data_to_insert):
                        raise ValueError(f"Fila {row_number}: Nombre de producto '{nombre_raw}' duplicado dentro del mismo archivo CSV.")

                    if nombre_upper in existing_products_map:
                        processed_row['id'] = existing_products_map[nombre_upper]
                        data_to_update.append(processed_row)
                    else:
                        data_to_insert.append(processed_row)
                
                if not data_to_insert and not data_to_update:
                    raise ValueError("El archivo CSV está vacío o no contiene datos válidos para procesar.")

                if data_to_update:
                    db.session.bulk_update_mappings(Producto, data_to_update)
                if data_to_insert:
                    db.session.bulk_insert_mappings(Producto, data_to_insert)

            flash(f'Importación exitosa. {len(data_to_insert)} productos creados, {len(data_to_update)} actualizados.', 'success')
            return redirect(url_for('inventario_completo'))

        except (SQLAlchemyError, ValueError, csv.Error, Exception) as e:
            flash(f'Importación fallida. Todos los cambios fueron revertidos. Error: {e}', 'danger')
            return render_template('importar_inventario.html', errors=[f"Error: {e}"])

    return render_template('importar_inventario.html')


# --- RUTAS DE GESTIÓN DE USUARIOS (SOLO ADMINS) ---
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
        email = request.form.get('email')
        nombre = request.form.get('nombre')
        rol = request.form.get('rol')
        password = request.form.get('password')

        existing_user = User.query.filter(User.email == email).first()
        if existing_user and (user is None or existing_user.id != user.id):
            flash('El correo electrónico ya está en uso por otro usuario.', 'danger')
            return render_template('gestion_usuario.html', user=user)

        if user is None:
            if not password:
                flash('La contraseña es obligatoria para los nuevos usuarios.', 'danger')
                return render_template('gestion_usuario.html', user=user)
            new_user = User(nombre=nombre, email=email, es_admin=(rol == 'admin'))
            new_user.set_password(password)
            db.session.add(new_user)
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

    return render_template('gestion_usuario.html', user=user)

@app.route('/panel/usuario/borrar/<int:id>', methods=['POST'])
@login_required
def borrar_usuario(id):
    if not current_user.es_admin: abort(403)
    user_a_borrar = db.session.get(User, id)
    if user_a_borrar:
        if user_a_borrar.id == current_user.id:
            flash('No puedes eliminar tu propia cuenta.', 'danger')
        else:
            db.session.delete(user_a_borrar)
            db.session.commit()
            flash(f'Usuario "{user_a_borrar.nombre}" eliminado.', 'success')
    return redirect(url_for('admin_usuarios'))

# --- COMANDOS CLI ---
@app.cli.command("init-db")
def init_db_command():
    db.create_all()
    print("Base de datos inicializada.")

@app.cli.command("create-user")
def create_user_cli():
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

if __name__ == '__main__':
    app.run(debug=True)