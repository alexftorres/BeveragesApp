from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta  # Import timedelta
import os
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///beer_prices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelos do banco de dados
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    has_whatsapp = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(120), nullable=False)
    points = db.Column(db.Integer, default=0)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)

    role = db.relationship('Role', backref='users')

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # supermercado, distribuidora, deposito
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(300), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Brand(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Beer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Nome específico da cerveja
    brand_id = db.Column(db.Integer, db.ForeignKey('brand.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # lager, ipa, pilsen, etc
    description = db.Column(db.Text, nullable=False)
    size = db.Column(db.String(20), nullable=False)  # 350ml, 500ml, 600ml, etc
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    brand = db.relationship('Brand', backref='beers')

class Price(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    beer_id = db.Column(db.Integer, db.ForeignKey('beer.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    confirmed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_confirmed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    beer = db.relationship('Beer', backref='prices')
    location = db.relationship('Location', backref='prices')
    reporter = db.relationship('User', foreign_keys=[reported_by], backref='reported_prices')
    confirmer = db.relationship('User', foreign_keys=[confirmed_by], backref='confirmed_prices')

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)

class RolePermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id'), nullable=False)

    role = db.relationship('Role', backref='role_permissions')
    permission = db.relationship('Permission', backref='permission_roles')

class Reward(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    points_required = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)

# Helper functions
def is_admin():
    if 'user_id' not in session:
        return False
    user = User.query.get(session['user_id'])
    return user and user.role and user.role.name == 'admin'

def has_permission(permission_name):
    if 'user_id' not in session:
        return False
    user = User.query.get(session['user_id'])
    if not user or not user.role:
        return False
    
    for role_permission in user.role.role_permissions:
        if role_permission.permission.name == permission_name:
            return True
    return False

def require_admin(f):
    def decorated_function(*args, **kwargs):
        if not is_admin():
            flash('Acesso negado! Apenas administradores podem acessar esta página.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def require_permission(permission_name):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if not has_permission(permission_name):
                flash(f'Acesso negado! Você não tem permissão para: {permission_name}', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# Rotas
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Buscar preços recentes
    recent_prices = db.session.query(Price).join(Beer).join(Brand).join(Location).order_by(Price.created_at.desc()).limit(10).all()

    # Buscar usuário atual
    user = User.query.get(session['user_id'])

    return render_template('index.html', recent_prices=recent_prices, user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        phone = request.form['phone']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado!', 'error')
            return redirect(url_for('register'))

        # Buscar perfil padrão de usuário comum
        user_role = Role.query.filter_by(name='user').first()

        user = User(
            email=email,
            name=name,
            phone=phone,
            has_whatsapp=bool(request.form.get('has_whatsapp')),
            password_hash=generate_password_hash(password),
            role_id=user_role.id if user_role else None
        )

        db.session.add(user)
        db.session.commit()

        flash('Cadastro realizado com sucesso!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            flash('Email ou senha incorretos!', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/locations')
def locations():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    locations = Location.query.all()
    return render_template('locations.html', locations=locations)

@app.route('/add_location', methods=['GET', 'POST'])
def add_location():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        location = Location(
            name=request.form['name'],
            type=request.form['type'],
            latitude=float(request.form['latitude']),
            longitude=float(request.form['longitude']),
            address=request.form['address'],
            created_by=session['user_id']
        )

        db.session.add(location)
        db.session.commit()

        flash('Local adicionado com sucesso!', 'success')
        return redirect(url_for('locations'))

    return render_template('add_location.html')

@app.route('/brands')
def brands():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    brands = Brand.query.all()
    return render_template('brands.html', brands=brands)

@app.route('/add_brand', methods=['GET', 'POST'])
def add_brand():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']

        if Brand.query.filter_by(name=name).first():
            flash('Esta marca já está cadastrada!', 'error')
            return redirect(url_for('add_brand'))

        brand = Brand(
            name=name,
            created_by=session['user_id']
        )

        db.session.add(brand)
        db.session.commit()

        flash('Marca adicionada com sucesso!', 'success')
        return redirect(url_for('brands'))

    return render_template('add_brand.html')

@app.route('/beers')
def beers():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    beers = Beer.query.join(Brand).all()
    return render_template('beers.html', beers=beers)

@app.route('/add_beer', methods=['GET', 'POST'])
def add_beer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        beer = Beer(
            name=request.form['name'],
            brand_id=request.form['brand_id'],
            type=request.form['type'],
            description=request.form['description'],
            size=request.form['size'],
            created_by=session['user_id']
        )

        db.session.add(beer)
        db.session.commit()

        flash('Cerveja adicionada com sucesso!', 'success')
        return redirect(url_for('beers'))

    brands = Brand.query.all()
    return render_template('add_beer.html', brands=brands)

@app.route('/add_price', methods=['GET', 'POST'])
def add_price():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        price = Price(
            beer_id=request.form['beer_id'],
            location_id=request.form['location_id'],
            price=float(request.form['price']),
            reported_by=session['user_id']
        )

        db.session.add(price)
        db.session.commit()

        flash('Preço adicionado com sucesso! Você ganhará 10 pontos quando outro usuário confirmar o preço.', 'success')
        return redirect(url_for('index'))

    beers = Beer.query.all()
    locations = Location.query.all()
    return render_template('add_price.html', beers=beers, locations=locations)

@app.route('/confirm_price/<int:price_id>')
def confirm_price(price_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    price = Price.query.get_or_404(price_id)

    if price.reported_by == session['user_id']:
        flash('Você não pode confirmar seu próprio preço!', 'error')
        return redirect(url_for('index'))

    if price.is_confirmed:
        flash('Este preço já foi confirmado!', 'error')
        return redirect(url_for('index'))

    price.confirmed_by = session['user_id']
    price.is_confirmed = True

    # Adicionar pontos aos usuários apenas na confirmação
    reporter = User.query.get(price.reported_by)
    confirmer = User.query.get(session['user_id'])

    reporter.points += 10  # Pontos por cadastrar o preço
    confirmer.points += 5  # Pontos por confirmar

    db.session.commit()

    flash('Preço confirmado! O usuário que reportou ganhou 10 pontos e você ganhou 5 pontos!', 'success')
    return redirect(url_for('index'))

@app.route('/rewards')
def rewards():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    rewards = Reward.query.filter_by(is_active=True).order_by(Reward.points_required).all()

    return render_template('rewards.html', user=user, rewards=rewards)

@app.route('/edit_price/<int:price_id>', methods=['GET', 'POST'])
def edit_price(price_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    price = Price.query.get_or_404(price_id)

    # Verificar se o usuário é o dono do preço
    if price.reported_by != session['user_id']:
        flash('Você só pode editar preços que você mesmo cadastrou!', 'error')
        return redirect(url_for('index'))

    # Verificar se o preço já foi confirmado
    if price.is_confirmed:
        flash('Não é possível editar preços que já foram confirmados!', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        price.price = float(request.form['price'])
        db.session.commit()
        flash('Preço atualizado com sucesso!', 'success')
        return redirect(url_for('index'))

    beers = Beer.query.all()
    locations = Location.query.all()
    return render_template('edit_price.html', price=price, beers=beers, locations=locations)

@app.route('/delete_price/<int:price_id>')
def delete_price(price_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    price = Price.query.get_or_404(price_id)

    # Verificar se o usuário é o dono do preço
    if price.reported_by != session['user_id']:
        flash('Você só pode apagar preços que você mesmo cadastrou!', 'error')
        return redirect(url_for('index'))

    # Verificar se o preço já foi confirmado
    if price.is_confirmed:
        flash('Não é possível apagar preços que já foram confirmados!', 'error')
        return redirect(url_for('index'))

    db.session.delete(price)
    db.session.commit()

    flash('Preço removido com sucesso!', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(user.password_hash, old_password):
            flash('Senha antiga incorreta!', 'error')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('Nova senha e confirmação não coincidem!', 'error')
            return redirect(url_for('change_password'))

        user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('profile'))

    return render_template('change_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = secrets.token_urlsafe(50)
            user.reset_token = token
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)  # Token válido por 1 hora
            db.session.commit()

            # TODO: Enviar email com link para resetar a senha
            print(f"Link de recuperação de senha: {url_for('reset_password', token=token, _external=True)}")
            flash('Um link de recuperação de senha foi enviado para o seu email.', 'success')
        else:
            flash('Email não encontrado!', 'error')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user or user.reset_token_expires < datetime.utcnow():
        flash('Token inválido ou expirado!', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Nova senha e confirmação não coincidem!', 'error')
            return render_template('reset_password.html', token=token)

        user.password_hash = generate_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()

        flash('Senha resetada com sucesso! Faça login com a nova senha.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# Admin routes
@app.route('/admin')
@require_admin
def admin_dashboard():
    users_count = User.query.count()
    roles_count = Role.query.count()
    permissions_count = Permission.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    
    return render_template('admin/dashboard.html', 
                         users_count=users_count, 
                         roles_count=roles_count,
                         permissions_count=permissions_count,
                         active_users=active_users)

@app.route('/admin/roles')
@require_admin
def admin_roles():
    roles = Role.query.all()
    return render_template('admin/roles.html', roles=roles)

@app.route('/admin/roles/add', methods=['GET', 'POST'])
@require_admin
def admin_add_role():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        permission_ids = request.form.getlist('permissions')

        if Role.query.filter_by(name=name).first():
            flash('Este nome de perfil já existe!', 'error')
            return redirect(url_for('admin_add_role'))

        role = Role(name=name, description=description)
        db.session.add(role)
        db.session.flush()  # Para obter o ID do role

        # Adicionar permissões
        for permission_id in permission_ids:
            role_permission = RolePermission(role_id=role.id, permission_id=int(permission_id))
            db.session.add(role_permission)

        db.session.commit()
        flash('Perfil criado com sucesso!', 'success')
        return redirect(url_for('admin_roles'))

    permissions = Permission.query.all()
    return render_template('admin/add_role.html', permissions=permissions)

@app.route('/admin/roles/edit/<int:role_id>', methods=['GET', 'POST'])
@require_admin
def admin_edit_role(role_id):
    role = Role.query.get_or_404(role_id)

    if request.method == 'POST':
        role.name = request.form['name']
        role.description = request.form['description']
        permission_ids = request.form.getlist('permissions')

        # Remover permissões existentes
        RolePermission.query.filter_by(role_id=role.id).delete()

        # Adicionar novas permissões
        for permission_id in permission_ids:
            role_permission = RolePermission(role_id=role.id, permission_id=int(permission_id))
            db.session.add(role_permission)

        db.session.commit()
        flash('Perfil atualizado com sucesso!', 'success')
        return redirect(url_for('admin_roles'))

    permissions = Permission.query.all()
    role_permission_ids = [rp.permission_id for rp in role.role_permissions]
    return render_template('admin/edit_role.html', role=role, permissions=permissions, role_permission_ids=role_permission_ids)

@app.route('/admin/users')
@require_admin
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@require_admin
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.role_id = request.form['role_id'] if request.form['role_id'] else None
        user.is_active = bool(request.form.get('is_active'))
        
        db.session.commit()
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('admin_users'))

    roles = Role.query.all()
    return render_template('admin/edit_user.html', user=user, roles=roles)

@app.route('/admin/rewards')
@require_admin
def admin_rewards():
    rewards = Reward.query.all()
    return render_template('admin/rewards.html', rewards=rewards)

@app.route('/admin/rewards/add', methods=['GET', 'POST'])
@require_admin
def admin_add_reward():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        points_required = int(request.form['points_required'])
        is_active = bool(request.form.get('is_active'))

        reward = Reward(
            name=name,
            description=description,
            points_required=points_required,
            is_active=is_active
        )

        db.session.add(reward)
        db.session.commit()

        flash('Recompensa criada com sucesso!', 'success')
        return redirect(url_for('admin_rewards'))

    return render_template('admin/add_reward.html')

@app.route('/admin/rewards/edit/<int:reward_id>', methods=['GET', 'POST'])
@require_admin
def admin_edit_reward(reward_id):
    reward = Reward.query.get_or_404(reward_id)

    if request.method == 'POST':
        reward.name = request.form['name']
        reward.description = request.form['description']
        reward.points_required = int(request.form['points_required'])
        reward.is_active = bool(request.form.get('is_active'))

        db.session.commit()
        flash('Recompensa atualizada com sucesso!', 'success')
        return redirect(url_for('admin_rewards'))

    return render_template('admin/edit_reward.html', reward=reward)

@app.route('/admin/rewards/delete/<int:reward_id>')
@require_admin
def admin_delete_reward(reward_id):
    reward = Reward.query.get_or_404(reward_id)
    
    db.session.delete(reward)
    db.session.commit()
    
    flash('Recompensa removida com sucesso!', 'success')
    return redirect(url_for('admin_rewards'))

# Inicializar banco de dados
with app.app_context():
    db.create_all()

    # Verificar e adicionar colunas se não existirem
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)
    columns = [column['name'] for column in inspector.get_columns('user')]

    if 'role' not in columns:
        # Adicionar coluna role se não existir
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT "user"'))
            conn.commit()
        print("Coluna 'role' adicionada à tabela user")

    if 'is_active' not in columns:
        # Adicionar coluna is_active se não existir
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1'))
            conn.commit()
        print("Coluna 'is_active' adicionada à tabela user")

    if 'reset_token' not in columns:
        # Adicionar coluna reset_token se não existir
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE user ADD COLUMN reset_token VARCHAR(100)'))
            conn.commit()
        print("Coluna 'reset_token' adicionada à tabela user")

    if 'reset_token_expires' not in columns:
        # Adicionar coluna reset_token_expires se não existir
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE user ADD COLUMN reset_token_expires DATETIME'))
            conn.commit()
        print("Coluna 'reset_token_expires' adicionada à tabela user")

    # Adicionar marcas padrão se não existirem
    if not Brand.query.first():
        brands = [
            Brand(name='Skol', created_by=1),
            Brand(name='Brahma', created_by=1),
            Brand(name='Antarctica', created_by=1),
            Brand(name='Heineken', created_by=1),
            Brand(name='Stella Artois', created_by=1),
            Brand(name='Corona', created_by=1),
            Brand(name='Budweiser', created_by=1),
            Brand(name='Eisenbahn', created_by=1),
            Brand(name='Colorado', created_by=1),
            Brand(name='Original', created_by=1),
        ]

        for brand in brands:
            db.session.add(brand)

        db.session.commit()

    # Adicionar permissões padrão se não existirem
    if not Permission.query.first():
        permissions = [
            Permission(name='add_location', description='Adicionar locais'),
            Permission(name='add_brand', description='Adicionar marcas'),
            Permission(name='add_beer', description='Adicionar cervejas'),
            Permission(name='add_price', description='Adicionar preços'),
            Permission(name='confirm_price', description='Confirmar preços'),
            Permission(name='edit_own_price', description='Editar próprios preços'),
            Permission(name='delete_own_price', description='Deletar próprios preços'),
            Permission(name='view_rewards', description='Ver recompensas'),
            Permission(name='admin_access', description='Acesso administrativo'),
        ]

        for permission in permissions:
            db.session.add(permission)

        db.session.commit()

    # Adicionar perfis padrão se não existirem
    if not Role.query.first():
        # Criar perfil de usuário comum
        user_role = Role(name='user', description='Usuário comum com permissões básicas')
        db.session.add(user_role)
        db.session.flush()

        # Criar perfil de administrador
        admin_role = Role(name='admin', description='Administrador com acesso total')
        db.session.add(admin_role)
        db.session.flush()

        # Permissões para usuário comum
        user_permissions = ['add_location', 'add_brand', 'add_beer', 'add_price', 'confirm_price', 'edit_own_price', 'delete_own_price', 'view_rewards']
        for perm_name in user_permissions:
            permission = Permission.query.filter_by(name=perm_name).first()
            if permission:
                role_permission = RolePermission(role_id=user_role.id, permission_id=permission.id)
                db.session.add(role_permission)

        # Permissões para admin (todas)
        all_permissions = Permission.query.all()
        for permission in all_permissions:
            role_permission = RolePermission(role_id=admin_role.id, permission_id=permission.id)
            db.session.add(role_permission)

        db.session.commit()

    # Adicionar recompensas padrão se não existirem
    if not Reward.query.first():
        rewards = [
            Reward(name='Adesivo do App', description='Adesivo exclusivo do aplicativo', points_required=50),
            Reward(name='Camiseta', description='Camiseta do aplicativo', points_required=200),
            Reward(name='Caneca Térmica', description='Caneca térmica para cerveja', points_required=500),
            Reward(name='Kit Degustação', description='Kit com copos para degustação', points_required=1000),
        ]

        for reward in rewards:
            db.session.add(reward)

        db.session.commit()

    # Criar usuário admin padrão se não existir
    admin_user = User.query.filter_by(email='admin@admin.com').first()
    if not admin_user:
        admin_role = Role.query.filter_by(name='admin').first()
        admin_user = User(
            email='admin@admin.com',
            name='Administrador',
            phone='(00) 00000-0000',
            password_hash=generate_password_hash('admin123'),
            role_id=admin_role.id if admin_role else None
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Usuário admin criado: admin@admin.com / admin123")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


