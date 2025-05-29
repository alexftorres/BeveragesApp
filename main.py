from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import secrets
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///beer_prices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Função auxiliar para templates
@app.context_processor
def inject_user():
    def get_current_user():
        if 'user_id' in session:
            return User.query.get(session['user_id'])
        return None
    return dict(get_current_user=get_current_user)

# Funções auxiliares para permissões
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Acesso negado! Apenas administradores podem acessar esta página.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def admin_or_collaborator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role not in ['admin', 'collaborator']:
            flash('Acesso negado! Apenas administradores e colaboradores podem acessar esta página.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Modelos do banco de dados
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    has_whatsapp = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(120), nullable=False)
    points = db.Column(db.Integer, default=0)
    role = db.Column(db.String(20), default='user')  # user, collaborator, admin
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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

class Reward(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    points_required = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    creator = db.relationship('User', backref='created_rewards')

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
        is_admin = request.form.get('is_admin') == '1'

        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado!', 'error')
            return redirect(url_for('register'))

        # Verificar se é o primeiro usuário (será admin automaticamente)
        user_count = User.query.count()
        role = 'admin' if (user_count == 0 or is_admin) else 'user'

        user = User(
            email=email,
            name=name,
            phone=phone,
            has_whatsapp=bool(request.form.get('has_whatsapp')),
            password_hash=generate_password_hash(password),
            role=role
        )

        db.session.add(user)
        db.session.commit()

        flash('Cadastro realizado com sucesso!', 'success')
        return redirect(url_for('login'))

    # Verificar se existe algum usuário (para mostrar opção de admin)
    has_users = User.query.count() > 0
    return render_template('register.html', has_users=has_users)

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

@app.route('/admin')
@admin_required
def admin_panel():
    users = User.query.all()
    return render_template('admin_panel.html', users=users)

@app.route('/admin/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/update_user_role/<int:user_id>', methods=['POST'])
@admin_required
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form['role']
    
    if new_role in ['user', 'collaborator', 'admin']:
        user.role = new_role
        db.session.commit()
        flash(f'Permissão do usuário {user.name} atualizada para {new_role}!', 'success')
    else:
        flash('Permissão inválida!', 'error')
    
    return redirect(url_for('manage_users'))

@app.route('/admin/toggle_user_status/<int:user_id>')
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'ativado' if user.is_active else 'desativado'
    flash(f'Usuário {user.name} foi {status}!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/update_user_points/<int:user_id>', methods=['POST'])
@admin_or_collaborator_required
def update_user_points(user_id):
    user = User.query.get_or_404(user_id)
    action = request.form['action']
    points = int(request.form['points'])
    
    if action == 'add':
        user.points += points
        flash(f'{points} pontos adicionados ao usuário {user.name}!', 'success')
    elif action == 'remove':
        user.points = max(0, user.points - points)
        flash(f'{points} pontos removidos do usuário {user.name}!', 'success')
    elif action == 'set':
        user.points = points
        flash(f'Pontos do usuário {user.name} definidos para {points}!', 'success')
    
    db.session.commit()
    return redirect(url_for('manage_users'))

@app.route('/admin/rewards')
@admin_or_collaborator_required
def manage_rewards():
    rewards = Reward.query.all()
    return render_template('manage_rewards.html', rewards=rewards)

@app.route('/admin/add_reward', methods=['GET', 'POST'])
@admin_or_collaborator_required
def add_reward():
    if request.method == 'POST':
        reward = Reward(
            name=request.form['name'],
            description=request.form['description'],
            points_required=int(request.form['points_required']),
            created_by=session['user_id']
        )
        
        db.session.add(reward)
        db.session.commit()
        
        flash('Recompensa adicionada com sucesso!', 'success')
        return redirect(url_for('manage_rewards'))
    
    return render_template('add_reward.html')

@app.route('/admin/edit_reward/<int:reward_id>', methods=['GET', 'POST'])
@admin_or_collaborator_required
def edit_reward(reward_id):
    reward = Reward.query.get_or_404(reward_id)
    
    if request.method == 'POST':
        reward.name = request.form['name']
        reward.description = request.form['description']
        reward.points_required = int(request.form['points_required'])
        reward.is_active = bool(request.form.get('is_active'))
        
        db.session.commit()
        
        flash('Recompensa atualizada com sucesso!', 'success')
        return redirect(url_for('manage_rewards'))
    
    return render_template('edit_reward.html', reward=reward)

@app.route('/admin/delete_reward/<int:reward_id>')
@admin_or_collaborator_required
def delete_reward(reward_id):
    reward = Reward.query.get_or_404(reward_id)
    db.session.delete(reward)
    db.session.commit()
    
    flash('Recompensa removida com sucesso!', 'success')
    return redirect(url_for('manage_rewards'))

# Inicializar banco de dados
with app.app_context():
    db.create_all()
    
    # Verificar e adicionar coluna role se não existir
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)
    columns = [column['name'] for column in inspector.get_columns('user')]
    
    if 'role' not in columns:
        # Adicionar coluna role se não existir
        with db.engine.connect() as conn:
            conn.execute(text('ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT "user"'))
            conn.commit()
        print("Coluna 'role' adicionada à tabela user")

    # Criar primeiro usuário admin se não existir nenhum usuário
    if not User.query.first():
        admin_user = User(
            email='admin@beerapp.com',
            name='Administrador',
            phone='(11) 99999-9999',
            has_whatsapp=True,
            password_hash=generate_password_hash('admin123'),
            role='admin',
            points=0
        )
        db.session.add(admin_user)
        db.session.commit()

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

    # Adicionar recompensas padrão se não existirem
    if not Reward.query.first():
        admin_user = User.query.filter_by(role='admin').first()
        admin_id = admin_user.id if admin_user else None
        
        rewards = [
            Reward(name='Adesivo do App', description='Adesivo exclusivo do aplicativo', points_required=50, created_by=admin_id),
            Reward(name='Camiseta', description='Camiseta do aplicativo', points_required=200, created_by=admin_id),
            Reward(name='Caneca Térmica', description='Caneca térmica para cerveja', points_required=500, created_by=admin_id),
            Reward(name='Kit Degustação', description='Kit com copos para degustação', points_required=1000, created_by=admin_id),
        ]

        for reward in rewards:
            db.session.add(reward)

        db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)