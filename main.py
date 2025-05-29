
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, PasswordField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua-chave-secreta-aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///beer_prices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    telefone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(128))
    pontos = db.Column(db.Integer, default=0)
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    
    precos = db.relationship('PrecoReportado', backref='usuario', lazy=True)
    confirmacoes = db.relationship('ConfirmacaoPreco', backref='usuario', lazy=True)

class Local(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    tipo = db.Column(db.String(50), nullable=False)  # supermercado, distribuidora, deposito
    endereco = db.Column(db.String(200), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    
    precos = db.relationship('PrecoReportado', backref='local', lazy=True)

class Cerveja(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    marca = db.Column(db.String(50), nullable=False)
    tipo = db.Column(db.String(50))  # lager, pilsen, ipa, etc
    volume = db.Column(db.String(20))  # 350ml, 600ml, etc
    descricao = db.Column(db.Text)
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    
    precos = db.relationship('PrecoReportado', backref='cerveja', lazy=True)

class PrecoReportado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    preco = db.Column(db.Float, nullable=False)
    data_reportado = db.Column(db.DateTime, default=datetime.utcnow)
    confirmado = db.Column(db.Boolean, default=False)
    numero_confirmacoes = db.Column(db.Integer, default=0)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    local_id = db.Column(db.Integer, db.ForeignKey('local.id'), nullable=False)
    cerveja_id = db.Column(db.Integer, db.ForeignKey('cerveja.id'), nullable=False)
    
    confirmacoes = db.relationship('ConfirmacaoPreco', backref='preco_reportado', lazy=True)

class ConfirmacaoPreco(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_confirmacao = db.Column(db.DateTime, default=datetime.utcnow)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    preco_id = db.Column(db.Integer, db.ForeignKey('preco_reportado.id'), nullable=False)

class Brinde(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.Text)
    pontos_necessarios = db.Column(db.Integer, nullable=False)
    disponivel = db.Column(db.Boolean, default=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class CadastroForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    telefone = StringField('Telefone', validators=[DataRequired(), Length(min=10, max=20)])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Cadastrar')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class LocalForm(FlaskForm):
    nome = StringField('Nome do Local', validators=[DataRequired(), Length(min=2, max=100)])
    tipo = SelectField('Tipo', choices=[
        ('supermercado', 'Supermercado'),
        ('distribuidora', 'Distribuidora'),
        ('deposito', 'Depósito de Bebidas')
    ], validators=[DataRequired()])
    endereco = StringField('Endereço', validators=[DataRequired(), Length(min=5, max=200)])
    submit = SubmitField('Cadastrar Local')

class CervejaForm(FlaskForm):
    nome = StringField('Nome da Cerveja', validators=[DataRequired(), Length(min=2, max=100)])
    marca = StringField('Marca', validators=[DataRequired(), Length(min=2, max=50)])
    tipo = StringField('Tipo (Lager, Pilsen, IPA, etc)', validators=[DataRequired(), Length(min=2, max=50)])
    volume = StringField('Volume (350ml, 600ml, etc)', validators=[DataRequired(), Length(min=2, max=20)])
    descricao = TextAreaField('Descrição')
    submit = SubmitField('Cadastrar Cerveja')

class PrecoForm(FlaskForm):
    local_id = SelectField('Local', coerce=int, validators=[DataRequired()])
    cerveja_id = SelectField('Cerveja', coerce=int, validators=[DataRequired()])
    preco = FloatField('Preço (R$)', validators=[DataRequired(), NumberRange(min=0.01, max=1000)])
    submit = SubmitField('Reportar Preço')

# Routes
@app.route('/')
def index():
    precos_recentes = PrecoReportado.query.order_by(PrecoReportado.data_reportado.desc()).limit(10).all()
    return render_template('index.html', precos_recentes=precos_recentes)

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    form = CadastroForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email já cadastrado!', 'error')
            return redirect(url_for('cadastro'))
        
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            nome=form.nome.data,
            email=form.email.data,
            telefone=form.telefone.data,
            password_hash=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        flash('Cadastro realizado com sucesso!', 'success')
        return redirect(url_for('login'))
    
    return render_template('cadastro.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Email ou senha incorretos!', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    meus_precos = PrecoReportado.query.filter_by(user_id=current_user.id).order_by(PrecoReportado.data_reportado.desc()).limit(5).all()
    return render_template('dashboard.html', meus_precos=meus_precos)

@app.route('/locais')
@login_required
def locais():
    todos_locais = Local.query.all()
    return render_template('locais.html', locais=todos_locais)

@app.route('/cadastrar_local', methods=['GET', 'POST'])
@login_required
def cadastrar_local():
    form = LocalForm()
    if form.validate_on_submit():
        local = Local(
            nome=form.nome.data,
            tipo=form.tipo.data,
            endereco=form.endereco.data
        )
        db.session.add(local)
        db.session.commit()
        flash('Local cadastrado com sucesso!', 'success')
        return redirect(url_for('locais'))
    
    return render_template('cadastrar_local.html', form=form)

@app.route('/reportar_preco', methods=['GET', 'POST'])
@login_required
def reportar_preco():
    form = PrecoForm()
    form.local_id.choices = [(l.id, l.nome) for l in Local.query.all()]
    form.cerveja_id.choices = [(c.id, f"{c.marca} {c.nome} {c.volume}") for c in Cerveja.query.all()]
    
    if form.validate_on_submit():
        preco = PrecoReportado(
            preco=form.preco.data,
            user_id=current_user.id,
            local_id=form.local_id.data,
            cerveja_id=form.cerveja_id.data
        )
        db.session.add(preco)
        
        # Dar pontos para o usuário
        current_user.pontos += 10
        db.session.commit()
        
        flash('Preço reportado com sucesso! Você ganhou 10 pontos!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('reportar_preco.html', form=form)

@app.route('/confirmar_preco/<int:preco_id>')
@login_required
def confirmar_preco(preco_id):
    preco = PrecoReportado.query.get_or_404(preco_id)
    
    # Verificar se o usuário já confirmou este preço
    confirmacao_existente = ConfirmacaoPreco.query.filter_by(
        user_id=current_user.id, 
        preco_id=preco_id
    ).first()
    
    if confirmacao_existente:
        flash('Você já confirmou este preço!', 'warning')
        return redirect(url_for('dashboard'))
    
    if preco.user_id == current_user.id:
        flash('Você não pode confirmar seu próprio preço!', 'warning')
        return redirect(url_for('dashboard'))
    
    # Criar confirmação
    confirmacao = ConfirmacaoPreco(user_id=current_user.id, preco_id=preco_id)
    db.session.add(confirmacao)
    
    # Atualizar contadores
    preco.numero_confirmacoes += 1
    if preco.numero_confirmacoes >= 3:
        preco.confirmado = True
    
    # Dar pontos para quem confirmou e para quem reportou
    current_user.pontos += 5
    preco.usuario.pontos += 5
    
    db.session.commit()
    flash('Preço confirmado! Você e o usuário que reportou ganharam 5 pontos!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/cervejas')
@login_required
def cervejas():
    todas_cervejas = Cerveja.query.order_by(Cerveja.marca, Cerveja.nome).all()
    return render_template('cervejas.html', cervejas=todas_cervejas)

@app.route('/cadastrar_cerveja', methods=['GET', 'POST'])
@login_required
def cadastrar_cerveja():
    form = CervejaForm()
    if form.validate_on_submit():
        cerveja = Cerveja(
            nome=form.nome.data,
            marca=form.marca.data,
            tipo=form.tipo.data,
            volume=form.volume.data,
            descricao=form.descricao.data
        )
        db.session.add(cerveja)
        db.session.commit()
        flash('Cerveja cadastrada com sucesso!', 'success')
        return redirect(url_for('cervejas'))
    
    return render_template('cadastrar_cerveja.html', form=form)

@app.route('/pontos')
@login_required
def pontos():
    brindes = Brinde.query.filter_by(disponivel=True).order_by(Brinde.pontos_necessarios).all()
    return render_template('pontos.html', brindes=brindes)

@app.route('/buscar_locais')
@login_required
def buscar_locais():
    term = request.args.get('q', '')
    if term:
        locais = Local.query.filter(Local.nome.contains(term)).all()
        return jsonify([{'id': l.id, 'nome': l.nome, 'endereco': l.endereco} for l in locais])
    return jsonify([])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Criar cervejas de exemplo se não existirem
        if not Cerveja.query.first():
            cervejas_exemplo = [
                Cerveja(nome='Original', marca='Brahma', tipo='Lager', volume='350ml'),
                Cerveja(nome='Pilsen', marca='Skol', tipo='Pilsen', volume='350ml'),
                Cerveja(nome='Premium', marca='Heineken', tipo='Lager', volume='330ml'),
                Cerveja(nome='Duplo Malte', marca='Brahma', tipo='Lager', volume='350ml'),
                Cerveja(nome='Pure Malt', marca='Stella Artois', tipo='Lager', volume='330ml'),
            ]
            
            for cerveja in cervejas_exemplo:
                db.session.add(cerveja)
            
            # Criar brindes de exemplo
            brindes_exemplo = [
                Brinde(nome='Copo Personalizado', descricao='Copo de cerveja com logo do app', pontos_necessarios=100),
                Brinde(nome='Camiseta', descricao='Camiseta exclusiva do app', pontos_necessarios=250),
                Brinde(nome='Desconto 10%', descricao='Cupom de 10% de desconto em lojas parceiras', pontos_necessarios=150),
                Brinde(nome='Kit Degustação', descricao='Kit com cervejas especiais', pontos_necessarios=500),
            ]
            
            for brinde in brindes_exemplo:
                db.session.add(brinde)
            
            db.session.commit()
    
    app.run(host='0.0.0.0', port=5000, debug=True)
