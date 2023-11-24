from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from gigachat import GigaChat
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.secret_key = 'mysecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///base.db'
db = SQLAlchemy(app)
app.app_context().push()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'Login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password_hash = db.Column(db.String(100))
    role = db.Column(db.String(20), default='buyer')
    @property
    def password(self):
        raise AttributeError('Проверьте пароль')
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    def is_seller(self):
        return self.role == 'seller'

class Productbase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    validuntil = db.Column(db.String(100), nullable=False)
    typeprod = db.Column(db.String(100), nullable=False)

class Ordersbase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    typeprod = db.Column(db.String(100), nullable=False)
    count = db.Column(db.Integer, nullable=False)
    date = db.Column(db.String(100), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    role = RadioField('Роль', choices=[('buyer', 'Покупатель'), ('seller', 'Магазин')], default='buyer', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')


class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Войти')



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/register', methods=['GET', 'POST'])
def Register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        role = form.role.data
        existing_user = User.query.filter_by(username=username).first()
        if existing_user is None:
            new_user = User(username=username, password=password, role=role)
            db.session.add(new_user)
            db.session.commit()

            flash('Регистрация успешна! Теперь вы можете войти.', 'success')
            return redirect(url_for('Login'))
        else:
            flash('Пользователь с таким логином уже существует.', 'danger')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def Login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            login_user(user)
            flash('Авторизация прошла успешно!', 'success')
            if user.is_seller():
                return redirect(url_for('SellerDashboard'))
            else:
                return redirect(url_for('Index'))
        else:
            flash('Ошибка авторизации. Проверьте логин и пароль.', 'danger')
    return render_template('login.html', form=form)
@app.route('/seller_dashboard')
@login_required
def SellerDashboard():
    if current_user.is_authenticated and current_user.is_seller():
        return render_template('Seller.html')
    else:
        flash('Для доступа к странице, вы должны быть зарегистрированным продавцом.', 'warning')
        return redirect(url_for('Login'))
@app.route('/logout')
@login_required
def Logout():
    logout_user()
    session.pop('username', None)
    flash('Вы успешно вышли из системы.', 'success')
    return redirect(url_for('Index'))

@app.route('/')
def Home():
    username = session.get('username')
    return render_template('home.html', username=username)

@app.route('/index')
@login_required
def Index():
    if current_user.is_authenticated:
        print('index')
        return render_template('index.html', username=current_user.username)
    else:
        print('home')
        flash('Для доступа к странице, вам необходимо войти.', 'warning')
        return redirect(url_for('Home'))

@app.route('/mystocks', methods=['GET', 'POST'])
@login_required
def Mystocks():
    if request.method == 'POST':
        name = request.form['name']
        validuntil = request.form['validuntil']
        typeprod = request.form['typeprod']
        new_product = Productbase(name=name, validuntil=validuntil, typeprod=typeprod)
        db.session.add(new_product)
        db.session.commit()
        return redirect(url_for('Mystocks'))
    products = Productbase.query.all()
    today = datetime.now().strftime('%Y-%m-%d')
    return render_template('mystocks.html', products=products, today=today)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def Delete_product(product_id):
    product = Productbase.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('Mystocks'))

@app.route('/delete_order/<int:orders_id>', methods=['POST'])
@login_required
def Delete_order(orders_id):
    order = Ordersbase.query.get_or_404(orders_id)
    db.session.delete(order)
    db.session.commit()
    return redirect(url_for('Orders'))

@app.route('/recipes')
@login_required
def Recipes():
    products = Productbase.query.all()
    prod = []
    for p in products:
        prod.append(p.name)
    prod = ' '.join(prod)
    with GigaChat(credentials='NDhiMTBhM2MtNzhhYS00ZmQ2LWJlYzYtZDViNzg1ZDk4OTBjOjRlNGM5Yjk5LWMzZjctNGViYi1hMjEwLTA2NDhkYThlNjg2OQ==',
                  verify_ssl_certs=False) as giga:
        response = giga.chat(f'какие есть кулинарные рецепты если у меня {prod}')
        result = response.choices[0].message.content

    return render_template('recipes.html', recipe = result)

@app.route('/orders', methods=['GET', 'POST'])
@login_required
def Orders():
    if request.method == 'POST':
        name = request.form['name']
        typeprod = request.form['typeprod']
        count = request.form['count']
        date = request.form['date']
        new_order = Ordersbase(name=name, typeprod=typeprod, count=count, date=date)
        db.session.add(new_order)
        db.session.commit()
        return redirect(url_for('Orders'))
    orders = Ordersbase.query.all()
    return render_template('orders.html', orders=orders)

@app.route('/allorders', methods=['GET', 'POST'])
@login_required
def Allorders():
    orders = Ordersbase.query.all()
    return render_template('allorders.html', orders=orders)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)