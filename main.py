from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'mysecretkey'

users = {}
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///products.db'
db = SQLAlchemy(app)
app.app_context().push()

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    validuntil = db.Column(db.String(100), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Войти')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username not in users:
            # Хэшируем пароль перед сохранением в базу данных
            users[username] = generate_password_hash(password)
            flash('Регистрация успешна! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Пользователь с таким логином уже существует.', 'danger')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            flash('Успешная авторизация!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Ошибка авторизации. Проверьте логин и пароль.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Вы успешно вышли из системы.', 'success')
    return redirect(url_for('home'))

@app.route('/')
def home():
    username = session.get('username')
    return render_template('home.html', username=username)

@app.route('/index')
def index():
    username = session.get('username')
    if username:
        return render_template('index.html', username=username)
    else:
        flash('Для доступа к странице, вам необходимо войти.', 'warning')
        return redirect(url_for('home'))

@app.route('/myprod', methods=['GET', 'POST'])
def myprod():
    if request.method == 'POST':
        name = request.form['name']
        validuntil = request.form['validuntil']
        new_product = Product(name=name, validuntil=validuntil)
        db.session.add(new_product)
        db.session.commit()
        return redirect(url_for('myprod'))

    products = Product.query.all()
    today = datetime.now().strftime('%Y-%m-%d')

    return render_template('myprod.html', products=products, today=today)


@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)

    db.session.delete(product)
    db.session.commit()

    return redirect(url_for('myprod'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
