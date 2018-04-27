from flask import Flask , render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import StringField, SubmitField, PasswordField, BooleanField, IntegerField, FloatField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy import Column, ForeignKey, Integer, String
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

# CSRF Config
app.config.update(
        SECRET_KEY='a random string',
        SQLALCHEMY_DATABASE_URI=('sqlite:///bookcatalogue.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS = False
    )

# CRUD Operations
from database_setup import Base, Book, Publication
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Create session and connect to DB
engine = create_engine('sqlite:///bookcatalogue.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

db = SQLAlchemy()
bootstrap = Bootstrap(app)
login_manager = LoginManager(app)
login_manager.login_view = 'do_the_login'
login_manager.session_protection = 'strong'
bcrypt = Bcrypt(app)
db.init_app(app)
login_manager.init_app(app)

#Classes begin
def email_exists(form, field):
    email = User.query.filter_by(user_email=field.data).first()
    if email:
        raise ValidationError('Email Already Exists')

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(3, 30, message='between 3 to 30 characters')])
    email = StringField('E-mail', validators=[DataRequired(), Email(), email_exists])
    password = PasswordField('Password', validators=[DataRequired(), Length(5), EqualTo('confirm', message='password must match')])
    confirm = PasswordField('Confirm', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    stay_loggedin = BooleanField('stay logged-in')
    submit = SubmitField('LogIn')

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    user_name = Column(String(20))
    user_email = Column(String(60), unique=True, index=True)
    user_password = Column(String(80))
    registration_date = Column(String(20), nullable=False)

    def check_password(self, password):
            return bcrypt.check_password_hash(self.user_password, password)

    @classmethod
    def create_user(cls, user, email, password):
            user = cls(user_name=user,
                       user_email=email,
                       user_password=bcrypt.generate_password_hash(password),
                       registration_date=datetime.now()
                       )

            session.add(user)
            session.commit()
            return user

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

class EditBookForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    format = StringField('Format', validators=[DataRequired()])
    num_pages = StringField('Pages', validators=[DataRequired()])
    submit = SubmitField('Update')

class CreateBookForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    author = StringField('Author', validators=[DataRequired()])
    avg_rating = FloatField('Rating out of 5', validators=[DataRequired()])
    format = StringField('Format', validators=[DataRequired()])
    img_url = StringField('Image', validators=[DataRequired()])
    num_pages = IntegerField('Pages', validators=[DataRequired()])
    pub_id = IntegerField('PublisherID', validators=[DataRequired()])
    submit = SubmitField('Create')

class Publication(db.Model):
    __tablename__ = 'publication'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return 'Publisher is {}'.format(self.name)

class Book(db.Model):
    __tablename__ = 'book'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(500), nullable=False, index=True)
    author = db.Column(db.String(350))
    avg_rating = db.Column(db.Float)
    format = db.Column(db.String(50))
    image = db.Column(db.String(100), unique=True)
    num_pages = db.Column(db.Integer)
    pub_date = db.Column(db.String(50), default=datetime.now())

    # Relationship
    pub_id = db.Column(db.Integer, db.ForeignKey('publication.id'))

    def __init__(self, title, author, avg_rating, book_format, image, num_pages, pub_id):
        self.title = title
        self.author = author
        self.avg_rating = avg_rating
        self.format = book_format
        self.image = image
        self.num_pages = num_pages
        self.pub_id = pub_id

    def __repr__(self):
        return '{} by {}'.format(self.title, self.author)
# Classes end

# Routes begin
@app.route('/register', methods=['GET', 'POST'])
def register_user():
    form = RegistrationForm()
    if form.validate_on_submit():
        User.create_user(
            user=form.name.data,
            email=form.email.data,
            password=form.password.data)
        flash('Registration Successful')
        return redirect(url_for('do_the_login'))
    return render_template('registration.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def do_the_login():
    if current_user.is_authenticated:
        flash('you are already logged-in')
        return redirect(url_for('display_books'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(user_email=form.email.data).first()
        if not user or not user.check_password(form.password.data):
            flash('Invalid Credentials, Please try again')
            return redirect(url_for('do_the_login'))
        login_user(user, form.stay_loggedin.data)
        return redirect(url_for('display_books'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def log_out_user():
    logout_user()
    flash('Logged out Successfully')
    return redirect(url_for('display_books'))

@app.route('/')
def display_books():
    books = session.query(Book).all()

    return render_template('home.html', books=books)

@app.route('/display/publisher/<publisher_id>')
def display_publisher(publisher_id):
    publisher = session.query(Publication).filter_by(id=publisher_id).first()
    publisher_books = session.query(Book).filter_by(pub_id = publisher.id).all()

    return render_template('publisher.html', publisher=publisher,
                           publisher_books=publisher_books)

@app.route('/book/delete/<book_id>', methods=['GET', 'POST'])
@login_required
def delete_book(book_id):
    book = Book.query.get(book_id)
    if request.method == 'POST':
        db.session.delete(book)
        db.session.commit()
        flash('book deleted successfully')
        return redirect(url_for('display_books'))
    return render_template('delete_book.html', book=book, book_id=book.id)

@app.route('/book/edit/<book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    book = Book.query.get(book_id)
    form = EditBookForm(obj=book)
    if form.validate_on_submit():
        book.title = form.title.data
        book.format = form.format.data
        book.num_pages = form.num_pages.data
        db.session.add(book)
        db.session.commit()
        flash('book edited successfully')
        return redirect(url_for('display_books'))
    return render_template('edit_book.html', form=form)

@app.route('/create/book/<pub_id>' , methods=['GET', 'POST'])
@login_required
def create_book(pub_id):
    form = CreateBookForm()
    form.pub_id.data = pub_id  # pre-populates pub_id
    if form.validate_on_submit():
        book = Book(title=form.title.data, author=form.author.data, avg_rating=form.avg_rating.data,
                    book_format=form.format.data, image=form.img_url.data, num_pages=form.num_pages.data,
                    pub_id=form.pub_id.data)
        db.session.add(book)
        db.session.commit()
        flash('book added successfully')
        return redirect(url_for('display_publisher', publisher_id=pub_id))
    return render_template('create_book.html', form=form, pub_id=pub_id)
# Routes end

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
