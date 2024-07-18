from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField,BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone, date
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

# Create flask instance
app = Flask(__name__)
# Old sqlite database
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

#New MySQL db
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/db_name'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/our_users'
# Add secret key
app.config['SECRET_KEY'] = "my secret key"  #don't push it to github

# Initialize db
db = SQLAlchemy(app)
migrate = Migrate(app, db)
        ###############

# Flask_Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

        ################

# Create Login Page
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # Check the hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login successful!")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong password. Please try again")
        else:
            flash("User doesn't exist. Check and try again")

    return render_template("login.html", form=form)

# Create Logout function
@app.route('/logout', methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    flash("You have successfully logged out")
    return redirect(url_for('login'))

# Create LoginForm
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])    
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create Dashboard
@app.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
    return render_template("dashboard.html")

# create model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable= False)
    email = db.Column(db.String(120), nullable = False, unique = True)
    residence = db.Column(db.String(40))
    date_added = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # Password
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('Password is not readable')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Create a string
    def __repr__(self):
        return '<Name %r>' % self.name
    

# Create a Blog post model
class Posts(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.String(255))
    content=db.Column(db.Text)
    author=db.Column(db.String(60))
    date_posted=db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    slug=db.Column(db.String(255))

# Create Posts Form
class PostForm(FlaskForm):
    title=StringField("Title", validators=[DataRequired()])
    content=StringField("Content", validators=[DataRequired()], widget=TextArea())
    author=StringField("Author", validators=[DataRequired()])
    slug=StringField("Appropriate Slug")
    submit=SubmitField("Submit")

# Post page
@app.route('/add-post', methods=['GET', 'POST'])
#@login_required
def add_post():
    form = PostForm()
    current_date = date.today()

    if form.validate_on_submit():
        post = Posts(title=form.title.data, content=form.content.data, author=form.author.data, slug=form.slug.data)
        
        
        #Add post to database
        db.session.add(post)
        db.session.commit()

        # Clear the form after successful submission
        form.title.data = ''
        form.content.data = ''
        form.author.data = ''
        form.slug.data = ''


        flash("Post added successfully!")

    # Redirect to webpage
    return render_template("add_post.html", current_date=current_date, form = form)


@app.route('/posts/<int:id>')
def post(id):
    post=Posts.query.get_or_404(id)
    return render_template("post.html", post=post)


@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post=Posts.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.author = form.author.data
        post.slug = form.slug.data
        post.content = form.content.data

        #Update Database
        db.session.add(post)
        db.session.commit()
        flash("Post updated successfully")
        return redirect(url_for('post', id=post.id))
    form.title.data = post.title
    form.author.data = post.author
    form.content.data = post.content
    form.slug.data = post.slug
    return render_template("edit_post.html", form=form, post=post)

@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)

    try:
        db.session.delete(post_to_delete)
        db.session.commit()
        #Return a message
        flash("Post deleted successfully!")
    
    #Grab all the posts from the database
        posts =  Posts.query.order_by(Posts.date_posted)
        return render_template("posts.html",
                               posts = posts)
    except:
        #Return error message
        flash("Not able to delete the post!")
        posts =  Posts.query.order_by(Posts.date_added)
        return render_template("posts.html",
                               posts = posts)

@app.route('/delete/<int:id>')
def delete(id):
    name = None
    form=NewUser()
    user_to_delete = Users.query.get_or_404(id)

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User deleted successfully!")

        all_users =  Users.query.order_by(Users.date_added).all()
        return render_template("add_user.html",
                               form = form,
                               name = name,
                               all_users = all_users)
    except:
        flash("Not able to delete the user!")
        return render_template("add_user.html",
                               form = form,
                               name = name,
                               all_users = all_users)

# Define a form class using FlaskForm
class NewUser(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    residence = StringField("Residence")
    password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Passwords should match!')])
    password_hash2 = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Update database record
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    form = NewUser()
    name_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.residence = request.form['residence']
        name_to_update.username = request.form['username']

        try:
            db.session.commit()
            flash("Record updated successfully!")
            return render_template("update.html",
                                   form=form,
                                   name_to_update=name_to_update,
                                   id=id)
        
        except:
            flash("Error! Looks like there was a problem")
            return render_template("update.html",
                                   form=form,
                                   name_to_update=name_to_update,
                                   id=id)
        
    else:
        return render_template("update.html",
                                   form=form,
                                   name_to_update=name_to_update,
                                   id=id)

# Create a route decorator
@app.route('/')
#def index():
#   return "<h2>Started</h2>"

def index():
    return render_template("index.html")

@app.route('/posts')
def posts():
    current_date = date.today()
    # Grab all posts form the db
    posts = Posts.query.order_by(Posts.date_posted)

    return render_template("posts.html", current_date=current_date, posts=posts)
    

@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    current_date = date.today()
    name = None
    form = NewUser()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            # Hash the password first
            hashed_pw = generate_password_hash(form.password_hash.data, method='pbkdf2:sha256')
            user = Users(username=form.username.data, name=form.name.data, email=form.email.data, residence=form.residence.data, password_hash=hashed_pw)
            
            db.session.add(user)
            db.session.commit()
            
            # Clear the form
            name = form.name.data
            form.username.data = ''
            form.name.data = ''
            form.email.data = ''
            form.residence.data = ''
            form.password_hash.data = ''
            flash("User Added Successfully!")
        else:
            flash('Email already exists. Please use a different email address.', 'error')
    all_users =  Users.query.order_by(Users.date_added).all()   
    return render_template("add_user.html",
                           current_date=current_date,
                           form = form,
                           name = name,
                           all_users = all_users)
    
#localhost:5000/user/john
@app.route("/user/<name>")
def user(name):
    return render_template("user.html", name=name)

# Json example
@app.route('/date')
def get_current_date():
    return {"Date": date.today()}

#custom error pages

#Invalid url
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# Error handler for 500
@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500


# PasswordForm
class PasswordForm(FlaskForm):
    email = StringField("Email")
    password_hash = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Password test page
@app.route('/test_pw', methods=['GET', 'POST'])
def test_pw():
    email = None
    password = None
    pw_to_check = None
    passed = None
    form = PasswordForm()

    # Validate form submission
    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data
        #clear the form
        form.password_hash.data = '' # Clear the form field after submission
        form.email.data = '' # Clear the form field after submission
        
        pw_to_check = Users.query.filter_by(email=email).first()
        # flash("Your details submitted successfully")
    # Render the template with form and name
    return render_template('test_pw.html',
                           password = password,
                           email = email,
                           pw_to_check=pw_to_check,
                           form = form)

# Define your route
@app.route('/name', methods=['GET', 'POST'])
def name():
    name = None
    email = None
    form = NewUser()

    # Validate form submission
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        form.name.data = '' # Clear the form field after submission
        form.email.data = '' # Clear the form field after submission
        flash("Your details submitted successfully")
    # Render the template with form and name
    return render_template('name.html',
                           name = name,
                           email = email,
                           form = form)