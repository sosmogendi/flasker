from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField,BooleanField, ValidationError, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField
from flask_wtf.file import FileField, FileAllowed

# Define a form class using FlaskForm
class NewUser(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    residence = StringField("Residence")
    about_author = TextAreaField("About Author")
    profile_pic = FileField('Profile Picture')
    password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Passwords should match!')])
    password_hash2 = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create Search Form
class SearchForm(FlaskForm):
    searched = StringField("Searched", validators=[DataRequired()])    
    submit = SubmitField("Submit")

# Create LoginForm
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])    
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create Posts Form
class PostForm(FlaskForm):
    title=StringField("Title", validators=[DataRequired()])
    #content=StringField("Content", validators=[DataRequired()], widget=TextArea())
    content = CKEditorField('Content', validators=[DataRequired()])
    author=StringField("Author")
    slug=StringField("Slug")
    submit=SubmitField("Submit")

# PasswordForm
class PasswordForm(FlaskForm):
    email = StringField("Email")
    password_hash = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

