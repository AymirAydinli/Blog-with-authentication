from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users


class RegisterForm(FlaskForm):
    email = EmailField("email", validators=[DataRequired()])
    name = StringField("name", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up")


# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = EmailField("email", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])
    submit = SubmitField("Le Me In")


# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    comment_body = CKEditorField("Comment Content", validators=[DataRequired()])
    submit = SubmitField("Submit Content")
