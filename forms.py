from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, PasswordField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo
from wtforms_sqlalchemy.fields import QuerySelectMultipleField
import main


def user_query():
    return main.User.query


class UserForm(FlaskForm):
    username = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    groups = QuerySelectMultipleField(query_factory=main.Group.query.all, get_label="Group name",
                                         get_pk=lambda obj: str(obj))
    submit = SubmitField('Login')


class SignUpForm(FlaskForm):
    username = StringField('Full name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    hashed_password = PasswordField('Repeat password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


    def validate_username(self, username):
        user = main.User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('User name already exists!')


    def validate_email(self, email):
        user = main.User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exists!')


class SignInForm(FlaskForm):
    username = StringField('Full name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class GroupForm(FlaskForm):
    name = IntegerField('Group name', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    users = QuerySelectMultipleField(
        query_factory=main.User.query.all, allow_blank=True, get_label='username', get_pk=lambda obj: str(obj)
    )
    submit = SubmitField('Add group')


class BillForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    sum = StringField('Sum', validators=[DataRequired()])
    user = QuerySelectMultipleField(
        query_factory=main.User.query.all, allow_blank=True, get_label='name', get_pk=lambda obj: str(obj)
    )
    submit = SubmitField('Add bill')









