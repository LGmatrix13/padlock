from flask_wtf import FlaskForm
from wtforms import FileField
from wtforms.fields import StringField, SubmitField, TextAreaField, SelectField
from wtforms.validators import InputRequired, EqualTo

class RegisterForm(FlaskForm):
    name = StringField("Name")
    submit = SubmitField("Continue")

class LoginForm(FlaskForm):
    file = FileField("Token")
    submit = SubmitField("Continue")

class SendForm(FlaskForm):
    recipient = SelectField("Recipient")
    context = StringField("Context", validators=[InputRequired()])
    message = TextAreaField("Message", validators=[InputRequired()])
    submit = SubmitField("Send")

class DangerZoneForm(FlaskForm):
    master_password = StringField("Master Password", validators=[InputRequired()])
    delete_user = SelectField("Delete User")
    submit = SubmitField("Continue")
    
