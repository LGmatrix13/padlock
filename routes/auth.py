from flask import Blueprint, render_template, redirect, url_for, flash

from lib.user_session import user_session
from lib.tables import users
from lib.decorators import reject_authenticated
from lib.forms import LoginForm, RegisterForm
import lib.crypto_backend as cb

auth_blueprint = Blueprint('auth', __name__, template_folder='templates')

@auth_blueprint.get('/auth/')
@reject_authenticated
def get_auth():
    login_form = LoginForm()
    register_form = RegisterForm()
    return render_template('auth.html', register_form = register_form, login_form = login_form)

@auth_blueprint.post("/auth/register/")
def post_auth_register():
    form = RegisterForm()

    if form.validate():
        private_key = cb.rsa_gen_keypair()
        public_key = private_key.public_key()
        user_id, name, _ = users.create(name=form.name.data, key=cb.rsa_serialize_public_key(public_key=public_key))
        user_session.create(user_id=user_id, name=name, private_key=cb.rsa_serialize_private_key(private_key=private_key))
        flash("Successfully created your account! Be sure to save your token for future use.")
        return redirect(url_for("save_token.get_save_token"))
    
    flash("Invalid submission.")
    return redirect(url_for("auth.get_auth"))

@auth_blueprint.post("/auth/login/")
def post_auth_login():
    try:
        login_form = LoginForm()
        token = login_form.file.data.read().decode('utf-8')
        private_key = cb.rsa_deserialize_private_key(token)
        public_key = private_key.public_key()
        user_id, name, public_key = users.read_from_public_key(public_key=cb.rsa_serialize_public_key(public_key=public_key))
        user_session.create(user_id=user_id, name=name, private_key=token)    
        flash(f"Welcome back, {name}!")
        return redirect(url_for("passwords.get_passwords"))
    except Exception:
        flash("Invalid token.")
        return redirect(url_for("auth.get_auth"))