from base64 import b64decode, b64encode
from functools import wraps
from flask import Flask, abort, jsonify, session, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms.fields import StringField, SubmitField, TextAreaField, SelectField
from wtforms.validators import InputRequired
from cryptography.hazmat.primitives.asymmetric import rsa
import crypto_backend as cb
import uuid
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = str(uuid.uuid4())

class CertificationForm(FlaskForm):
    name = StringField("Name")
    submit = SubmitField("Submit")

class ImportKeyForm(FlaskForm):
    key = TextAreaField("Key", validators=[InputRequired()])
    submit = SubmitField("Submit")

class SendLocationForm(FlaskForm):
    contact = SelectField("Contacts")
    note = TextAreaField("Note", validators=[InputRequired()])
    submit = SubmitField("Submit")

class AddedUsers:
    def __init__(self) -> None:
        self.data = {}
    def create(self, user_id: str, owner: str, public_key: str) -> None:
        if self.data.get(session["user_id"]) is None:
            self.data[session["user_id"]] = {}
        self.data[session["user_id"]][user_id] = {
            "owner": owner,
            "public": cb.rsa_deserialize_public_key(public_key),
        }
    def me(self) -> dict:
        return self.data.get(session.get("user_id"))

class Locations:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}
    def create(self, to: int, message: dict):
        self.data[(session["user_id"], to)] = message
    def me(self, added_users: AddedUsers) -> list[dict]:
        return {
            added_user: self.data[(added_user, session["user_id"])]
            for added_user in added_users.me().keys()
            if self.data.get((added_user, session["user_id"])) is not None
        }
        

class Users:
    def __init__(self) -> None:
        self.data: dict[str, dict] = {}
    def create(self, owner: str, key):
        if isinstance(key, rsa.RSAPrivateKey):
            self.data[session["user_id"]] = {
                "owner": owner,
                "public": cb.rsa_serialize_public_key(key.public_key()),
                "private": key
            }
        elif isinstance(key, rsa.RSAPublicKey):
            self.data[session["user_id"]] = {
                "owner": owner,
                "public": cb.rsa_serialize_public_key(key),
                "private": None
            }
        else:
            raise Exception("Unrecognized key type!")
    def me(self) -> dict:
        return self.data.get(session["user_id"])

users = Users()
added_users = AddedUsers()
locations = Locations()

def setup_required(f):
    @wraps(f)
    def decorated_function():
        if session.get("user_id") is None or users.me() is None:
            session["user_id"] = str(uuid.uuid4())
            flash("This requires you to setup your account first")
            return redirect(url_for("get_setup"))
        return f()
    return decorated_function

def added_user_required(f):
    @wraps(f)
    def decorated_function():
        if added_users.me() is None:
            flash("This requires you to add a user to your circle first")
            return redirect(url_for("get_add"))
        return f()
    return decorated_function

@app.get('/setup/')
def get_setup():
    form = CertificationForm()
    return render_template('setup.html', form = form)

@app.post("/setup/")
def post_setup():
    form = CertificationForm()
    users.create(owner=form.name.data, key=cb.rsa_gen_keypair())
    flash("Successfully created your key pair")
    return redirect(url_for("get_share"))

@app.get('/')
@setup_required
@added_user_required
def get_index():   
    contacts = [
        {
            "user_id": user_id,
            "name": added_user["owner"]
        } for user_id, added_user in added_users.me().items()
    ] 
    return render_template('contacts.html', contacts = contacts)

@app.get('/contact/<user_id>/')
def get_contact(user_id):
    user = users.me()
    contact = added_users.me().get(user_id)
    location = locations.me(added_users).get(user_id)

    location["plaintext"] = cb.decrypt_message_with_aes_and_rsa(
        user.get("private"), 
        b64decode(location.get('sessionkey'), validate=True),
        b64decode(location.get('nonce'), validate=True),
        b64decode(location.get('ciphertext'), validate=True)
    ).decode('utf-8')

    return render_template('contact.html', name = contact.get('owner'), location = location)

@app.get("/add/")
@setup_required
def get_add():
    form = ImportKeyForm()
    return render_template("add_contact.html", form = form)

@app.post("/add/")
@setup_required
def post_add():
    form = ImportKeyForm()
    if form.validate():
        cert = json.loads(form.key.data)
        added_users.create(cert["userId"], cert["owner"], cert.get("publicKey"))
        return redirect(url_for("get_index"))

@app.get("/send-location/")
@setup_required
@added_user_required
def get_send_location():
    form = SendLocationForm()
    form.contact.choices = [(user_id, user["owner"]) for user_id, user in added_users.me().items()]
    return render_template("send_location.html", form = form)

@app.post("/send-location/")
@setup_required
@added_user_required
def post_send_location():
    form = SendLocationForm()
    form.contact.choices = [(user_id, user["owner"]) for user_id, user in added_users.me().items()]

    if form.validate():
        user_id = form.contact.data
        note = form.note.data.encode('utf-8')
        contacts = added_users.me()
        public_key = contacts.get(user_id).get("public")
        encrypted_session_key, nonce, ciphertext = cb.encrypt_message_with_aes_and_rsa(public_key, note)
        message = {
            "sessionkey": b64encode(encrypted_session_key).decode('ascii'),
            'nonce': b64encode(nonce).decode('ascii'),
            'ciphertext': b64encode(ciphertext).decode('ascii')
        }
        locations.create(user_id, message)
        flash("Sent message successfully")
        return redirect(url_for("get_send_location"))




@app.get("/share/")
@setup_required
def get_share():
    user = users.me()
    private_key = json.dumps({
        "userId": session["user_id"],
        "owner": user["owner"],
        "privateKey": cb.rsa_serialize_private_key(user["private"])
    })
    public_key = json.dumps({
        "userId": session["user_id"],
        "owner": user["owner"],
        "publicKey": user["public"]
    })
    return render_template("share.html", public_key = public_key, private_key = private_key)