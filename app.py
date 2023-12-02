from base64 import b64decode, b64encode
from functools import wraps
from flask import Flask, abort, session, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms.fields import StringField, SubmitField, TextAreaField, SelectField
from wtforms.validators import InputRequired
from cryptography.hazmat.primitives.asymmetric import rsa
import crypto_backend as cb
import pandas as pd
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
        self.data: pd.DataFrame = pd.DataFrame(columns = ["contact_id", "user_id", "name", "public"])
    def create(self, contact_id: str, owner: str, public: str) -> None:
        self.data.loc[len(self.data)] = [
            contact_id,
            session["user_id"],
            owner,
            cb.rsa_deserialize_public_key(public),
        ]
    def me(self) -> pd.DataFrame:
        return self.data[self.data['user_id'] == session['user_id']]

class Locations:
    def __init__(self) -> None:
        self.data: pd.DataFrame = pd.DataFrame(columns=['user_id', 'contact_id', 'nonce', 'sessionkey', 'ciphertext'])
    def create(self, contact_id: str, nonce: str, sessionkey: str, ciphertext: str):
        self.data.loc[len(self.data)] = [
            session['user_id'],
            contact_id,
            nonce,
            sessionkey,
            ciphertext
        ]

    def me(self, added_users: AddedUsers) -> pd.DataFrame:
        temp = self.data[self.data['user_id'] == session['user_id']].merge(added_users.me(), on="contact_id")
        return temp[['contact_id', 'name', 'ciphertext', 'nonce', 'sessionkey']]
        

class Users:
    def __init__(self) -> None:
        self.data: pd.DataFrame = pd.DataFrame(columns=['user_id', 'name', 'public', 'private'])
    def create(self, name: str, key):
        self.data.loc[len(self.data)] = [
            session['user_id'],
            name,
            cb.rsa_serialize_public_key(key.public_key()),
            key
        ]
    def me(self) -> pd.DataFrame:
        return self.data[self.data['user_id'] == session['user_id']].iloc[0].to_dict()

users = Users()
added_users = AddedUsers()
locations = Locations()

def setup_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None or users.me() is None:
            session["user_id"] = str(uuid.uuid4())
            flash("This requires you to setup your account first")
            return redirect(url_for("get_setup"))
        return f(*args, **kwargs)
    return decorated_function

def added_user_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if added_users.me() is None:
            flash("This requires you to add a user to your circle first")
            return redirect(url_for("get_add"))
        return f(*args, **kwargs)
    return decorated_function

@app.get('/setup/')
def get_setup():
    form = CertificationForm()
    return render_template('setup.html', form = form)

@app.post("/setup/")
def post_setup():
    form = CertificationForm()
    users.create(name=form.name.data, key=cb.rsa_gen_keypair())
    flash("Successfully created your key pair")
    return redirect(url_for("get_share"))

@app.get('/')
@setup_required
@added_user_required
def get_index():   
    user = users.me()
    messages = locations.me(added_users).to_dict(orient="records")
    
    for message in messages:
        message["plaintext"] = cb.decrypt_message_with_aes_and_rsa(
            user.get("private"), 
            b64decode(message.get('sessionkey'), validate=True),
            b64decode(message.get('nonce'), validate=True),
            b64decode(message.get('ciphertext'), validate=True)
        ).decode('utf-8')
    
    return render_template('locations.html', locations = messages)


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
        added_users.create(cert["userId"], cert["name"], cert.get("publicKey"))
        flash("Contact added successfully")
        return redirect(url_for("get_index"))

@app.get("/send-location/")
@setup_required
@added_user_required
def get_send_location():
    form = SendLocationForm()
    form.contact.choices = [(user["user_id"], user["name"]) for user in added_users.me().to_dict(orient="records")]
    return render_template("send_location.html", form = form)

@app.post("/send-location/")
@setup_required
@added_user_required
def post_send_location():
    form = SendLocationForm()
    form.contact.choices = [(user['user_id'], user["name"]) for user in added_users.me().to_dict(orient="records")]

    if form.validate():
        contact_id = form.contact.data
        note = form.note.data.encode('utf-8')
        contacts = added_users.me()
        contact = contacts[contacts['contact_id'] == contact_id].iloc[0].to_dict()
        encrypted_session_key, nonce, ciphertext = cb.encrypt_message_with_aes_and_rsa(contact["public"], note)
        sessionkey = b64encode(encrypted_session_key).decode('ascii')
        nonce = b64encode(nonce).decode('ascii')
        ciphertext = b64encode(ciphertext).decode('ascii')
        locations.create(contact_id=contact_id, nonce=nonce, sessionkey=sessionkey, ciphertext=ciphertext)
        flash("Sent message successfully")
        return redirect(url_for("get_send_location"))


@app.get("/share/")
@setup_required
def get_share():
    user = users.me()
    private_key = json.dumps({
        "userId": session["user_id"],
        "name": user["name"],
        "privateKey": cb.rsa_serialize_private_key(user["private"])
    })
    public_key = json.dumps({
        "userId": session["user_id"],
        "name": user["name"],
        "publicKey": user["public"]
    })
    return render_template("share.html", public_key = public_key, private_key = private_key)