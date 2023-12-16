from base64 import b64decode, b64encode
from functools import wraps
from flask import Flask, session, render_template, redirect, url_for, flash, Response, jsonify
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms.fields import StringField, SubmitField, TextAreaField, SelectField, FloatField
from wtforms.validators import InputRequired
import crypto_backend as cb
import pandas as pd
import uuid
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = str(uuid.uuid4())

class SetupForm(FlaskForm):
    name = StringField("Name")
    submit = SubmitField("Submit")

class ImportKeyForm(FlaskForm):
    file = FileField("Contact File")
    submit = SubmitField("Submit")

class SendLocationForm(FlaskForm):
    contact = SelectField("Contacts")
    longitude = FloatField("Longitude")
    latitude = FloatField("Latitude")
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
        self.data: pd.DataFrame = pd.DataFrame(columns=['user_id', 'contact_id', 'nonce', 'sessionkey', 'ciphertext', 'signature'])
    def create(self, contact_id: str, nonce: str, sessionkey: str, ciphertext: str, signature: str):
        self.data.loc[len(self.data)] = [
            session['user_id'],
            contact_id,
            nonce,
            sessionkey,
            ciphertext,
            signature
        ]
    def me(self, added_users: AddedUsers) -> pd.DataFrame:
        temp = self.data[['contact_id', 'nonce', 'sessionkey', 'ciphertext', 'signature']]
        temp = temp[self.data['contact_id'] == session['user_id']].merge(added_users.me(), left_on="contact_id", right_on="user_id")
        return temp
        

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
        if session.get('user_id') is None:
            flash("This requires you to setup your account first")
            return redirect(url_for("get_setup"))
        return f(*args, **kwargs)
    return decorated_function

def added_user_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if added_users.me().empty:
            flash("This requires you to add a contact first")
            return redirect(url_for("get_add_contact"))
        return f(*args, **kwargs)
    return decorated_function

@app.get('/setup/')
def get_setup():
    if session.get('user_id') is not None:
        return redirect(url_for("get_index"))

    session["user_id"] = str(uuid.uuid4())
    form = SetupForm()
    return render_template('setup.html', form = form)

@app.post("/setup/")
def post_setup():
    form = SetupForm()
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
        sessionkey = b64decode(message.get('sessionkey'), validate=True)
        nonce = b64decode(message.get('nonce'), validate=True)
        ciphertext = b64decode(message.get('ciphertext'), validate=True)
        message["verified"] = cb.RSA_Verify(
            public_key=message.get("public"), 
            signature=b64decode(message.get("signature"), validate=True), 
            message= sessionkey + nonce + ciphertext
        )
        message["data"] = json.loads(
            cb.decrypt_message_with_aes_and_rsa(
                user.get("private"), 
                sessionkey,
                nonce,
                ciphertext
            ).decode('utf-8')
        )
    return render_template('locations.html', locations = messages)


@app.get("/add/")
@setup_required
def get_add_contact():
    form = ImportKeyForm()
    return render_template("upload_contact.html", form = form)

@app.post("/add/")
@setup_required
def post_add_contact():
    form = ImportKeyForm()
    if form.validate():
        file = form.file.data
        content = file.read()
        cert = json.loads(content)
        added_users.create(cert["userId"], cert["name"], cert.get("publicKey"))
        flash("Contact added successfully")
        return redirect(url_for("get_add_contact"))

@app.get("/send-location/")
@setup_required
@added_user_required
def get_send_location():
    form = SendLocationForm()
    form.contact.choices = [(user["contact_id"], user["name"]) for user in added_users.me().to_dict(orient="records")]
    return render_template("send_location.html", form = form)

@app.post("/send-location/")
@setup_required
@added_user_required
def post_send_location():
    form = SendLocationForm()
    form.contact.choices = [(user['contact_id'], user["name"]) for user in added_users.me().to_dict(orient="records")]
    if form.validate():
        contact_id = form.contact.data
        data = {
            "note": form.note.data,
            "latitude": form.latitude.data,
            "longitude": form.longitude.data
        }
        contacts = added_users.me()
        user = users.me()
        contact = contacts[contacts["contact_id"] == contact_id].iloc[0].to_dict()
        encrypted_session_key, nonce, ciphertext = cb.encrypt_message_with_aes_and_rsa(
            contact.get("public"),
            json.dumps(data).encode('utf-8')
        )
        signature = b64encode(cb.RSA_Signature(
            private_key = user.get("private"), 
            message = encrypted_session_key + nonce + ciphertext
        )).decode('ascii')
        sessionkey = b64encode(encrypted_session_key).decode('ascii')
        nonce = b64encode(nonce).decode('ascii')
        ciphertext = b64encode(ciphertext).decode('ascii')
        locations.create(
            contact_id=contact_id, 
            nonce=nonce, 
            sessionkey=sessionkey, 
            ciphertext=ciphertext, 
            signature=signature    
        )
        print(signature)
        flash("Sent location successfully")
        return redirect(url_for("get_send_location"))

@app.get('/api/create-bad-message')
@setup_required
@added_user_required
def get_api_create_bad_message():
    data = {
        "note": "This is a bad message 🙂",
        "latitude": 40.7704396,
        "longitude": -111.8919675
    }
    contact = added_users.me().iloc[0].to_dict()
    user = users.me()
    encrypted_session_key, nonce, ciphertext = cb.encrypt_message_with_aes_and_rsa(
        contact.get("public"),
        json.dumps(data).encode('utf-8')
    )
    signature =  b64encode("BAD SIGNATURE".encode('utf-8')).decode('ascii')
    sessionkey = b64encode(encrypted_session_key).decode('ascii')
    nonce = b64encode(nonce).decode('ascii')
    ciphertext = b64encode(ciphertext).decode('ascii')
    locations.create(
        contact_id=contact["contact_id"], 
        nonce=nonce, 
        sessionkey=sessionkey, 
        ciphertext=ciphertext, 
        signature=signature    
    )
    return f"Sent unverified message to {contact.get('name')}", 200


@app.get("/share/")
@setup_required
def get_share():
    return render_template("share.html")

@app.get("/download/")
@setup_required
def get_download_public():
    user = users.me()
    user_name = user["name"].lower().replace(' ', '_')
    public_key = json.dumps({
        "userId": session["user_id"],
        "name": user["name"],
        "publicKey": user["public"]
    })
    return Response(
        public_key,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename=contact_{user_name}.json"}
    )