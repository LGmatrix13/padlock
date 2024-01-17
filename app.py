from base64 import b64decode, b64encode
from functools import wraps
from flask import Flask, Response, session, render_template, redirect, url_for, flash, jsonify
import uuid

import utilities.crypto_backend as cb
from utilities.forms import DangerZoneForm, LoginForm, RegisterForm, SendForm
from utilities.tables import Texts, Users


app = Flask(__name__)
app.config['SECRET_KEY'] = str(uuid.uuid4())

users = Users()
texts = Texts()

def reject_unauthenticated(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            flash("This requires you to authenticate first")
            return redirect(url_for("get_auth"))
        return f(*args, **kwargs)
    return decorated_function

def reject_authenticated(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is not None:
            flash("You are already authenticated")
            return redirect(url_for("get_index"))
        return f(*args, **kwargs)
    return decorated_function

def save_user_session(user_id: int, name: str, private_key: str):
    session["user_id"] = user_id
    session["name"] = name
    session["private_key"] = private_key


@app.get('/api/texts/')
@reject_unauthenticated
def get_api_texts():
    user_id = session.get("user_id")
    data = texts.read(user_id=user_id)
    return jsonify(data)

@app.get('/auth/')
@reject_authenticated
def get_auth():
    login_form = LoginForm()
    register_form = RegisterForm()
    return render_template('auth.html', register_form = register_form, login_form = login_form)

@app.post("/auth/register/")
def post_auth_register():
    form = RegisterForm()
    private_key = cb.rsa_gen_keypair()
    public_key = private_key.public_key()
    user_id, name, _ = users.create(name=form.name.data, key=cb.rsa_serialize_public_key(public_key=public_key))
    save_user_session(user_id=user_id, name=name, private_key=cb.rsa_serialize_private_key(private_key=private_key))
    flash("Successfully created your account! Be sure to save your token for future use.")
    return redirect(url_for("get_send"))

@app.post("/auth/login/")
def post_auth_login():
    try:
        login_form = LoginForm()
        token = login_form.file.data.read().decode('utf-8')
        private_key = cb.rsa_deserialize_private_key(token)
        public_key = private_key.public_key()
        user_id, name, public_key = users.read_from_public_key(public_key=cb.rsa_serialize_public_key(public_key=public_key))
        save_user_session(user_id=user_id, name=name, private_key=token)    
        flash(f"Welcome back, {name}!")
        return redirect(url_for("get_index"))
    except Exception:
        flash("Invalid token.")
        return redirect(url_for("get_auth"))

@app.get('/')
@reject_unauthenticated
def get_index():   
    encrypted_texts = texts.read(user_id=session.get("user_id"))
    decrypted_texts = []
    for encrypted_text in encrypted_texts:
        _, _, sender_user_id, _, context, nonce, sessionkey, ciphertext, signature = encrypted_text
        sessionkey_bytes = b64decode(sessionkey, validate=True)
        nonce_bytes = b64decode(nonce, validate=True)
        ciphertext_bytes = b64decode(ciphertext, validate=True)
        signature_bytes = b64decode(signature, validate=True)
        sender_user_id, sender_name, sender_public_key = users.read(sender_user_id)
        recipient_private_key = cb.rsa_deserialize_private_key(session.get("private_key"))
        decrypted_texts.append({
            "sender": sender_name,
            "context": context,
            "verified": cb.RSA_Verify(
                public_key=cb.rsa_deserialize_public_key(sender_public_key), 
                signature=signature_bytes, 
                message= sessionkey_bytes + nonce_bytes + ciphertext_bytes
            ),
            "text": cb.decrypt_message_with_aes_and_rsa(
                recipient_private_key,
                sessionkey_bytes,
                nonce_bytes,
                ciphertext_bytes        
            ).decode('utf-8')
        })

    return render_template('texts.html', name = session.get("name"), texts = decrypted_texts)

@app.get("/send/")
@reject_unauthenticated
def get_send():
    form = SendForm()
    form.recipient.choices = [(id, name) for (id, name) in users.read_all()]
    return render_template("send.html", form = form)

@app.post("/send/")
@reject_unauthenticated
def post_send():
    form = SendForm()
    form.recipient.choices = [(id, name) for (id, name) in users.read_all()]

    if form.validate():
        recipient_user_id, sender_name, sender_public_key = users.read(user_id=form.recipient.data)
        encrypted_session_key, nonce, ciphertext = cb.encrypt_message_with_aes_and_rsa(
            cb.rsa_deserialize_public_key(sender_public_key),
            form.message.data.encode('utf-8')
        )
        signature = b64encode(cb.RSA_Signature(
            private_key = cb.rsa_deserialize_private_key(session.get("private_key")),
            message = encrypted_session_key + nonce + ciphertext
        )).decode('ascii')
        sessionkey = b64encode(encrypted_session_key).decode('ascii')
        nonce = b64encode(nonce).decode('ascii')
        ciphertext = b64encode(ciphertext).decode('ascii')
        texts.create(
            sender_user_id=session.get("user_id"),
            recipient_user_id=recipient_user_id,
            sender=sender_name,
            context=form.context.data,
            nonce=nonce,
            session_key=sessionkey,
            ciphertext=ciphertext,
            signature=signature 
        )
        
        flash(f"Sent message successfully to {sender_name}!")
        return redirect(url_for("get_send"))
    
    flash("Invalid submission.")
    return redirect(url_for("get_send"))

@app.get("/danger-zone/")
@reject_unauthenticated
def get_danger_zone():
    form = DangerZoneForm()
    form.delete_user.choices = [(id, name) for (id, name) in users.read_all()]
    return render_template("danger_zone.html", form = form)

@app.post("/danger-zone/")
@reject_unauthenticated
def post_danger_zone():
    form = DangerZoneForm()
    form.delete_user.choices = [(id, name) for (id, name) in users.read_all()]

    if form.validate() and form.master_password.data == app.config["MASTER_PASSWORD"]:        
        delete_user_id = form.delete_user.data
        _, deleted_user_name, _ = users.delete(user_id=delete_user_id)

        flash(f"Successfully deleted {deleted_user_name}.")
        return redirect(url_for("get_danger_zone"))
    
    flash("Invalid submission or the master password was incorrect.")
    return redirect(url_for("get_danger_zone"))

@app.get("/save-token/")
@reject_unauthenticated
def get_save_token():
    private_key = session.get("private_key")   
    name = session.get("name") 
    return Response(
        private_key,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename={name}_token.pem"}
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)