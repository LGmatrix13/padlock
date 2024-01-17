from base64 import b64encode
from flask import Blueprint, render_template, session, redirect, url_for, flash
from utilities.tables import users, texts
from utilities.decorators import reject_unauthenticated
from utilities.forms import SendForm
import utilities.crypto_backend as cb
from utilities.user_session import user_session

send_blueprint = Blueprint('send', __name__, template_folder='templates')

@send_blueprint.get("/send/")
@reject_unauthenticated
def get_send():
    form = SendForm()
    form.recipient.choices = [(id, name) for (id, name) in users.read_all()]
    return render_template("send.html", form = form)

@send_blueprint.post("/send/")
@reject_unauthenticated
def post_send():
    form = SendForm()
    form.recipient.choices = [(id, name) for (id, name) in users.read_all()]
    user_id, _, private_key = user_session.read

    if form.validate():
        recipient_user_id, sender_name, sender_public_key = users.read(user_id=form.recipient.data)
        encrypted_session_key, nonce, ciphertext = cb.encrypt_message_with_aes_and_rsa(
            cb.rsa_deserialize_public_key(sender_public_key),
            form.message.data.encode('utf-8')
        )
        signature = b64encode(cb.RSA_Signature(
            private_key = cb.rsa_deserialize_private_key(private_key),
            message = encrypted_session_key + nonce + ciphertext
        )).decode('ascii')
        sessionkey = b64encode(encrypted_session_key).decode('ascii')
        nonce = b64encode(nonce).decode('ascii')
        ciphertext = b64encode(ciphertext).decode('ascii')
        texts.create(
            sender_user_id=user_id,
            recipient_user_id=recipient_user_id,
            sender=sender_name,
            context=form.context.data,
            nonce=nonce,
            session_key=sessionkey,
            ciphertext=ciphertext,
            signature=signature 
        )
        
        flash(f"Sent message successfully to {sender_name}!")
        return redirect(url_for("send.get_send"))
    
    flash("Invalid submission.")
    return redirect(url_for("send.get_send"))