from base64 import b64decode
from flask import Blueprint, render_template, session

from lib.tables import texts, users
import lib.crypto_backend as cb
from lib.decorators import reject_unauthenticated
from lib.user_session import user_session
from lib.cache import Cache

passwords_blueprint = Blueprint('passwords', __name__, template_folder='templates')

@passwords_blueprint.get('/')
@reject_unauthenticated
def get_passwords():   
    user_id, name, private_key = user_session.read
    encrypted_texts = texts.read(user_id=user_id)
    decrypted_texts = []
    cache = Cache(namespace="passwords")
    for encrypted_text in encrypted_texts:
        text_id, _, sender_user_id, _, context, nonce, sessionkey, ciphertext, signature = encrypted_text

        if cache.read(text_id) is None:
            sender_user_id, sender_name, sender_public_key = users.read(sender_user_id)
            recipient_private_key = cb.rsa_deserialize_private_key(private_key)
            decrypted_text = {
                "sender": sender_name,
                "context": context,
                "verified": cb.RSA_Verify(
                    public_key=cb.rsa_deserialize_public_key(sender_public_key), 
                    signature=signature, 
                    message=sessionkey + nonce + ciphertext
                ),
                "password": cb.decrypt_message_with_aes_and_rsa(
                    recipient_private_key,
                    sessionkey,
                    nonce,
                    ciphertext        
                ).decode('utf-8')
            }
            cache.create(text_id, decrypted_text)
            decrypted_texts.append(decrypted_text)
        else:
            decrypted_texts.append(cache.read(text_id))

    return render_template('passwords.html', name = name, passwords = decrypted_texts)