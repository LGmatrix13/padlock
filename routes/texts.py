from base64 import b64decode
from flask import Blueprint, render_template

from utilities.tables import texts, users
import utilities.crypto_backend as cb
from utilities.decorators import reject_unauthenticated
from utilities.user_session import user_session

texts_blueprint = Blueprint('texts', __name__, template_folder='templates')

@texts_blueprint.get('/')
@reject_unauthenticated
def get_texts():   
    user_id, name, private_key = user_session.read
    encrypted_texts = texts.read(user_id=user_id)
    decrypted_texts = []
    for encrypted_text in encrypted_texts:
        _, _, sender_user_id, _, context, nonce, sessionkey, ciphertext, signature = encrypted_text
        sessionkey_bytes = b64decode(sessionkey, validate=True)
        nonce_bytes = b64decode(nonce, validate=True)
        ciphertext_bytes = b64decode(ciphertext, validate=True)
        signature_bytes = b64decode(signature, validate=True)
        sender_user_id, sender_name, sender_public_key = users.read(sender_user_id)
        recipient_private_key = cb.rsa_deserialize_private_key(private_key)
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

    return render_template('texts.html', name = name, texts = decrypted_texts)