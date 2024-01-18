from flask import Blueprint, Response, render_template

from lib.decorators import reject_unauthenticated
from lib.user_session import user_session

save_token_blueprint = Blueprint('save_token', __name__, template_folder='templates')

@save_token_blueprint.get("/save-token/")
@reject_unauthenticated
def get_save_token():
    return render_template("save_token.html")

@save_token_blueprint.get("/save-token/download/")
@reject_unauthenticated
def get_save_token_download():
    _, name, private_key = user_session.read

    return Response(
        private_key,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename={name}_token.txt"}
    )
