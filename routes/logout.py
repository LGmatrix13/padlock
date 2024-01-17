from flask import Blueprint, redirect, url_for
from lib.user_session import user_session

logout_blueprint = Blueprint('logout', __name__, template_folder='templates')

@logout_blueprint.get('/logout/')
def get_logout():
    user_session.delete()
    return redirect(url_for("auth.get_auth"))
