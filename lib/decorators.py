
from functools import wraps
from flask import flash, session, url_for, redirect

from lib.user_session import user_session

def reject_unauthenticated(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id, _, _ = user_session.read
        if user_id is None:
            flash("This requires you to authenticate first")
            return redirect(url_for("auth.get_auth"))
        return f(*args, **kwargs)
    return decorated_function

def reject_authenticated(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is not None:
            flash("You are already authenticated")
            return redirect(url_for("texts.get_texts"))
        return f(*args, **kwargs)
    return decorated_function