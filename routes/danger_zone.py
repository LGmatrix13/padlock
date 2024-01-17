from flask import Blueprint, render_template, redirect, url_for, flash
import os

from lib.tables import users
from lib.decorators import reject_unauthenticated
from lib.forms import DangerZoneForm

danger_zone_blueprint = Blueprint('danger_zone', __name__, template_folder='templates')

@danger_zone_blueprint.get("/danger-zone/")
@reject_unauthenticated
def get_danger_zone():
    form = DangerZoneForm()
    form.delete_user.choices = [(id, name) for (id, name) in users.read_all()]
    return render_template("danger_zone.html", form = form)

@danger_zone_blueprint.post("/danger-zone/")
@reject_unauthenticated
def post_danger_zone():
    form = DangerZoneForm()
    form.delete_user.choices = [(id, name) for (id, name) in users.read_all()]

    if form.validate() and form.master_password.data == str(os.environ.get("MASTER_PASSWORD")):        
        delete_user_id = form.delete_user.data
        _, deleted_user_name, _ = users.delete(user_id=delete_user_id)

        flash(f"Successfully deleted {deleted_user_name}.")
        return redirect(url_for("danger_zone.get_danger_zone"))
    
    flash("Invalid submission or the master password was incorrect.")
    return redirect(url_for("danger_zone.get_danger_zone"))
