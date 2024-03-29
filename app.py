import os
from flask import Flask, redirect

from routes.auth import auth_blueprint
from routes.danger_zone import danger_zone_blueprint
from routes.save_token import save_token_blueprint
from routes.send import send_blueprint
from routes.passwords import passwords_blueprint
from routes.logout import logout_blueprint

app = Flask(__name__)
app.config['SECRET_KEY'] = str(os.environ.get("MASTER_PASSWORD"))

app.register_blueprint(auth_blueprint)
app.register_blueprint(danger_zone_blueprint)
app.register_blueprint(save_token_blueprint)
app.register_blueprint(send_blueprint)
app.register_blueprint(passwords_blueprint)
app.register_blueprint(logout_blueprint)

@app.get("/about/")
def get_about():
    return redirect(location="https://github.com/LGmatrix13/padlock/blob/main/README.md", code=308)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)