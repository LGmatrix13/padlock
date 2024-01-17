from flask import Flask, session
import uuid

from routes.auth import auth_blueprint
from routes.danger_zone import danger_zone_blueprint
from routes.save_token import save_token_blueprint
from routes.send import send_blueprint
from routes.texts import texts_blueprint

app = Flask(__name__)
app.config['SECRET_KEY'] = str(uuid.uuid4())


app.register_blueprint(auth_blueprint)
app.register_blueprint(danger_zone_blueprint)
app.register_blueprint(save_token_blueprint)
app.register_blueprint(send_blueprint)
app.register_blueprint(texts_blueprint)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)