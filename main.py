import configparser
import os

from flask import Flask, redirect

from api.Clients import app_Clients
from api.Applications import app_Applications
from api.RBAC import app_RBAC
from api.OAuth import app_OAuth

CONFIG_FILEPATH = os.path.join(os.getcwd(), "configs/environment.cfg")
CONFIG_ENV = os.environ.get('CONFIG_ENV') or 'DEV'

cfg = configparser.RawConfigParser()
cfg.read(CONFIG_FILEPATH)

MONGO_HOST = str(cfg.get(CONFIG_ENV, "MONGO_HOST"))
MONGO_PORT = int(cfg.get(CONFIG_ENV, "MONGO_PORT"))
MONGO_USERNAME = str(cfg.get(CONFIG_ENV, "MONGO_USERNAME"))
MONGO_PASSWORD = str(cfg.get(CONFIG_ENV, "MONGO_PASSWORD"))
MONGO_DB = str(cfg.get(CONFIG_ENV, "MONGO_DB"))
MEMCACHE_HOST = str(cfg.get(CONFIG_ENV, "MEMCACHE_HOST"))
MEMCACHE_PORT = str(cfg.get(CONFIG_ENV, "MEMCACHE_PORT"))

app = Flask(__name__, template_folder='static')

app.register_blueprint(app_Clients)
app.register_blueprint(app_RBAC)
app.register_blueprint(app_Applications)
app.register_blueprint(app_OAuth)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
