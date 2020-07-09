import configparser
import os

from flask import Flask

from api.Clients import app_Clients
from api.Applications import app_Applications
from api.RBAC import app_RBAC
from api.OAuth import app_OAuth

if os.path.isfile("configs/environment.cfg"):
    CONFIG_FILEPATH = os.path.join(os.getcwd(), "configs/environment.cfg")
    CONFIG_ENV = os.environ.get('CONFIG_ENV') or 'DEV'

    cfg = configparser.RawConfigParser()
    cfg.read(CONFIG_FILEPATH)

    MONGO_HOST = str(cfg.get(CONFIG_ENV, "MONGO_HOST")) if cfg.has_option(CONFIG_ENV, "MONGO_HOST") else "localhost"
    MONGO_PORT = int(cfg.get(CONFIG_ENV, "MONGO_PORT")) if cfg.has_option(CONFIG_ENV, "MONGO_PORT") else 27017
    MONGO_USERNAME = str(cfg.get(CONFIG_ENV, "MONGO_USERNAME")) if cfg.has_option(CONFIG_ENV, "MONGO_USERNAME") else ""
    MONGO_PASSWORD = str(cfg.get(CONFIG_ENV, "MONGO_PASSWORD")) if cfg.has_option(CONFIG_ENV, "MONGO_PASSWORD") else ""
    MONGO_DB = str(cfg.get(CONFIG_ENV, "MONGO_DB")) if cfg.has_option(CONFIG_ENV, "MONGO_DB") else "authDb"
    MEMCACHE_HOST = str(cfg.get(CONFIG_ENV, "MEMCACHE_HOST")) if cfg.has_option(CONFIG_ENV, "MEMCACHE_HOST") else "localhost"
    MEMCACHE_PORT = int(cfg.get(CONFIG_ENV, "MEMCACHE_PORT")) if cfg.has_option(CONFIG_ENV, "MEMCACHE_PORT") else 11211
else:
    MONGO_HOST = str(os.environ.get("MONGO_HOST")) if os.environ.get("MONGO_HOST") is not None else "localhost"
    MONGO_PORT = int(os.environ.get("MONGO_PORT")) if os.environ.get("MONGO_PORT") is not None else 27017
    MONGO_USERNAME = str(os.environ.get("MONGO_USERNAME")) if os.environ.get("MONGO_USERNAME") is not None else ""
    MONGO_PASSWORD = str(os.environ.get("MONGO_PASSWORD")) if os.environ.get("MONGO_PASSWORD") is not None else ""
    MONGO_DB = str(os.environ.get("MONGO_DB")) if os.environ.get("MONGO_DB") is not None else "authDb"
    MEMCACHE_HOST = str(os.environ.get("MEMCACHE_HOST")) if os.environ.get("MEMCACHE_HOST") is not None else "localhost"
    MEMCACHE_PORT = int(os.environ.get("MEMCACHE_PORT")) if os.environ.get("MEMCACHE_PORT") is not None else 11211

SUPPORTED_GRANT_TYPES = ['implicit', 'authorization_code', 'client_credentials']

app = Flask(__name__, template_folder='static')

app.register_blueprint(app_Clients)
app.register_blueprint(app_RBAC)
app.register_blueprint(app_Applications)
app.register_blueprint(app_OAuth)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
