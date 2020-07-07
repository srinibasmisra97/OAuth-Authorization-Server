import secrets, string, random

from Utils.DBOperations import Read, Insert, Update, Delete
from Utils.Security import b64encode

db_obj = None

COL_NAME = 'applications'


def db_init():
    """
    This functions checks the mongodb connection object.
    :return: Mongodb connections object.
    """
    global db_obj

    if db_obj is None:
        from main import MONGO_HOST, MONGO_PORT, MONGO_USERNAME, MONGO_PASSWORD, MONGO_DB
        from Utils.MongoHandler import ConnectDB

        db_obj = ConnectDB(host=MONGO_HOST, port=MONGO_PORT, username=MONGO_USERNAME, password=MONGO_PASSWORD, db=MONGO_DB).getMongoDbObject()

    return db_obj


class Application(object):

    def __init__(self, id_=None, name="", api="", exp=20, owner=None, redirect_uris=[], permissions=[], roles=[], users=[], creds=[]):
        """
        Init method for an Application.
        :param id_: Mongodb document id.
        :param name: App name.
        :param api: App id.
        :param exp: App token expiry.
        :param owner: App owner.
        :param redirect_uris: Allowed Redirect URIs for the application.
        :param permissions: Permissions for the application.
        :param roles: Roles defined for the app.
        :param users: Members of the app.
        :param creds: Key Secret pairs.
        """
        self.id_ = id_
        self.name = name
        self.api = api
        self.exp = exp
        self.owner = owner
        self.redirect_uris = redirect_uris
        self.permissions = permissions
        self.roles = roles
        self.users = users
        self.creds = creds

    def setattr(self, doc):
        """
        This function sets attributes from a given document.
        :param doc: Dictionary
        """
        if '_id' in doc:
            self.id_ = doc['_id']
        if 'name' in doc:
            self.name = doc['name']
        if 'api' in doc:
            self.api = doc['api']
        if 'exp' in doc:
            self.exp = int(doc['exp'])
        if 'owner' in doc:
            self.owner = doc['owner']
        if 'redirect_uris' in doc:
            self.direct_uris = doc['redirect_uris']
        if 'permissions' in doc:
            self.permissions = doc['permissions']
        if 'roles' in doc:
            self.roles = doc['roles']
        if 'users' in doc:
            self.users = doc['users']
        if 'creds' in doc:
            self.creds = doc['creds']

    def register(self, client):
        """
        This function registers an app for the client developer.
        :param client: Client entity.
        :return: Document containing app details.
        """

        result = self.get_by_api_id(api_id=self.api)
        if result:
            return None, "existing api id"

        key = "".join((random.choice(string.ascii_letters + string.digits) for i in range(20)))
        secret = secrets.token_hex(32)

        app = {
            'name': self.name,
            'api': self.api,
            'exp': self.exp,
            'owner': client.id_,
            'permissions': [],
            'redirect_uris': [],
            'roles': [],
            'users': [],
            'creds': [
                {
                    'key': key,
                    'secret': secret
                }
            ]
        }

        conditions = {
            "first_name": client.first_name,
            "last_name": client.last_name,
            "email": client.email
        }

        db_obj = db_init()

        result, oid = Insert().insert_one(db_obj=db_obj,
                                     collection=COL_NAME,
                                     document=app)

        Update().update_one_by_condition(db_obj=db_obj,
                                         collection='clients',
                                         condition=conditions,
                                         data={"$push":{"apps": oid}})

        return result, b64encode(key + ":" + secret) if result else "fail"

    def get_by_id(self, oid, projection={}):
        """
        Get an application using Mongodb document id.
        :param oid: Mongodb document id.
        :param projection: Mongodb query projection.
        :return: Application document.
        """
        db_obj = db_init()

        if projection:
            result = Read().find_by_id(db_obj=db_obj, collection=COL_NAME, id=oid, projection=projection)
        else:
            result = Read().find_by_id(db_obj=db_obj, collection=COL_NAME, id=oid)

        if result:
            self.setattr(result)

        return result

    def get_by_api_id(self, api_id, projection={}):
        """
        Get an application based on app id.
        :param api_id: Application id.
        :param projection: Mongodb projection query.
        :return: Mongodb document.
        """
        db_obj = db_init()

        condition = { 'api': api_id }

        result = Read().find_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, projection=projection)

        if result:
            self.setattr(result[0])

        return result

    def get_by_key(self, api_id, key, projection={}):
        """
        Gets an application based on a application key.
        :param api_id: Application id.
        :param key: Application key or client id.
        :param projection: Mongodb projection.
        :return: Mongodb document.
        """
        db_obj = db_init()

        condition = { 'api': api_id, 'creds.key': key }

        result = Read().find_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, projection=projection)

        if result:
            self.setattr(result[0])

        return result

    def get_by_key_secret(self, api_id, key, secret, projection={}):
        """
        Gets an application based on the app id, key and secret.
        :param api_id: Application id.
        :param key: Application key.
        :param secret: Application secret.
        :param projection: Mongodb projection.
        :return: Mongodb document.
        """
        db_obj = db_init()

        condition = { 'api': api_id, 'creds.key': key, 'creds.secret': secret }

        result = Read().find_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, projection=projection)

        if result:
            self.setattr(result[0])

        return result

    def add_key_secret(self, api_id):
        """
        Adds a new key secret pair.
        :param api_id: Application id.
        :return: Update object, message.
        """
        db_obj = db_init()

        if not self.get_by_api_id(api_id=api_id):
            return None, "app not found"

        key = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
        secret = secrets.token_hex(32)

        condition = { 'api': api_id }

        data = { '$push': {'creds': {'key': key, 'secret': secret}} }

        result = Update().update_one_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, data=data)

        return result, b64encode(key + ":" + secret) if result else "failed"

    def revoke_key_secret(self, api_id, key):
        """
        Revokes a key secret pair for an application.
        :param api_id: Application id.
        :param key: Application key.
        :return: Delete object, message.
        """
        db_obj = db_init()

        if not self.get_by_api_id(api_id=api_id):
            return None, "app not found"

        found = False
        for cred in self.creds:
            if key == cred['key']:
                found = True

        if not found:
            return None, 'key not found'

        condition = {'api': api_id, 'creds.key': key}

        data = {'$pull': {'creds':{'key': key}}}

        result = Update().update_one_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, data=data)

        return result, "success" if result else "failed"

    def delete(self, api_id):
        """
        Deletes an application.
        :param api_id: Application id.
        :return: Delete object.
        """
        db_obj = db_init()

        if not self.get_by_api_id(api_id=api_id):
            return None, "app not found"

        result = Delete().delete_one_by_id(db_obj=db_obj, collection=COL_NAME, id=self.id_)

        return result, "deleted" if result else "failed"

    def set_redirect_uris(self, uris):
        """
        This function simply pushes an uri in to the allowed redirect uris list.
        :param uri: URI to add.
        :return: Update object.
        """
        db_obj = db_init()

        condition = {'api': self.api}
        data = {'$set': {'redirect_uris': uris}}

        result = Update().update_one_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, data=data)

        return result, "updated" if result else "failed"
