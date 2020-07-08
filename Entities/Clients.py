from bson.objectid import ObjectId

from Utils.DBOperations import Read, Insert, Delete, Update

db_obj = None

COL_NAME = 'clients'


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


class Clients(object):

    def __init__(self, id_=None, email="", password="", first_name="", last_name=""):
        """
        Init function for the Client class.
        :param id_: Mongodb document id.
        :param password: Client password.
        :param first_name: First name of the app developer.
        :param last_name: Last name of the app developer.
        :param email: Email ID of the app developer.
        """
        self.id_ = ObjectId(id_)
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = password
        self.apps = []

    def signup(self):
        """
        This function signs up the client developer.
        :return: Client document from the DB.
        """
        db_obj = db_init()

        condition = {
            'email': self.email
        }

        existing = Read().find_by_condition(db_obj=db_obj,
                                            collection=COL_NAME,
                                            condition=condition)

        if existing:
            return False, "existing"

        result, oid = Insert().insert_one(db_obj=db_obj,
                            collection=COL_NAME,
                            document={
                                'first_name': self.first_name,
                                'last_name': self.last_name,
                                'email': self.email,
                                'password': self.password,
                                'apps': self.apps
                            })
        if result:
            self.id_ = oid
        return True if result else False, "success" if result else "failed"

    def setattr(self, doc):
        """
        This function sets the attributes from the document.
        :param doc: Dictionary object.
        """
        if "_id" in doc:
            self.id_ = doc["_id"]
        if "email" in doc:
            self.email = doc["email"]
        if "password" in doc:
            self.password = doc["password"]
        if "first_name" in doc:
            self.first_name = doc["first_name"]
        if "last_name" in doc:
            self.last_name = doc["last_name"]
        if "apps" in doc:
            self.apps = doc["apps"]


    def get_by_email(self, email="", projection={}):
        """
        This is used to get the client details based on developer email.
        :param email: Email of the developer.
        :param projection: Projection for mongodb query
        :return: Client document.
        """
        db_obj = db_init()

        if email == "":
            email = self.email

        conditions = {
            "email": email
        }

        result = Read().find_by_condition(db_obj=db_obj, collection=COL_NAME, condition=conditions, projection=projection)

        if result:
            self.setattr(result[0])

        return result

    def get_by_id(self, oid, projection={}):
        """
        This function retrieves an entire object based on the mongodb object id.
        :param oid: Mongodb document ID.
        :param projection: Mongodb projection.
        :return: Mongodb document.
        """
        db_obj = db_init()

        result = Read().find_by_id(db_obj=db_obj, collection=COL_NAME, id=oid, projection=projection)

        if result:
            self.setattr(result)
        return result

    def remove_app(self, application):
        """
        This function removes an application.
        :param application: Application object.
        :return: Update object.
        """
        db_obj = db_init()

        condition = {
            'email': self.email,
            'apps': application.id_
        }

        data = {
            '$pull': {'apps': application.id_}
        }

        result = Update().update_one_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, data=data)

        return result, "updated" if result else "failed"

    def delete(self, email=""):
        """
        This function deletes a client document for a specific email id.
        :param email: Email id of the registered client.
        :return: Deleted client document.
        """
        db_obj = db_init()

        if email == "":
            email = self.email

        condition = {
            'email': email
        }

        result = Delete().delete_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  condition=condition)
        return result
