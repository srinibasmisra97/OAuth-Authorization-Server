from pymongo import MongoClient


class ConnectDB(object):

    def __init__(self, host, port, username, password, db):
        """
        Init method for db connection.
        :param host: Host ip address.
        :param port: Host port number.
        :param username: Username of db user.
        :param password: Password for db user.
        :param db: Name of the database.
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.db = db

    def getMongoDbObject(self):
        """
        This function returns the database object.
        :return: Database Object
        """
        conn = MongoClient(host=self.host, port=self.port, username=self.username, password=self.password, authSource=self.db)

        return conn[self.db]
