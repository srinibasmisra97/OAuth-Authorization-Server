from bson.objectid import ObjectId

class Read(object):

    def find_by_id(self, db_obj, collection, id, projection = {}):
        """
        This function returns a document by looking for the specific object id.
        :param db_obj: DB Connection Object.
        :param collection: Collection in the DB.
        :param id: Mongodb document ID.
        :param projection: Mongodb projection. Accepts a dictionary.
        :return: Array of documents.
        """
        try:
            if projection:
                result = db_obj[collection].find_one({'_id': ObjectId(id)}, projection)
            else:
                result = db_obj[collection].find_one({'_id': ObjectId(id)})
            return result
        except:
            return {}

    def find_by_condition(self, db_obj, collection, condition = {}, projection = {}):
        """
        This function returns all documents matching the conditions specified.
        :param db_obj: DB Connection Object.
        :param collection: Collection in the DB.
        :param condition: Conditions document to be used to query the collection. Accepts a dictionary.
        :param projection: Mongodb projection for query. Accepts a dictionary.
        :return: Array of documents.
        """
        try:
            if projection:
                result = db_obj[collection].find(condition, projection)
            else:
                result = db_obj[collection].find(condition)
            return list(result)
        except Exception as e:
            print(e)
            return []

class Insert(object):

    def insert_one(self, db_obj, collection, document):
        """
        This function inserts one document into the collection.
        :param db_obj: DB Connections Object.
        :param collection: Collection in the DB.
        :param document: Document to be inserted into the collection. Accepts a dictionary.
        :return: Document inserted.
        """

        try:
            result = db_obj[collection].insert_one(document)
            return result, result.inserted_id
        except Exception as e:
            print(e)
            return {}

    def insert_many(self, db_obj, collection, documents):
        """
        This function inserts multiple documents into the collection at once.
        :param db_obj: DB Connections Object.
        :param collection: Collection in the DB.
        :param documents: Array of documents to be inserted into the collection. Accepts a list of dictionaries.
        :return: List of documents inserted.
        """

        try:
            result = db_obj[collection].insert_many(documents)
            return result, result.inserted_ids
        except Exception as e:
            print(e)
            return []

class Delete(object):

    def delete_one_by_id(self, db_obj, collection, id):
        """
        This function deletes one document of the specific object id.
        :param db_obj: DB Connections Object.
        :param collection: Collection in the DB.
        :param id: Mongodb document id.
        :return: Deleted document.
        """

        try:
            result = db_obj[collection].delete_one({'_id': ObjectId(id)})
            return result
        except Exception as e:
            print(e)
            return {}

    def delete_one_by_condition(self, db_obj, collection, condition={}):
        """
        This function deletes one document based on a condition.
        :param db_obj: DB Connections Object.
        :param collection: Collection in the DB.
        :param condition: Conditions document to be used to query the collection. Accepts a dictionary.
        :return: Deleted document.
        """

        try:
            result = db_obj[collection].delete_one(condition)
            return result
        except Exception as e:
            print(e)
            return {}

    def delete_many_by_condition(self, db_obj, collection, condition={}):
        """
        This function deletes multiple documents based on a condition. If no condition passed, it deletes all documents in the collection.
        :param db_obj: DB Connections Object.
        :param collection: Collection in the DB.
        :param condition: Conditions document to be used to query the collection. Accepts a dictionary.
        :return:
        """

        try:
            result = db_obj[collection].delete_many(condition)
            return result
        except Exception as e:
            print(e)
            return []

class Update(object):

    def update_one_by_id(self, db_obj, collection, id, data, array_filters={}):
        """
        This function updates the document of a specific object id.
        :param db_obj: DB Connections Object.
        :param collection: Collection in the DB.
        :param id: Object Id of the document in the collection.
        :param data: Dictionary containing all the keys with their updated values. Accepts a dictionary.
        :param array_filters: Array filters for mongodb query.
        :return: Updated document.
        """

        try:
            if array_filters:
                result = db_obj[collection].update_one({'_id': ObjectId(id)}, data, array_filters=array_filters)
            else:
                result = db_obj[collection].update_one({'_id':ObjectId(id)}, data)
            return result
        except Exception as e:
            print(e)
            return {}

    def update_one_by_condition(self, db_obj, collection, data, condition={}, array_filters={}):
        """
        This function upates one document by a specific condition.
        :param db_obj: DB Connections Object.
        :param collection: Collection in the DB.
        :param data: Dictionary containing all the keys with their updated values. Accepts a dictionary.
        :param condition: Conditions to select the documents to be updated. Accepts a dictionary.
        :param array_filters: Array filters for mongodb query.
        :return: Updated document.
        """

        try:
            if array_filters:
                result = db_obj[collection].update_one(condition, data, array_filters=array_filters)
            else:
                result = db_obj[collection].update_one(condition, data)
            return result
        except Exception as e:
            print(e)
            return {}

    def update_many(self, db_obj, collection, data, condition={}, array_filters={}):
        """
        This function upates many documents by a specific condition.
        :param db_obj: DB Connections Object.
        :param collection: Collection in the DB.
        :param data: Dictionary containing all the keys with their updated values. Accepts a dictionary.
        :param condition: Conditions to select the documents to be updated. Accepts a dictionary.
        :param array_filters: Array filters for mongodb query.
        :return: Updated documents.
        """

        try:
            if array_filters:
                result = db_obj[collection].update_many(condition, data, array_filters=array_filters)
            else:
                result = db_obj[collection].update_many(condition, data)
            return result
        except Exception as e:
            print(e)
            return {}
