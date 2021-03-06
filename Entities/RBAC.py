from Utils.DBOperations import Read, Update
from Entities.Clients import Clients

import json, uuid

db_obj = None

COL_NAME = 'applications'


def db_init():
    """
    This function checks the mongodb connections object.
    :return: Mongodb connections object.
    """
    global db_obj

    if db_obj is None:
        from main import MONGO_HOST, MONGO_PORT, MONGO_USERNAME, MONGO_PASSWORD, MONGO_DB
        from Utils.MongoHandler import ConnectDB

        db_obj = ConnectDB(host=MONGO_HOST, port=MONGO_PORT, username=MONGO_USERNAME, password=MONGO_PASSWORD,
                           db=MONGO_DB).getMongoDbObject()

    return db_obj


class Permission(object):

    def __init__(self, name="", value=""):
        """
        Init method for a permission.
        :param name: Name of the permission.
        :param value: Permission string. Should be unique.
        """
        self.name = name
        self.value = value

    def get(self, application, permission=""):
        """
        This function returns a permission document.
        :param application: Application.
        :param permission: Value of the permission.
        :return: Dictionary.
        """
        db_obj = db_init()

        if permission == "":
            permission = self.value

        condition = {
            "permissions.value": permission
        }

        result = Read().find_by_condition(db_obj=db_obj,
                                          collection=COL_NAME,
                                          condition=condition)

        for app in result:
            if app['api'] == application.api:
                for perm in app['permissions']:
                    if permission == perm['value']:
                        return perm

        return {}

    def add(self, client, application, name="", value=""):
        """
        This function adds a permission for a specific app.
        :param client: Client entity object for the application client.
        :param application: Application.
        :param name: Name of the permission.
        :param value: String value of the permission. Should be unique.
        :return: Added permission.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if name == "":
            name = self.name
        if value == "":
            value = self.value

        if self.get(application=application, permission=value):
            return None, "existing permission"

        condition = {
            "api": application.api
        }

        data = {
            "$push": {
                "permissions": {
                    "name": name,
                    "value": value
                }
            }
        }

        result = Update().update_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  condition=condition,
                                                  data=data)
        return result, "updated" if result else "fail"

    def add_many(self, client, application, permissions):
        """
        Add multiple permissions.
        :param client: Client entity object.
        :param application: Application.
        :param permissions: Permissions array.
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        existing = application.permissions

        common = []
        for value in existing:
            for p in permissions:
                if value['value'] == p['value']:
                    common.append(value)

        if len(common) != 0:
            return None, "existing"

        condition = {
            "api": application.api
        }

        data = {
            "$push": {
                "permissions": {
                    "$each": permissions
                }
            }
        }

        result = Update().update_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  condition=condition,
                                                  data=data)
        return result, "updated" if result else "fail"

    def remove(self, client, application, permission=""):
        """
        This function removes a permission for an application.
        :param client: Client entities object.
        :param application: Application.
        :param permission: Permission string to remove.
        :return: Delete Object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if permission == "":
            permission = self.value

        condition = {
            "api": application.api
        }

        data = {
            "$pull": {
                "permissions": {
                    "value": permission
                }
            }
        }

        result = Update().update_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  data=data,
                                                  condition=condition)

        return result, "removed" if result else "fail"

    def update_name(self, client, application, name, permission=""):
        """
        This function updates the name of the permission.
        :param client: Client entities object.
        :param application: Application.
        :param name: Name value to update.
        :param permission: Permission value.
        :return: Update result object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if permission == "":
            permission = self.value

        condition = {
            "api": application.api,
            "permissions.value": permission
        }

        data = {
            "$set": {
                "permissions.$[permission].name": name
            }
        }

        array_filters = [{"permission.value": permission}]

        result = Update().update_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  data=data,
                                                  condition=condition,
                                                  array_filters=array_filters)

        return result, "updated" if result else "failed"

    def update_value(self, client, application, new_value, old_value=""):
        """
        This function updates the value of the permission.
        :param client: Client entities object.
        :param application: Application.
        :param new_value: New value to set.
        :param old_value: Old value to look for.
        :return: Result object
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if new_value in application.permissions:
            return None, "existing"

        if old_value == "":
            old_value = self.value

        condition = {
            "api": application.api,
            "permissions.value": old_value
        }

        data = {
            "$set": {"permissions.$[permission].value": new_value}
        }

        array_filters = [{"permission.value": old_value}]

        result = Update().update_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  data=data,
                                                  condition=condition,
                                                  array_filters=array_filters)

        return result, "updated" if result else "failed"


class Role(object):

    def __init__(self, name="", id="", permissions=[]):
        """
        Init function for role object.
        :param name: Name of the role.
        :param id: Unique id of the role.
        :param permissions: List of permissions.
        """
        self.name = name
        self.id = id
        self.permissions = permissions

    def setattr(self, doc):
        """
        This function is used to set attributes for the Role object.
        :param doc: Role document from db.
        """
        if "name" in doc:
            self.name = doc['name']
        if "id" in doc:
            self.id = doc['id']
        if "permissions" in doc:
            self.permissions = doc['permissions']

    def get(self, application, client=None, role_id=""):
        """
        Gets the roles for the application.
        :param client: Client object.
        :param application: Application object.
        :param role_id: Role id.
        :return: List.
        """
        db_obj = db_init()
        if client is not None:
            if client.email != Clients().get_by_id(oid=application.owner)['email']:
                return None, "not allowed"

        if role_id == "":
            role_id = self.id

        condition = {'api': application.api, 'roles.id': role_id}

        result = Read().find_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition)

        for app in result:
            if app['api'] == application.api:
                for role in app['roles']:
                    if role_id == role['id']:
                        self.setattr(doc=role)
                        return role

        return {}

    def add(self, client, application, name="", role_id="", permissions=[]):
        """
        Adds a role for the application.
        :param client: Client object.
        :param application: Application object.
        :param name: Role name.
        :param role_id: Role id.
        :param permissions: Permissions list.
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if name == "":
            name = self.name
        if role_id == "":
            role_id = self.id
        if permissions:
            permissions = self.permissions

        condition = {'api': application.api}

        data = {"$push": {"roles": {"name": name, "id": role_id, "permissions": permissions}}}

        result = Update().update_one_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, data=data)

        return result, "updated" if result else "failed"

    def add_many(self, client, application, roles):
        """
        Adds multiple roles for the application.
        :param client: Client object.
        :param application: Application object.
        :param roles: Roles array.
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        existing = application.roles

        common = []
        for value in existing:
            for role in roles:
                if value['id'] == role['id']:
                    common.append(value)

        if len(common) != 0:
            return None, "existing"

        condition = {
            "api": application.api
        }

        data = {
            "$push": {
                "roles": {
                    "$each": roles
                }
            }
        }

        result = Update().update_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  condition=condition,
                                                  data=data)
        return result, "updated" if result else "fail"

    def update_name(self, client, application, name, role_id=""):
        """
        Updates the name of the role.
        :param client: Client object.
        :param application: Application Object.
        :param name: New name.
        :param role_id: Role id.
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if role_id == "":
            role_id = self.id

        condition = {
            "api": application.api,
            "roles.id": role_id
        }

        data = {
            "$set": {
                "roles.$[role].name": name
            }
        }

        array_filters = [{"role.id": role_id}]

        result = Update().update_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  data=data,
                                                  condition=condition,
                                                  array_filters=array_filters)

        return result, "updated" if result else "failed"

    def update_permissions(self, client, application, permissions, role_id=""):
        """
        This function sets the new set of permissions for a role.
        :param client: Client object.
        :param application: Application object.
        :param permissions: Permissions array.
        :param role_id: Role id.
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if role_id == "":
            role_id = self.id

        condition = {
            "api": application.api,
            "roles.id": role_id
        }

        data = {"$set": {"roles.$[role].permissions": permissions}}

        array_filters = [{"role.id": role_id}]

        result = Update().update_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  condition=condition,
                                                  data=data,
                                                  array_filters=array_filters)

        return result, "removed" if result else "failed"

    def add_permissions(self, client, application, permissions, role_id=""):
        """
        Add permissions for a role.
        :param client: Client object.
        :param application: Application object.
        :param permissions: Permissions list.
        :param role_id: Role id.
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if role_id == "":
            role_id = self.id

        for p in permissions:
            if p not in application.permissions:
                return None, "permission not defined"

        condition = {
            "api": application.api,
            "roles.id": role_id
        }

        data = {"$push": {"roles.$[role].permissions": {"$each": permissions}}}

        array_filters = [{"role.id": role_id}]

        result = Update().update_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  condition=condition,
                                                  data=data,
                                                  array_filters=array_filters)

        return result, "updated" if result else "failed"

    def remove_permissions(self, client, application, permissions, role_id=""):
        """
        Remove permissions for a role.
        :param client: Client object.
        :param application: Application object.
        :param permissions: Permissions to remove.
        :param role_id: Role id.
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if role_id == "":
            role_id = self.id

        to_remove = []
        for p in permissions:
            if p in application.permissions:
                to_remove.append(p)

        condition = {
            "api": application.api,
            "roles.id": role_id
        }

        data = {"$set": {"roles.$[role].permissions": to_remove}}

        array_filters = [{"role.id": role_id}]

        result = Update().update_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  condition=condition,
                                                  data=data,
                                                  array_filters=array_filters)

        return result, "removed" if result else "failed"

    def delete(self, client, application, role_id=""):
        """
        This function deletes a role for an application.
        :param client: Client object.
        :param application: Application object.
        :param role_id: Role id.
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if role_id == "":
            role_id = self.id

        condition = {
            'api': application.api,
            'roles.id': role_id
        }

        data = {
            '$pull': {'roles': {'id': role_id}}
        }

        result = Update().update_one_by_condition(db_obj=db_obj, collection=COL_NAME, data=data, condition=condition)

        return result, "removed" if result else "failed"


class User(object):

    def __init__(self, id_="", email="", name="", role=""):
        """
        Init function for creating a member object.
        :param id_: Unique id of the user.
        :param email: Email id.
        :param name: Name
        :param role: Role id.
        """
        self.id_ = id_
        self.email = email
        self.name = name
        self.role = role

    def __str__(self):
        """
        Returns a string of the user object.
        :return: String.
        """
        return json.dumps({'email': self.email, 'name': self.name, 'role': self.role, 'id_': self.id_})

    def json(self):
        """
        Returns a json object.
        :return: JSON.
        """
        return {'email': self.email, 'name': self.name, 'role': self.role, 'id_': self.id_}

    def setattr(self, doc):
        """
        Set object attributes from document.
        :param doc: Document.
        """
        if "id_" in doc:
            self.id_ = doc['id_']
        if "email" in doc:
            self.email = doc['email']
        if "name" in doc:
            self.name = doc['name']
        if "role" in doc:
            self.role = doc['role']

    def get_by_id(self, application, client=None, id_=""):
        """
        Get an user by its id.
        :param application: Application object.
        :param client: Client object.
        :param id_: Id to look for.
        :return: Document
        """
        db_obj = db_init()

        if client is not None:
            if client.email != Clients().get_by_id(oid=application.owner)['email']:
                return None, "not allowed"

        if id_ == "":
            id_ = self.id_

        condition = {'api': application.api, 'users.id_': id_}

        result = Read().find_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition)

        for app in result:
            for user in app['users']:
                if user['id_'] == id_:
                    self.setattr(user)
                    return user

        return {}

    def get_by_email(self, application, client=None, email=""):
        """
        Get an user by its email.
        :param client: Client object.
        :param application: Application object.
        :param email: Email id.
        :return: Document.
        """
        db_obj = db_init()

        if client is not None:
            if client.email != Clients().get_by_id(oid=application.owner)['email']:
                return None, "not allowed"

        if email == "":
            email = self.email

        condition = {'api': application.api, 'users.email': email}

        result = Read().find_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition)

        for app in result:
            for user in app['users']:
                if user['email'] == email:
                    self.setattr(user)
                    return user

        return {}

    def add(self, client, application, email="", role="", name=""):
        """
        Adding a single user for an application.
        :param client: Client object.
        :param application: Application object.
        :param email: Email id.
        :param role: Role.
        :param name: Name
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if email == "":
            email = self.email
        if role == "":
            role = self.role
        if name == "":
            name = self.name

        self.id_ = str(uuid.uuid1().hex)

        condition = {'api': application.api}

        data = {
            '$push': {
                'users': {
                    'id_': self.id_,
                    'email': email,
                    'name': name,
                    'role': role
                }
            }
        }

        result = Update().update_one_by_condition(db_obj=db_obj, collection=COL_NAME, data=data, condition=condition)

        return result, "updated" if result else "failed"

    def add_many(self, client, application, users=[]):
        """
        Add multiple users to an app at once.
        :param client: Client object.
        :param application: Application object.
        :param users: Users array.
        :return:
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        existing = application.users

        common = []
        for value in existing:
            for user in users:
                user['id_'] = str(uuid.uuid1().hex)
                if value['email'] == user['email']:
                    common.append(value)

        if len(common) != 0:
            return None, "existing"

        condition = {
            "api": application.api
        }

        data = {
            "$push": {
                "users": {
                    "$each": users
                }
            }
        }

        result = Update().update_one_by_condition(db_obj=db_obj,
                                                  collection=COL_NAME,
                                                  condition=condition,
                                                  data=data)
        return result, "updated" if result else "fail"

    def remove(self, client, application, email=""):
        """
        Removes an user from the application.
        :param client: Client object.
        :param application: Application object.
        :param email: Email id.
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if email == "":
            email = self.email

        condition = {'api': application.api, 'users.email': email}
        data = {'$pull': {'users': {'email': email}}}
        result = Update().update_one_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, data=data)

        return result, "removed" if result else "failed"

    def update_email(self, client, application, new_email="", old_email=""):
        """
        Updates the email address of an user.
        :param client: Client object.
        :param application: Application object.
        :param new_email: New email id.
        :param old_email: Old email id.
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if old_email == "":
            old_email = self.email

        existing = application.users

        if new_email in existing:
            return None, "existing"

        condition = {'api': application.api, 'users.email': old_email}

        data = {'$set': {'users.$[user].email': new_email}}

        array_filters = [{'user.email': old_email}]

        result = Update().update_one_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, data=data,
                                                  array_filters=array_filters)

        return result, "update" if result else "failed"

    def update_name(self, client, application, name, email=""):
        """
        Update name of user.
        :param client: Client object.
        :param application: Application object.
        :param name: Name.
        :param email: Email id.
        :return: Update object.
        """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if email == "":
            email = self.email

        condition = {'api': application.api, 'users.email': email}

        data = {'$set': {'users.$[user].name': name}}

        array_filters = [{'user.email': email}]

        result = Update().update_one_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, data=data,
                                                  array_filters=array_filters)

        return result, "update" if result else "failed"

    def update_role(self, client, application, role, email=""):
        """
                Updates the email address of an user.
                :param client: Client object.
                :param application: Application object.
                :param role: New role.
                :param email: Email id.
                :return: Update object.
                """
        db_obj = db_init()

        if client.email != Clients().get_by_id(oid=application.owner)['email']:
            return None, "not allowed"

        if email == "":
            email = self.email

        existing = application.roles

        found = False
        for er in existing:
            if role == er['id']:
                found = True

        if not found:
            return None, "role not defined"

        condition = {'api': application.api, 'users.email': email}

        data = {'$set': {'users.$[user].role': role}}

        array_filters = [{'user.email': email}]

        result = Update().update_one_by_condition(db_obj=db_obj, collection=COL_NAME, condition=condition, data=data,
                                                  array_filters=array_filters)

        return result, "update" if result else "failed"
