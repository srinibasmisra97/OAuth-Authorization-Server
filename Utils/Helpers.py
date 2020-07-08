import memcache


def memcache_connection():
    """
    This returns a memcache connection client.
    :return: Memcache client.
    """
    from main import MEMCACHE_HOST, MEMCACHE_PORT
    client = memcache.Client(servers=[MEMCACHE_HOST + ":" + MEMCACHE_PORT])
    return client


def list_to_string(list):
    """
    Converts list to string.
    :param list: List to convert.
    :return: String
    """
    string = ""
    for a in list:
        string = string + a + " "
    return string.strip()