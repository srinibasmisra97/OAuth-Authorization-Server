import memcache

from main import MEMCACHE_HOST, MEMCACHE_PORT


def memcache_connection():
    """
    This returns a memcache connection client.
    :return: Memcache client.
    """
    client = memcache.Client(servers=[MEMCACHE_HOST + ":" + MEMCACHE_PORT])
    return client
