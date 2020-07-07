import memcache

def memcache_connection():
    """
    This returns a memcache connection client.
    :return: Memcache client.
    """
    from main import MEMCACHE_HOST, MEMCACHE_PORT
    client = memcache.Client(servers=[MEMCACHE_HOST + ":" + MEMCACHE_PORT])
    return client
