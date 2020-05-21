"""实现 MySQL 验证插件的加密逻辑
"""

import struct
from hashlib import sha256


class BaseAuthPlugin(object):
    """
    """
    requires_ssl = False
    plugin_name = ''

    def __init__(self, auth_data, username=None, password=None, database=None,
                 ssl_enabled=False):
        self._auth_data = auth_data
        self._username = username
        self._password = password
        self._database = database
        self._ssl_enabled = ssl_enabled

    def prepare_password(self):
        raise NotImplementedError('')

    def auth_response(self):
        return self.prepare_password()


class MySQLCachingSHA2PasswordAuthPlugin(BaseAuthPlugin):
    """
    """
    requires_ssl = False
    plugin_name = 'caching_sha2_password'
    perform_full_authentication = 4
    fast_auth_success = 3

    def auth_response(self):
        """
        """
        if isinstance(self._password, (str)):
            password = self._password.encode("utf8")
        else:
            password = self._password

        auth_data = self._auth_data
        hash1 = sha256(password).digest()
        hash2 = sha256()
        hash2.update(sha256(hash1).digest())
        hash2.update(auth_data)
        hash2 = hash2.digest()
        xored = [h1 ^ h2 for (h1, h2) in zip(hash1, hash2)]
        hash3 = struct.pack('32B', *xored)
        return hash3


def get_auth_plugin(plugin_name):
    for authclass in BaseAuthPlugin.__subclasses__():
        if authclass.plugin_name == plugin_name:
            return authclass
