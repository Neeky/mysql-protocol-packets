#!/usr/bin/evn python3
"""打包 HandshakeResponse
https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
"""


import struct
import logging
import argparse
from plugins import get_auth_plugin


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(threadName)s - %(levelname)s - %(lineno)s  - %(message)s')


def make_auth_response_packet(auth_data=None, plugin_name='caching_sha2_password',
                              username=None, password=None, database=None, charset=45,
                              client_flags=0, max_allowed_packet=1073741824, ssl_enabled=False,
                              auth_plugin=None, conn_attrs=None):
    """
    """
    # 打包 client_flags,max_allowed_packet,charset
    packet = struct.pack("IIB" + "x"*23, client_flags,
                         max_allowed_packet, charset)

    # 打包 username
    username_bytes = username.encode("utf8")
    packet = packet + username_bytes + b'\x00'
    logging.info(packet)

    with open("./packets/make_auth.bin", 'rb') as f:
        stand_make_auth_packet = f.read()

    # capabilities & CLIENT_SECURE_CONNECTION == True
    auth = get_auth_plugin('caching_sha2_password')(
        auth_data, username, password, ssl_enabled)
    auth_response = auth.auth_response()
    auth_response_len = len(auth_response)
    packet = packet + struct.pack("B", auth_response_len) + auth_response

    # capabilities & CLIENT_CONNECT_WITH_DB == False
    packet = packet + b'\x00'

    #capabilities & CLIENT_PLUGIN_AUTH == True
    packet = packet + auth_plugin.encode('utf8') + b'\x00'

    # capabilities & CLIENT_CONNECT_ATTRS == True
    attrs_len = sum([(2 + len(name) + len(conn_attrs[name]))
                     for name in conn_attrs])
    packet = packet + struct.pack("B", attrs_len)

    for name in conn_attrs:
        packet = packet + struct.pack("B", len(name)) + name.encode('utf8')
        packet = packet + \
            struct.pack("B", len(conn_attrs[name])) + \
            conn_attrs[name].encode('utf8')

    logging.info(packet)
    logging.info(stand_make_auth_packet)
    if packet == stand_make_auth_packet:
        logging.info("match.")
    else:
        logging.error("not match.")

    logging.info("complete.")


def main():
    conn_attrs = {
        "_pid": "19557",
        "_platform": "x86_64",
        "_source_host": "NEEKYJIANG-MB1",
        "_client_name": "mysql-connector-python",
        "_client_license": "GPL-2.0",
        "_client_version": "8.0.20",
        "_os": "macOS-10.15.3"
    }
    make_auth_response_packet(auth_data=b'5\x10d\x1c\x06<\x1f\x03cxy\x1eY?2Cz\x02sX',
                              auth_plugin='caching_sha2_password', username='appuser', password='123456', database='',
                              charset=45, client_flags=1813005, max_allowed_packet=1073741824, ssl_enabled=True, conn_attrs=conn_attrs)


if __name__ == "__main__":
    main()
