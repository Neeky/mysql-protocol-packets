#!/usr/bin/env python3

"""打包 ssl-connection-requests-packet
https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest
"""

import struct
import logging
import argparse

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(threadName)s - %(levelname)s - %(lineno)s  - %(message)s')


def make_ssl_connect_request_packet(client_flags=0, charset=45, max_allowed_packets=1073741824):
    logging.info("make_ssl_request_packet start.")
    logging.info(f"client_flags={client_flags} .")
    logging.info(f"charset={charset} .")
    logging.info(f"max_allowed_packets={max_allowed_packets} .")
    packet = struct.pack("IIB" + 'x' * 23, client_flags,
                         max_allowed_packets, charset)
    logging.info("make_ssl_request_packet complete.")
    return packet


def main():
    packet = make_ssl_connect_request_packet(
        charset=45, client_flags=1813005, max_allowed_packets=1073741824)

    with open("./packets/make_auth_ssl.bin", 'br') as f:
        make_auth_packet = f.read()

    logging.info(f"{packet}")
    logging.info(f"{make_auth_packet}")
    if packet == make_auth_packet:
        logging.info("match.")
    else:
        logging.error("not match.")

    logging.info("complete.")


if __name__ == "__main__":
    main()
