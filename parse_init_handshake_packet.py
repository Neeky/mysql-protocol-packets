#!/usr/bin/evn python3
"""解析握手包
https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
"""

import json
import struct
import logging

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(threadName)s - %(levelname)s - %(lineno)s  - %(message)s')


def read_str(packet, ends=None, size=None):
    """
    """
    if ends is None and size is None:
        raise ValueError("either ends not None or size not None.")

    if not isinstance(packet, (bytes, bytearray)):
        raise ValueError('packet must be a bytes or bytearray.')

    if ends is not None:
        index = packet.index(ends)
        return packet[index + 1:], packet[0:index]

    if size is not None and size < len(packet):
        return packet[size + 1], packet[0:size]
    else:
        raise ValueError('size must less than len(packet)')


def parse_init_handshake_packet():
    """解析初始化握手包
    https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
    """

    # 从磁盘中读取 init-handshake-packet 实例
    with open("packets/init_handshake_pakcet.bin", 'br') as f:
        packet = f.read()

    logging.info(f"packet length {len(packet)}")
    logging.info(f"packet {packet}")

    # 从磁盘中读取处理完成之后得到的字典
    with open("packets/init_handshake_pakcet.args") as f:
        init_str = f.read()

    # 读取解析完成之后的字典值
    stand_init_dict = json.loads(init_str)
    stand_init_dict['auth_data'] = stand_init_dict['auth_data'].encode('utf8')
    logging.info(stand_init_dict)

    # 解析
    # payload length
    payload_len, *_ = struct.unpack("<I", packet[0:3] + b'\x00')
    logging.info(
        f"packet length 78 ,pakcet header length 4 ,payload length {payload_len}")
    packet_number = packet[3]
    logging.info(f"packet number {packet_number}")
    packet = packet[4:]

    # 解析
    # protocol-version
    protocal_version = packet[0]
    packet = packet[1:]
    logging.info(f"protocol version {protocal_version}")

    # 解析
    # mysql-version
    packet, mysql_version = read_str(packet, ends=b'\x00')
    mysql_version = mysql_version.decode("utf8")
    logging.info(f"mysql_version {mysql_version}")
    logging.info(f"remaining packet {packet}")

    #
    connection_id, auth_data_1, capability_lower = struct.unpack(
        "<I8sx2s", packet[0:15])
    logging.info(f"connection-id {connection_id}")

    packet = packet[15:]
    logging.info(f"remaing pcket {packet}")

    if len(packet) > 0:
        charset, status_flags, capability_uper = struct.unpack(
            f"<BH2s", packet[0:5])
        logging.info(f"charset {charset}")
        packet = packet[5:]

    auth_data_2_len = packet[0]
    auth_data_2_len = max(13, (auth_data_2_len-8))
    logging.info(f"auth-data-2 length {auth_data_2_len}")
    #packet = packet[1:]
    packet = packet[11:]
    auth_data_2 = packet[0:13]
    if auth_data_2.endswith(b'\x00'):
        auth_data_2 = auth_data_2[0:-1]

    packet = packet[13:]
    packet, auth_plugin = read_str(packet, ends=b'\x00')
    auth_plugin = auth_plugin.decode('utf8')
    capabilities, *_ = struct.unpack("<I", capability_lower + capability_uper)
    res = {
        'protocol': protocal_version,
        'server_version_original': mysql_version,
        'server_threadid': connection_id,
        'charset': charset,
        'server_status': status_flags,
        'auth_plugin': auth_plugin,
        'auth_data': auth_data_1 + auth_data_2,
        'capabilities': capabilities
    }
    logging.info(res)
    logging.info(stand_init_dict)

    if res == stand_init_dict:
        logging.info("match.")
    else:
        logging.info("not match.")
    logging.info("complete.")


def main():
    parse_init_handshake_packet()


if __name__ == "__main__":
    main()
