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
    # logging.info(stand_init_dict)
    logging.info("-"*56)

    # 解析
    # payload length
    payload_len, *_ = struct.unpack("<I", packet[0:3] + b'\x00')
    packet_number = packet[3]
    logging.info(f"payload_len {payload_len} packet_number {packet_number}")
    packet = packet[4:]

    # 解析
    # protocol-version
    protocal_version = packet[0]
    packet = packet[1:]
    logging.info(f"protocol {protocal_version}")

    # 解析
    # mysql-version
    packet, mysql_version = read_str(packet, ends=b'\x00')
    mysql_version = mysql_version.decode("utf8")
    logging.info(f"server_version_original {mysql_version}")

    #
    connection_id, auth_data_1, capability_lower = struct.unpack(
        "<I8sx2s", packet[0:15])
    logging.info(f"connection_id {connection_id}")

    packet = packet[15:]

    if len(packet) > 0:
        charset, status_flags, capability_uper = struct.unpack(
            f"<BH2s", packet[0:5])
        logging.info(f"charset {charset}")
        logging.info(f"server_status {status_flags}")
        packet = packet[5:]

    auth_plugin_data_length = packet[0]
    logging.info(f"auth_plugin_data_length {auth_plugin_data_length}")
    auth_data_2_len = max(13, (auth_plugin_data_length - 8))

    #packet = packet[1:]
    packet = packet[11:]
    auth_data_2 = packet[0:auth_data_2_len]
    if auth_data_2.endswith(b'\x00'):
        auth_data_2 = auth_data_2[0:-1]

    logging.info(f"auth_plugin_data {auth_data_1 + auth_data_2}")

    packet = packet[13:]
    packet, auth_plugin = read_str(packet, ends=b'\x00')
    auth_plugin = auth_plugin.decode('utf8')
    logging.info(f"auth-plugin-name {auth_plugin}")

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


def parse_init_handshake_packet_v2():
    """解析初始化握手包
    希望以更少的代码实现解析
    这里假设后端数据库是 MySQL-8.0.x 
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
    # logging.info(stand_init_dict)

    logging.info("-"*35)

    # 解析 payload_len,packet_number
    payload_len, *_ = struct.unpack(
        "<I", packet[0:3] + b'\x00')
    packet_number = packet[3]
    packet = packet[4:]
    logging.info(f"payload_len {payload_len} packet_number {packet_number}")

    # protocol
    protocol = packet[0]
    packet = packet[1:]
    logging.info(f"protocol {protocol}")

    # server_version_original
    packet, server_version_original = read_str(packet, ends=b'\x00')
    server_version_original = server_version_original.decode('utf8')
    logging.info(f"server_version_original {server_version_original}")

    # I8sx2sBHHBxxxxxxxxxx  31 bytes
    (connection_id, auth_plugin_data_part_1, capability_flags_lower,
     charset, status_flags, capability_flags_uper, auth_plugin_data_length) = struct.unpack(
         "<I8sx2sBH2sBxxxxxxxxxx", packet[0:31]
    )
    capabilities, *_ = struct.unpack(
        "<I", capability_flags_lower+capability_flags_uper)
    packet = packet[31:]
    logging.info(f"connection_id {connection_id}")
    logging.info(f"charset {charset}")
    logging.info(f"server_status {status_flags}")
    logging.info(f"auth_plugin_data_length {auth_plugin_data_length}")
    logging.info(f"capabilitys {capabilities}")

    remainningg_auth_data = max(13, auth_plugin_data_length - 8)
    logging.info(f"remainningg_auth_data {remainningg_auth_data}")
    auth_plugin_data_part_2 = packet[0:13]

    # 官方文档中没有说明为什么要去掉最后的这个 \x00 字节
    if auth_plugin_data_part_2.endswith(b'\x00'):
        auth_plugin_data_part_2 = auth_plugin_data_part_2[0:-1]

    logging.info(
        f"auth_plugin_data {auth_plugin_data_part_1 + auth_plugin_data_part_2}")
    auth_data = auth_plugin_data_part_1 + auth_plugin_data_part_2
    packet = packet[13:]
    packet, auth_plugin_name = read_str(packet, ends=b'\x00')
    auth_plugin_name = auth_plugin_name.decode('utf8')
    logging.info(f"auth-plugin-name {auth_plugin_name}")
    logging.info("-" * 56)

    res = {
        'protocol': protocol,
        'server_version_original': server_version_original,
        'server_threadid': connection_id,
        'charset': charset,
        'server_status': status_flags,
        'auth_plugin': auth_plugin_name,
        'auth_data': auth_data,
        'capabilities': capabilities,
    }

    if res == stand_init_dict:
        logging.info("match.")
    else:
        logging.info(res)
        logging.info(stand_init_dict)
        logging.info("not match.")

    logging.info("complete.")


def main():
    parse_init_handshake_packet_v2()

    # parse_init_handshake_packet()


if __name__ == "__main__":
    main()
