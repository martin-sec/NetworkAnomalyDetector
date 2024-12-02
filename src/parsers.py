import pyshark
from pyshark import FileCapture
from pyshark.packet.packet import Packet

import pprint


def load_pcap(filepath: str) -> FileCapture | None:
    try:
        capture = pyshark.FileCapture(filepath)
        return capture
    except FileNotFoundError:
        return None

def has_timestamp(pkt: Packet) -> bool:
    return bool(pkt.sniff_timestamp)

def has_network_layer(pkt: Packet) -> bool:
    return bool(pkt.ip)

def has_transport_layer(pkt: Packet) -> bool:
    return bool(pkt.transport_layer)

def extract_basic_info(capture: FileCapture) -> dict[int, dict[str, str]]:
    basic_pkt_info: dict[int, dict[str, str | dict[str, str]]] = {}
    counter = 0
    for pkt in capture:
        counter += 1
        basic_pkt_info[counter] = {
            "Timestamp": {
                "Date": "N/A",
                "Time": "N/A",
            },
            "Source IP": "N/A",
            "Destination IP": "N/A",
            "Transport Protocol": "N/A",
            "Source Port": "N/A",
            "Destination Port": "N/A",
            "Packet Length": "N/A"
        }
        if has_timestamp(pkt):
            timestamp = str(pkt.sniff_time)
            date, time = timestamp.split()
            basic_pkt_info[counter]["Timestamp"]["Date"] = date
            basic_pkt_info[counter]["Timestamp"]['Time'] = time

        if has_network_layer(pkt):
            basic_pkt_info[counter]["Source IP"] = str(pkt.ip.src)
            basic_pkt_info[counter]["Destination IP"] = str(pkt.ip.dst)
            basic_pkt_info[counter]["Packet Length"] = str(pkt.ip.len)

        if has_transport_layer(pkt):
            basic_pkt_info[counter]["Transport Protocol"] = str(pkt.transport_layer)
            basic_pkt_info[counter]["Source Port"] = str(pkt[pkt.transport_layer].srcport)
            basic_pkt_info[counter]["Destination Port"] = str(pkt[pkt.transport_layer].dstport)

    return dict(basic_pkt_info)

pprint.pprint(extract_basic_info(load_pcap("../data/raw/3-way-handshake.pcap")), sort_dicts=False)
