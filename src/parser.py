import pyshark
from pyshark import FileCapture
from pyshark.packet.packet import Packet
from pyshark.capture.capture import TSharkCrashException
import logging
import sys

PCAP_FILE_NOT_FOUND_ERROR = 1
FILE_IS_NOT_PCAP_ERROR = 2

def load_pcap(filepath: str) -> FileCapture | None:
    logging.info(f"Loading PCAP file: {filepath}")
    try:
        with open(filepath, "rb") as file:
            data = file.read()
            if not (data.startswith(b"\xd4\xc3\xb2\xa1") or data.startswith(b"\xa1\xb2\xc3\xd4")):
                # Supported packet capture formats .pcapng, .pcap, .cap, and .libcap
                raise ValueError
        return pyshark.FileCapture(input_file=filepath)
    except FileNotFoundError:
        raise FileNotFoundError(f"PCAP file not found: {filepath}")
    except PermissionError:
        raise PermissionError(f"PCAP file not readable: {filepath}")


def has_timestamp(pkt: Packet) -> bool:
    return bool(pkt.sniff_timestamp)

def has_network_layer(pkt: Packet) -> bool:
    return bool(pkt.ip)

def has_transport_layer(pkt: Packet) -> bool:
    return bool(pkt.transport_layer)

def extract_basic_info(capture: FileCapture) -> dict[int, dict[str, str ]]:
    basic_pkt_info: dict[int, dict[str, str]] = {}
    counter = 1
    logging.info(f"Extracting basic information from {capture}")
    for pkt in capture:
        # If a .pcap file without .pcap contents is passed to this function, it will raise a TSharkCrashException here
        # However, that will exit the program with error code 1 before the exception can be caught.
        # To be reviewed in a few days
        logging.debug(f"Extracting basic information for packet #{counter}...")
        basic_pkt_info[counter] = {
            "Timestamp": "N/A",
            "Source IP": "N/A",
            "Destination IP": "N/A",
            "Transport Protocol": "N/A",
            "Source Port": "N/A",
            "Destination Port": "N/A",
            "Packet Length": "N/A"
        }
        if has_timestamp(pkt):
            basic_pkt_info[counter]["Timestamp"] = str(pkt.sniff_time)


        if has_network_layer(pkt):
            basic_pkt_info[counter]["Source IP"] = str(pkt.ip.src)
            basic_pkt_info[counter]["Destination IP"] = str(pkt.ip.dst)
            basic_pkt_info[counter]["Packet Length"] = str(pkt.ip.len)

        if has_transport_layer(pkt):
            basic_pkt_info[counter]["Transport Protocol"] = str(pkt.transport_layer)
            basic_pkt_info[counter]["Source Port"] = str(pkt[pkt.transport_layer].srcport)
            basic_pkt_info[counter]["Destination Port"] = str(pkt[pkt.transport_layer].dstport)

        counter += 1
    logging.info(f"All basic information from {capture} was successfully extracted.")
    return dict(basic_pkt_info)
