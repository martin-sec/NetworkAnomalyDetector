import pyshark
from pyshark import FileCapture
from pyshark.packet.packet import Packet
from pyshark.capture.capture import TSharkCrashException
import pprint
import logging
import sys

PCAP_FILE_NOT_FOUND_ERROR = 1
FILE_IS_NOT_PCAP_ERROR = 2

logging.basicConfig(filename='../logs/parser.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def load_pcap(filepath: str) -> FileCapture | None:
    logging.info(f"Loading PCAP file: {filepath}")
    try:
        capture = pyshark.FileCapture(input_file=filepath)
        logging.info(f"PCAP file '{filepath}' loaded successfully.")
        return capture
    except FileNotFoundError:
        # Catches instances of the filepath given not being found
        logging.error(f"Error({PCAP_FILE_NOT_FOUND_ERROR}): PCAP file '{filepath}' could not be found or is not a PCAP file.")
        sys.exit(PCAP_FILE_NOT_FOUND_ERROR)


def has_timestamp(pkt: Packet) -> bool:
    return bool(pkt.sniff_timestamp)

def has_network_layer(pkt: Packet) -> bool:
    return bool(pkt.ip)

def has_transport_layer(pkt: Packet) -> bool:
    return bool(pkt.transport_layer)

def extract_basic_info(capture: FileCapture) -> dict[int, dict[str, str]]:
    basic_pkt_info: dict[int, dict[str, str | dict[str, str]]] = {}
    counter = 1
    logging.info(f"Extracting basic information from {capture}")
    for pkt in capture:
        # If a .pcap file without .pcap contents is passed to this function, it will raise a TSharkCrashException here
        # However, that will exit the program with error code 1 before the exception can be caught.
        # To be reviewed in a few days
        logging.debug(f"Extracting basic information for packet #{counter}...")
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
            basic_pkt_info[counter]["Timestamp"]["Time"] = time

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







pprint.pprint(extract_basic_info(load_pcap("../data/raw/3-way-handshake.pcap")), sort_dicts=False)
