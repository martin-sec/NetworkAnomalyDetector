import pyshark
from pyshark import FileCapture
from pyshark.packet.packet import Packet
import pprint
import logging
import sys

PCAP_FILE_NOT_FOUND_ERROR = 1
FILE_IS_NOT_PCAP_ERROR = 2

logging.basicConfig(filename='../logs/parser.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def load_pcap(filepath: str) -> FileCapture | None:
    """
    Load a PCAP file and return a PyShark FileCapture object.

    This function attempts to load a PCAP (packet capture) file using PyShark's
    FileCapture class. If the specified file is not found, it returns None.

    Args:
        filepath (str): The path to the PCAP file.

    Returns:
        FileCapture | None: A PyShark FileCapture object if the file is successfully loaded;
        None if the file is not found.

    Raises:
        FileNotFoundError: If the PCAP file is not found, though this is caught and
        handled within the function.
    """
    try:
        capture = pyshark.FileCapture(filepath)
        logging.info(f"PCAP file '{filepath}' loaded successfully.")
        return capture
    except FileNotFoundError:
         logging.error(f"Error({PCAP_FILE_NOT_FOUND_ERROR}): PCAP file '{filepath}' could not be found or is not a PCAP file.")
         sys.exit(PCAP_FILE_NOT_FOUND_ERROR)


def has_timestamp(pkt: Packet) -> bool:
    return bool(pkt.sniff_timestamp)

def has_network_layer(pkt: Packet) -> bool:
    return bool(pkt.ip)

def has_transport_layer(pkt: Packet) -> bool:
    return bool(pkt.transport_layer)

def extract_basic_info(capture: FileCapture) -> dict[int, dict[str, str]]:
    if capture is not FileCapture:
        logging.error(f"Error({FILE_IS_NOT_PCAP_ERROR}): {capture} is not a valid PCAP file.")
        sys.exit(2)
    else:
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
                basic_pkt_info[counter]["Timestamp"]["Time"] = time

            if has_network_layer(pkt):
                basic_pkt_info[counter]["Source IP"] = str(pkt.ip.src)
                basic_pkt_info[counter]["Destination IP"] = str(pkt.ip.dst)
                basic_pkt_info[counter]["Packet Length"] = str(pkt.ip.len)

            if has_transport_layer(pkt):
                basic_pkt_info[counter]["Transport Protocol"] = str(pkt.transport_layer)
                basic_pkt_info[counter]["Source Port"] = str(pkt[pkt.transport_layer].srcport)
                basic_pkt_info[counter]["Destination Port"] = str(pkt[pkt.transport_layer].dstport)

        return dict(basic_pkt_info)


# pprint.pprint(extract_basic_info(load_pcap("../data/raw/3-way-handshake.pca")), sort_dicts=False)
print(extract_basic_info(load_pcap("../data/raw/text.txt")))