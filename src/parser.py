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
        Loads a PCAP file and returns a capture object for further processing.

        This function attempts to load a PCAP file from the specified filepath using the pyshark library.
        If successful, it returns a FileCapture object for the given file. If the file cannot be found,
        an error is logged, and the program exits.

        Args:
            filepath (str): The path to the PCAP file to be loaded.

        Returns:
            FileCapture | None: A FileCapture object for the specified PCAP file, or None if the file cannot be found.

        Raises:
            SystemExit: If the PCAP file is not found, an error is logged and the program exits.
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
    """
        Extracts basic packet information from a given capture file (PCAP).

        This function processes each packet in the provided PCAP capture and extracts key
        information such as timestamp, source and destination IP addresses, transport protocol,
        source and destination ports, and packet length. It returns this data in a structured format.

        Args:
            capture (FileCapture): The capture file (PCAP) from which packet information is to be extracted.

        Returns:
            dict[int, dict[str, str]]: A dictionary where the keys are packet numbers (integers),
                                       and the values are dictionaries containing the extracted information for each packet.
                                       The information includes:
                                       - Timestamp: A dictionary with "Date" and "Time" keys.
                                       - Source IP: The source IP address as a string.
                                       - Destination IP: The destination IP address as a string.
                                       - Transport Protocol: The transport protocol used (e.g., TCP, UDP).
                                       - Source Port: The source port number as a string.
                                       - Destination Port: The destination port number as a string.
                                       - Packet Length: The length of the packet as a string.

        Raises:
            SystemExit: If the provided capture is not a valid PCAP file, an error message is logged and the program exits.
        """
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
print(extract_basic_info(load_pcap("../data/raw/test.txt")))