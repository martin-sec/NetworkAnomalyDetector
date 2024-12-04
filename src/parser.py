import pyshark
from pyshark import FileCapture
from pyshark.packet.packet import Packet
from src import error_codes as err
import logging

# Logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

info_handler = logging.FileHandler("./logs/parser.log")
info_handler.setLevel(logging.INFO)
info_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
info_handler.setFormatter(info_formatter)

error_handler = logging.FileHandler("./logs/parser_error.log")
error_handler.setLevel(logging.ERROR)
error_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
error_handler.setFormatter(error_formatter)

logger.addHandler(info_handler)
logger.addHandler(error_handler)

def load_pcap(filepath: str) -> FileCapture | None:
    logger.info(f"Loading PCAP file: {filepath}...")
    if not isinstance(filepath, str):
        logger.error(f"Error({err.INVALID_FILEPATH_TYPE_ERROR}): filepath {filepath} must be a valid string.")
        raise TypeError(f"The filepath {filepath} must be a string")
    logger.info(f"PCAP file loaded successfully")

    try:
        logger.info(f"Opening PCAP file: {filepath}...")
        with open(filepath, "rb") as file:
            data = file.read()
            if not (data.startswith(b"\xd4\xc3\xb2\xa1") or
                    data.startswith(b"\xa1\xb2\xc3\xd4") or
                    data.startswith(b"\x0a\x0d\x0d\x0a")):
                # Supported packet capture formats .pcapng, .pcap, .cap, and .libcap
                logger.error(f"Error({err.INVALID_PCAP_FILE_SIGNATURE_ERROR}): The PCAP's file signature is not supported."
                             f" It may not be a PCAP file.")
                raise ValueError(f"{filepath} is not a valid PCAP file")
            logger.info("PCAP file contains a valid signature and was opened successfully")
        return pyshark.FileCapture(input_file=filepath)

    except FileNotFoundError:
        logger.error(f"Error({err.PCAP_FILE_NOT_FOUND_ERROR}): the PCAP file was not found. Please, check the filepath provided.")
        raise FileNotFoundError(f"PCAP file not found: {filepath}")
    except IsADirectoryError:
        logger.error(f"Error({err.FILE_IS_A_DIRECTORY_ERROR}): the path is a directory, not a PCAP file.")
        raise IsADirectoryError(f"{filepath} is a directory")
    except PermissionError:
        logger.error(f"Error({err.PCAP_FILE_PERMISSION_ERROR}): you do not have permission to access the PCAP.")
        raise PermissionError(f"PCAP file not readable due to lack of permission: {filepath}")


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
