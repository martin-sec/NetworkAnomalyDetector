import pyshark
from pyshark import FileCapture
from pyshark import packet


def load_pcap(filepath: str) -> FileCapture | None:
    try:
        capture = pyshark.FileCapture(filepath)
        return capture
    except FileNotFoundError:
        return None

def extract_basic_info(capture: FileCapture) -> dict:
    basic_pkt_info: dict[int, {str, str}] = {}
    counter = 0
    for pkt in capture:
        basic_pkt_info[counter] = {
            "Timestamp": pkt.sniff_timestamp,
            "Source IP": pkt.ip.src,
            "Destination IP": pkt.ip.dst,
            "Source Port": "N/A",
            "Destination Port": "N/A",
        }
        # Logic for src and dst port has to be different to account for lack of transport layer details
        counter += 1

    return basic_pkt_info

print(extract_basic_info(load_pcap("../data/raw/test.pcapng")))