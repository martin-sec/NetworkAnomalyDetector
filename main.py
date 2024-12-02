import pprint
from src import parser as parser
from src import exporter as exporter
import logging


def main():
    logging.basicConfig(filename='logs/parser.log',
                        level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    pprint.pprint(parser.extract_basic_info(parser.load_pcap("data/raw/3-way-handshake.pcap")), sort_dicts=False)
    exporter.csv_export(parser.extract_basic_info(parser.load_pcap("data/raw/200722_tcp_anon.pcapng")))

if __name__ == "__main__":
    main()