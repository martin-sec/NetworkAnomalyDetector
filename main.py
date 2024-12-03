import pprint
from src import parser as parser
from src import exporter as exporter
import logging
import sys

logging.basicConfig(filename='logs/parser.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    try:
        print(parser.extract_basic_info(parser.load_pcap("data/raw/200722_tcp_anon.pcapng")))
        # pprint.pprint(output, sort_dicts=False)
        exporter.csv_export(parser.extract_basic_info(parser.load_pcap("data/raw/200722_tcp_anon.pcapng")))
        exporter.json_export(parser.extract_basic_info(parser.load_pcap("data/raw/200722_tcp_anon.pcapng")))
    except FileNotFoundError:
        sys.exit(10)
    except PermissionError:
        logging.error("Error(20) - Permission Error, The user does not have enough permissions to open the file")
        sys.exit(20)
    except ValueError:
        sys.exit(30)

if __name__ == "__main__":
    main()