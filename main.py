import pprint
from pyshark.capture.capture import TSharkCrashException
from src import parser as parser
from src import exporter as exporter
import logging
import sys

logging.basicConfig(filename='logs/parser.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    try:
        output = (parser.extract_basic_info(parser.load_pcap("data/raw/test.pcap")))
        pprint.pprint(output, sort_dicts=False)
    except FileNotFoundError:
        sys.exit(10)
    except PermissionError:
        sys.exit(20)
    except ValueError:
        sys.exit(30)

if __name__ == "__main__":
    main()