import pprint
from src import parser as parser
from src import exporter as exporter
from src import error_codes as err
import logging
import sys


def main():
    try:
        output = parser.extract_basic_info(parser.load_pcap("data/raw/"))
        pprint.pprint(output)
        # pprint.pprint(output, sort_dicts=False)
    except FileNotFoundError:
        sys.exit(err.PCAP_FILE_NOT_FOUND_ERROR)
    except PermissionError:
        sys.exit(err.PCAP_FILE_PERMISSION_ERROR)
    except ValueError:
        sys.exit(err.INVALID_PCAP_FILE_SIGNATURE_ERROR)
    except IsADirectoryError:
        sys.exit(err.FILE_IS_A_DIRECTORY_ERROR)
    except TypeError:
        sys.exit(err.INVALID_FILEPATH_TYPE_ERROR)

if __name__ == "__main__":
    main()