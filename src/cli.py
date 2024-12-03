import argparse
import parser as psr

def cli_operations():
    parser = argparse.ArgumentParser(description="Process a PCAP file and performs some operations on it.")

    # Parsing Group
    parsing_group = parser.add_argument_group('Parsing Options')
    parsing_group.add_argument('-f', '--file', required=True, help="Path to the input data file")
    parsing_group.add_argument("-b", "--basic",
                        action="store_true",
                        help="Processes the PCAP to provide basic information from each packet:"
                             "Timestamp, Source and Destination IP, Source and Destination Port, Transport Protocol,"
                             "and Packet Length.")

    # Exporting Group
    exporting_group = parser.add_argument_group('Exporting Options')
    exporting_group.add_argument("-e", "--export",
                        choices=["csv", "json", "all"],
                        help="[Optional] Allows to export the processed PCAP file to a CSV file or JSON file."
                             "use -e/--export csv to export a .csv file and use -e/--export json to export a .json file."
                             "If you want to export both, please use -e/--export all.")

    # Visualization Group


    # Miscellaneous Group
    miscellaneous_group = parser.add_argument_group('Miscellaneous Options')
    miscellaneous_group.add_argument('--verbose',
                                     action='store_true',
                                     help="Enable verbose output")

    args = parser.parse_args()



    parser.add_argument("-f", "--file",
                        required = True,
                        help="[Required] Pass the PCAP filepath file to process.")

    args = parser.parse_args()

    filename: str = args.file
    analysis: dict = {}

    if args.basic:
        analysis = psr.extract_basic_info(psr.load_pcap(filename))

    if not args.export:
        print(analysis)





