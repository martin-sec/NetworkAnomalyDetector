# NetworkAnomalyDetector
(subject to change as the project evolves)

# PCAP Traffic Analysis and Anomaly Detection

This project aims to provide tools for parsing and analyzing PCAP (Packet Capture) files. The goal is to explore network traffic data, extract useful insights, and detect anomalies using various analysis techniques. The project also includes data visualization and a web dashboard for interactive exploration.

## Table of Contents

- [Project Overview](#project-overview)
- [Environment Setup](#environment-setup)
  - [Install Necessary Libraries](#install-necessary-libraries)
  - [Set Up Virtual Environment](#set-up-virtual-environment)
- [Data Exploration](#data-exploration)
  - [Sample PCAP Files](#sample-pcap-files)
  - [Exploring PCAP Data](#exploring-pcap-data)
- [Features](#features)
  - [Parsing PCAP Files](#parsing-pcap-files)
  - [Exporting Data](#exporting-data)
  - [Anomaly Detection](#anomaly-detection)
  - [Data Visualization](#data-visualization)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Project Overview

This project is designed to analyze network traffic from PCAP files, detect potential anomalies, and visualize the results. It uses several Python libraries like `pyshark`, `scapy`, `pandas`, and `matplotlib` for parsing, analyzing, and visualizing data. The project is divided into multiple phases, from basic data exploration to advanced anomaly detection and visualization.

## Environment Setup

To get started with the project, you need to set up your development environment.

### Install Necessary Libraries

The project depends on several libraries for data parsing, analysis, and visualization. These include:

- `scapy`
- `pyshark`
- `dpkt`
- `matplotlib`
- `seaborn`
- `pandas`
- `flask`
- `streamlit`

You can install these dependencies using the `requirements.txt` file. To generate the `requirements.txt` file, run the following command:

```bash
pip freeze > requirements.txt
```

### Set Up Virtual Environment

To manage dependencies effectively, it is recommended to set up a virtual environment:

1. Create a virtual environment:
   ```bash
   python3 -m venv venv
    ```

2. Activate the virtual environment:
   - On Windows:
     ```bash
     .\venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

3. Install the required libraries:
   ```bash
   pip install -r requirements.txt
   ```

4. Add the following to your `.gitignore` to avoid committing environment files:


## Data Exploration

### Sample PCAP Files

For the initial exploration, sample PCAP files should be placed in the `data/raw/` directory. You can download sample PCAP files from [Wireshark Sample Captures](https://www.wireshark.org/sample-captures/).

### Exploring PCAP Data

The notebooks in `notebooks/exploration.ipynb` provide an interactive way to explore the data. Key observations, such as source and destination IPs, protocols, timestamps, and packet lengths, are noted for further reference.

## Features

### Parsing PCAP Files

The project includes functions for reading and extracting basic information from PCAP files. The parser extracts:

- Timestamp
- Source IP
- Destination IP
- Source and Destination Ports
- Transport Protocol
- Packet Length

The extracted data is stored in a structured format (e.g., CSV or JSON).

### Exporting Data

Parsed data can be exported to CSV or JSON formats using the `csv_export` and `json_export` functions. This allows for easy sharing and further analysis in tools like Excel or Python.

### Anomaly Detection

The project aims to build anomaly detection features to identify unusual patterns in network traffic. This includes:

- Identifying IPs with unusually high traffic.
- Detecting rare or unusual protocols.
- Detecting high packet counts in a short period.

The analysis uses simple heuristics and integrates with external threat intelligence APIs.

### Data Visualization

Matplotlib and Seaborn are used to generate visualizations, such as:

- Traffic volume over time.
- Distribution of protocols or IPs.
- Anomalies and flagged suspicious activity.

## Usage

1. **Parse a PCAP file** and print basic information:
```bash
python main.py -f path/to/your/pcap/file --basic
```

2. **Export data** to CSV or JSON:
```bash
python main.py -f path/to/your/pcap/file --basic --export csv
```
```bash
python main.py -f path/to/your/pcap/file --basic --export json
```

## Contributing

Contributions are welcome! Please feel free to fork the repository, make changes, and submit pull requests. If you encounter any issues, feel free to open an issue in the GitHub repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.