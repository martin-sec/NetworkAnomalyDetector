import pandas as pd
import logging

def csv_export(data: dict[int, dict[str, str]]) -> None:
    data_frame = pd.DataFrame.from_dict(data, orient='index')
    data_frame.to_csv("./export.csv", index=True)
    logging.info("Exported data")

def json_export(data: dict[int, dict[str, str]]) -> None:
    data_frame = pd.DataFrame.from_dict(data, orient='index')
    data_frame.reset_index(inplace=True)
    data_frame.rename(columns={'index': 'Packet ID'}, inplace=True)
    data_frame.to_json("./export.json", orient='records')
    logging.info("Exported data")

