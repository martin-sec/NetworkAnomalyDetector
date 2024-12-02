import pandas as pd
import logging

def csv_export(data: dict):
    data_frame = pd.DataFrame.from_dict(data, orient='index')
    date_frame = data_frame.T
    data_frame.to_csv("data/raw/export.csv", index=True)
    logging.info("Exported data")