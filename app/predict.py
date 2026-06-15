import pandas as pd
import numpy as np


def clean_data(df):

    df.columns = df.columns.str.strip()

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    df.dropna(inplace=True)

    return df