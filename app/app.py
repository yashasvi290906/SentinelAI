import streamlit as st
import pandas as pd

from predict import clean_data
from model_loader import model, encoder

st.title("🛡 SentinelAI")

st.subheader(
    "AI-Powered Intrusion Detection System"
)

uploaded_file = st.file_uploader(
    "Upload Network Flow CSV",
    type=["csv"]
)

if uploaded_file:

    df = pd.read_csv(
        uploaded_file,
        low_memory=False
    )

    st.success(
        "File uploaded successfully!"
    )

    st.write(
        f"Original Rows: {len(df)}"
    )

    df = clean_data(df)

    st.write(
        f"Rows After Cleaning: {len(df)}"
    )

    X = df.drop(
        columns=["Label"],
        errors="ignore"
    )

    predictions = model.predict(X)

    labels = encoder.inverse_transform(
        predictions.astype(int)
    )

    result_df = pd.DataFrame({
        "Prediction": labels
    })

    st.subheader(
        "Prediction Summary"
    )

    st.dataframe(
        result_df["Prediction"]
        .value_counts()
        .reset_index()
    )