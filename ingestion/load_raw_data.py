"""
load_raw_data.py

Purpose: Load the raw CICIDS2017 CSV into a SQLite database,
with minimal transformation (just column name cleanup).
Uses chunked reading/writing to avoid high memory usage on
memory-constrained systems (e.g., VMs with limited RAM).
"""

import pandas as pd
from sqlalchemy import create_engine
from pathlib import Path

# --- Configuration ---
RAW_CSV_PATH = Path("data/raw/Tuesday-WorkingHours.pcap_ISCX.csv")
DB_PATH = Path("database/soc_ai_triage.db")
TABLE_NAME = "raw_flows"
CHUNK_SIZE = 20_000  # rows processed at a time


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names (CICIDS2017 has leading spaces)."""
    df.columns = [col.strip() for col in df.columns]
    return df


def main():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{DB_PATH}")

    print(f"Reading and loading CSV in chunks of {CHUNK_SIZE:,} rows ...")

    total_rows = 0
    first_chunk = True

    for chunk_num, chunk in enumerate(
        pd.read_csv(RAW_CSV_PATH, chunksize=CHUNK_SIZE), start=1
    ):
        chunk = clean_column_names(chunk)

        # First chunk replaces any existing table; later chunks append to it
        write_mode = "replace" if first_chunk else "append"
        chunk.to_sql(TABLE_NAME, engine, if_exists=write_mode, index=False)

        total_rows += len(chunk)
        first_chunk = False
        print(f"  Chunk {chunk_num}: wrote {len(chunk):,} rows "
              f"(total so far: {total_rows:,})")

    print(f"Done. Loaded {total_rows:,} total rows into '{TABLE_NAME}'.")


if __name__ == "__main__":
    main()
