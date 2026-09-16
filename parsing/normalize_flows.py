"""
normalize_flows.py

Purpose: Read raw_flows from SQLite, clean and normalize it into a new
'flows' table with proper types, handled edge cases (inf/NaN), a
synthetic sequential timestamp, and a simplified label schema.

Uses SEPARATE engines for reading and writing to avoid SQLite
self-locking when streaming reads and writes happen against the
same file at the same time.
"""

import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from pathlib import Path
from datetime import datetime, timedelta

DB_PATH = Path("database/soc_ai_triage.db")
SOURCE_TABLE = "raw_flows"
TARGET_TABLE = "flows"
CHUNK_SIZE = 20_000

SIMULATED_START = datetime(2017, 7, 4, 8, 0, 0)


def clean_chunk(df: pd.DataFrame, row_offset: int) -> pd.DataFrame:
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    df[numeric_cols] = df[numeric_cols].fillna(0)

    # Drop rows with a physically impossible negative Flow Duration
    # (a known CICIDS2017 capture artifact affecting a small number of rows)
    df = df[df["Flow Duration"] >= 0]

    df["Label"] = df["Label"].str.strip()
    df["is_attack"] = (df["Label"] != "BENIGN").astype(int)

    seconds_per_row = (8 * 3600) / 450_000
    df["timestamp"] = [
        SIMULATED_START + timedelta(seconds=(row_offset + i) * seconds_per_row)
        for i in range(len(df))
    ]

    return df


def main():
    # Separate engines: one dedicated to reading, one to writing.
    # This avoids SQLite locking itself when a streamed read and a
    # write happen close together against the same file.
    read_engine = create_engine(
        f"sqlite:///{DB_PATH}", connect_args={"timeout": 30}
    )
    write_engine = create_engine(
        f"sqlite:///{DB_PATH}", connect_args={"timeout": 30}
    )

    print(f"Reading '{SOURCE_TABLE}' in chunks and writing to '{TARGET_TABLE}' ...")

    total_rows = 0
    first_chunk = True

    # Read ALL chunks into memory first as a list of small DataFrames,
    # closing the read connection fully before any writing starts.
    chunks = []
    with read_engine.connect() as read_conn:
        for chunk in pd.read_sql(
            f"SELECT * FROM {SOURCE_TABLE}", read_conn, chunksize=CHUNK_SIZE
        ):
            chunks.append(chunk)
    # read_engine connection is now fully closed here

    print(f"  Read {len(chunks)} chunks into memory. Now writing...")

    for chunk_num, chunk in enumerate(chunks, start=1):
        chunk = clean_chunk(chunk, row_offset=total_rows)

        write_mode = "replace" if first_chunk else "append"
        chunk.to_sql(TARGET_TABLE, write_engine, if_exists=write_mode, index=False)

        total_rows += len(chunk)
        first_chunk = False
        print(f"  Chunk {chunk_num}: wrote {len(chunk):,} rows "
              f"(total so far: {total_rows:,})")

    print(f"Done. Normalized {total_rows:,} rows into '{TARGET_TABLE}'.")


if __name__ == "__main__":
    main()
