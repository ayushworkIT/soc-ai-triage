"""
normalize_flows.py

Purpose: Read raw_flows from SQLite, clean and normalize it into a new
'flows' table with proper types, handled edge cases (inf/NaN), a
synthetic sequential timestamp, a simplified label schema, and
simulated source IPs (this dataset variant does not include real IPs).

Uses SEPARATE engines for reading and writing to avoid SQLite
self-locking when streaming reads and writes happen against the
same file at the same time.
"""

import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from pathlib import Path
from datetime import datetime, timedelta
import random

DB_PATH = Path("database/soc_ai_triage.db")
SOURCE_TABLE = "raw_flows"
TARGET_TABLE = "flows"
CHUNK_SIZE = 20_000

SIMULATED_START = datetime(2017, 7, 4, 8, 0, 0)

# --- Simulated source IPs ---
# This CICIDS2017 file variant (MachineLearningCVE) does not include
# real Source IP addresses. We simulate them so correlation logic
# (Phase 4) has a realistic entity to group by: a small pool of
# "attacker" IPs per attack type (few sources, many attempts - a
# realistic brute-force pattern), and a larger pool of "normal" IPs
# for benign traffic. This is a documented limitation/simulation,
# not real captured data.
ATTACKER_IP_POOLS = {
    "FTP-Patator": ["10.0.0.50", "10.0.0.51", "10.0.0.52"],
    "SSH-Patator": ["10.0.0.60", "10.0.0.61", "10.0.0.62"],
}
BENIGN_IP_POOL = [f"192.168.1.{i}" for i in range(10, 60)]  # 50 IPs

random.seed(42)  # reproducible assignment across re-runs


def assign_source_ip(row):
    """Pick a source IP from the appropriate pool based on the row's label."""
    if row["is_attack"] == 1:
        pool = ATTACKER_IP_POOLS.get(row["Label"], ["10.0.0.99"])
    else:
        pool = BENIGN_IP_POOL
    return random.choice(pool)


def clean_chunk(df: pd.DataFrame, row_offset: int) -> pd.DataFrame:
    """Clean one chunk: handle inf/NaN, filter bad rows, add timestamp,
    simplify label, and assign a simulated source IP."""

    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    df[numeric_cols] = df[numeric_cols].fillna(0)

    # Drop rows with a physically impossible negative Flow Duration
    # (a known CICIDS2017 capture artifact affecting a small number of rows)
    df = df[df["Flow Duration"] >= 0]

    df["Label"] = df["Label"].str.strip()
    df["is_attack"] = (df["Label"] != "BENIGN").astype(int)

    # Simulated source IP (see note above - no real IPs in this file variant)
    df["source_ip"] = df.apply(assign_source_ip, axis=1)

    seconds_per_row = (8 * 3600) / 450_000
    df["timestamp"] = [
        SIMULATED_START + timedelta(seconds=(row_offset + i) * seconds_per_row)
        for i in range(len(df))
    ]

    return df


def main():
    read_engine = create_engine(
        f"sqlite:///{DB_PATH}", connect_args={"timeout": 30}
    )
    write_engine = create_engine(
        f"sqlite:///{DB_PATH}", connect_args={"timeout": 30}
    )

    print(f"Reading '{SOURCE_TABLE}' in chunks and writing to '{TARGET_TABLE}' ...")

    total_rows = 0
    first_chunk = True

    chunks = []
    with read_engine.connect() as read_conn:
        for chunk in pd.read_sql(
            f"SELECT * FROM {SOURCE_TABLE}", read_conn, chunksize=CHUNK_SIZE
        ):
            chunks.append(chunk)

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
