import sqlite3
import json
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("database")
parser.add_argument("--user-id", type=int, required=True)
parser.add_argument(
    "--output",
    default="osint-evaluation.json"
)
args = parser.parse_args()

db_path = Path(args.database).expanduser().resolve()

if not db_path.is_file():
    raise SystemExit("Database file not found.")

conn = sqlite3.connect(
    db_path.as_uri() + "?mode=ro",
    uri=True
)

conn.row_factory = sqlite3.Row

try:
    rows = conn.execute("""
        SELECT
            source_name,
            verification_status,
            user_verified
        FROM findings
        WHERE user_id = ?
        ORDER BY id
    """, (args.user_id,)).fetchall()
finally:
    conn.close()

dataset = []

for row in rows:
    status = row["verification_status"]

    if status == "Verified Match" and row["user_verified"]:
        verdict = "relevant"
    elif status == "False Positive":
        verdict = "irrelevant"
    else:
        verdict = "uncertain"

    dataset.append({
        "provider": row["source_name"] or "Unknown",
        "verdict": verdict
    })

output = Path(args.output)

output.write_text(
    json.dumps(dataset, indent=2),
    encoding="utf-8"
)

print("Evaluation dataset exported.")
print("Total findings:", len(dataset))
print("Output:", output.resolve())
