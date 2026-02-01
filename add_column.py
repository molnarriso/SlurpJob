#!/usr/bin/env python3
import sqlite3
conn = sqlite3.connect('/opt/slurpjob/slurp.db')
try:
    conn.execute("ALTER TABLE IncidentLog ADD COLUMN ClassifierId TEXT DEFAULT 'unknown'")
    conn.commit()
    print("Column added successfully")
except Exception as e:
    print(f"Note: {e}")
conn.close()
