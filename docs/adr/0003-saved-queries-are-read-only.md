# Saved queries are read-only, with no write mode

ToolHarness's SQL Workbench had a write toggle behind a typed confirmation. Stackwell drops it: Saved queries run in a read-only database session and anything other than a single `SELECT` is refused. A support rep's diagnostic tool should never be able to change production data; ad-hoc writes belong in a real database client.
