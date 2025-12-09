from pathlib import Path

QUERIES: dict[str, str] = {}

_sql_folder = Path(__file__).parent
for _file in _sql_folder.glob("*.sql"):
    QUERIES[_file.stem] = _file.read_text()
