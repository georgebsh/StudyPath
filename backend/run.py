
import os
import re
from pathlib import Path

import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_env_file(path: Path) -> list[str]:
    """Read KEY=value lines into the environment. Returns the names that were set."""
    if not path.exists():
        return []
    loaded = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]  # KEY="value" or KEY='value'
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and value and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


if __name__ == "__main__":
    names = load_env_file(PROJECT_ROOT / ".env")
    if names:
        print("Loaded from .env:", ", ".join(names))  # names only, never the values
    uvicorn.run("app.main:app", app_dir=str(Path(__file__).resolve().parent),
                host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")),
                reload=os.environ.get("RELOAD") == "1")
