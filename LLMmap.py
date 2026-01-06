import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from cli.main import app

if __name__ == "__main__":
    app()