"""Pytest configuration — adds project root to sys.path for imports."""
import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
