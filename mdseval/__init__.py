"""Source-checkout import shim; installed packages use ``src/mdseval`` directly."""

from pathlib import Path

__path__ = [str(Path(__file__).resolve().parents[1] / "src" / "mdseval")]
__version__ = "0.1.0"
