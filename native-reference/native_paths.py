"""Portable input locations for the historical native generators.

No proprietary input is downloaded, copied, installed or executed here.
Relative environment values resolve from native-reference, never the caller cwd.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def configured(name, default):
    value = Path(os.environ.get(name, default)).expanduser()
    return value if value.is_absolute() else ROOT / value

SF2_ORIGINAL = configured('CCF_SF2_ORIGINAL', 'external/sf2/CM Shock Force 2.exe')
COLDWAR_ORIGINAL = configured('CCF_COLDWAR_ORIGINAL', 'external/coldwar/CM Cold War.exe')
NORMANDY_IMAGE = configured('CCF_NORMANDY_IMAGE', 'external/normandy/mapped-image.bin')
INTERMEDIATES = configured('CCF_INTERMEDIATES', 'engine/candidates')

def capstone_path():
    """Normally use the installed capstone package; optional vendor directory."""
    import sys
    if os.environ.get('CCF_PYTHON_LIBS'):
        sys.path.insert(0, str(configured('CCF_PYTHON_LIBS', '.')))
