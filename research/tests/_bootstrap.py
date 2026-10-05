"""Makes research/ importable when tests run via `python -m unittest discover -s tests`."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
