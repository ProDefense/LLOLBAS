"""The LOLBAS library."""
# We disable a Flake8 check for "Module imported but unused (F401)" here because
# although this import is not directly used, it populates the value
# package_name.__version__, which is used to get version information about this
# Python package.
from ._version import __version__  # noqa: F401
from .core import Analyzer, functions, refs
from .digestlol import main, parse_n_serve

__all__ = ["main", "parse_n_serve", "Analyzer", "refs", "functions"]
