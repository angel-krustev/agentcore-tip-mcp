"""Test bootstrap.

Local Cython builds leave ``*.pyd`` / ``*.so`` files next to the sources, and the
import system prefers those over ``.py``. Tests must exercise the sources, so
paths inside the ``agentcore_tip`` package are resolved from ``.py`` files only.
Third-party extension modules elsewhere on ``sys.path`` are not affected.
"""

import importlib.machinery
import os
import sys

_PACKAGE_DIR = os.path.normcase(
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agentcore_tip")
)


def _source_only_hook(path: str):
    normalized = os.path.normcase(os.path.abspath(path))
    if normalized != _PACKAGE_DIR and not normalized.startswith(_PACKAGE_DIR + os.sep):
        raise ImportError
    loader = (importlib.machinery.SourceFileLoader, importlib.machinery.SOURCE_SUFFIXES)
    return importlib.machinery.FileFinder(path, loader)


sys.path_hooks.insert(0, _source_only_hook)
sys.path_importer_cache.clear()
for _name in [m for m in sys.modules if m == "agentcore_tip" or m.startswith("agentcore_tip.")]:
    del sys.modules[_name]
