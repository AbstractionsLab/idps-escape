"""
Where SONAR keeps its files, independent of the working directory.

- A relative path in a configuration or scenario file is relative to **that file**.
- Unset paths default to the SONAR home: ``$SONAR_HOME`` if set; otherwise the ``sonar/``
  directory of a source checkout (so ``sonar/models`` in this repository, and in the Docker
  image built from it); otherwise ``~/.sonar`` for an installed package.
- Models live in ``<models_dir>/<model_name>/``; delivery state in ``<models_dir>/state/``
  unless ``output.state_dir`` says otherwise.
- Example scenarios and the debug datasets ship inside the package (``packaged()``).

Paths given on the command line keep their usual meaning (relative to the shell's directory).
"""

import os
import re
from pathlib import Path
from typing import Optional, Union

SONAR_HOME_ENV = "SONAR_HOME"
PACKAGE_DIR = Path(__file__).resolve().parent
MODELS_SUBDIR = "models"
STATE_SUBDIR = "state"
DEFAULT_MODEL_NAME = "sonar"


def is_source_checkout() -> bool:
    """True when SONAR runs from a checkout of its repository rather than an installed wheel."""
    return (PACKAGE_DIR.parent / "pyproject.toml").is_file()


def sonar_home() -> Path:
    """``$SONAR_HOME``, else the package directory of a source checkout, else ``~/.sonar``."""
    env = os.environ.get(SONAR_HOME_ENV)
    if env:
        return Path(env).expanduser().resolve()
    if is_source_checkout():
        return PACKAGE_DIR
    return Path.home() / ".sonar"


def default_models_dir() -> Path:
    return sonar_home() / MODELS_SUBDIR


def packaged(*parts: str) -> Path:
    """A file shipped inside the package (example scenarios, debug datasets, Wazuh rules)."""
    return PACKAGE_DIR.joinpath(*parts)


def resolve(value: Union[str, os.PathLike], base: Union[str, os.PathLike]) -> str:
    """``value`` with ``~`` expanded, made absolute against ``base`` (a directory) if relative."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path(base) / path
    return str(path.resolve())


def file_dir(path: Union[str, os.PathLike]) -> Path:
    """Directory of a configuration or scenario file: the base of the relative paths it contains."""
    return Path(path).expanduser().resolve().parent


def slug(name: str) -> str:
    """A name usable in file names and index names: lower case, ``[a-z0-9_-]`` only."""
    text = re.sub(r"[^a-z0-9_-]+", "_", str(name).strip().lower()).strip("_-")
    return text or DEFAULT_MODEL_NAME


def model_dir(models_dir: Optional[str], model_name: str) -> Path:
    """Directory of a model: ``<models_dir>/<model_name>``."""
    return Path(models_dir or default_models_dir()) / model_name


def packaged_scenario(name: str) -> Optional[Path]:
    """The packaged example scenario ``name`` (with or without ``.yaml``), or None."""
    candidate = packaged("scenarios", name if name.endswith((".yaml", ".yml")) else f"{name}.yaml")
    return candidate if candidate.is_file() else None
