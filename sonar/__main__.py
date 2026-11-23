"""``python -m sonar``: the same as the ``sonar`` command."""

import sys

from sonar.cli import main

sys.exit(main())
