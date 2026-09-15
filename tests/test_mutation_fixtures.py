"""The mutation fixtures in <ir>/test must match what the generator produces.

They are checked into the IR repo and referenced by expect tests there, so a
change to mutate.py or to the translator that silently changes them would
leave those tests asserting a verdict about a program nobody generated.
"""

import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


class TestFixturesCurrent(unittest.TestCase):
    def test_fixtures_are_up_to_date(self):
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "make_mutation_fixtures.py"),
             "--check"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0,
                         "mutation fixtures are stale; regenerate with\n"
                         "  .venv/bin/python tests/make_mutation_fixtures.py\n"
                         + r.stdout + r.stderr)
