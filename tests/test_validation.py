import unittest
from pathlib import Path
from sigmaforge.parser import validate_paths

class ValidationTests(unittest.TestCase):
    def test_repository_rules_valid(self):
        rules=Path(__file__).parents[1]/"rules"
        docs=validate_paths(rules)
        self.assertGreaterEqual(len(docs),5)
        self.assertTrue(all(not d.errors for d in docs),[(str(d.path),d.errors) for d in docs if d.errors])

if __name__=="__main__": unittest.main()
