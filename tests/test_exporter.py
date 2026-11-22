import unittest
from pathlib import Path
from sigmaforge.exporter import export_sentinelops

class ExporterTests(unittest.TestCase):
    def test_rules_export(self):
        docs=Path(__file__).parents[1]/"rules"
        exported=export_sentinelops(docs)
        self.assertEqual(len(exported),6)
        self.assertTrue(all(item["conditions"] for item in exported))

if __name__=="__main__": unittest.main()
