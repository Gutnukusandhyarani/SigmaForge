import unittest
from pathlib import Path
from sigmaforge.parser import load_rule
from sigmaforge.compiler import compile_rule

class CompilerTests(unittest.TestCase):
    def test_splunk(self):
        path=Path(__file__).parents[1]/"rules"/"windows"/"account_created.yml"
        doc=load_rule(path)
        query=compile_rule(doc,"splunk")
        self.assertIn("EventCode",query)
        self.assertIn("4720",query)

    def test_sentinel(self):
        path=Path(__file__).parents[1]/"rules"/"windows"/"audit_log_cleared.yml"
        doc=load_rule(path)
        query=compile_rule(doc,"sentinel")
        self.assertIn("SecurityEvent",query)
        self.assertIn("EventID",query)

if __name__=="__main__": unittest.main()
