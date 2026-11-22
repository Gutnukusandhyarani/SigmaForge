import unittest
from pathlib import Path
from sigmaforge.parser import load_rule
from sigmaforge.matcher import match_rule

class MatcherTests(unittest.TestCase):
    def test_exact_match(self):
        path=Path(__file__).parents[1]/"rules"/"windows"/"account_created.yml"
        rule=load_rule(path).data
        event={"event_id":"4720","action":"account_created"}
        self.assertTrue(match_rule(rule,event))
        self.assertFalse(match_rule(rule,{"event_id":"4624","action":"login_success"}))

    def test_list_alternative(self):
        path=Path(__file__).parents[1]/"rules"/"windows"/"service_installed.yml"
        rule=load_rule(path).data
        self.assertTrue(match_rule(rule,{"event_id":"4697","action":"service_installed"}))

if __name__=="__main__": unittest.main()
