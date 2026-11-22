import unittest
from sigmaforge.condition import parse_condition,referenced_selectors,select_names

class ConditionTests(unittest.TestCase):
    def test_precedence(self):
        tree=parse_condition("selection_a or selection_b and not filter")
        self.assertEqual(tree[0],"or")
        self.assertEqual(tree[2][0],"and")

    def test_parentheses(self):
        tree=parse_condition("(a or b) and c")
        self.assertEqual(tree[0],"and")
        self.assertEqual(tree[1][0],"or")

    def test_of_expansion(self):
        tree=select_names(parse_condition("1 of selection_*"),{"selection_a","selection_b","filter"})
        self.assertEqual(tree[0],"of_expanded")
        self.assertEqual(len(tree[2]),2)

    def test_them_expands_all_selectors(self):
        tree=select_names(parse_condition("1 of them"),{"selection_a","filter"})
        self.assertEqual(set(tree[2]),{"selection_a","filter"})

    def test_missing_selector_is_rejected(self):
        with self.assertRaises(ValueError):
            select_names(parse_condition("missing"),{"selection"})

if __name__=="__main__": unittest.main()
