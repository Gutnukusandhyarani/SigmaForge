"""Parser for a bounded Sigma-like condition expression language."""
from __future__ import annotations
import re

TOKEN_RE=re.compile(r"\s*(\(|\)|\bAND\b|\bOR\b|\bNOT\b|\d+\s+of\s+[\w*?-]+|all\s+of\s+[\w*?-]+|them|[\w*?-]+)\s*",re.I)

def tokenize(expression: str) -> list[str]:
    tokens=[]; pos=0
    while pos<len(expression):
        match=TOKEN_RE.match(expression,pos)
        if not match:
            raise ValueError(f"unsupported condition syntax near: {expression[pos:pos+24]!r}")
        tokens.append(match.group(1))
        pos=match.end()
    return tokens

class Parser:
    def __init__(self,tokens): self.tokens=tokens; self.i=0
    def peek(self): return self.tokens[self.i] if self.i<len(self.tokens) else None
    def take(self):
        token=self.peek()
        if token is None: raise ValueError("unexpected end of condition")
        self.i+=1; return token
    def parse(self):
        result=self.parse_or()
        if self.peek() is not None: raise ValueError(f"unexpected token {self.peek()!r}")
        return result
    def parse_or(self):
        node=self.parse_and()
        while self.peek() and self.peek().upper()=="OR":
            self.take(); node=("or",node,self.parse_and())
        return node
    def parse_and(self):
        node=self.parse_not()
        while self.peek() and self.peek().upper()=="AND":
            self.take(); node=("and",node,self.parse_not())
        return node
    def parse_not(self):
        if self.peek() and self.peek().upper()=="NOT":
            self.take(); return ("not",self.parse_not())
        return self.parse_primary()
    def parse_primary(self):
        token=self.take()
        if token=="(":
            node=self.parse_or()
            if self.take()!=")": raise ValueError("missing closing parenthesis")
            return node
        upper=token.upper()
        if upper in ("AND","OR",")"): raise ValueError(f"unexpected operator {token!r}")
        match=re.fullmatch(r"(\d+|all)\s+of\s+([\w*?-]+)",token,re.I)
        if match:
            raw=match.group(1).lower(); pattern=match.group(2)
            return ("of",raw,pattern)
        return ("selector",token)

def parse_condition(expression: str):
    return Parser(tokenize(expression)).parse()

def referenced_selectors(tree):
    op=tree[0]
    if op=="selector": return {tree[1]}
    if op=="of": return set()
    if op=="not": return referenced_selectors(tree[1])
    return referenced_selectors(tree[1])|referenced_selectors(tree[2])

def select_names(tree, names):
    """Expand wildcard `of` clauses and validate that they resolve at least one selector."""
    op=tree[0]
    if op=="of":
        pattern=tree[2]
        matches=sorted(names) if pattern.lower()=="them" else sorted(n for n in names if __import__("fnmatch").fnmatch(n,pattern))
        if not matches: raise ValueError(f"selector pattern {pattern!r} did not match any selector")
        return ("of_expanded",tree[1],matches)
    if op=="selector":
        if tree[1] not in names: raise ValueError(f"undefined selector {tree[1]!r}")
        return tree
    if op=="not": return ("not",select_names(tree[1],names))
    return (op,select_names(tree[1],names),select_names(tree[2],names))
