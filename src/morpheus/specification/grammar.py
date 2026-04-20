"""
Specification Grammar
=====================

This module defines the grammar for Morpheus's specification language
and provides parsing utilities.

Grammar:
    specification ::= property | invariant | requires | ensures | axiom
    
    property      ::= 'property' IDENTIFIER ':' expression
    invariant     ::= 'invariant' IDENTIFIER (scope)? ':' expression
    requires      ::= 'requires' IDENTIFIER ':' expression
    ensures       ::= 'ensures' IDENTIFIER ':' expression
    axiom         ::= 'axiom' IDENTIFIER ':' expression
    
    scope         ::= '[' ('global' | 'function' | 'loop') ']'
    
    expression     ::= or_expr
    
    or_expr       ::= and_expr ('or' and_expr)*
    and_expr      ::= not_expr ('and' not_expr)*
    not_expr      ::= 'not' not_expr | comparison
    comparison    ::= sum_expr (('==' | '!=' | '<' | '>' | '<=' | '>=') sum_expr)*
    sum_expr      ::= product_expr (('+' | '-') product_expr)*
    product_expr  ::= unary_expr (('*' | '/' | '%') unary_expr)*
    unary_expr    ::= ('-' | '+') unary_expr | postfix_expr
    postfix_expr  ::= primary ('[' expression ']' | '.' IDENTIFIER | '(' args? ')')*
    primary       ::= IDENTIFIER | NUMBER | STRING | '(' expression ')' | 'old' '(' expression ')'
    
    args          ::= expression (',' expression)*

Author: Morpheus Team
"""

from __future__ import annotations
from typing import List, Optional, Dict, Any, Tuple, Union
from dataclasses import dataclass
import re
import z3
import logging

logger = logging.getLogger(__name__)


class TokenType:
    """Token types for specification grammar."""
    IDENTIFIER = "IDENTIFIER"
    NUMBER = "NUMBER"
    STRING = "STRING"
    PLUS = "PLUS"
    MINUS = "MINUS"
    STAR = "STAR"
    SLASH = "SLASH"
    PERCENT = "PERCENT"
    EQUAL = "EQUAL"
    EQUAL_EQUAL = "EQUAL_EQUAL"
    NOT_EQUAL = "NOT_EQUAL"
    LESS = "LESS"
    LESS_EQUAL = "LESS_EQUAL"
    GREATER = "GREATER"
    GREATER_EQUAL = "GREATER_EQUAL"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    LBRACKET = "LBRACKET"
    RBRACKET = "RBRACKET"
    COMMA = "COMMA"
    DOT = "DOT"
    COLON = "COLON"
    KEYWORD = "KEYWORD"
    EOF = "EOF"


class Token:
    """Token in specification grammar."""
    
    KEYWORDS = {
        'property', 'invariant', 'requires', 'ensures', 'axiom',
        'global', 'function', 'loop',
        'and', 'or', 'not',
        'old', 'sum', 'product', 'forall', 'exists',
        'true', 'false', 'implies', 'iff'
    }
    
    def __init__(self, token_type: str, value: str, line: int = 0, column: int = 0):
        self.token_type = token_type
        self.value = value
        self.line = line
        self.column = column


class Lexer:
    """Lexer for specification grammar."""
    
    def __init__(self, source: str):
        self.source = source
        self.position = 0
        self.line = 1
        self.column = 1
        self.tokens: List[Token] = []
    
    def current_char(self) -> Optional[str]:
        if self.position < len(self.source):
            return self.source[self.position]
        return None
    
    def advance(self) -> Optional[str]:
        char = self.current_char()
        if char:
            self.position += 1
            if char == '\n':
                self.line += 1
                self.column = 1
            else:
                self.column += 1
        return char
    
    def skip_whitespace(self) -> None:
        while self.current_char() and self.current_char() in ' \t\r':
            self.advance()
    
    def tokenize(self) -> List[Token]:
        while self.position < len(self.source):
            self.skip_whitespace()
            
            if not self.current_char():
                break
            
            char = self.current_char()
            start_line = self.line
            start_col = self.column
            
            # Two-character operators
            two_char = char + (self.source[self.position + 1] if self.position + 1 < len(self.source) else '')
            if two_char in ('==', '!=', '<=', '>=', '=>'):
                self.advance()
                self.advance()
                self.tokens.append(Token(two_char, two_char, start_line, start_col))
            
            # Single character operators
            elif char in '+-*/%<>=!()[]{},.:':
                self.advance()
                self.tokens.append(Token(char, char, start_line, start_col))
            
            # Identifiers and keywords
            elif char.isalpha() or char == '_':
                result = ''
                while self.current_char() and (self.current_char().isalnum() or self.current_char() == '_'):
                    result += self.advance()
                
                if result.lower() in Token.KEYWORDS:
                    self.tokens.append(Token('KEYWORD', result.lower(), start_line, start_col))
                else:
                    self.tokens.append(Token('IDENTIFIER', result, start_line, start_col))
            
            # Numbers
            elif char.isdigit():
                result = ''
                while self.current_char() and (self.current_char().isdigit() or self.current_char() == 'x'):
                    result += self.advance()
                self.tokens.append(Token('NUMBER', result, start_line, start_col))
            
            # String literals
            elif char == '"':
                self.advance()
                result = ''
                while self.current_char() and self.current_char() != '"':
                    result += self.advance()
                if self.current_char() == '"':
                    self.advance()
                self.tokens.append(Token('STRING', result, start_line, start_col))
            
            # Comments
            elif char == '#':
                while self.current_char() and self.current_char() != '\n':
                    self.advance()
            
            else:
                logger.warning(f"Unknown character: {char}")
                self.advance()
        
        self.tokens.append(Token('EOF', '', self.line, self.column))
        return self.tokens


@dataclass
class ASTNode:
    """Base AST node for specification grammar."""
    pass


@dataclass
class PropertyNode(ASTNode):
    """Property specification node."""
    name: str
    expression: ASTNode


@dataclass
class InvariantNode(ASTNode):
    """Invariant specification node."""
    name: str
    scope: str
    expression: ASTNode


@dataclass
class RequiresNode(ASTNode):
    """Precondition specification node."""
    function: str
    expression: ASTNode


@dataclass
class EnsuresNode(ASTNode):
    """Postcondition specification node."""
    function: str
    expression: ASTNode


@dataclass
class AxiomNode(ASTNode):
    """Axiom specification node."""
    name: str
    expression: ASTNode


@dataclass
class BinaryOpNode(ASTNode):
    """Binary operation node."""
    operator: str
    left: ASTNode
    right: ASTNode


@dataclass
class UnaryOpNode(ASTNode):
    """Unary operation node."""
    operator: str
    operand: ASTNode


@dataclass
class IdentifierNode(ASTNode):
    """Identifier node."""
    name: str


@dataclass
class NumberNode(ASTNode):
    """Number literal node."""
    value: int


@dataclass
class StringNode(ASTNode):
    """String literal node."""
    value: str


@dataclass
class FunctionCallNode(ASTNode):
    """Function call node."""
    name: str
    arguments: List[ASTNode]


@dataclass
class IndexAccessNode(ASTNode):
    """Index access node."""
    base: ASTNode
    index: ASTNode


@dataclass
class MemberAccessNode(ASTNode):
    """Member access node."""
    base: ASTNode
    member: str


@dataclass
class OldNode(ASTNode):
    """Old value node."""
    expression: ASTNode


class Parser:
    """Parser for specification grammar."""
    
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.position = 0
    
    def current(self) -> Token:
        if self.position < len(self.tokens):
            return self.tokens[self.position]
        return Token('EOF', '')
    
    def advance(self) -> Token:
        token = self.current()
        self.position += 1
        return token
    
    def match(self, token_type: str) -> bool:
        return self.current().token_type == token_type
    
    def consume(self, token_type: str) -> Optional[Token]:
        if self.match(token_type):
            return self.advance()
        return None
    
    def parse(self) -> List[ASTNode]:
        """Parse specifications."""
        specs = []
        
        while not self.match('EOF'):
            if self.match('KEYWORD'):
                keyword = self.current().value
                
                if keyword == 'property':
                    specs.append(self.parse_property())
                elif keyword == 'invariant':
                    specs.append(self.parse_invariant())
                elif keyword == 'requires':
                    specs.append(self.parse_requires())
                elif keyword == 'ensures':
                    specs.append(self.parse_ensures())
                elif keyword == 'axiom':
                    specs.append(self.parse_axiom())
                else:
                    self.advance()  # Skip unknown keyword
            else:
                self.advance()  # Skip unknown token
        
        return specs
    
    def parse_property(self) -> PropertyNode:
        """Parse property specification."""
        self.advance()  # 'property'
        name = self.advance().value  # identifier
        self.consume(':')
        expr = self.parse_expression()
        return PropertyNode(name, expr)
    
    def parse_invariant(self) -> InvariantNode:
        """Parse invariant specification."""
        self.advance()  # 'invariant'
        name = self.advance().value  # identifier
        
        # Parse optional scope
        scope = 'global'
        if self.consume('['):
            scope_token = self.advance()
            scope = scope_token.value
            self.consume(']')
        
        self.consume(':')
        expr = self.parse_expression()
        return InvariantNode(name, scope, expr)
    
    def parse_requires(self) -> RequiresNode:
        """Parse requires specification."""
        self.advance()  # 'requires'
        function = self.advance().value  # identifier
        self.consume(':')
        expr = self.parse_expression()
        return RequiresNode(function, expr)
    
    def parse_ensures(self) -> EnsuresNode:
        """Parse ensures specification."""
        self.advance()  # 'ensures'
        function = self.advance().value  # identifier
        self.consume(':')
        expr = self.parse_expression()
        return EnsuresNode(function, expr)
    
    def parse_axiom(self) -> AxiomNode:
        """Parse axiom specification."""
        self.advance()  # 'axiom'
        name = self.advance().value  # identifier
        self.consume(':')
        expr = self.parse_expression()
        return AxiomNode(name, expr)
    
    def parse_expression(self) -> ASTNode:
        """Parse expression (or -> and -> not -> comparison)."""
        return self.parse_or()
    
    def parse_or(self) -> ASTNode:
        """Parse logical OR."""
        left = self.parse_and()
        
        while self.match('KEYWORD') and self.current().value == 'or':
            self.advance()
            right = self.parse_and()
            left = BinaryOpNode('or', left, right)
        
        return left
    
    def parse_and(self) -> ASTNode:
        """Parse logical AND."""
        left = self.parse_not()
        
        while self.match('KEYWORD') and self.current().value == 'and':
            self.advance()
            right = self.parse_not()
            left = BinaryOpNode('and', left, right)
        
        return left
    
    def parse_not(self) -> ASTNode:
        """Parse logical NOT."""
        if self.match('KEYWORD') and self.current().value == 'not':
            self.advance()
            operand = self.parse_not()
            return UnaryOpNode('not', operand)
        
        return self.parse_comparison()
    
    def parse_comparison(self) -> ASTNode:
        """Parse comparison operators."""
        left = self.parse_sum()
        
        while True:
            op = None
            if self.match('EQUAL_EQUAL'):
                op = '=='
            elif self.match('NOT_EQUAL'):
                op = '!='
            elif self.match('LESS'):
                op = '<'
            elif self.match('LESS_EQUAL'):
                op = '<='
            elif self.match('GREATER'):
                op = '>'
            elif self.match('GREATER_EQUAL'):
                op = '>='
            
            if op:
                self.advance()
                right = self.parse_sum()
                left = BinaryOpNode(op, left, right)
            else:
                break
        
        return left
    
    def parse_sum(self) -> ASTNode:
        """Parse addition/subtraction."""
        left = self.parse_product()
        
        while True:
            op = None
            if self.match('PLUS'):
                op = '+'
            elif self.match('MINUS'):
                op = '-'
            
            if op:
                self.advance()
                right = self.parse_product()
                left = BinaryOpNode(op, left, right)
            else:
                break
        
        return left
    
    def parse_product(self) -> ASTNode:
        """Parse multiplication/division."""
        left = self.parse_unary()
        
        while True:
            op = None
            if self.match('STAR'):
                op = '*'
            elif self.match('SLASH'):
                op = '/'
            elif self.match('PERCENT'):
                op = '%'
            
            if op:
                self.advance()
                right = self.parse_unary()
                left = BinaryOpNode(op, left, right)
            else:
                break
        
        return left
    
    def parse_unary(self) -> ASTNode:
        """Parse unary operators."""
        if self.match('MINUS'):
            self.advance()
            operand = self.parse_unary()
            return UnaryOpNode('-', operand)
        elif self.match('PLUS'):
            self.advance()
            return self.parse_unary()
        
        return self.parse_postfix()
    
    def parse_postfix(self) -> ASTNode:
        """Parse postfix operations."""
        node = self.parse_primary()
        
        while True:
            if self.match('['):
                self.advance()
                index = self.parse_expression()
                self.consume(']')
                node = IndexAccessNode(node, index)
            elif self.match('.'):
                self.advance()
                member = self.advance().value
                node = MemberAccessNode(node, member)
            elif self.match('('):
                args = self.parse_function_args()
                node = FunctionCallNode(node.name if isinstance(node, IdentifierNode) else 'func', args)
            else:
                break
        
        return node
    
    def parse_primary(self) -> ASTNode:
        """Parse primary expressions."""
        if self.match('IDENTIFIER'):
            name = self.advance().value
            if self.match('('):
                args = self.parse_function_args()
                return FunctionCallNode(name, args)
            return IdentifierNode(name)
        
        if self.match('NUMBER'):
            value = self.advance().value
            try:
                if value.startswith('0x'):
                    return NumberNode(int(value, 16))
                return NumberNode(int(value))
            except ValueError:
                return NumberNode(0)
        
        if self.match('STRING'):
            return StringNode(self.advance().value)
        
        if self.match('KEYWORD') and self.current().value == 'old':
            self.advance()
            self.consume('(')
            expr = self.parse_expression()
            self.consume(')')
            return OldNode(expr)
        
        if self.match('KEYWORD') and self.current().value == 'true':
            self.advance()
            return IdentifierNode('true')
        
        if self.match('KEYWORD') and self.current().value == 'false':
            self.advance()
            return IdentifierNode('false')
        
        if self.match('LPAREN'):
            self.advance()
            expr = self.parse_expression()
            self.consume(')')
            return expr
        
        # Default: return identifier
        return IdentifierNode('unknown')
    
    def parse_function_args(self) -> List[ASTNode]:
        """Parse function arguments."""
        self.advance()  # (
        args = []
        
        if not self.match(')'):
            args.append(self.parse_expression())
            while self.consume(','):
                args.append(self.parse_expression())
        
        self.consume(')')
        return args


class Z3Translator:
    """Translate specification AST to Z3 formulas."""
    
    def __init__(self, context: Dict[str, z3.ExprRef] = None):
        self.context = context or {}
        self.var_counter = 0
    
    def translate(self, node: ASTNode) -> z3.ExprRef:
        """Translate AST node to Z3 expression."""
        if isinstance(node, PropertyNode):
            return self.translate(node.expression)
        elif isinstance(node, InvariantNode):
            return self.translate(node.expression)
        elif isinstance(node, RequiresNode):
            return self.translate(node.expression)
        elif isinstance(node, EnsuresNode):
            return self.translate(node.expression)
        elif isinstance(node, AxiomNode):
            return self.translate(node.expression)
        elif isinstance(node, BinaryOpNode):
            return self.translate_binary_op(node)
        elif isinstance(node, UnaryOpNode):
            return self.translate_unary_op(node)
        elif isinstance(node, IdentifierNode):
            return self.translate_identifier(node)
        elif isinstance(node, NumberNode):
            return z3.BitVecVal(node.value, 256)
        elif isinstance(node, StringNode):
            return z3.StringVal(node.value)
        elif isinstance(node, FunctionCallNode):
            return self.translate_function_call(node)
        elif isinstance(node, IndexAccessNode):
            return self.translate_index_access(node)
        elif isinstance(node, MemberAccessNode):
            return self.translate_member_access(node)
        elif isinstance(node, OldNode):
            return self.translate_old(node)
        else:
            return z3.BoolVal(True)
    
    def translate_binary_op(self, node: BinaryOpNode) -> z3.ExprRef:
        """Translate binary operation."""
        left = self.translate(node.left)
        right = self.translate(node.right)
        
        ops = {
            '+': lambda a, b: a + b if isinstance(a, z3.BitVecRef) else z3.BitVecVal(int(str(a)) + int(str(b)), 256),
            '-': lambda a, b: a - b if isinstance(a, z3.BitVecRef) else z3.BitVecVal(int(str(a)) - int(str(b)), 256),
            '*': lambda a, b: a * b if isinstance(a, z3.BitVecRef) else z3.BitVecVal(int(str(a)) * int(str(b)), 256),
            '/': lambda a, b: z3.UDiv(a, b) if isinstance(a, z3.BitVecRef) else z3.UDiv(z3.BitVecVal(int(str(a)), 256), z3.BitVecVal(int(str(b)), 256)),
            '%': lambda a, b: z3.URem(a, b) if isinstance(a, z3.BitVecRef) else z3.URem(z3.BitVecVal(int(str(a)), 256), z3.BitVecVal(int(str(b)), 256)),
            '==': lambda a, b: a == b,
            '!=': lambda a, b: a != b,
            '<': lambda a, b: z3.ULT(a, b) if isinstance(a, z3.BitVecRef) else z3.BitVecVal(int(str(a)) < int(str(b)), 256) == z3.BitVecVal(1, 256),
            '<=': lambda a, b: z3.ULE(a, b),
            '>': lambda a, b: z3.UGT(a, b),
            '>=': lambda a, b: z3.UGE(a, b),
            'and': lambda a, b: z3.And(a, b),
            'or': lambda a, b: z3.Or(a, b),
        }
        
        if node.operator in ops:
            return ops[node.operator](left, right)
        
        return z3.BoolVal(True)
    
    def translate_unary_op(self, node: UnaryOpNode) -> z3.ExprRef:
        """Translate unary operation."""
        operand = self.translate(node.operand)
        
        if node.operator == 'not':
            return z3.Not(operand)
        elif node.operator == '-':
            if isinstance(operand, z3.BitVecRef):
                return -operand
            return z3.BitVecVal(-int(str(operand)), 256)
        
        return operand
    
    def translate_identifier(self, node: IdentifierNode) -> z3.ExprRef:
        """Translate identifier."""
        name = node.name
        
        if name in self.context:
            return self.context[name]
        
        if name == 'true':
            return z3.BoolVal(True)
        elif name == 'false':
            return z3.BoolVal(False)
        
        # Create symbolic variable
        if name not in self.context:
            var = z3.FreshConst(z3.BitVecSort(256), name=name)
            self.context[name] = var
        
        return self.context[name]
    
    def translate_function_call(self, node: FunctionCallNode) -> z3.ExprRef:
        """Translate function call."""
        args = [self.translate(arg) for arg in node.arguments]
        
        func_map = {
            'abs': lambda x: z3.Abs(x) if hasattr(z3, 'Abs') else x,
            'min': lambda a, b: z3.If(a < b, a, b),
            'max': lambda a, b: z3.If(a > b, a, b),
        }
        
        if node.name in func_map:
            return func_map[node.name](*args)
        
        return z3.BoolVal(True)
    
    def translate_index_access(self, node: IndexAccessNode) -> z3.ExprRef:
        """Translate index access."""
        base = self.translate(node.base)
        index = self.translate(node.index)
        return base[index]
    
    def translate_member_access(self, node: MemberAccessNode) -> z3.ExprRef:
        """Translate member access."""
        base = self.translate(node.base)
        # Simplified: return base for now
        return base
    
    def translate_old(self, node: OldNode) -> z3.ExprRef:
        """Translate old() expression."""
        expr = self.translate(node.expression)
        # For old values, we need special handling
        # Return a fresh variable representing the old value
        var = z3.FreshConst(z3.BitVecSort(256), name=f"old_{self.var_counter}")
        self.var_counter += 1
        return var


class SpecificationGrammar:
    """
    Specification grammar parser and translator.
    
    Parses .mspec files and translates them to Z3 formulas.
    """
    
    def __init__(self, context: Dict[str, z3.ExprRef] = None):
        self.context = context or {}
        self.lexer = None
        self.parser = None
        self.translator = Z3Translator(context)
    
    def parse(self, source: str) -> List[z3.BoolRef]:
        """
        Parse specification source to Z3 formulas.
        
        Args:
            source: Specification source code
            
        Returns:
            List of Z3 boolean formulas
        """
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        ast = parser.parse()
        
        return [self.translator.translate(node) for node in ast]
    
    def parse_file(self, filepath: str) -> List[z3.BoolRef]:
        """
        Parse specification file.
        
        Args:
            filepath: Path to .mspec file
            
        Returns:
            List of Z3 boolean formulas
        """
        with open(filepath, 'r') as f:
            source = f.read()
        return self.parse(source)
