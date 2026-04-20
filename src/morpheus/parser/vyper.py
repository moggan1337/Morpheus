"""
Vyper Parser
============

This module provides a parser for Vyper smart contract source code,
converting it to an Abstract Syntax Tree (AST) suitable for
formal verification.

Author: Morpheus Team
"""

from __future__ import annotations
from typing import List, Optional, Dict, Any, Set
import re
import logging
from morpheus.parser.ast import (
    SourceUnit, Contract, Function, StateVariable, Parameter,
    Block, Statement, Expression, Identifier, Literal, BinaryOp,
    UnaryOp, Assignment, FunctionCall, IndexAccess, MemberAccess,
    SourceLocation, NodeType, ContractType, Visibility, StateMutability,
    ElementaryTypeName, ArrayTypeName, Mapping, ASTVisitor, Node
)

logger = logging.getLogger(__name__)


class VyperLexer:
    """Lexer for Vyper source code."""
    
    KEYWORDS = {
        'def': 'DEF',
        'init': 'INIT',
        'struct': 'STRUCT',
        'event': 'EVENT',
        'enum': 'ENUM',
        'import': 'IMPORT',
        'from': 'FROM',
        'as': 'AS',
        'if': 'IF',
        'elif': 'ELIF',
        'else': 'ELSE',
        'for': 'FOR',
        'in': 'IN',
        'while': 'WHILE',
        'break': 'BREAK',
        'continue': 'CONTINUE',
        'return': 'RETURN',
        'pass': 'PASS',
        'raise': 'RAISE',
        'assert': 'ASSERT',
        '寿': 'CONSTANT',  # Chinese for constant (Vyper allows unicode)
        'immutable': 'IMMUTABLE',
        'self': 'SELF',
        'super': 'SUPER',
        'raw_call': 'RAW_CALL',
        'create_forwarder_to': 'CREATE_FORWARDER',
        'send': 'SEND',
        'selfdestruct': 'SELFDESTRUCT',
        'delegatecall': 'DELEGATECALL',
        'staticcall': 'STATICCALL',
        'create': 'CREATE',
        'create2': 'CREATE2',
        'emit': 'EMIT',
        'and': 'AND',
        'or': 'OR',
        'not': 'NOT',
        'None': 'NONE',
        'True': 'TRUE',
        'false': 'FALSE',  # Vyper uses lowercase for false
        'int128': 'INT128',
        'int256': 'INT256',
        'uint256': 'UINT256',
        'decimal': 'DECIMAL',
        'bool': 'BOOL',
        'address': 'ADDRESS',
        'bytes32': 'BYTES32',
        'bytes': 'BYTES',
        'string': 'STRING',
    }
    
    def __init__(self, source: str):
        self.source = source
        self.position = 0
        self.line = 1
        self.column = 1
        self.tokens: List[Any] = []
    
    def current_char(self) -> Optional[str]:
        if self.position < len(self.source):
            return self.source[self.position]
        return None
    
    def peek(self, offset: int = 1) -> Optional[str]:
        pos = self.position + offset
        if pos < len(self.source):
            return self.source[pos]
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
        while self.current_char() and self.current_char() in ' \t\r\n':
            self.advance()
    
    def skip_comment(self) -> None:
        if self.current_char() == '#':
            while self.current_char() and self.current_char() != '\n':
                self.advance()
    
    def read_identifier(self) -> str:
        result = ''
        while self.current_char() and (self.current_char().isalnum() or 
                                       self.current_char() in '_$'):
            result += self.advance()
        return result
    
    def read_number(self) -> str:
        result = ''
        while self.current_char() and (self.current_char().isdigit() or 
                                       self.current_char() in '.eExX'):
            result += self.advance()
        return result
    
    def read_string(self) -> str:
        quote_char = self.advance()  # opening quote
        result = ''
        
        while self.current_char() and self.current_char() != quote_char:
            if self.current_char() == '\\':
                self.advance()
                if self.current_char():
                    result += self.advance()
            else:
                result += self.advance()
        
        if self.current_char() == quote_char:
            self.advance()
        
        return result
    
    def tokenize(self) -> List[Any]:
        while self.position < len(self.source):
            self.skip_whitespace()
            self.skip_comment()
            
            if not self.current_char():
                break
            
            char = self.current_char()
            start_line = self.line
            start_col = self.column
            start_pos = self.position
            
            # Operators
            if char == '+':
                self.advance()
                if self.current_char() == '=':
                    self.advance()
                    self.tokens.append(('PLUS_EQUAL', '+=', start_line, start_col))
                elif self.current_char() == '+':
                    self.advance()
                    self.tokens.append(('PLUS_PLUS', '++', start_line, start_col))
                else:
                    self.tokens.append(('PLUS', '+', start_line, start_col))
            
            elif char == '-':
                self.advance()
                if self.current_char() == '=':
                    self.advance()
                    self.tokens.append(('MINUS_EQUAL', '-=', start_line, start_col))
                elif self.current_char() == '-':
                    self.advance()
                    self.tokens.append(('MINUS_MINUS', '--', start_line, start_col))
                else:
                    self.tokens.append(('MINUS', '-', start_line, start_col))
            
            elif char == '*':
                self.advance()
                if self.current_char() == '*':
                    self.advance()
                    self.tokens.append(('POWER', '**', start_line, start_col))
                else:
                    self.tokens.append(('STAR', '*', start_line, start_col))
            
            elif char == '/':
                self.advance()
                if self.current_char() == '/':
                    self.advance()
                    self.tokens.append(('DOUBLE_SLASH', '//', start_line, start_col))
                else:
                    self.tokens.append(('SLASH', '/', start_line, start_col))
            
            elif char == '%':
                self.advance()
                self.tokens.append(('PERCENT', '%', start_line, start_col))
            
            elif char == '=':
                self.advance()
                if self.current_char() == '=':
                    self.advance()
                    self.tokens.append(('EQUAL_EQUAL', '==', start_line, start_col))
                else:
                    self.tokens.append(('EQUAL', '=', start_line, start_col))
            
            elif char == '!':
                self.advance()
                if self.current_char() == '=':
                    self.advance()
                    self.tokens.append(('NOT_EQUAL', '!=', start_line, start_col))
                else:
                    self.tokens.append(('NOT', '!', start_line, start_col))
            
            elif char == '<':
                self.advance()
                if self.current_char() == '=':
                    self.advance()
                    self.tokens.append(('LESS_EQUAL', '<=', start_line, start_col))
                elif self.current_char() == '<':
                    self.advance()
                    self.tokens.append(('LESS_LESS', '<<', start_line, start_col))
                else:
                    self.tokens.append(('LESS', '<', start_line, start_col))
            
            elif char == '>':
                self.advance()
                if self.current_char() == '=':
                    self.advance()
                    self.tokens.append(('GREATER_EQUAL', '>=', start_line, start_col))
                elif self.current_char() == '>':
                    self.advance()
                    self.tokens.append(('GREATER_GREATER', '>>', start_line, start_col))
                else:
                    self.tokens.append(('GREATER', '>', start_line, start_col))
            
            elif char == '&':
                self.advance()
                if self.current_char() == '&':
                    self.advance()
                    self.tokens.append(('AND', 'and', start_line, start_col))
                else:
                    self.tokens.append(('AMPERSAND', '&', start_line, start_col))
            
            elif char == '|':
                self.advance()
                if self.current_char() == '|':
                    self.advance()
                    self.tokens.append(('OR', 'or', start_line, start_col))
                else:
                    self.tokens.append(('BAR', '|', start_line, start_col))
            
            # Delimiters
            elif char == '(':
                self.advance()
                self.tokens.append(('LPAREN', '(', start_line, start_col))
            elif char == ')':
                self.advance()
                self.tokens.append(('RPAREN', ')', start_line, start_col))
            elif char == '[':
                self.advance()
                self.tokens.append(('LBRACKET', '[', start_line, start_col))
            elif char == ']':
                self.advance()
                self.tokens.append(('RBRACKET', ']', start_line, start_col))
            elif char == '{':
                self.advance()
                self.tokens.append(('LBRACE', '{', start_line, start_col))
            elif char == '}':
                self.advance()
                self.tokens.append(('RBRACE', '}', start_line, start_col))
            elif char == ':':
                self.advance()
                self.tokens.append(('COLON', ':', start_line, start_col))
            elif char == ',':
                self.advance()
                self.tokens.append(('COMMA', ',', start_line, start_col))
            elif char == '.':
                self.advance()
                self.tokens.append(('DOT', '.', start_line, start_col))
            elif char == ';':
                self.advance()
                self.tokens.append(('SEMICOLON', ';', start_line, start_col))
            elif char == '@':
                self.advance()
                self.tokens.append(('AT', '@', start_line, start_col))
            
            # String literals
            elif char in '"\'':
                string = self.read_string()
                self.tokens.append(('STRING', string, start_line, start_col))
            
            # Numbers
            elif char.isdigit():
                number = self.read_number()
                self.tokens.append(('NUMBER', number, start_line, start_col))
            
            # Identifiers and keywords
            elif char.isalpha() or char in '_$':
                identifier = self.read_identifier()
                token_type = self.KEYWORDS.get(identifier, 'IDENTIFIER')
                self.tokens.append((token_type, identifier, start_line, start_col))
            
            else:
                logger.warning(f"Unknown character: {char} at {start_line}:{start_col}")
                self.advance()
        
        self.tokens.append(('EOF', '', self.line, self.column))
        return self.tokens


class VyperParser:
    """Parser for Vyper source code."""
    
    def __init__(self, tokens: List[Any]):
        self.tokens = tokens
        self.position = 0
        self.contract_type = "contract"  # or "struct", "interface"
    
    def current(self) -> Any:
        if self.position < len(self.tokens):
            return self.tokens[self.position]
        return ('EOF', '', 0, 0)
    
    def peek(self, offset: int = 1) -> Any:
        pos = self.position + offset
        if pos < len(self.tokens):
            return self.tokens[pos]
        return ('EOF', '', 0, 0)
    
    def advance(self) -> Any:
        token = self.current()
        self.position += 1
        return token
    
    def expect(self, token_type: str) -> Any:
        token = self.current()
        if token[0] != token_type:
            raise SyntaxError(f"Expected {token_type}, got {token[0]}")
        return self.advance()
    
    def match(self, token_type: str) -> bool:
        return self.current()[0] == token_type
    
    def consume(self, token_type: str) -> Optional[Any]:
        if self.match(token_type):
            return self.advance()
        return None
    
    def parse(self) -> SourceUnit:
        """Parse Vyper source."""
        source_unit = SourceUnit()
        
        while not self.match('EOF'):
            try:
                if self.match('IMPORT'):
                    self.parse_import(source_unit)
                elif self.match('DEF'):
                    func = self.parse_function_def()
                    source_unit.functions.append(func)
                elif self.match('STRUCT'):
                    source_unit.structs.append(self.parse_struct())
                elif self.match('EVENT'):
                    source_unit.contracts.append(self.parse_event())
                elif self.match('INTERFACE'):
                    self.parse_interface()
                elif self.match('ENUM'):
                    source_unit.enums.append(self.parse_enum())
                else:
                    logger.warning(f"Unexpected token: {self.current()}")
                    self.advance()
            except Exception as e:
                logger.error(f"Parse error at {self.current()}: {e}")
                while not self.match('NEWLINE') and not self.match('EOF'):
                    self.advance()
                if self.match('NEWLINE'):
                    self.advance()
        
        return source_unit
    
    def parse_import(self, source_unit: SourceUnit) -> None:
        """Parse import statement."""
        self.expect('IMPORT')
        
        if self.match('IDENTIFIER'):
            module = self.advance()[1]
            if self.consume('AS'):
                alias = self.advance()[1]
            
        self.consume_newline()
    
    def parse_function_def(self) -> Function:
        """Parse function definition."""
        self.expect('DEF')
        name = self.advance()[1]  # function name
        
        func = Function(name)
        
        # Parse parameters
        self.expect('LPAREN')
        if not self.match('RPAREN'):
            func.parameters = self.parse_parameter_list()
        self.expect('RPAREN')
        
        # Parse return type
        if self.consume('->'):
            func.return_parameters = self.parse_parameter_list()
        
        # Parse decorators
        while self.match('AT'):
            self.parse_decorator()
        
        # Parse function body
        func.body = self.parse_block()
        
        return func
    
    def parse_decorator(self) -> None:
        """Parse decorator."""
        self.expect('AT')
        decorator_name = self.advance()[1]
        
        if self.match('LPAREN'):
            self.advance()
            if not self.match('RPAREN'):
                while True:
                    self.advance()
                    if not self.match('COMMA'):
                        break
            self.expect('RPAREN')
    
    def parse_parameter_list(self) -> List[Parameter]:
        """Parse parameter list."""
        params = []
        
        while True:
            if self.match('RPAREN') or self.match('ARROW'):
                break
            
            param_type = self.parse_type()
            name = ''
            
            if self.match('IDENTIFIER'):
                name = self.advance()[1]
            
            params.append(Parameter(name, param_type))
            
            if not self.consume('COMMA'):
                break
        
        return params
    
    def parse_type(self) -> Node:
        """Parse type."""
        token = self.current()
        
        if token[0] == 'INT128':
            self.advance()
            return ElementaryTypeName('int128')
        elif token[0] == 'INT256':
            self.advance()
            return ElementaryTypeName('int256')
        elif token[0] == 'UINT256':
            self.advance()
            return ElementaryTypeName('uint256')
        elif token[0] == 'DECIMAL':
            self.advance()
            return ElementaryTypeName('decimal')
        elif token[0] == 'BOOL':
            self.advance()
            return ElementaryTypeName('bool')
        elif token[0] == 'ADDRESS':
            self.advance()
            return ElementaryTypeName('address')
        elif token[0] == 'BYTES32':
            self.advance()
            return ElementaryTypeName('bytes32')
        elif token[0] == 'BYTES':
            self.advance()
            if self.match('LBRACKET'):
                self.advance()
                if self.match('NUMBER'):
                    length = self.advance()[1]
                    self.expect('RBRACKET')
                else:
                    self.expect('RBRACKET')
                return ArrayTypeName(ElementaryTypeName('bytes'), int(length))
            return ElementaryTypeName('bytes')
        elif token[0] == 'STRING':
            self.advance()
            return ElementaryTypeName('string')
        elif token[0] == 'IDENTIFIER':
            self.advance()
            return ElementaryTypeName(token[1])
        else:
            logger.warning(f"Unknown type: {token}")
            self.advance()
            return ElementaryTypeName('unknown')
    
    def parse_block(self) -> Block:
        """Parse block."""
        self.consume_newline()
        self.expect('INDENT')
        
        block = Block()
        
        while not self.match('DEDENT') and not self.match('EOF'):
            stmt = self.parse_statement()
            if stmt:
                block.statements.append(stmt)
        
        self.expect('DEDENT')
        
        return block
    
    def parse_statement(self) -> Optional[Statement]:
        """Parse statement."""
        token = self.current()
        
        if self.match('NEWLINE') or self.match('DEDENT'):
            self.advance()
            return None
        
        if self.match('IF'):
            return self.parse_if_statement()
        elif self.match('FOR'):
            return self.parse_for_statement()
        elif self.match('WHILE'):
            return self.parse_while_statement()
        elif self.match('RETURN'):
            return self.parse_return_statement()
        elif self.match('BREAK'):
            self.advance()
            self.consume_newline()
            return Statement(NodeType.BREAK_STATEMENT)
        elif self.match('CONTINUE'):
            self.advance()
            self.consume_newline()
            return Statement(NodeType.CONTINUE_STATEMENT)
        elif self.match('PASS'):
            self.advance()
            self.consume_newline()
            return Statement(NodeType.BLOCK)
        elif self.match('ASSERT'):
            return self.parse_assert_statement()
        elif self.match('RAISE'):
            return self.parse_raise_statement()
        elif self.match('IDENTIFIER'):
            return self.parse_expression_statement()
        elif self.match('SELF'):
            return self.parse_self_statement()
        else:
            logger.warning(f"Unknown statement: {token}")
            self.advance()
            self.consume_newline()
            return None
    
    def parse_if_statement(self) -> IfStatement:
        """Parse if statement."""
        self.expect('IF')
        condition = self.parse_expression()
        self.consume_newline()
        
        true_body = self.parse_block()
        false_body = None
        
        if self.match('ELIF'):
            false_body = self.parse_elif_chain()
        elif self.match('ELSE'):
            self.advance()
            self.consume_newline()
            false_body = self.parse_block()
        
        return IfStatement(condition, true_body, false_body)
    
    def parse_elif_chain(self) -> Statement:
        """Parse elif chain."""
        self.expect('ELIF')
        condition = self.parse_expression()
        self.consume_newline()
        
        body = self.parse_block()
        
        if self.match('ELIF'):
            else_body = self.parse_elif_chain()
        elif self.match('ELSE'):
            self.advance()
            self.consume_newline()
            else_body = self.parse_block()
        else:
            else_body = Block()
        
        return IfStatement(condition, body, else_body)
    
    def parse_for_statement(self) -> ForStatement:
        """Parse for statement."""
        self.expect('FOR')
        
        var_name = self.advance()[1]  # loop variable
        self.expect('IN')
        
        # Parse range or iterable
        iterable = self.parse_expression()
        
        self.consume_newline()
        body = self.parse_block()
        
        stmt = ForStatement()
        # Simplified: represent as a basic for statement
        return stmt
    
    def parse_while_statement(self) -> WhileStatement:
        """Parse while statement."""
        self.expect('WHILE')
        condition = self.parse_expression()
        self.consume_newline()
        
        body = self.parse_block()
        
        return WhileStatement(condition, body)
    
    def parse_return_statement(self) -> ReturnStatement:
        """Parse return statement."""
        self.expect('RETURN')
        
        expr = None
        if not self.match('NEWLINE'):
            expr = self.parse_expression()
        
        self.consume_newline()
        
        return ReturnStatement(expr)
    
    def parse_assert_statement(self) -> Statement:
        """Parse assert statement."""
        self.expect('ASSERT')
        condition = self.parse_expression()
        
        message = None
        if self.consume('COMMA'):
            message = self.parse_expression()
        
        self.consume_newline()
        
        return Statement(NodeType.ASSERT_STATEMENT)
    
    def parse_raise_statement(self) -> Statement:
        """Parse raise statement."""
        self.expect('RAISE')
        self.consume_newline()
        
        return Statement(NodeType.REVERT_STATEMENT)
    
    def parse_self_statement(self) -> Statement:
        """Parse self.* statement."""
        self.expect('SELF')
        self.expect('DOT')
        
        member = self.advance()[1]
        
        if self.match('LPAREN'):
            # self.function_call()
            args = self.parse_function_call_args()
            self.consume_newline()
            return FunctionCall(Identifier(member))
        else:
            # self.variable
            self.consume_newline()
            return MemberAccess(Identifier('self'), member)
    
    def parse_expression_statement(self) -> ExpressionStatement:
        """Parse expression statement."""
        expr = self.parse_expression()
        self.consume_newline()
        return ExpressionStatement(expr)
    
    def parse_expression(self) -> Expression:
        """Parse expression."""
        return self.parse_or()
    
    def parse_or(self) -> Expression:
        """Parse or expression."""
        left = self.parse_and()
        
        while self.match('OR'):
            self.advance()
            right = self.parse_and()
            left = BinaryOp('or', left, right)
        
        return left
    
    def parse_and(self) -> Expression:
        """Parse and expression."""
        left = self.parse_not()
        
        while self.match('AND'):
            self.advance()
            right = self.parse_not()
            left = BinaryOp('and', left, right)
        
        return left
    
    def parse_not(self) -> Expression:
        """Parse not expression."""
        if self.match('NOT'):
            self.advance()
            operand = self.parse_not()
            return UnaryOp('not', operand)
        
        return self.parse_comparison()
    
    def parse_comparison(self) -> Expression:
        """Parse comparison expressions."""
        left = self.parse_addition()
        
        while True:
            if self.match('EQUAL_EQUAL'):
                self.advance()
                right = self.parse_addition()
                left = BinaryOp('==', left, right)
            elif self.match('NOT_EQUAL'):
                self.advance()
                right = self.parse_addition()
                left = BinaryOp('!=', left, right)
            elif self.match('LESS'):
                self.advance()
                right = self.parse_addition()
                left = BinaryOp('<', left, right)
            elif self.match('LESS_EQUAL'):
                self.advance()
                right = self.parse_addition()
                left = BinaryOp('<=', left, right)
            elif self.match('GREATER'):
                self.advance()
                right = self.parse_addition()
                left = BinaryOp('>', left, right)
            elif self.match('GREATER_EQUAL'):
                self.advance()
                right = self.parse_addition()
                left = BinaryOp('>=', left, right)
            else:
                break
        
        return left
    
    def parse_addition(self) -> Expression:
        """Parse addition/subtraction."""
        left = self.parse_multiplication()
        
        while True:
            if self.match('PLUS'):
                self.advance()
                right = self.parse_multiplication()
                left = BinaryOp('+', left, right)
            elif self.match('MINUS'):
                self.advance()
                right = self.parse_multiplication()
                left = BinaryOp('-', left, right)
            else:
                break
        
        return left
    
    def parse_multiplication(self) -> Expression:
        """Parse multiplication/division."""
        left = self.parse_power()
        
        while True:
            if self.match('STAR'):
                self.advance()
                right = self.parse_power()
                left = BinaryOp('*', left, right)
            elif self.match('SLASH'):
                self.advance()
                right = self.parse_power()
                left = BinaryOp('/', left, right)
            elif self.match('DOUBLE_SLASH'):
                self.advance()
                right = self.parse_power()
                left = BinaryOp('//', left, right)
            elif self.match('PERCENT'):
                self.advance()
                right = self.parse_power()
                left = BinaryOp('%', left, right)
            else:
                break
        
        return left
    
    def parse_power(self) -> Expression:
        """Parse power expression."""
        left = self.parse_unary()
        
        if self.match('POWER'):
            self.advance()
            right = self.parse_power()  # Right associative
            left = BinaryOp('**', left, right)
        
        return left
    
    def parse_unary(self) -> Expression:
        """Parse unary expressions."""
        if self.match('MINUS'):
            self.advance()
            operand = self.parse_unary()
            return UnaryOp('-', operand)
        elif self.match('PLUS'):
            self.advance()
            return self.parse_unary()
        
        return self.parse_postfix()
    
    def parse_postfix(self) -> Expression:
        """Parse postfix expressions."""
        expr = self.parse_primary()
        
        while True:
            if self.match('LBRACKET'):
                self.advance()
                index = self.parse_expression()
                self.expect('RBRACKET')
                expr = IndexAccess(expr, index)
            elif self.match('DOT'):
                self.advance()
                member = self.advance()[1]
                expr = MemberAccess(expr, member)
            elif self.match('LPAREN'):
                args = self.parse_function_call_args()
                expr = FunctionCall(expr, args)
            else:
                break
        
        return expr
    
    def parse_primary(self) -> Expression:
        """Parse primary expressions."""
        token = self.current()
        
        if self.match('IDENTIFIER'):
            name = self.advance()[1]
            return Identifier(name)
        elif self.match('NUMBER'):
            value = self.advance()[1]
            return Literal(int(value))
        elif self.match('STRING'):
            value = self.advance()[1]
            return Literal(value)
        elif self.match('TRUE'):
            self.advance()
            return Literal(True)
        elif self.match('FALSE'):
            self.advance()
            return Literal(False)
        elif self.match('LPAREN'):
            self.advance()
            expr = self.parse_expression()
            self.expect('RPAREN')
            return expr
        elif self.match('IDENTIFIER'):
            return Identifier(self.advance()[1])
        else:
            logger.warning(f"Unexpected token: {token}")
            self.advance()
            return Literal(0)
    
    def parse_function_call_args(self) -> List[Expression]:
        """Parse function call arguments."""
        self.expect('LPAREN')
        
        args = []
        if not self.match('RPAREN'):
            args = self.parse_expression_list()
        
        self.expect('RPAREN')
        
        return args
    
    def parse_expression_list(self) -> List[Expression]:
        """Parse expression list."""
        expressions = []
        
        while True:
            expressions.append(self.parse_expression())
            
            if not self.consume('COMMA'):
                break
        
        return expressions
    
    def parse_struct(self) -> Any:
        """Parse struct definition."""
        self.expect('STRUCT')
        name = self.advance()[1]
        
        self.consume_newline()
        self.expect('INDENT')
        
        members = []
        while not self.match('DEDENT') and not self.match('EOF'):
            member_type = self.parse_type()
            member_name = self.advance()[1]
            members.append(StateVariable(member_name, member_type))
            self.consume_newline()
        
        self.expect('DEDENT')
        
        return StructDefinition(name, members)
    
    def parse_event(self) -> Any:
        """Parse event definition."""
        self.expect('EVENT')
        name = self.advance()[1]
        
        self.expect('LPAREN')
        if not self.match('RPAREN'):
            while True:
                self.parse_type()
                self.advance()  # param name
                if not self.consume('COMMA'):
                    break
        self.expect('RPAREN')
        self.consume_newline()
        
        return Event(name)
    
    def parse_interface(self) -> None:
        """Parse interface definition."""
        self.expect('INTERFACE')
        name = self.advance()[1]
        
        self.consume_newline()
        self.expect('INDENT')
        
        while not self.match('DEDENT') and not self.match('EOF'):
            if self.match('DEF'):
                self.parse_function_def()
            else:
                self.advance()
        
        self.expect('DEDENT')
    
    def parse_enum(self) -> EnumDefinition:
        """Parse enum definition."""
        self.expect('ENUM')
        name = self.advance()[1]
        
        self.consume_newline()
        self.expect('INDENT')
        
        members = []
        while not self.match('DEDENT') and not self.match('EOF'):
            members.append(self.advance()[1])
            self.consume_newline()
        
        self.expect('DEDENT')
        
        return EnumDefinition(name, members)
    
    def consume_newline(self) -> None:
        """Consume newlines."""
        while self.match('NEWLINE'):
            self.advance()


class VyperParserInterface:
    """
    High-level Vyper parser interface.
    
    Provides methods for parsing Vyper source code.
    """
    
    def __init__(self):
        self.ast_cache: Dict[str, SourceUnit] = {}
    
    def parse_source(self, source: str) -> SourceUnit:
        """
        Parse Vyper source code.
        
        Args:
            source: Vyper source code string
            
        Returns:
            SourceUnit AST
        """
        lexer = VyperLexer(source)
        tokens = lexer.tokenize()
        parser = VyperParser(tokens)
        return parser.parse()
    
    def parse_file(self, filepath: str) -> SourceUnit:
        """
        Parse a Vyper file.
        
        Args:
            filepath: Path to Vyper file
            
        Returns:
            SourceUnit AST
        """
        if filepath in self.ast_cache:
            return self.ast_cache[filepath]
        
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
        
        ast = self.parse_source(source)
        self.ast_cache[filepath] = ast
        return ast
