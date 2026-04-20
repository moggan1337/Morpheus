"""
Solidity Parser
===============

This module provides a parser for Solidity source code, converting
source text into an Abstract Syntax Tree (AST) suitable for
formal verification.

Author: Morpheus Team
"""

from __future__ import annotations
from typing import List, Optional, Dict, Any, Tuple, TextIO
import re
import logging
from morpheus.parser.ast import (
    SourceUnit, Contract, Function, StateVariable, Parameter,
    Block, Statement, Expression, Identifier, Literal, BinaryOp,
    UnaryOp, Assignment, FunctionCall, IndexAccess, MemberAccess,
    NewExpression, TypeConversion, Conditional, IfStatement,
    WhileStatement, ForStatement, ReturnStatement, EmitStatement,
    RequireStatement, AssertStatement, RevertStatement, BreakStatement,
    ContinueStatement, VariableDeclarationStatement, Event, Error,
    EnumDefinition, StructDefinition, PragmaDirective, ImportDirective,
    SourceLocation, NodeType, ContractType, Visibility, StateMutability,
    ElementaryTypeName, ArrayTypeName, Mapping, UserDefinedTypeName,
    ASTVisitor, Node
)

logger = logging.getLogger(__name__)


class TokenType:
    """Token types for Solidity lexer."""
    # Literals
    IDENTIFIER = "IDENTIFIER"
    INTEGER = "INTEGER"
    STRING = "STRING"
    HEX_STRING = "HEX_STRING"
    UnicodeString = "UNICODE_STRING"
    
    # Operators
    PLUS = "PLUS"
    MINUS = "MINUS"
    STAR = "STAR"
    SLASH = "SLASH"
    PERCENT = "PERCENT"
    DOUBLE_STAR = "DOUBLE_STAR"
    LESS_LESS = "LESS_LESS"
    GREATER_GREATER = "GREATER_GREATER"
    GREATER_GREATER_GREATER = "GREATER_GREATER_GREATER"
    
    # Comparison
    EQUAL_EQUAL = "EQUAL_EQUAL"
    EXCLAMATION_EQUAL = "EXCLAMATION_EQUAL"
    LESS_EQUAL = "LESS_EQUAL"
    GREATER_EQUAL = "GREATER_EQUAL"
    
    # Bitwise
    AMPERSAND = "AMPERSAND"
    BAR = "BAR"
    CARET = "CARET"
    TILDE = "TILDE"
    
    # Boolean
    AMPERSAND_AMPERSAND = "AMPERSAND_AMPERSAND"
    BAR_BAR = "BAR_BAR"
    EXCLAMATION = "EXCLAMATION"
    
    # Assignment
    EQUAL = "EQUAL"
    PLUS_EQUAL = "PLUS_EQUAL"
    MINUS_EQUAL = "MINUS_EQUAL"
    STAR_EQUAL = "STAR_EQUAL"
    SLASH_EQUAL = "SLASH_EQUAL"
    PERCENT_EQUAL = "PERCENT_EQUAL"
    LESS_LESS_EQUAL = "LESS_LESS_EQUAL"
    GREATER_GREATER_EQUAL = "GREATER_GREATER_EQUAL"
    AMPERSAND_EQUAL = "AMPERSAND_EQUAL"
    BAR_EQUAL = "BAR_EQUAL"
    CARET_EQUAL = "CARET_EQUAL"
    
    # Increment/Decrement
    PLUS_PLUS = "PLUS_PLUS"
    MINUS_MINUS = "MINUS_MINUS"
    
    # Ternary
    QUESTION = "QUESTION"
    COLON = "COLON"
    
    # Delimiters
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    LBRACKET = "LBRACKET"
    RBRACKET = "RBRACKET"
    LBRACE = "LBRACE"
    RBRACE = "RBRACE"
    COMMA = "COMMA"
    SEMICOLON = "SEMICOLON"
    DOT = "DOT"
    
    # Keywords
    Pragma = "PRAGMA"
    Import = "IMPORT"
    Contract = "CONTRACT"
    Interface = "INTERFACE"
    Library = "LIBRARY"
    Struct = "STRUCT"
    Enum = "ENUM"
    Function = "FUNCTION"
    Constructor = "CONSTRUCTOR"
    Fallback = "FALLBACK"
    Receive = "RECEIVE"
    Modifier = "MODIFIER"
    Event = "EVENT"
    Error = "ERROR"
    Enum = "ENUM"
    Throw = "THROW"
    Emit = "EMIT"
    Require = "REQUIRE"
    Assert = "ASSERT"
    Revert = "REVERT"
    Return = "RETURN"
    If = "IF"
    Else = "ELSE"
    For = "FOR"
    While = "WHILE"
    Do = "DO"
    Break = "BREAK"
    Continue = "CONTINUE"
    Public = "PUBLIC"
    Private = "PRIVATE"
    Internal = "INTERNAL"
    External = "EXTERNAL"
    Pure = "PURE"
    View = "VIEW"
    Payable = "PAYABLE"
    Nonpayable = "NONPAYABLE"
    Virtual = "VIRTUAL"
    Override = "OVERRIDE"
    Indexed = "INDEXED"
    Anonymous = "ANONYMOUS"
    Storage = "STORAGE"
    Memory = "MEMORY"
    Calldata = "CALLDATA"
    Immutable = "IMMUTABLE"
    Constant = "CONSTANT"
    Type = "TYPE"
    Is = "IS"
    As = "AS"
    From = "FROM"
    Using = "USING"
    Step = "STEP"
    UsingFor = "USING_FOR"
    
    # Types
    Address = "ADDRESS"
    Bool = "BOOL"
    String = "STRING"
    Bytes = "BYTES"
    Int = "INT"
    Uint = "UINT"
    Fixed = "FIXED"
    Ufixed = "UFIXED"
    
    # Special
    EOF = "EOF"
    WHITESPACE = "WHITESPACE"
    COMMENT = "COMMENT"
    LINE_COMMENT = "LINE_COMMENT"


class Token:
    """Represents a token in Solidity source."""
    
    def __init__(
        self,
        token_type: str,
        value: str,
        line: int = 0,
        column: int = 0,
        position: int = 0
    ):
        self.token_type = token_type
        self.value = value
        self.line = line
        self.column = column
        self.position = position
    
    def __repr__(self) -> str:
        return f"Token({self.token_type}, {self.value!r}, {self.line}:{self.column})"


class Lexer:
    """Lexer for Solidity source code."""
    
    KEYWORDS = {
        'pragma': TokenType.Pragma,
        'import': TokenType.Import,
        'contract': TokenType.Contract,
        'interface': TokenType.Interface,
        'library': TokenType.Library,
        'struct': TokenType.Struct,
        'enum': TokenType.Enum,
        'function': TokenType.Function,
        'constructor': TokenType.Constructor,
        'fallback': TokenType.Fallback,
        'receive': TokenType.Receive,
        'modifier': TokenType.Modifier,
        'event': TokenType.Event,
        'error': TokenType.Error,
        'throw': TokenType.Throw,
        'emit': TokenType.Emit,
        'require': TokenType.Require,
        'assert': TokenType.Assert,
        'revert': TokenType.Revert,
        'return': TokenType.Return,
        'if': TokenType.If,
        'else': TokenType.Else,
        'for': TokenType.For,
        'while': TokenType.While,
        'do': TokenType.Do,
        'break': TokenType.Break,
        'continue': TokenType.Continue,
        'public': TokenType.Public,
        'private': TokenType.Private,
        'internal': TokenType.Internal,
        'external': TokenType.External,
        'pure': TokenType.Pure,
        'view': TokenType.View,
        'payable': TokenType.Payable,
        'nonpayable': TokenType.Nonpayable,
        'virtual': TokenType.Virtual,
        'override': TokenType.Override,
        'indexed': TokenType.Indexed,
        'anonymous': TokenType.Anonymous,
        'storage': TokenType.Storage,
        'memory': TokenType.Memory,
        'calldata': TokenType.Calldata,
        'immutable': TokenType.Immutable,
        'constant': TokenType.Constant,
        'type': TokenType.Type,
        'is': TokenType.Is,
        'as': TokenType.As,
        'from': TokenType.From,
        'using': TokenType.Using,
        'address': TokenType.Address,
        'bool': TokenType.Bool,
        'string': TokenType.String,
        'bytes': TokenType.Bytes,
        'int': TokenType.Int,
        'uint': TokenType.Uint,
        'fixed': TokenType.Fixed,
        'ufixed': TokenType.Ufixed,
        'true': TokenType.Identifier,  # boolean literal
        'false': TokenType.Identifier,  # boolean literal
    }
    
    def __init__(self, source: str):
        self.source = source
        self.position = 0
        self.line = 1
        self.column = 1
        self.tokens: List[Token] = []
    
    def current_char(self) -> Optional[str]:
        """Get current character."""
        if self.position < len(self.source):
            return self.source[self.position]
        return None
    
    def peek(self, offset: int = 1) -> Optional[str]:
        """Peek at character ahead."""
        pos = self.position + offset
        if pos < len(self.source):
            return self.source[pos]
        return None
    
    def advance(self) -> Optional[str]:
        """Advance position and return current character."""
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
        """Skip whitespace characters."""
        while self.current_char() and self.current_char() in ' \t\r\n':
            self.advance()
    
    def skip_comment(self) -> None:
        """Skip block comments."""
        if self.current_char() == '/' and self.peek() == '*':
            self.advance()  # /
            self.advance()  # *
            while self.current_char():
                if self.current_char() == '*' and self.peek() == '/':
                    self.advance()  # *
                    self.advance()  # /
                    return
                self.advance()
    
    def skip_line_comment(self) -> None:
        """Skip line comments."""
        if self.current_char() == '/' and self.peek() == '/':
            while self.current_char() and self.current_char() != '\n':
                self.advance()
    
    def read_identifier(self) -> str:
        """Read an identifier."""
        result = ''
        while self.current_char() and (self.current_char().isalnum() or self.current_char() in '_$'):
            result += self.advance()
        return result
    
    def read_number(self) -> str:
        """Read a number literal."""
        result = ''
        has_decimal = False
        
        while self.current_char() and (self.current_char().isdigit() or 
                                       self.current_char() in 'xXbBoOdDaAfF_'):
            if self.current_char() in 'xXbBoOdDaA':
                has_decimal = True
            result += self.advance()
        
        return result
    
    def read_string(self) -> str:
        """Read a string literal."""
        quote_char = self.advance()  # opening quote
        result = ''
        
        while self.current_char() and self.current_char() != quote_char:
            if self.current_char() == '\\':
                self.advance()
                if self.current_char():
                    escape_map = {
                        'n': '\n', 't': '\t', 'r': '\r', '\\': '\\',
                        '"': '"', "'": "'", 'u': ''
                    }
                    result += escape_map.get(self.current_char(), self.advance())
                else:
                    break
            else:
                result += self.advance()
        
        if self.current_char() == quote_char:
            self.advance()  # closing quote
        
        return result
    
    def read_hex_string(self) -> str:
        """Read a hex string literal."""
        self.advance()  # opening quote
        result = ''
        
        while self.current_char() and self.current_char() != "'":
            if self.current_char() in '0123456789abcdefABCDEF':
                result += self.advance()
            elif self.current_char() in ' \t\n\r':
                self.advance()
            else:
                break
        
        if self.current_char() == "'":
            self.advance()
        
        return result
    
    def tokenize(self) -> List[Token]:
        """Tokenize the entire source."""
        while self.position < len(self.source):
            self.skip_whitespace()
            self.skip_comment()
            self.skip_line_comment()
            
            if not self.current_char():
                break
            
            char = self.current_char()
            start_pos = self.position
            start_line = self.line
            start_col = self.column
            
            # Two-character operators
            two_char = char + (self.peek() or '')
            
            if two_char in ('==', '!=', '<=', '>=', '&&', '||', '++', '--',
                           '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=',
                           '<<', '>>', '**', '=>', '..', '::'):
                self.advance()
                self.advance()
                self.tokens.append(Token(two_char, two_char, start_line, start_col, start_pos))
            
            # Three-character operators
            elif char + (self.peek() or '') + (self.peek(2) or '') in ('>>>', '<<='):
                three_char = char + self.peek() + self.peek(2)
                self.advance()
                self.advance()
                self.advance()
                self.tokens.append(Token(three_char, three_char, start_line, start_col, start_pos))
            
            # Single character operators and delimiters
            elif char in '+-*/%<>=!&|^~?:;(),.[]{}':
                self.advance()
                self.tokens.append(Token(char, char, start_line, start_col, start_pos))
            
            # Identifiers and keywords
            elif char.isalpha() or char in '_$':
                identifier = self.read_identifier()
                token_type = self.KEYWORDS.get(identifier, TokenType.IDENTIFIER)
                self.tokens.append(Token(token_type, identifier, start_line, start_col, start_pos))
            
            # Numbers
            elif char.isdigit():
                number = self.read_number()
                self.tokens.append(Token(TokenType.INTEGER, number, start_line, start_col, start_pos))
            
            # String literals
            elif char in '"\'':
                string = self.read_string()
                token_type = TokenType.STRING if char == '"' else TokenType.STRING
                self.tokens.append(Token(token_type, string, start_line, start_col, start_pos))
            
            # Hex string
            elif char == 'h' and self.peek() == '"':
                string = self.read_hex_string()
                self.tokens.append(Token(TokenType.HEX_STRING, string, start_line, start_col, start_pos))
            
            else:
                logger.warning(f"Unknown character: {char} at {start_line}:{start_col}")
                self.advance()
        
        self.tokens.append(Token(TokenType.EOF, '', self.line, self.column, self.position))
        return self.tokens


class Parser:
    """Parser for Solidity source code."""
    
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.position = 0
    
    def current(self) -> Token:
        """Get current token."""
        if self.position < len(self.tokens):
            return self.tokens[self.position]
        return self.tokens[-1]  # EOF
    
    def peek(self, offset: int = 1) -> Token:
        """Peek at token ahead."""
        pos = self.position + offset
        if pos < len(self.tokens):
            return self.tokens[pos]
        return self.tokens[-1]
    
    def advance(self) -> Token:
        """Advance and return current token."""
        token = self.current()
        self.position += 1
        return token
    
    def expect(self, token_type: str, value: Optional[str] = None) -> Token:
        """Expect a specific token type."""
        token = self.current()
        if token.token_type != token_type:
            raise SyntaxError(f"Expected {token_type}, got {token.token_type}")
        if value and token.value != value:
            raise SyntaxError(f"Expected '{value}', got '{token.value}'")
        return self.advance()
    
    def match(self, token_type: str, value: Optional[str] = None) -> bool:
        """Check if current token matches."""
        token = self.current()
        if token.token_type != token_type:
            return False
        if value and token.value != value:
            return False
        return True
    
    def consume(self, token_type: str, value: Optional[str] = None) -> Optional[Token]:
        """Consume token if it matches, otherwise return None."""
        if self.match(token_type, value):
            return self.advance()
        return None
    
    def parse(self) -> SourceUnit:
        """Parse the source unit."""
        source_unit = SourceUnit()
        
        while not self.match(TokenType.EOF):
            try:
                if self.match(TokenType.Pragma):
                    source_unit.pragmas.append(self.parse_pragma())
                elif self.match(TokenType.Import):
                    source_unit.imports.append(self.parse_import())
                elif self.match(TokenType.Contract):
                    source_unit.contracts.append(self.parse_contract())
                elif self.match(TokenType.Interface):
                    source_unit.contracts.append(self.parse_interface())
                elif self.match(TokenType.Library):
                    source_unit.contracts.append(self.parse_library())
                elif self.match(TokenType.Enum):
                    source_unit.enums.append(self.parse_enum())
                elif self.match(TokenType.Struct):
                    source_unit.structs.append(self.parse_struct())
                elif self.match(TokenType.Function):
                    source_unit.functions.append(self.parse_function())
                else:
                    logger.warning(f"Unexpected token: {self.current()}")
                    self.advance()
            except Exception as e:
                logger.error(f"Parse error at {self.current()}: {e}")
                # Try to recover
                while not self.match(TokenType.SEMICOLON, ';') and not self.match(TokenType.EOF):
                    self.advance()
                if self.match(TokenType.SEMICOLON, ';'):
                    self.advance()
        
        return source_unit
    
    def parse_pragma(self) -> PragmaDirective:
        """Parse pragma directive."""
        token = self.expect(TokenType.Pragma)
        name = self.expect(TokenType.Identifier).value
        
        # Parse pragma value (e.g., ">=0.8.0 <0.9.0")
        value = ''
        while not self.match(TokenType.SEMICOLON, ';') and not self.match(TokenType.EOF):
            value += self.advance().value + ' '
        
        self.consume(TokenType.SEMICOLON, ';')
        
        return PragmaDirective(name, value.strip())
    
    def parse_import(self) -> ImportDirective:
        """Parse import directive."""
        self.expect(TokenType.Import)
        
        path = ''
        alias = None
        
        if self.match(TokenType.STRING):
            path = self.advance().value
        else:
            # Path could be identifier chain
            while self.match(TokenType.Identifier):
                path += self.advance().value
                if self.match(TokenType.DOT, '.'):
                    path += '.'
                    self.advance()
                else:
                    break
        
        if self.consume(TokenType.As, 'as'):
            alias = self.expect(TokenType.Identifier).value
        
        if self.consume(TokenType.From, 'from'):
            self.expect(TokenType.STRING)
        
        self.consume(TokenType.SEMICOLON, ';')
        
        return ImportDirective(path, alias)
    
    def parse_contract(self) -> Contract:
        """Parse contract definition."""
        self.expect(TokenType.Contract)
        name = self.expect(TokenType.Identifier).value
        
        contract = Contract(name, ContractType.CONTRACT)
        
        # Parse inheritance
        if self.consume(TokenType.Is, 'is'):
            while True:
                contract.base_contracts.append(self.parse_identifier())
                if not self.consume(TokenType.COMMA, ','):
                    break
        
        self.expect(TokenType.LBRACE, '{')
        
        while not self.match(TokenType.RBRACE, '}') and not self.match(TokenType.EOF):
            self.parse_contract_member(contract)
        
        self.expect(TokenType.RBRACE, '}')
        
        return contract
    
    def parse_interface(self) -> Contract:
        """Parse interface definition."""
        self.expect(TokenType.Interface)
        name = self.expect(TokenType.Identifier).value
        
        contract = Contract(name, ContractType.INTERFACE)
        
        if self.consume(TokenType.Is, 'is'):
            while True:
                contract.base_contracts.append(self.parse_identifier())
                if not self.consume(TokenType.COMMA, ','):
                    break
        
        self.expect(TokenType.LBRACE, '{')
        
        while not self.match(TokenType.RBRACE, '}') and not self.match(TokenType.EOF):
            self.parse_contract_member(contract)
        
        self.expect(TokenType.RBRACE, '}')
        
        return contract
    
    def parse_library(self) -> Contract:
        """Parse library definition."""
        self.expect(TokenType.Library)
        name = self.expect(TokenType.Identifier).value
        
        contract = Contract(name, ContractType.LIBRARY)
        
        self.expect(TokenType.LBRACE, '{')
        
        while not self.match(TokenType.RBRACE, '}') and not self.match(TokenType.EOF):
            self.parse_contract_member(contract)
        
        self.expect(TokenType.RBRACE, '}')
        
        return contract
    
    def parse_contract_member(self, contract: Contract) -> None:
        """Parse a contract member."""
        # Parse visibility and modifiers first
        visibility = Visibility.PUBLIC
        mutability = StateMutability.NONPAYABLE
        is_virtual = False
        is_override = False
        
        while True:
            if self.match(TokenType.Public):
                visibility = Visibility.PUBLIC
                self.advance()
            elif self.match(TokenType.Private):
                visibility = Visibility.PRIVATE
                self.advance()
            elif self.match(TokenType.Internal):
                visibility = Visibility.INTERNAL
                self.advance()
            elif self.match(TokenType.External):
                visibility = Visibility.EXTERNAL
                self.advance()
            elif self.match(TokenType.Pure):
                mutability = StateMutability.PURE
                self.advance()
            elif self.match(TokenType.View):
                mutability = StateMutability.VIEW
                self.advance()
            elif self.match(TokenType.Payable):
                mutability = StateMutability.PAYABLE
                self.advance()
            elif self.match(TokenType.Virtual):
                is_virtual = True
                self.advance()
            elif self.match(TokenType.Override):
                is_override = True
                self.advance()
            else:
                break
        
        if self.match(TokenType.Event):
            contract.events.append(self.parse_event())
        elif self.match(TokenType.Error):
            contract.errors.append(self.parse_error())
        elif self.match(TokenType.Enum):
            contract.enums.append(self.parse_enum())
        elif self.match(TokenType.Struct):
            contract.structs.append(self.parse_struct())
        elif self.match(TokenType.Function):
            func = self.parse_function()
            func.visibility = visibility
            func.mutability = mutability
            func.is_virtual = is_virtual
            func.is_override = is_override
            contract.functions.append(func)
        elif self.match(TokenType.Modifier):
            mod = self.parse_modifier()
            mod.visibility = visibility
            mod.is_virtual = is_virtual
            mod.is_override = is_override
            contract.modifiers.append(mod)
        elif self.match(TokenType.Identifier) and self.peek().token_type in (TokenType.Identifier, TokenType.SEMICOLON, TokenType.EQUAL, TokenType.LBRACKET):
            # State variable
            var = self.parse_state_variable()
            var.visibility = visibility
            var.mutability = mutability
            contract.state_variables.append(var)
        else:
            logger.warning(f"Unexpected member at {self.current()}")
            self.advance()
    
    def parse_function(self) -> Function:
        """Parse function definition."""
        self.expect(TokenType.Function)
        name = self.expect(TokenType.Identifier).value
        
        func = Function(name)
        
        # Parse parameters
        self.expect(TokenType.LPAREN, '(')
        if not self.match(TokenType.RPAREN, ')'):
            func.parameters = self.parse_parameter_list()
        self.expect(TokenType.RPAREN, ')')
        
        # Parse modifiers and return parameters
        while True:
            if self.match(TokenType.Returns):
                self.advance()
                self.expect(TokenType.LPAREN, '(')
                if not self.match(TokenType.RPAREN, ')'):
                    func.return_parameters = self.parse_parameter_list()
                self.expect(TokenType.RPAREN, ')')
            elif self.match(TokenType.Identifier):
                func.modifiers.append(self.parse_identifier())
            else:
                break
        
        # Parse function body
        if self.match(TokenType.LBRACE, '{'):
            func.body = self.parse_block()
        
        return func
    
    def parse_modifier(self) -> Any:
        """Parse modifier definition."""
        self.expect(TokenType.Modifier)
        name = self.expect(TokenType.Identifier).value
        
        modifier = Modifier(name)
        
        # Parse parameters
        if self.match(TokenType.LPAREN, '('):
            self.advance()
            if not self.match(TokenType.RPAREN, ')'):
                modifier.parameters = self.parse_parameter_list()
            self.expect(TokenType.RPAREN, ')')
        
        # Parse body
        if self.match(TokenType.LBRACE, '{'):
            modifier.body = self.parse_block()
        elif self.match(TokenType.SEMICOLON, ';'):
            self.advance()
        elif self.match(TokenType.Identifier):
            # Inline modifier body
            pass
        
        return modifier
    
    def parse_parameter_list(self) -> List[Parameter]:
        """Parse parameter list."""
        params = []
        
        while True:
            param_type = self.parse_type_name()
            name = ''
            
            if self.match(TokenType.Identifier):
                name = self.advance().value
            
            param = Parameter(name, param_type)
            
            if self.consume(TokenType.Indexed, 'indexed'):
                param.is_indexed = True
            
            params.append(param)
            
            if not self.consume(TokenType.COMMA, ','):
                break
        
        return params
    
    def parse_state_variable(self) -> StateVariable:
        """Parse state variable declaration."""
        var_type = self.parse_type_name()
        name = self.expect(TokenType.Identifier).value
        
        var = StateVariable(name, var_type)
        
        # Parse immutability/const
        if self.consume(TokenType.Immutable, 'immutable'):
            var.is_immutable = True
        elif self.consume(TokenType.Constant, 'constant'):
            var.is_constant = True
        
        # Parse initial value
        if self.consume(TokenType.EQUAL, '='):
            var.initial_value = self.parse_expression()
        
        self.consume(TokenType.SEMICOLON, ';')
        
        return var
    
    def parse_type_name(self) -> Node:
        """Parse a type name."""
        if self.match(TokenType.Address):
            type_name = ElementaryTypeName(self.advance().value)
            if self.consume(TokenType.Payable, 'payable'):
                return type_name  # address payable
            return type_name
        elif self.match(TokenType.Bool):
            return ElementaryTypeName(self.advance().value)
        elif self.match(TokenType.String):
            return ElementaryTypeName(self.advance().value)
        elif self.match(TokenType.Bytes):
            if self.match(TokenType.INTEGER):
                return ElementaryTypeName(self.advance().value)
            return ElementaryTypeName(self.advance().value)
        elif self.match(TokenType.Int):
            size = ''
            if self.match(TokenType.INTEGER):
                size = self.advance().value
            return ElementaryTypeName(f"int{size}")
        elif self.match(TokenType.Uint):
            size = ''
            if self.match(TokenType.INTEGER):
                size = self.advance().value
            return ElementaryTypeName(f"uint{size}")
        elif self.match(TokenType.Fixed):
            return ElementaryTypeName(self.advance().value)
        elif self.match(TokenType.Ufixed):
            return ElementaryTypeName(self.advance().value)
        elif self.match(TokenType.Identifier):
            return UserDefinedTypeName(self.advance().value)
        elif self.match(TokenType.Mapping):
            return self.parse_mapping()
        elif self.match(TokenType.Function):
            return self.parse_function_type()
        else:
            return ElementaryTypeName("unknown")
    
    def parse_mapping(self) -> Mapping:
        """Parse mapping type."""
        self.expect(TokenType.Mapping)
        self.expect(TokenType.LPAREN, '(')
        
        key_type = self.parse_type_name()
        
        self.expect(TokenType.Arrow)  # =>
        
        value_type = self.parse_type_name()
        
        self.expect(TokenType.RPAREN, ')')
        
        return Mapping(key_type, value_type)
    
    def parse_function_type(self) -> Any:
        """Parse function type."""
        self.expect(TokenType.Function)
        self.expect(TokenType.LPAREN, '(')
        # Simplified - skip parameter parsing
        self.expect(TokenType.RPAREN, ')')
        return ElementaryTypeName("function")
    
    def parse_block(self) -> Block:
        """Parse a block."""
        self.expect(TokenType.LBRACE, '{')
        block = Block()
        
        while not self.match(TokenType.RBRACE, '}') and not self.match(TokenType.EOF):
            block.statements.append(self.parse_statement())
        
        self.expect(TokenType.RBRACE, '}')
        
        return block
    
    def parse_statement(self) -> Statement:
        """Parse a statement."""
        if self.match(TokenType.LBRACE, '{'):
            return self.parse_block()
        elif self.match(TokenType.If, 'if'):
            return self.parse_if_statement()
        elif self.match(TokenType.While, 'while'):
            return self.parse_while_statement()
        elif self.match(TokenType.For, 'for'):
            return self.parse_for_statement()
        elif self.match(TokenType.Do, 'do'):
            return self.parse_do_while_statement()
        elif self.match(TokenType.Return, 'return'):
            return self.parse_return_statement()
        elif self.match(TokenType.Break, 'break'):
            self.advance()
            self.consume(TokenType.SEMICOLON, ';')
            return BreakStatement()
        elif self.match(TokenType.Continue, 'continue'):
            self.advance()
            self.consume(TokenType.SEMICOLON, ';')
            return ContinueStatement()
        elif self.match(TokenType.Emit, 'emit'):
            return self.parse_emit_statement()
        elif self.match(TokenType.Require, 'require'):
            return self.parse_require_statement()
        elif self.match(TokenType.Assert, 'assert'):
            return self.parse_assert_statement()
        elif self.match(TokenType.Revert, 'revert'):
            return self.parse_revert_statement()
        elif self.match(TokenType.Throw, 'throw'):
            self.advance()
            self.consume(TokenType.SEMICOLON, ';')
            return BreakStatement()  # throw is similar to revert
        elif self.match(TokenType.Semicolon, ';'):
            self.advance()
            return ExpressionStatement(Literal(""))
        else:
            return self.parse_expression_statement()
    
    def parse_if_statement(self) -> IfStatement:
        """Parse if statement."""
        self.expect(TokenType.If, 'if')
        self.expect(TokenType.LPAREN, '(')
        condition = self.parse_expression()
        self.expect(TokenType.RPAREN, ')')
        
        true_body = self.parse_statement()
        false_body = None
        
        if self.consume(TokenType.Else, 'else'):
            false_body = self.parse_statement()
        
        return IfStatement(condition, true_body, false_body)
    
    def parse_while_statement(self) -> WhileStatement:
        """Parse while statement."""
        self.expect(TokenType.While, 'while')
        self.expect(TokenType.LPAREN, '(')
        condition = self.parse_expression()
        self.expect(TokenType.RPAREN, ')')
        
        body = self.parse_statement()
        
        return WhileStatement(condition, body)
    
    def parse_for_statement(self) -> ForStatement:
        """Parse for statement."""
        self.expect(TokenType.For, 'for')
        self.expect(TokenType.LPAREN, '(')
        
        stmt = ForStatement()
        
        # Init
        if not self.match(TokenType.Semicolon, ';'):
            if self.match(TokenType.Var, 'var') or self.match(TokenType.Identifier):
                stmt.init = self.parse_variable_declaration()
            else:
                stmt.init = self.parse_expression_statement()
        self.expect(TokenType.Semicolon, ';')
        
        # Condition
        if not self.match(TokenType.Semicolon, ';'):
            stmt.condition = self.parse_expression()
        self.expect(TokenType.Semicolon, ';')
        
        # Update
        if not self.match(TokenType.RPAREN, ')'):
            stmt.update = self.parse_expression_statement()
        
        self.expect(TokenType.RPAREN, ')')
        
        stmt.body = self.parse_statement()
        
        return stmt
    
    def parse_do_while_statement(self) -> WhileStatement:
        """Parse do-while statement."""
        self.expect(TokenType.Do, 'do')
        
        body = self.parse_statement()
        
        self.expect(TokenType.While, 'while')
        self.expect(TokenType.LPAREN, '(')
        condition = self.parse_expression()
        self.expect(TokenType.RPAREN, ')')
        self.consume(TokenType.Semicolon, ';')
        
        stmt = WhileStatement(condition, body)
        stmt.is_do_while = True
        return stmt
    
    def parse_return_statement(self) -> ReturnStatement:
        """Parse return statement."""
        self.expect(TokenType.Return, 'return')
        
        expr = None
        if not self.match(TokenType.Semicolon, ';'):
            expr = self.parse_expression()
        
        self.consume(TokenType.Semicolon, ';')
        
        return ReturnStatement(expr)
    
    def parse_emit_statement(self) -> EmitStatement:
        """Parse emit statement."""
        self.expect(TokenType.Emit, 'emit')
        event = self.parse_expression()
        
        self.consume(TokenType.Semicolon, ';')
        
        return EmitStatement(event)
    
    def parse_require_statement(self) -> RequireStatement:
        """Parse require statement."""
        self.expect(TokenType.Require, 'require')
        self.expect(TokenType.LPAREN, '(')
        
        condition = self.parse_expression()
        message = None
        
        if self.consume(TokenType.COMMA, ','):
            message = self.parse_expression()
        
        self.expect(TokenType.RPAREN, ')')
        self.consume(TokenType.SEMICOLON, ';')
        
        return RequireStatement(condition, message)
    
    def parse_assert_statement(self) -> AssertStatement:
        """Parse assert statement."""
        self.expect(TokenType.Assert, 'assert')
        self.expect(TokenType.LPAREN, '(')
        
        condition = self.parse_expression()
        message = None
        
        if self.consume(TokenType.COMMA, ','):
            message = self.parse_expression()
        
        self.expect(TokenType.RPAREN, ')')
        self.consume(TokenType.SEMICOLON, ';')
        
        return AssertStatement(condition, message)
    
    def parse_revert_statement(self) -> RevertStatement:
        """Parse revert statement."""
        self.expect(TokenType.Revert, 'revert')
        
        error_call = None
        if self.match(TokenType.LPAREN, '('):
            self.advance()
            if not self.match(TokenType.RPAREN, ')'):
                error_call = self.parse_expression()
            self.expect(TokenType.RPAREN, ')')
        
        self.consume(TokenType.SEMICOLON, ';')
        
        return RevertStatement(error_call)
    
    def parse_variable_declaration(self) -> VariableDeclarationStatement:
        """Parse variable declaration statement."""
        # Simplified
        self.expect(TokenType.Var, 'var')
        name = self.expect(TokenType.Identifier).value
        
        initial_value = None
        if self.consume(TokenType.EQUAL, '='):
            initial_value = self.parse_expression()
        
        self.consume(TokenType.SEMICOLON, ';')
        
        return VariableDeclarationStatement([Parameter(name, ElementaryTypeName("uint256"))], initial_value)
    
    def parse_expression_statement(self) -> ExpressionStatement:
        """Parse expression statement."""
        expr = self.parse_expression()
        self.consume(TokenType.SEMICOLON, ';')
        return ExpressionStatement(expr)
    
    def parse_expression(self) -> Expression:
        """Parse expression."""
        return self.parse_assignment()
    
    def parse_assignment(self) -> Expression:
        """Parse assignment expression."""
        expr = self.parse_conditional()
        
        if self.match(TokenType.EQUAL, '='):
            self.advance()
            right = self.parse_assignment()
            expr = Assignment(expr, right, '=')
        elif self.match(TokenType.PLUS_EQUAL, '+='):
            self.advance()
            right = self.parse_assignment()
            expr = Assignment(expr, right, '+=')
        elif self.match(TokenType.MINUS_EQUAL, '-='):
            self.advance()
            right = self.parse_assignment()
            expr = Assignment(expr, right, '-=')
        elif self.match(TokenType.STAR_EQUAL, '*='):
            self.advance()
            right = self.parse_assignment()
            expr = Assignment(expr, right, '*=')
        elif self.match(TokenType.SLASH_EQUAL, '/='):
            self.advance()
            right = self.parse_assignment()
            expr = Assignment(expr, right, '/=')
        
        return expr
    
    def parse_conditional(self) -> Expression:
        """Parse conditional expression."""
        expr = self.parse_logical_or()
        
        if self.match(TokenType.QUESTION, '?'):
            self.advance()
            true_expr = self.parse_expression()
            self.expect(TokenType.COLON, ':')
            false_expr = self.parse_conditional()
            expr = Conditional(expr, true_expr, false_expr)
        
        return expr
    
    def parse_logical_or(self) -> Expression:
        """Parse logical OR expression."""
        left = self.parse_logical_and()
        
        while self.match(TokenType.BAR_BAR, '||'):
            self.advance()
            right = self.parse_logical_and()
            left = BinaryOp('||', left, right)
        
        return left
    
    def parse_logical_and(self) -> Expression:
        """Parse logical AND expression."""
        left = self.parse_bitwise_or()
        
        while self.match(TokenType.AMPERSAND_AMPERSAND, '&&'):
            self.advance()
            right = self.parse_bitwise_or()
            left = BinaryOp('&&', left, right)
        
        return left
    
    def parse_bitwise_or(self) -> Expression:
        """Parse bitwise OR expression."""
        left = self.parse_bitwise_xor()
        
        while self.match(TokenType.BAR, '|') and not self.match(TokenType.BAR_BAR, '||'):
            self.advance()
            right = self.parse_bitwise_xor()
            left = BinaryOp('|', left, right)
        
        return left
    
    def parse_bitwise_xor(self) -> Expression:
        """Parse bitwise XOR expression."""
        left = self.parse_bitwise_and()
        
        while self.match(TokenType.CARET, '^'):
            self.advance()
            right = self.parse_bitwise_and()
            left = BinaryOp('^', left, right)
        
        return left
    
    def parse_bitwise_and(self) -> Expression:
        """Parse bitwise AND expression."""
        left = self.parse_equality()
        
        while self.match(TokenType.AMPERSAND, '&') and not self.match(TokenType.AMPERSAND_AMPERSAND, '&&'):
            self.advance()
            right = self.parse_equality()
            left = BinaryOp('&', left, right)
        
        return left
    
    def parse_equality(self) -> Expression:
        """Parse equality expressions."""
        left = self.parse_comparison()
        
        while True:
            if self.match(TokenType.EQUAL_EQUAL, '=='):
                self.advance()
                right = self.parse_comparison()
                left = BinaryOp('==', left, right)
            elif self.match(TokenType.EXCLAMATION_EQUAL, '!='):
                self.advance()
                right = self.parse_comparison()
                left = BinaryOp('!=', left, right)
            else:
                break
        
        return left
    
    def parse_comparison(self) -> Expression:
        """Parse comparison expressions."""
        left = self.parse_shift()
        
        while True:
            if self.match(TokenType.LESS_EQUAL, '<='):
                self.advance()
                right = self.parse_shift()
                left = BinaryOp('<=', left, right)
            elif self.match(TokenType.GREATER_EQUAL, '>='):
                self.advance()
                right = self.parse_shift()
                left = BinaryOp('>=', left, right)
            elif self.match(TokenType.LESS_LESS, '<<'):
                self.advance()
                right = self.parse_shift()
                left = BinaryOp('<<', left, right)
            elif self.match(TokenType.GREATER_GREATER, '>>'):
                self.advance()
                right = self.parse_shift()
                left = BinaryOp('>>', left, right)
            elif self.match(TokenType.GREATER_GREATER_GREATER, '>>>'):
                self.advance()
                right = self.parse_shift()
                left = BinaryOp('>>>', left, right)
            elif self.match(TokenType.LESS, '<'):
                self.advance()
                right = self.parse_shift()
                left = BinaryOp('<', left, right)
            elif self.match(TokenType.GREATER, '>'):
                self.advance()
                right = self.parse_shift()
                left = BinaryOp('>', left, right)
            else:
                break
        
        return left
    
    def parse_shift(self) -> Expression:
        """Parse shift expressions."""
        left = self.parse_additive()
        
        while True:
            if self.match(TokenType.LESS_LESS, '<<'):
                self.advance()
                right = self.parse_additive()
                left = BinaryOp('<<', left, right)
            elif self.match(TokenType.GREATER_GREATER, '>>'):
                self.advance()
                right = self.parse_additive()
                left = BinaryOp('>>', left, right)
            elif self.match(TokenType.GREATER_GREATER_GREATER, '>>>'):
                self.advance()
                right = self.parse_additive()
                left = BinaryOp('>>>', left, right)
            else:
                break
        
        return left
    
    def parse_additive(self) -> Expression:
        """Parse additive expressions."""
        left = self.parse_multiplicative()
        
        while True:
            if self.match(TokenType.PLUS, '+'):
                self.advance()
                right = self.parse_multiplicative()
                left = BinaryOp('+', left, right)
            elif self.match(TokenType.MINUS, '-'):
                self.advance()
                right = self.parse_multiplicative()
                left = BinaryOp('-', left, right)
            else:
                break
        
        return left
    
    def parse_multiplicative(self) -> Expression:
        """Parse multiplicative expressions."""
        left = self.parse_unary()
        
        while True:
            if self.match(TokenType.STAR, '*'):
                self.advance()
                right = self.parse_unary()
                left = BinaryOp('*', left, right)
            elif self.match(TokenType.SLASH, '/'):
                self.advance()
                right = self.parse_unary()
                left = BinaryOp('/', left, right)
            elif self.match(TokenType.PERCENT, '%'):
                self.advance()
                right = self.parse_unary()
                left = BinaryOp('%', left, right)
            elif self.match(TokenType.DOUBLE_STAR, '**'):
                self.advance()
                right = self.parse_unary()
                left = BinaryOp('**', left, right)
            else:
                break
        
        return left
    
    def parse_unary(self) -> Expression:
        """Parse unary expressions."""
        if self.match(TokenType.PLUS_PLUS, '++'):
            self.advance()
            operand = self.parse_unary()
            return UnaryOp('++', operand, True)
        elif self.match(TokenType.MINUS_MINUS, '--'):
            self.advance()
            operand = self.parse_unary()
            return UnaryOp('--', operand, True)
        elif self.match(TokenType.MINUS, '-'):
            self.advance()
            operand = self.parse_unary()
            return UnaryOp('-', operand, True)
        elif self.match(TokenType.EXCLAMATION, '!'):
            self.advance()
            operand = self.parse_unary()
            return UnaryOp('!', operand, True)
        elif self.match(TokenType.TILDE, '~'):
            self.advance()
            operand = self.parse_unary()
            return UnaryOp('~', operand, True)
        elif self.match(TokenType.Delete, 'delete'):
            self.advance()
            operand = self.parse_unary()
            return UnaryOp('delete', operand, True)
        else:
            return self.parse_postfix()
    
    def parse_postfix(self) -> Expression:
        """Parse postfix expressions."""
        expr = self.parse_primary()
        
        while True:
            if self.match(TokenType.PLUS_PLUS, '++'):
                self.advance()
                expr = UnaryOp('++', expr, False)
            elif self.match(TokenType.MINUS_MINUS, '--'):
                self.advance()
                expr = UnaryOp('--', expr, False)
            elif self.match(TokenType.LBRACKET, '['):
                self.advance()
                index = self.parse_expression()
                self.expect(TokenType.RBRACKET, ']')
                expr = IndexAccess(expr, index)
            elif self.match(TokenType.DOT, '.'):
                self.advance()
                member = self.expect(TokenType.Identifier).value
                expr = MemberAccess(expr, member)
            else:
                break
        
        return expr
    
    def parse_primary(self) -> Expression:
        """Parse primary expressions."""
        if self.match(TokenType.New, 'new'):
            self.advance()
            contract_type = self.parse_type_name()
            return NewExpression(contract_type)
        elif self.match(TokenType.Type, 'type'):
            self.advance()
            return Identifier("type")
        elif self.match(TokenType.LPAREN, '('):
            self.advance()
            expr = self.parse_expression()
            self.expect(TokenType.RPAREN, ')')
            return expr
        elif self.match(TokenType.INTEGER):
            value = self.advance().value
            return Literal(int(value, 0) if value.startswith(('0x', '0b', '0o')) else int(value))
        elif self.match(TokenType.STRING):
            value = self.advance().value
            return Literal(value)
        elif self.match(TokenType.Identifier):
            name = self.advance().value
            expr = Identifier(name)
            
            if self.match(TokenType.LPAREN, '('):
                return self.parse_function_call_expression(expr)
            
            return expr
        else:
            logger.warning(f"Unexpected token in primary: {self.current()}")
            self.advance()
            return Literal(0)
    
    def parse_function_call_expression(self, callee: Expression) -> FunctionCall:
        """Parse function call expression."""
        self.expect(TokenType.LPAREN, '(')
        
        args = []
        if not self.match(TokenType.RPAREN, ')'):
            args = self.parse_expression_list()
        
        self.expect(TokenType.RPAREN, ')')
        
        return FunctionCall(callee, args)
    
    def parse_expression_list(self) -> List[Expression]:
        """Parse expression list."""
        expressions = []
        
        while True:
            expressions.append(self.parse_expression())
            
            if not self.consume(TokenType.COMMA, ','):
                break
        
        return expressions
    
    def parse_identifier(self) -> Identifier:
        """Parse identifier."""
        return Identifier(self.expect(TokenType.Identifier).value)
    
    def parse_event(self) -> Event:
        """Parse event definition."""
        self.expect(TokenType.Event)
        name = self.expect(TokenType.Identifier).value
        
        params = []
        if self.match(TokenType.LPAREN, '('):
            self.advance()
            if not self.match(TokenType.RPAREN, ')'):
                params = self.parse_parameter_list()
            self.expect(TokenType.RPAREN, ')')
        
        event = Event(name, params)
        
        if self.consume(TokenType.Anonymous, 'anonymous'):
            event.is_anonymous = True
        
        self.consume(TokenType.SEMICOLON, ';')
        
        return event
    
    def parse_error(self) -> Error:
        """Parse error definition."""
        self.expect(TokenType.Error)
        name = self.expect(TokenType.Identifier).value
        
        params = []
        if self.match(TokenType.LPAREN, '('):
            self.advance()
            if not self.match(TokenType.RPAREN, ')'):
                params = self.parse_parameter_list()
            self.expect(TokenType.RPAREN, ')')
        
        self.consume(TokenType.SEMICOLON, ';')
        
        return Error(name, params)
    
    def parse_enum(self) -> EnumDefinition:
        """Parse enum definition."""
        self.expect(TokenType.Enum)
        name = self.expect(TokenType.Identifier).value
        
        members = []
        self.expect(TokenType.LBRACE, '{')
        
        while not self.match(TokenType.RBRACE, '}') and not self.match(TokenType.EOF):
            members.append(self.expect(TokenType.Identifier).value)
            if not self.consume(TokenType.COMMA, ','):
                break
        
        self.expect(TokenType.RBRACE, '}')
        
        return EnumDefinition(name, members)
    
    def parse_struct(self) -> StructDefinition:
        """Parse struct definition."""
        self.expect(TokenType.Struct)
        name = self.expect(TokenType.Identifier).value
        
        members = []
        self.expect(TokenType.LBRACE, '{')
        
        while not self.match(TokenType.RBRACE, '}') and not self.match(TokenType.EOF):
            var_type = self.parse_type_name()
            var_name = self.expect(TokenType.Identifier).value
            members.append(StateVariable(var_name, var_type))
            self.consume(TokenType.SEMICOLON, ';')
        
        self.expect(TokenType.RBRACE, '}')
        
        return StructDefinition(name, members)


class SolidityParser:
    """
    High-level Solidity parser interface.
    
    Provides methods for parsing Solidity source code and files.
    """
    
    def __init__(self):
        self.ast_cache: Dict[str, SourceUnit] = {}
    
    def parse_source(self, source: str) -> SourceUnit:
        """
        Parse Solidity source code.
        
        Args:
            source: Solidity source code string
            
        Returns:
            SourceUnit AST
        """
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        return parser.parse()
    
    def parse_file(self, filepath: str) -> SourceUnit:
        """
        Parse a Solidity file.
        
        Args:
            filepath: Path to Solidity file
            
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
    
    def get_function(self, source_unit: SourceUnit, contract_name: str, function_name: str) -> Optional[Function]:
        """Get a function from a contract."""
        for contract in source_unit.contracts:
            if contract.name == contract_name:
                return contract.get_function(function_name)
        return None
    
    def get_state_variables(self, contract: Contract) -> List[StateVariable]:
        """Get all state variables from a contract."""
        return contract.state_variables
    
    def get_functions(self, contract: Contract) -> List[Function]:
        """Get all functions from a contract."""
        return contract.functions
