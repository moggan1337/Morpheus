"""
Abstract Syntax Tree (AST) for Solidity and Vyper
=================================================

This module defines the AST node types used to represent
smart contract source code for formal verification.

Author: Morpheus Team
"""

from __future__ import annotations
from typing import List, Optional, Dict, Any, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod


class NodeType(Enum):
    """Enumeration of AST node types."""
    # Source level
    SOURCE_UNIT = auto()
    PRAGMA_DIRECTIVE = auto()
    IMPORT_DIRECTIVE = auto()
    
    # Contract level
    CONTRACT_DEFINITION = auto()
    INTERFACE_DEFINITION = auto()
    LIBRARY_DEFINITION = auto()
    ENUM_DEFINITION = auto()
    STRUCT_DEFINITION = auto()
    
    # Members
    FUNCTION_DEFINITION = auto()
    FUNCTION_CALL = auto()
    STATE_VARIABLE_DECLARATION = auto()
    EVENT_DEFINITION = auto()
    ERROR_DEFINITION = auto()
    MODIFIER_DEFINITION = auto()
    CONSTRUCTOR_DEFINITION = auto()
    FALLBACK_FUNCTION = auto()
    RECEIVE_FUNCTION = auto()
    
    # Statements
    BLOCK = auto()
    VARIABLE_DECLARATION = auto()
    ASSIGNMENT = auto()
    EXPRESSION_STATEMENT = auto()
    IF_STATEMENT = auto()
    WHILE_STATEMENT = auto()
    DO_WHILE_STATEMENT = auto()
    FOR_STATEMENT = auto()
    CONTINUE_STATEMENT = auto()
    BREAK_STATEMENT = auto()
    RETURN_STATEMENT = auto()
    THROW_STATEMENT = auto()
    ASSERT_STATEMENT = auto()
    REQUIRE_STATEMENT = auto()
    REVERT_STATEMENT = auto()
    EMIT_STATEMENT = auto()
    
    # Expressions
    IDENTIFIER = auto()
    LITERAL = auto()
    BINARY_OPERATION = auto()
    UNARY_OPERATION = auto()
    TERNARY_OPERATION = auto()
    INDEX_ACCESS = auto()
    MEMBER_ACCESS = auto()
    FUNCTION_CALL = auto()
    NEW_EXPRESSION = auto()
    TYPE_CONVERSION = auto()
    MAPPING = auto()
    ARRAY_LITERAL = auto()
    STRUCT_LITERAL = auto()
    
    # Types
    ELEMENTARY_TYPE = auto()
    ARRAY_TYPE = auto()
    MAPPING_TYPE = auto()
    USER_DEFINED_TYPE = auto()
    FUNCTION_TYPE = auto()
    ADDRESS_TYPE = auto()
    BOOL_TYPE = auto()
    INT_TYPE = auto()
    UINT_TYPE = auto()
    BYTES_TYPE = auto()
    STRING_TYPE = auto()
    FIXED_TYPE = auto()
    UFIXED_TYPE = auto()


class ContractType(Enum):
    """Types of contracts."""
    CONTRACT = auto()
    INTERFACE = auto()
    LIBRARY = auto()
    ABSTRACT = auto()


class Visibility(Enum):
    """Function and state variable visibility."""
    PUBLIC = auto()
    PRIVATE = auto()
    INTERNAL = auto()
    EXTERNAL = auto()


class StateMutability(Enum):
    """State mutability specifiers."""
    PURE = auto()
    VIEW = auto()
    PAYABLE = auto()
    NONPAYABLE = auto()


@dataclass
class SourceLocation:
    """Source code location information."""
    file: str = ""
    start_line: int = 0
    start_column: int = 0
    end_line: int = 0
    end_column: int = 0
    
    @property
    def line_range(self) -> str:
        """Get line range as string."""
        if self.start_line == self.end_line:
            return f"{self.start_line}"
        return f"{self.start_line}-{self.end_line}"
    
    def __str__(self) -> str:
        return f"{self.file}:{self.line_range}"


class Node(ABC):
    """Base class for all AST nodes."""
    
    def __init__(
        self,
        node_type: NodeType,
        location: Optional[SourceLocation] = None,
        doc_string: Optional[str] = None
    ):
        self.node_type = node_type
        self.location = location or SourceLocation()
        self.doc_string = doc_string
        self.attributes: Dict[str, Any] = {}
        self.parent: Optional[Node] = None
    
    @abstractmethod
    def accept(self, visitor: Any) -> Any:
        """Accept a visitor for pattern matching."""
        pass
    
    def children(self) -> List[Node]:
        """Get all child nodes."""
        return []
    
    def find_children(self, node_type: NodeType) -> List[Node]:
        """Find all descendant nodes of a specific type."""
        result = []
        for child in self.children():
            if child.node_type == node_type:
                result.append(child)
            if hasattr(child, 'find_children'):
                result.extend(child.find_children(node_type))
        return result
    
    def get_ancestors(self) -> List[Node]:
        """Get all ancestor nodes up to the root."""
        ancestors = []
        current = self.parent
        while current:
            ancestors.append(current)
            current = current.parent
        return ancestors
    
    def set_parent(self, parent: Node) -> None:
        """Set parent and update parent references."""
        self.parent = parent


@dataclass
class SourceUnit(Node):
    """Root node representing a source file."""
    
    def __init__(self, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.SOURCE_UNIT, location)
        self.license: Optional[str] = None
        self.pragmas: List[PragmaDirective] = field(default_factory=list)
        self.imports: List[ImportDirective] = field(default_factory=list)
        self.contracts: List[Contract] = field(default_factory=list)
        self.enums: List[EnumDefinition] = field(default_factory=list)
        self.structs: List[StructDefinition] = field(default_factory=list)
        self.functions: List[FunctionDefinition] = field(default_factory=list)
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_source_unit(self)
    
    def children(self) -> List[Node]:
        children = []
        children.extend(self.pragmas)
        children.extend(self.imports)
        children.extend(self.contracts)
        return children


@dataclass
class PragmaDirective(Node):
    """Pragma directive node."""
    
    def __init__(self, name: str, value: str, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.PRAGMA_DIRECTIVE, location)
        self.name = name
        self.value = value
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_pragma(self)


@dataclass
class ImportDirective(Node):
    """Import directive node."""
    
    def __init__(self, path: str, alias: Optional[str] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.IMPORT_DIRECTIVE, location)
        self.path = path
        self.alias = alias
        self.symbol_aliases: Dict[str, str] = {}
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_import(self)


@dataclass
class Contract(Node):
    """
    Contract definition node.
    
    Represents a Solidity contract, interface, or library.
    """
    
    def __init__(
        self,
        name: str,
        contract_type: ContractType = ContractType.CONTRACT,
        location: Optional[SourceLocation] = None
    ):
        super().__init__(NodeType.CONTRACT_DEFINITION, location)
        self.name = name
        self.contract_type = contract_type
        self.base_contracts: List[Identifier] = field(default_factory=list)
        self.state_variables: List[StateVariable] = field(default_factory=list)
        self.functions: List[Function] = field(default_factory=list)
        self.modifiers: List[Modifier] = field(default_factory=list)
        self.events: List[Event] = field(default_factory=list)
        self.errors: List[Error] = field(default_factory=list)
        self.enums: List[EnumDefinition] = field(default_factory=list)
        self.structs: List[StructDefinition] = field(default_factory=list)
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_contract(self)
    
    def children(self) -> List[Node]:
        children = []
        children.extend(self.base_contracts)
        children.extend(self.state_variables)
        children.extend(self.functions)
        children.extend(self.modifiers)
        return children
    
    def get_function(self, name: str) -> Optional[Function]:
        """Get a function by name."""
        for func in self.functions:
            if func.name == name:
                return func
        return None
    
    def get_state_variable(self, name: str) -> Optional[StateVariable]:
        """Get a state variable by name."""
        for var in self.state_variables:
            if var.name == name:
                return var
        return None


@dataclass
class StateVariable(Node):
    """State variable declaration node."""
    
    def __init__(
        self,
        name: str,
        var_type: Node,
        visibility: Visibility = Visibility.PUBLIC,
        mutability: StateMutability = StateMutability.NONPAYABLE,
        location: Optional[SourceLocation] = None
    ):
        super().__init__(NodeType.STATE_VARIABLE_DECLARATION, location)
        self.name = name
        self.var_type = var_type
        self.visibility = visibility
        self.mutability = mutability
        self.initial_value: Optional[Expression] = None
        self.is_constant: bool = False
        self.is_immutable: bool = False
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_state_variable(self)
    
    def children(self) -> List[Node]:
        children = [self.var_type]
        if self.initial_value:
            children.append(self.initial_value)
        return children


@dataclass
class Function(Node):
    """
    Function definition node.
    
    Represents a Solidity function including constructor,
    fallback, and receive functions.
    """
    
    def __init__(
        self,
        name: str,
        location: Optional[SourceLocation] = None
    ):
        super().__init__(NodeType.FUNCTION_DEFINITION, location)
        self.name = name
        self.parameters: List[Parameter] = field(default_factory=list)
        self.return_parameters: List[Parameter] = field(default_factory=list)
        self.visibility: Visibility = Visibility.PUBLIC
        self.mutability: StateMutability = StateMutability.NONPAYABLE
        self.modifiers: List[Identifier] = field(default_factory=list)
        self.body: Optional[Block] = None
        self.overrides: Optional[Identifier] = None
        self.is_virtual: bool = False
        self.is_override: bool = False
        self.is_constructor: bool = False
        self.is_fallback: bool = False
        self.is_receive: bool = False
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_function(self)
    
    def children(self) -> List[Node]:
        children = []
        children.extend(self.parameters)
        children.extend(self.return_parameters)
        children.extend(self.modifiers)
        if self.body:
            children.append(self.body)
        return children
    
    def get_parameter_names(self) -> List[str]:
        """Get list of parameter names."""
        return [p.name for p in self.parameters]
    
    def get_return_names(self) -> List[str]:
        """Get list of return parameter names."""
        return [p.name for p in self.return_parameters]


@dataclass
class Parameter(Node):
    """Function parameter node."""
    
    def __init__(
        self,
        name: str,
        param_type: Node,
        location: Optional[SourceLocation] = None
    ):
        super().__init__(NodeType.VARIABLE_DECLARATION, location)
        self.name = name
        self.param_type = param_type
        self.is_indexed: bool = False
        self.is_storage: bool = False
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_parameter(self)
    
    def children(self) -> List[Node]:
        return [self.param_type]


@dataclass
class Modifier(Node):
    """Modifier definition node."""
    
    def __init__(
        self,
        name: str,
        location: Optional[SourceLocation] = None
    ):
        super().__init__(NodeType.MODIFIER_DEFINITION, location)
        self.name = name
        self.parameters: List[Parameter] = field(default_factory=list)
        self.body: Optional[Block] = None
        self.visibility: Visibility = Visibility.INTERNAL
        self.is_virtual: bool = False
        self.is_override: bool = False
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_modifier(self)
    
    def children(self) -> List[Node]:
        children = []
        children.extend(self.parameters)
        if self.body:
            children.append(self.body)
        return children


@dataclass
class Block(Node):
    """Block statement node."""
    
    def __init__(self, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.BLOCK, location)
        self.statements: List[Statement] = field(default_factory=list)
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_block(self)
    
    def children(self) -> List[Node]:
        return self.statements


@dataclass
class Statement(Node):
    """Base class for statement nodes."""
    
    def __init__(self, node_type: NodeType, location: Optional[SourceLocation] = None):
        super().__init__(node_type, location)


@dataclass
class ExpressionStatement(Statement):
    """Expression statement node."""
    
    def __init__(self, expression: Expression, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.EXPRESSION_STATEMENT, location)
        self.expression = expression
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_expression_statement(self)
    
    def children(self) -> List[Node]:
        return [self.expression]


@dataclass
class IfStatement(Statement):
    """If statement node."""
    
    def __init__(self, condition: Expression, true_body: Statement, false_body: Optional[Statement] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.IF_STATEMENT, location)
        self.condition = condition
        self.true_body = true_body
        self.false_body = false_body
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_if_statement(self)
    
    def children(self) -> List[Node]:
        children = [self.condition, self.true_body]
        if self.false_body:
            children.append(self.false_body)
        return children


@dataclass
class WhileStatement(Statement):
    """While statement node."""
    
    def __init__(self, condition: Expression, body: Statement, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.WHILE_STATEMENT, location)
        self.condition = condition
        self.body = body
        self.is_do_while: bool = False
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_while_statement(self)
    
    def children(self) -> List[Node]:
        return [self.condition, self.body]


@dataclass
class ForStatement(Statement):
    """For statement node."""
    
    def __init__(self, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.FOR_STATEMENT, location)
        self.init: Optional[Statement] = None
        self.condition: Optional[Expression] = None
        self.update: Optional[Statement] = None
        self.body: Optional[Statement] = None
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_for_statement(self)
    
    def children(self) -> List[Node]:
        children = []
        if self.init:
            children.append(self.init)
        if self.condition:
            children.append(self.condition)
        if self.update:
            children.append(self.update)
        if self.body:
            children.append(self.body)
        return children


@dataclass
class ReturnStatement(Statement):
    """Return statement node."""
    
    def __init__(self, expression: Optional[Expression] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.RETURN_STATEMENT, location)
        self.expression = expression
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_return_statement(self)
    
    def children(self) -> List[Node]:
        if self.expression:
            return [self.expression]
        return []


@dataclass
class Expression(Node):
    """Base class for expression nodes."""
    
    def __init__(self, node_type: NodeType, location: Optional[SourceLocation] = None):
        super().__init__(node_type, location)
        self.evaluated_type: Optional[Node] = None


@dataclass
class Identifier(Expression):
    """Identifier expression node."""
    
    def __init__(self, name: str, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.IDENTIFIER, location)
        self.name = name
        self.referenced_node: Optional[Node] = None
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_identifier(self)
    
    def __str__(self) -> str:
        return self.name


@dataclass
class Literal(Expression):
    """Literal value expression node."""
    
    def __init__(self, value: Any, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.LITERAL, location)
        self.value = value
        self.token: str = ""
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_literal(self)
    
    def __str__(self) -> str:
        if isinstance(self.value, str):
            return f'"{self.value}"'
        return str(self.value)


@dataclass
class BinaryOp(Expression):
    """Binary operation expression node."""
    
    def __init__(
        self,
        operator: str,
        left: Expression,
        right: Expression,
        location: Optional[SourceLocation] = None
    ):
        super().__init__(NodeType.BINARY_OPERATION, location)
        self.operator = operator
        self.left = left
        self.right = right
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_binary_op(self)
    
    def children(self) -> List[Node]:
        return [self.left, self.right]
    
    def __str__(self) -> str:
        return f"({self.left} {self.operator} {self.right})"


@dataclass
class UnaryOp(Expression):
    """Unary operation expression node."""
    
    def __init__(
        self,
        operator: str,
        operand: Expression,
        is_prefix: bool = True,
        location: Optional[SourceLocation] = None
    ):
        super().__init__(NodeType.UNARY_OPERATION, location)
        self.operator = operator
        self.operand = operand
        self.is_prefix = is_prefix
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_unary_op(self)
    
    def children(self) -> List[Node]:
        return [self.operand]
    
    def __str__(self) -> str:
        if self.is_prefix:
            return f"{self.operator}{self.operand}"
        return f"{self.operand}{self.operator}"


@dataclass
class Assignment(Expression):
    """Assignment expression node."""
    
    def __init__(
        self,
        left: Expression,
        right: Expression,
        operator: str = "=",
        location: Optional[SourceLocation] = None
    ):
        super().__init__(NodeType.ASSIGNMENT, location)
        self.left = left
        self.right = right
        self.operator = operator
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_assignment(self)
    
    def children(self) -> List[Node]:
        return [self.left, self.right]
    
    def __str__(self) -> str:
        return f"{self.left} {self.operator} {self.right}"


@dataclass
class FunctionCall(Expression):
    """Function call expression node."""
    
    def __init__(self, callee: Expression, arguments: List[Expression] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.FUNCTION_CALL, location)
        self.callee = callee
        self.arguments = arguments or []
        self.names: List[str] = []
        self.is_tail_call: bool = False
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_function_call(self)
    
    def children(self) -> List[Node]:
        children = [self.callee]
        children.extend(self.arguments)
        return children


@dataclass
class IndexAccess(Expression):
    """Index access expression node (e.g., array[index])."""
    
    def __init__(self, base: Expression, index: Expression, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.INDEX_ACCESS, location)
        self.base = base
        self.index = index
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_index_access(self)
    
    def children(self) -> List[Node]:
        return [self.base, self.index]


@dataclass
class MemberAccess(Expression):
    """Member access expression node (e.g., object.member)."""
    
    def __init__(self, base: Expression, member_name: str, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.MEMBER_ACCESS, location)
        self.base = base
        self.member_name = member_name
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_member_access(self)
    
    def children(self) -> List[Node]:
        return [self.base]


@dataclass
class NewExpression(Expression):
    """New expression node (contract creation)."""
    
    def __init__(self, contract_type: Node, arguments: List[Expression] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.NEW_EXPRESSION, location)
        self.contract_type = contract_type
        self.arguments = arguments or []
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_new_expression(self)
    
    def children(self) -> List[Node]:
        children = [self.contract_type]
        children.extend(self.arguments)
        return children


@dataclass
class TypeConversion(Expression):
    """Type conversion expression node."""
    
    def __init__(self, expression: Expression, target_type: Node, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.TYPE_CONVERSION, location)
        self.expression = expression
        self.target_type = target_type
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_type_conversion(self)
    
    def children(self) -> List[Node]:
        return [self.expression, self.target_type]


@dataclass
class Conditional(Expression):
    """Conditional (ternary) expression node."""
    
    def __init__(self, condition: Expression, true_expr: Expression, false_expr: Expression, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.TERNARY_OPERATION, location)
        self.condition = condition
        self.true_expr = true_expr
        self.false_expr = false_expr
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_conditional(self)
    
    def children(self) -> List[Node]:
        return [self.condition, self.true_expr, self.false_expr]


@dataclass
class Event(Node):
    """Event definition node."""
    
    def __init__(self, name: str, parameters: List[Parameter] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.EVENT_DEFINITION, location)
        self.name = name
        self.parameters = parameters or []
        self.is_anonymous: bool = False
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_event(self)


@dataclass
class Error(Node):
    """Error definition node."""
    
    def __init__(self, name: str, parameters: List[Parameter] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.ERROR_DEFINITION, location)
        self.name = name
        self.parameters = parameters or []
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_error(self)


@dataclass
class EnumDefinition(Node):
    """Enum definition node."""
    
    def __init__(self, name: str, members: List[str] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.ENUM_DEFINITION, location)
        self.name = name
        self.members = members or []
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_enum(self)


@dataclass
class StructDefinition(Node):
    """Struct definition node."""
    
    def __init__(self, name: str, members: List[StateVariable] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.STRUCT_DEFINITION, location)
        self.name = name
        self.members = members or []
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_struct(self)


@dataclass
class EmitStatement(Statement):
    """Emit statement node."""
    
    def __init__(self, event: Expression, arguments: List[Expression] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.EMIT_STATEMENT, location)
        self.event = event
        self.arguments = arguments or []
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_emit(self)
    
    def children(self) -> List[Node]:
        children = [self.event]
        children.extend(self.arguments)
        return children


@dataclass
class RequireStatement(Statement):
    """Require statement node."""
    
    def __init__(self, condition: Expression, message: Optional[Expression] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.REQUIRE_STATEMENT, location)
        self.condition = condition
        self.message = message
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_require(self)
    
    def children(self) -> List[Node]:
        children = [self.condition]
        if self.message:
            children.append(self.message)
        return children


@dataclass
class AssertStatement(Statement):
    """Assert statement node."""
    
    def __init__(self, condition: Expression, message: Optional[Expression] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.ASSERT_STATEMENT, location)
        self.condition = condition
        self.message = message
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_assert(self)
    
    def children(self) -> List[Node]:
        children = [self.condition]
        if self.message:
            children.append(self.message)
        return children


@dataclass
class RevertStatement(Statement):
    """Revert statement node."""
    
    def __init__(self, error_call: Optional[FunctionCall] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.REVERT_STATEMENT, location)
        self.error_call = error_call
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_revert(self)
    
    def children(self) -> List[Node]:
        if self.error_call:
            return [self.error_call]
        return []


@dataclass
class BreakStatement(Statement):
    """Break statement node."""
    
    def __init__(self, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.BREAK_STATEMENT, location)
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_break(self)


@dataclass
class ContinueStatement(Statement):
    """Continue statement node."""
    
    def __init__(self, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.CONTINUE_STATEMENT, location)
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_continue(self)


@dataclass
class VariableDeclarationStatement(Statement):
    """Local variable declaration statement node."""
    
    def __init__(self, variables: List[Parameter] = None, initial_value: Optional[Expression] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.VARIABLE_DECLARATION, location)
        self.variables = variables or []
        self.initial_value = initial_value
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_variable_declaration(self)
    
    def children(self) -> List[Node]:
        children = self.variables
        if self.initial_value:
            children.append(self.initial_value)
        return children


class TypeNode(Node):
    """Base class for type nodes."""
    
    def __init__(self, node_type: NodeType, location: Optional[SourceLocation] = None):
        super().__init__(node_type, location)


@dataclass
class ElementaryTypeName(TypeNode):
    """Elementary type name node (e.g., uint256, address)."""
    
    def __init__(self, name: str, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.ELEMENTARY_TYPE, location)
        self.name = name
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_elementary_type(self)
    
    def __str__(self) -> str:
        return self.name


@dataclass
class ArrayTypeName(TypeNode):
    """Array type name node."""
    
    def __init__(self, base_type: TypeNode, length: Optional[int] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.ARRAY_TYPE, location)
        self.base_type = base_type
        self.length = length  # None means dynamic array
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_array_type(self)
    
    def __str__(self) -> str:
        if self.length:
            return f"{self.base_type}[{self.length}]"
        return f"{self.base_type}[]"


@dataclass
class Mapping(TypeNode):
    """Mapping type node."""
    
    def __init__(self, key_type: TypeNode, value_type: TypeNode, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.MAPPING_TYPE, location)
        self.key_type = key_type
        self.value_type = value_type
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_mapping(self)
    
    def __str__(self) -> str:
        return f"mapping({self.key_type} => {self.value_type})"


@dataclass
class UserDefinedTypeName(TypeNode):
    """User-defined type name node (contract, enum, struct)."""
    
    def __init__(self, name: str, path: Optional[List[str]] = None, location: Optional[SourceLocation] = None):
        super().__init__(NodeType.USER_DEFINED_TYPE, location)
        self.name = name
        self.path = path or [name]
    
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_user_defined_type(self)
    
    def __str__(self) -> str:
        return ".".join(self.path)


class ASTVisitor:
    """Base visitor for AST traversal."""
    
    def visit(self, node: Node) -> Any:
        """Visit a node and dispatch to appropriate method."""
        return node.accept(self)
    
    def visit_children(self, node: Node) -> List[Any]:
        """Visit all children of a node."""
        return [self.visit(child) for child in node.children()]
    
    # Override these methods in subclasses
    def visit_source_unit(self, node: SourceUnit) -> Any:
        return self.visit_children(node)
    
    def visit_pragma(self, node: PragmaDirective) -> Any:
        pass
    
    def visit_import(self, node: ImportDirective) -> Any:
        pass
    
    def visit_contract(self, node: Contract) -> Any:
        return self.visit_children(node)
    
    def visit_state_variable(self, node: StateVariable) -> Any:
        return self.visit_children(node)
    
    def visit_function(self, node: Function) -> Any:
        return self.visit_children(node)
    
    def visit_modifier(self, node: Modifier) -> Any:
        return self.visit_children(node)
    
    def visit_block(self, node: Block) -> Any:
        return self.visit_children(node)
    
    def visit_expression_statement(self, node: ExpressionStatement) -> Any:
        return self.visit(node.expression)
    
    def visit_if_statement(self, node: IfStatement) -> Any:
        self.visit(node.condition)
        self.visit(node.true_body)
        if node.false_body:
            self.visit(node.false_body)
    
    def visit_while_statement(self, node: WhileStatement) -> Any:
        self.visit(node.condition)
        self.visit(node.body)
    
    def visit_for_statement(self, node: ForStatement) -> Any:
        if node.init:
            self.visit(node.init)
        if node.condition:
            self.visit(node.condition)
        if node.update:
            self.visit(node.update)
        if node.body:
            self.visit(node.body)
    
    def visit_return_statement(self, node: ReturnStatement) -> Any:
        if node.expression:
            self.visit(node.expression)
    
    def visit_identifier(self, node: Identifier) -> Any:
        pass
    
    def visit_literal(self, node: Literal) -> Any:
        pass
    
    def visit_binary_op(self, node: BinaryOp) -> Any:
        self.visit(node.left)
        self.visit(node.right)
    
    def visit_unary_op(self, node: UnaryOp) -> Any:
        self.visit(node.operand)
    
    def visit_assignment(self, node: Assignment) -> Any:
        self.visit(node.left)
        self.visit(node.right)
    
    def visit_function_call(self, node: FunctionCall) -> Any:
        self.visit(node.callee)
        for arg in node.arguments:
            self.visit(arg)
    
    def visit_index_access(self, node: IndexAccess) -> Any:
        self.visit(node.base)
        self.visit(node.index)
    
    def visit_member_access(self, node: MemberAccess) -> Any:
        self.visit(node.base)
    
    def visit_new_expression(self, node: NewExpression) -> Any:
        self.visit(node.contract_type)
        for arg in node.arguments:
            self.visit(arg)
    
    def visit_type_conversion(self, node: TypeConversion) -> Any:
        self.visit(node.expression)
        self.visit(node.target_type)
    
    def visit_conditional(self, node: Conditional) -> Any:
        self.visit(node.condition)
        self.visit(node.true_expr)
        self.visit(node.false_expr)
    
    def visit_event(self, node: Event) -> Any:
        pass
    
    def visit_error(self, node: Error) -> Any:
        pass
    
    def visit_enum(self, node: EnumDefinition) -> Any:
        pass
    
    def visit_struct(self, node: StructDefinition) -> Any:
        return self.visit_children(node)
    
    def visit_emit(self, node: EmitStatement) -> Any:
        self.visit(node.event)
    
    def visit_require(self, node: RequireStatement) -> Any:
        self.visit(node.condition)
    
    def visit_assert(self, node: AssertStatement) -> Any:
        self.visit(node.condition)
    
    def visit_revert(self, node: RevertStatement) -> Any:
        if node.error_call:
            self.visit(node.error_call)
    
    def visit_break(self, node: BreakStatement) -> Any:
        pass
    
    def visit_continue(self, node: ContinueStatement) -> Any:
        pass
    
    def visit_variable_declaration(self, node: VariableDeclarationStatement) -> Any:
        if node.initial_value:
            self.visit(node.initial_value)
    
    def visit_elementary_type(self, node: ElementaryTypeName) -> Any:
        pass
    
    def visit_array_type(self, node: ArrayTypeName) -> Any:
        self.visit(node.base_type)
    
    def visit_mapping(self, node: Mapping) -> Any:
        self.visit(node.key_type)
        self.visit(node.value_type)
    
    def visit_user_defined_type(self, node: UserDefinedTypeName) -> Any:
        pass
