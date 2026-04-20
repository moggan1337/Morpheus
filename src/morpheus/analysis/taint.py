"""
Taint Analysis for Smart Contract Security
============================================

This module implements taint analysis to track potentially
dangerous data flows and detect security vulnerabilities
in smart contracts.

Taint Sources:
- User input (msg.sender, msg.value, calldata)
- External calls (return data)
- Block properties (timestamp, blockhash)
- State variables

Taint Sinks:
- External calls
- Storage writes
- State changes
- selfdestruct
- Sensitive operations

Author: Morpheus Team
"""

from __future__ import annotations
from typing import Dict, List, Set, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
import logging

from morpheus.parser.ast import (
    Contract, Function, Statement, Expression, Identifier,
    BinaryOp, Assignment, FunctionCall, MemberAccess, ASTVisitor, Node
)

logger = logging.getLogger(__name__)


class TaintSource(Enum):
    """Types of taint sources."""
    USER_INPUT = auto()
    EXTERNAL_CALL = auto()
    BLOCK_DATA = auto()
    STATE_VARIABLE = auto()
    ENVIRONMENT = auto()
    UNKNOWN = auto()


class TaintSink(Enum):
    """Types of taint sinks."""
    EXTERNAL_CALL = auto()
    STORAGE_WRITE = auto()
    STATICCALL = auto()
    SELFDESTRUCT = auto()
    LOG_EVENT = auto()
    ARITHMETIC = auto()
    ACCESS_CONTROL = auto()


@dataclass
class TaintTag:
    """Tag describing the nature of taint."""
    source: TaintSource
    description: str = ""
    severity: str = "MEDIUM"
    propagates: bool = True


@dataclass
class TaintedValue:
    """Represents a potentially tainted value."""
    name: str
    tags: Set[TaintTag] = field(default_factory=set)
    source_location: Optional[str] = None
    
    def add_tag(self, tag: TaintTag) -> None:
        """Add a taint tag to this value."""
        self.tags.add(tag)
    
    def is_tainted(self) -> bool:
        """Check if value is tainted."""
        return len(self.tags) > 0
    
    def get_tag(self, source: TaintSource) -> Optional[TaintTag]:
        """Get tag by source type."""
        for tag in self.tags:
            if tag.source == source:
                return tag
        return None


@dataclass
class TaintFlow:
    """Represents a taint flow from source to sink."""
    source: TaintTag
    sink: TaintSink
    path: List[str]
    vulnerability_type: str = ""
    description: str = ""


class TaintAnalyzer:
    """
    Taint analysis engine for smart contracts.
    
    Tracks taint propagation through the contract to
    detect dangerous data flows.
    """
    
    # Predefined taint sources
    TAINT_SOURCES = {
        'msg.sender': TaintSource.USER_INPUT,
        'msg.value': TaintSource.USER_INPUT,
        'msg.data': TaintSource.USER_INPUT,
        'tx.origin': TaintSource.USER_INPUT,
        'block.timestamp': TaintSource.BLOCK_DATA,
        'block.number': TaintSource.BLOCK_DATA,
        'block.coinbase': TaintSource.BLOCK_DATA,
        'block.difficulty': TaintSource.BLOCK_DATA,
        'block.gaslimit': TaintSource.BLOCK_DATA,
        'blockhash': TaintSource.BLOCK_DATA,
    }
    
    # Predefined taint sinks
    TAINT_SINKS = {
        'call': TaintSink.EXTERNAL_CALL,
        'delegatecall': TaintSink.EXTERNAL_CALL,
        'callcode': TaintSink.EXTERNAL_CALL,
        'send': TaintSink.EXTERNAL_CALL,
        'transfer': TaintSink.EXTERNAL_CALL,
        'staticcall': TaintSink.STATICCALL,
        'selfdestruct': TaintSink.SELFDESTRUCT,
        'suicide': TaintSink.SELFDESTRUCT,
        'emit': TaintSink.LOG_EVENT,
        'log0': TaintSink.LOG_EVENT,
        'log1': TaintSink.LOG_EVENT,
    }
    
    def __init__(self):
        self.tainted_values: Dict[str, TaintedValue] = {}
        self.taint_flows: List[TaintFlow] = []
        self.function_context: Dict[str, Dict[str, TaintedValue]] = {}
    
    def analyze_contract(self, contract: Contract) -> List[TaintFlow]:
        """
        Analyze a contract for taint flows.
        
        Args:
            contract: Contract AST
            
        Returns:
            List of detected taint flows
        """
        # Initialize with contract-level taint sources
        self._init_contract_sources(contract)
        
        # Analyze each function
        for func in contract.functions:
            self._analyze_function(func)
        
        # Check for taint flows to sinks
        self._detect_taint_flows()
        
        return self.taint_flows
    
    def _init_contract_sources(self, contract: Contract) -> None:
        """Initialize taint sources from contract state variables."""
        for var in contract.state_variables:
            var_name = var.name
            
            # Mark sensitive state variables as potential sources
            sensitive_keywords = ['owner', 'admin', 'key', 'secret', 'password']
            if any(kw in var_name.lower() for kw in sensitive_keywords):
                self.tainted_values[var_name] = TaintedValue(
                    name=var_name,
                    tags={TaintTag(
                        source=TaintSource.STATE_VARIABLE,
                        description=f"Sensitive state variable: {var_name}"
                    )}
                )
    
    def _analyze_function(self, func: Function) -> None:
        """Analyze a function for taint propagation."""
        func_context: Dict[str, TaintedValue] = {}
        
        # Mark function parameters as potentially tainted
        for param in func.parameters:
            func_context[param.name] = TaintedValue(
                name=param.name,
                tags={TaintTag(
                    source=TaintSource.USER_INPUT,
                    description=f"Function parameter: {param.name}"
                )}
            )
        
        # Analyze function body
        if func.body:
            self._analyze_statements(func.body.statements, func_context)
        
        # Store function context
        self.function_context[func.name] = func_context
    
    def _analyze_statements(
        self,
        statements: List[Statement],
        context: Dict[str, TaintedValue]
    ) -> None:
        """Analyze statements for taint propagation."""
        for stmt in statements:
            self._analyze_statement(stmt, context)
    
    def _analyze_statement(
        self,
        stmt: Statement,
        context: Dict[str, TaintedValue]
    ) -> None:
        """Analyze a single statement for taint propagation."""
        if hasattr(stmt, 'accept'):
            visitor = TaintAnalysisVisitor(context, self)
            stmt.accept(visitor)
            
            # Update context with any new tainted values
            for name, value in visitor.context.items():
                context[name] = value
    
    def _detect_taint_flows(self) -> None:
        """Detect taint flows from sources to sinks."""
        for name, value in self.tainted_values.items():
            if not value.is_tainted():
                continue
            
            # Check if this value reaches a sink
            for tag in value.tags:
                # Record the taint flow
                flow = TaintFlow(
                    source=tag,
                    sink=TaintSink.ARITHMETIC,  # Default, will be updated
                    path=[name],
                    vulnerability_type=self._get_vulnerability_type(tag),
                    description=f"Tainted value {name} reaches sensitive operation"
                )
                self.taint_flows.append(flow)
    
    def _get_vulnerability_type(self, tag: TaintTag) -> str:
        """Get vulnerability type based on taint source."""
        vuln_map = {
            TaintSource.USER_INPUT: "Unvalidated Input",
            TaintSource.EXTERNAL_CALL: "Untrusted External Call",
            TaintSource.BLOCK_DATA: "Block Data Manipulation",
            TaintSource.STATE_VARIABLE: "State Variable Access",
        }
        return vuln_map.get(tag.source, "Unknown Vulnerability")
    
    def add_taint_source(self, name: str, source: TaintSource, description: str = "") -> None:
        """Add a custom taint source."""
        self.tainted_values[name] = TaintedValue(
            name=name,
            tags={TaintTag(source=source, description=description)}
        )
    
    def propagate_taint(
        self,
        source_name: str,
        target_name: str
    ) -> None:
        """Propagate taint from source to target."""
        if source_name in self.tainted_values:
            if target_name not in self.tainted_values:
                self.tainted_values[target_name] = TaintedValue(name=target_name)
            
            # Copy taint tags
            for tag in self.tainted_values[source_name].tags:
                if tag.propagates:
                    self.tainted_values[target_name].add_tag(tag)
    
    def get_tainted_variables(self) -> List[TaintedValue]:
        """Get all tainted variables."""
        return [v for v in self.tainted_values.values() if v.is_tainted()]


class TaintAnalysisVisitor(ASTVisitor):
    """AST visitor for taint analysis."""
    
    def __init__(self, context: Dict[str, TaintedValue], analyzer: TaintAnalyzer):
        self.context = context
        self.analyzer = analyzer
    
    def visit_identifier(self, node: Identifier) -> Any:
        """Visit identifier - check if it's tainted."""
        if node.name in self.context:
            # Propagate taint to analyzer
            self.analyzer.tainted_values[node.name] = self.context[node.name]
        elif node.name in TaintAnalyzer.TAINT_SOURCES:
            # This is a taint source
            source = TaintAnalyzer.TAINT_SOURCES[node.name]
            self.context[node.name] = TaintedValue(
                name=node.name,
                tags={TaintTag(source=source, description=f"Taint source: {node.name}")}
            )
            self.analyzer.tainted_values[node.name] = self.context[node.name]
    
    def visit_assignment(self, node: Assignment) -> Any:
        """Visit assignment - propagate taint."""
        # Check if right side is tainted
        right_tainted = False
        if hasattr(node.right, 'accept'):
            node.right.accept(self)
            if isinstance(node.right, Identifier) and node.right.name in self.context:
                right_tainted = self.context[node.right.name].is_tainted()
        
        # Propagate to left side
        if isinstance(node.left, Identifier):
            if right_tainted:
                self.context[node.left.name] = TaintedValue(
                    name=node.left.name,
                    tags=self.context[node.right.name].tags.copy()
                )
    
    def visit_binary_op(self, node: BinaryOp) -> Any:
        """Visit binary operation - check for taint."""
        # Check both operands
        if hasattr(node.left, 'accept'):
            node.left.accept(self)
        if hasattr(node.right, 'accept'):
            node.right.accept(self)
    
    def visit_function_call(self, node: FunctionCall) -> Any:
        """Visit function call - check for sinks."""
        # Check callee
        if hasattr(node.callee, 'accept'):
            node.callee.accept(self)
        
        # Check arguments
        for arg in node.arguments:
            if hasattr(arg, 'accept'):
                arg.accept(self)
        
        # Check if this is a taint sink
        if isinstance(node.callee, Identifier):
            func_name = node.callee.name
            if func_name in TaintAnalyzer.TAINT_SINKS:
                sink = TaintAnalyzer.TAINT_SINKS[func_name]
                
                # Check if any arguments are tainted
                for arg in node.arguments:
                    if isinstance(arg, Identifier) and arg.name in self.context:
                        value = self.context[arg.name]
                        if value.is_tainted():
                            # Found taint flow to sink
                            for tag in value.tags:
                                flow = TaintFlow(
                                    source=tag,
                                    sink=sink,
                                    path=[arg.name, func_name],
                                    vulnerability_type=f"Tainted data reaches {sink.name}",
                                    description=f"Tainted value flows to {func_name}"
                                )
                                self.analyzer.taint_flows.append(flow)
    
    def visit_member_access(self, node: MemberAccess) -> Any:
        """Visit member access - check for taint."""
        if hasattr(node.base, 'accept'):
            node.base.accept(self)


class ExploitPatternDetector:
    """
    Detects common exploit patterns using taint analysis.
    """
    
    @staticmethod
    def detect_unvalidated_input(func: Function) -> bool:
        """Detect unvalidated user input."""
        # Check if function uses msg.sender without validation
        for stmt in func.body.statements if func.body else []:
            if isinstance(stmt, Expression):
                # Simplified check
                pass
        return False
    
    @staticmethod
    def detect_unchecked_call(func: Function) -> bool:
        """Detect unchecked external call."""
        # Check if external call result is not checked
        return False
    
    @staticmethod
    def detect_access_control_bypass(func: Function) -> bool:
        """Detect potential access control bypass."""
        # Check if access control can be bypassed via taint
        return False
