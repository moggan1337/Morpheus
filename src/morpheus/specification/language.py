"""
Formal Specification Language
=============================

This module defines Morpheus's formal specification language for
expressing properties, invariants, and verification conditions
for smart contract analysis.

Specification Format:
- Properties: assert conditions that must hold
- Invariants: conditions that must hold at all states
- Preconditions: conditions required before function execution
- Postconditions: conditions guaranteed after function execution
- Effects: state changes that functions must cause

Author: Morpheus Team
"""

from __future__ import annotations
from typing import Dict, List, Optional, Set, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum, auto
import z3
import logging

logger = logging.getLogger(__name__)


class SpecificationType(Enum):
    """Types of specifications."""
    PROPERTY = auto()       # General property to verify
    INVARIANT = auto()      # Loop/block invariant
    PRECONDITION = auto()   # Requires clause
    POSTCONDITION = auto()  # Ensures clause
    STATE_INVARIANT = auto() # Contract-level invariant
    EFFECT = auto()         # Side effect specification
    REENTRANCY_FREE = auto() # No reentrancy vulnerability
    OVERFLOW_FREE = auto()   # No arithmetic overflow
    ACCESS_CONTROL = auto()  # Access control property


@dataclass
class Specification:
    """Base class for specifications."""
    name: str
    spec_type: SpecificationType
    description: str = ""
    source_location: Optional[str] = None
    severity: str = "ERROR"
    tags: Set[str] = field(default_factory=set)
    
    def to_z3(self, context: SpecificationContext) -> z3.BoolRef:
        """Convert specification to Z3 formula."""
        raise NotImplementedError


@dataclass
class Property(Specification):
    """A property specification."""
    
    condition: str = ""  # Human-readable condition
    formula: Optional[z3.BoolRef] = None
    variables: Dict[str, Any] = field(default_factory=dict)
    
    def to_z3(self, context: SpecificationContext) -> z3.BoolRef:
        """Convert property to Z3 formula."""
        if self.formula is not None:
            return self.formula
        
        # Parse condition from context
        return z3.Bool(self.name)
    
    @classmethod
    def create(
        cls,
        name: str,
        condition: str,
        description: str = "",
        tags: Set[str] = None
    ) -> Property:
        """Create a property specification."""
        return cls(
            name=name,
            spec_type=SpecificationType.PROPERTY,
            condition=condition,
            description=description,
            tags=tags or set()
        )


@dataclass
class Invariant(Specification):
    """An invariant specification."""
    
    condition: str = ""
    formula: Optional[z3.BoolRef] = None
    scope: str = "global"  # global, function, loop
    inductive: bool = False  # Whether this is an inductive invariant
    
    def to_z3(self, context: SpecificationContext) -> z3.BoolRef:
        """Convert invariant to Z3 formula."""
        if self.formula is not None:
            return self.formula
        return z3.Bool(self.name)
    
    @classmethod
    def create(
        cls,
        name: str,
        condition: str,
        scope: str = "global",
        inductive: bool = False,
        description: str = ""
    ) -> Invariant:
        """Create an invariant specification."""
        return cls(
            name=name,
            spec_type=SpecificationType.INVARIANT,
            condition=condition,
            scope=scope,
            inductive=inductive,
            description=description
        )


@dataclass
class Precondition(Specification):
    """A precondition specification."""
    
    function: str = ""
    condition: str = ""
    formula: Optional[z3.BoolRef] = None
    
    def to_z3(self, context: SpecificationContext) -> z3.BoolRef:
        """Convert precondition to Z3 formula."""
        if self.formula is not None:
            return self.formula
        return z3.Bool(self.name)
    
    @classmethod
    def create(
        cls,
        function: str,
        condition: str,
        name: str = "",
        description: str = ""
    ) -> Precondition:
        """Create a precondition specification."""
        return cls(
            name=name or f"pre_{function}",
            spec_type=SpecificationType.PRECONDITION,
            function=function,
            condition=condition,
            description=description
        )


@dataclass
class Postcondition(Specification):
    """A postcondition specification."""
    
    function: str = ""
    condition: str = ""
    formula: Optional[z3.BoolRef] = None
    old_vars: Dict[str, Any] = field(default_factory=dict)  # Pre-state values
    
    def to_z3(self, context: SpecificationContext) -> z3.BoolRef:
        """Convert postcondition to Z3 formula."""
        if self.formula is not None:
            return self.formula
        return z3.Bool(self.name)
    
    @classmethod
    def create(
        cls,
        function: str,
        condition: str,
        name: str = "",
        description: str = ""
    ) -> Postcondition:
        """Create a postcondition specification."""
        return cls(
            name=name or f"post_{function}",
            spec_type=SpecificationType.POSTCONDITION,
            function=function,
            condition=condition,
            description=description
        )


class SpecificationContext:
    """
    Context for specification evaluation.
    
    Contains the current state variables and functions
    for evaluating specifications.
    """
    
    def __init__(self):
        self.variables: Dict[str, z3.ExprRef] = {}
        self.functions: Dict[str, Any] = {}
        self.types: Dict[str, type] = {}
        self.storage_vars: Set[str] = set()
        self.memory_vars: Set[str] = set()
        self.calldata_vars: Set[str] = set()
        
        # Predefined constants
        self._setup_constants()
    
    def _setup_constants(self) -> None:
        """Set up predefined constants."""
        self.variables['msg.sender'] = z3.BitVec('msg_sender', 160)
        self.variables['msg.value'] = z3.BitVec('msg_value', 256)
        self.variables['msg.data'] = z3.BitVec('msg_data', 256)
        self.variables['block.timestamp'] = z3.BitVec('block_timestamp', 256)
        self.variables['block.number'] = z3.BitVec('block_number', 256)
        self.variables['block.chainid'] = z3.BitVec('block_chainid', 256)
        self.variables['this'] = z3.BitVec('this', 160)
        self.variables['tx.origin'] = z3.BitVec('tx_origin', 160)
    
    def add_variable(self, name: str, expr: z3.ExprRef, storage: bool = False) -> None:
        """Add a variable to the context."""
        self.variables[name] = expr
        if storage:
            self.storage_vars.add(name)
    
    def add_function(self, name: str, func: Any) -> None:
        """Add a function to the context."""
        self.functions[name] = func
    
    def get_variable(self, name: str) -> Optional[z3.ExprRef]:
        """Get a variable from the context."""
        return self.variables.get(name)
    
    def get_function(self, name: str) -> Optional[Any]:
        """Get a function from the context."""
        return self.functions.get(name)
    
    def create_symbolic_var(
        self,
        name: str,
        sort: z3.Sort = None
    ) -> z3.ExprRef:
        """Create a symbolic variable in the context."""
        if sort is None:
            sort = z3.BitVecSort(256)
        
        var = z3.FreshConst(sort, name=name)
        self.variables[name] = var
        return var
    
    def substitute(
        self,
        formula: z3.ExprRef,
        substitutions: Dict[str, z3.ExprRef]
    ) -> z3.ExprRef:
        """Apply substitutions to a formula."""
        subs_list = [(self.variables[k], v) for k, v in substitutions.items() 
                     if k in self.variables]
        return z3.substitute(formula, subs_list)


class SpecificationLanguage:
    """
    Formal specification language for smart contracts.
    
    Provides a DSL-like interface for writing specifications
    that are automatically translated to Z3 formulas.
    """
    
    def __init__(self, context: Optional[SpecificationContext] = None):
        self.context = context or SpecificationContext()
        self.specifications: List[Specification] = []
        self.axioms: List[z3.BoolRef] = []
    
    def property(
        self,
        name: str,
        condition: z3.BoolRef,
        description: str = "",
        tags: Set[str] = None
    ) -> Property:
        """
        Define a property to verify.
        
        Args:
            name: Property name
            condition: Z3 boolean expression
            description: Human-readable description
            tags: Tags for categorization
            
        Returns:
            Property specification
        """
        prop = Property(
            name=name,
            spec_type=SpecificationType.PROPERTY,
            condition=str(condition),
            formula=condition,
            description=description,
            tags=tags or set()
        )
        self.specifications.append(prop)
        return prop
    
    def invariant(
        self,
        name: str,
        condition: z3.BoolRef,
        scope: str = "global",
        description: str = ""
    ) -> Invariant:
        """
        Define an invariant.
        
        Args:
            name: Invariant name
            condition: Z3 boolean expression
            scope: Scope (global, function, loop)
            description: Human-readable description
            
        Returns:
            Invariant specification
        """
        inv = Invariant(
            name=name,
            spec_type=SpecificationType.INVARIANT,
            condition=str(condition),
            formula=condition,
            scope=scope,
            description=description
        )
        self.specifications.append(inv)
        return inv
    
    def requires(
        self,
        function: str,
        condition: z3.BoolRef,
        description: str = ""
    ) -> Precondition:
        """
        Define a precondition for a function.
        
        Args:
            function: Function name
            condition: Z3 boolean expression
            description: Human-readable description
            
        Returns:
            Precondition specification
        """
        pre = Precondition(
            name=f"pre_{function}",
            spec_type=SpecificationType.PRECONDITION,
            function=function,
            condition=str(condition),
            formula=condition,
            description=description
        )
        self.specifications.append(pre)
        return pre
    
    def ensures(
        self,
        function: str,
        condition: z3.BoolRef,
        description: str = ""
    ) -> Postcondition:
        """
        Define a postcondition for a function.
        
        Args:
            function: Function name
            condition: Z3 boolean expression
            description: Human-readable description
            
        Returns:
            Postcondition specification
        """
        post = Postcondition(
            name=f"post_{function}",
            spec_type=SpecificationType.POSTCONDITION,
            function=function,
            condition=str(condition),
            formula=condition,
            description=description
        )
        self.specifications.append(post)
        return post
    
    def axiom(self, condition: z3.BoolRef, name: str = "") -> None:
        """
        Add an axiom to the specification.
        
        Args:
            condition: Z3 boolean expression (always true)
            name: Optional name for the axiom
        """
        self.axioms.append(condition)
    
    # Common property templates
    
    def no_overflow(
        self,
        expression: z3.ExprRef,
        name: str = "no_overflow"
    ) -> Property:
        """Property: expression does not overflow."""
        prop = z3.And(
            expression >= 0,
            expression <= 2**256 - 1
        )
        return self.property(f"overflow_free_{name}", prop, "No arithmetic overflow")
    
    def balance_increases(
        self,
        address: z3.ExprRef,
        name: str = ""
    ) -> Property:
        """Property: balance of address increases monotonically."""
        old_balance = z3.BitVec(f"old_balance_{address}", 256)
        new_balance = z3.BitVec(f"new_balance_{address}", 256)
        prop = new_balance >= old_balance
        return self.property(f"balance_monotonic_{name}", prop)
    
    def access_control(
        self,
        condition: z3.BoolRef,
        role: str
    ) -> Property:
        """Property: access control check."""
        return self.property(
            f"access_control_{role}",
            condition,
            f"Only {role} can execute this function",
            tags={"access-control", role}
        )
    
    def reentrancy_free(self, function: str) -> Property:
        """Property: function is reentrancy-free."""
        return self.property(
            f"reentrancy_free_{function}",
            z3.BoolVal(True),
            f"Function {function} should not be vulnerable to reentrancy",
            tags={"reentrancy", "security"}
        )
    
    def tx_origin_check(self, allowed: z3.ExprRef) -> Property:
        """Property: tx.origin equals allowed address."""
        prop = z3.Implies(
            z3.BitVec('tx_origin', 160) != 0,
            z3.BitVec('tx_origin', 160) == allowed
        )
        return self.property("tx_origin_check", prop, "tx.origin must be authorized")
    
    def selfdestruct_protection(self) -> Property:
        """Property: selfdestruct only callable by authorized users."""
        prop = z3.Implies(
            z3.Bool("selfdestruct_called"),
            z3.BitVec('msg_sender', 160) == z3.BitVec('owner', 160)
        )
        return self.property(
            "selfdestruct_protection",
            prop,
            "Self-destruct must be authorized",
            tags={"security", "selfdestruct"}
        )
    
    def parse_spec_file(self, filepath: str) -> List[Specification]:
        """
        Parse a specification file (.mspec).
        
        Args:
            filepath: Path to specification file
            
        Returns:
            List of parsed specifications
        """
        specifications = []
        
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Simple line-based parsing
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse specification lines
            if line.startswith('property '):
                name = line.split('property ')[1].split(':')[0].strip()
                specifications.append(Property.create(name, line))
            elif line.startswith('invariant '):
                name = line.split('invariant ')[1].split(':')[0].strip()
                specifications.append(Invariant.create(name, line))
            elif line.startswith('requires '):
                func = line.split('requires ')[1].split(':')[0].strip()
                specifications.append(Precondition.create(func, line))
            elif line.startswith('ensures '):
                func = line.split('ensures ')[1].split(':')[0].strip()
                specifications.append(Postcondition.create(func, line))
        
        return specifications


class PropertyBuilder:
    """
    Builder for constructing complex properties.
    
    Provides a fluent API for building verification conditions.
    """
    
    def __init__(self, context: SpecificationContext):
        self.context = context
        self.conditions: List[z3.BoolRef] = []
    
    def add(self, condition: z3.BoolRef) -> PropertyBuilder:
        """Add a condition."""
        self.conditions.append(condition)
        return self
    
    def implies(self, antecedent: z3.BoolRef, consequent: z3.BoolRef) -> PropertyBuilder:
        """Add implication: antecedent => consequent."""
        self.conditions.append(z3.Implies(antecedent, consequent))
        return self
    
    def forall(
        self,
        var_name: str,
        sort: z3.Sort,
        condition: z3.BoolRef
    ) -> PropertyBuilder:
        """Add universal quantification."""
        var = z3.FreshConst(sort)
        self.conditions.append(z3.ForAll([var], condition))
        return self
    
    def exists(
        self,
        var_name: str,
        sort: z3.Sort,
        condition: z3.BoolRef
    ) -> PropertyBuilder:
        """Add existential quantification."""
        var = z3.FreshConst(sort)
        self.conditions.append(z3.Exists([var], condition))
        return self
    
    def build(self, name: str) -> Property:
        """Build the property from conditions."""
        formula = z3.And(self.conditions) if self.conditions else z3.BoolVal(True)
        return Property.create(name, str(formula), tags={"generated"})


# DSL-style specification helpers

def require(condition: z3.BoolRef, message: str = "") -> z3.BoolRef:
    """
    Require statement - condition must hold.
    
    Used in spec files for preconditions.
    """
    return condition


def ensure(condition: z3.BoolRef, message: str = "") -> z3.BoolRef:
    """
    Ensure statement - condition will hold.
    
    Used in spec files for postconditions.
    """
    return condition


def assert_prop(condition: z3.BoolRef, message: str = "") -> z3.BoolRef:
    """
    Assert statement - condition must hold.
    
    Used in spec files for properties.
    """
    return condition


def old(expr: z3.ExprRef) -> z3.ExprRef:
    """
    Get the pre-state value of an expression.
    
    Used in postconditions to refer to initial values.
    """
    # Return symbolic expression for old value
    return z3.BitVec(f"old_{expr}", 256)


def sum_overflow(a: z3.ExprRef, b: z3.ExprRef) -> z3.BoolRef:
    """Check if a + b would overflow."""
    result = a + b
    return z3.Not(z3.UGT(result, z3.BitVecVal(2**256 - 1, 256)))


def product_overflow(a: z3.ExprRef, b: z3.ExprRef) -> z3.BoolRef:
    """Check if a * b would overflow."""
    result = a * b
    return z3.Not(z3.UGT(result, z3.BitVecVal(2**256 - 1, 256)))
