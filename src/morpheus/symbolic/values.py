"""
Symbolic Value Representations
===============================

This module provides specialized symbolic value classes for different
data types used in smart contracts.

Author: Morpheus Team
"""

from __future__ import annotations
from typing import Optional, Any, Union
from dataclasses import dataclass
import z3
from morpheus.symbolic.state import SymbolicValue, ValueType


class SymbolicInt(SymbolicValue):
    """
    Symbolic integer value for EVM word-sized (256-bit) integers.
    
    Extends SymbolicValue with integer-specific operations and
    overflow/underflow tracking.
    """
    
    def __init__(
        self,
        name: str,
        z3_expr: Optional[z3.ExprRef] = None,
        value_type: ValueType = ValueType.SYMBOLIC,
        constraints: list = None,
        source_info: Optional[str] = None,
        min_value: Optional[int] = None,
        max_value: Optional[int] = None
    ):
        super().__init__(
            name=name,
            z3_expr=z3_expr or z3.BitVec(name, 256),
            value_type=value_type,
            constraints=constraints or [],
            source_info=source_info
        )
        self.min_value = min_value
        self.max_value = max_value
    
    @classmethod
    def concrete(cls, value: int, name: str = "") -> SymbolicInt:
        """Create a concrete symbolic integer."""
        return cls(
            name=name or f"const_{value}",
            z3_expr=z3.BitVecVal(value, 256),
            value_type=ValueType.CONCRETE,
            min_value=value,
            max_value=value
        )
    
    @classmethod
    def symbolic(cls, name: str) -> SymbolicInt:
        """Create a fresh symbolic integer."""
        return cls(
            name=name,
            z3_expr=z3.BitVec(name, 256),
            value_type=ValueType.SYMBOLIC,
            min_value=0,
            max_value=2**256 - 1
        )
    
    def add(self, other: Union[int, SymbolicInt]) -> SymbolicInt:
        """Add with overflow detection."""
        other_expr = self._to_expr(other)
        result_expr = self.z3_expr + other_expr
        
        # Check for overflow (unsigned)
        overflow = z3.UGT(result_expr, z3.BitVecVal(2**256 - 1, 256))
        
        return SymbolicInt(
            name=f"{self.name}_add_{hash(str(other_expr))}",
            z3_expr=result_expr,
            constraints=self.constraints + [overflow == 0],
            source_info=f"add: {self.name} + {other}"
        )
    
    def sub(self, other: Union[int, SymbolicInt]) -> SymbolicInt:
        """Subtract with underflow detection."""
        other_expr = self._to_expr(other)
        result_expr = self.z3_expr - other_expr
        
        # Check for underflow (unsigned)
        underflow = z3.UGT(other_expr, self.z3_expr)
        
        return SymbolicInt(
            name=f"{self.name}_sub_{hash(str(other_expr))}",
            z3_expr=result_expr,
            constraints=self.constraints + [underflow == 0],
            source_info=f"sub: {self.name} - {other}"
        )
    
    def mul(self, other: Union[int, SymbolicInt]) -> SymbolicInt:
        """Multiply with overflow detection."""
        other_expr = self._to_expr(other)
        result_expr = self.z3_expr * other_expr
        
        # Check for overflow (unsigned)
        overflow = z3.UGT(result_expr, z3.BitVecVal(2**256 - 1, 256))
        
        return SymbolicInt(
            name=f"{self.name}_mul_{hash(str(other_expr))}",
            z3_expr=result_expr,
            constraints=self.constraints + [overflow == 0],
            source_info=f"mul: {self.name} * {other}"
        )
    
    def div(self, other: Union[int, SymbolicInt]) -> SymbolicInt:
        """Unsigned division."""
        other_expr = self._to_expr(other)
        # Z3 UDIV returns 0 on division by zero
        result_expr = z3.UDiv(self.z3_expr, other_expr)
        
        return SymbolicInt(
            name=f"{self.name}_div_{hash(str(other_expr))}",
            z3_expr=result_expr,
            constraints=self.constraints + [other_expr != 0],
            source_info=f"div: {self.name} / {other}"
        )
    
    def sdiv(self, other: Union[int, SymbolicInt]) -> SymbolicInt:
        """Signed division."""
        other_expr = self._to_expr(other)
        result_expr = z3.BVSDiv(self.z3_expr, other_expr)
        
        return SymbolicInt(
            name=f"{self.name}_sdiv_{hash(str(other_expr))}",
            z3_expr=result_expr,
            constraints=self.constraints + [other_expr != 0],
            source_info=f"sdiv: {self.name} / {other}"
        )
    
    def mod(self, other: Union[int, SymbolicInt]) -> SymbolicInt:
        """Unsigned modulo."""
        other_expr = self._to_expr(other)
        result_expr = z3.URem(self.z3_expr, other_expr)
        
        return SymbolicInt(
            name=f"{self.name}_mod_{hash(str(other_expr))}",
            z3_expr=result_expr,
            constraints=self.constraints + [other_expr != 0],
            source_info=f"mod: {self.name} % {other}"
        )
    
    def smod(self, other: Union[int, SymbolicInt]) -> SymbolicInt:
        """Signed modulo."""
        other_expr = self._to_expr(other)
        result_expr = z3.BVSRem(self.z3_expr, other_expr)
        
        return SymbolicInt(
            name=f"{self.name}_smod_{hash(str(other_expr))}",
            z3_expr=result_expr,
            constraints=self.constraints + [other_expr != 0],
            source_info=f"smod: {self.name} % {other}"
        )
    
    def lt(self, other: Union[int, SymbolicInt]) -> SymbolicBool:
        """Unsigned less than comparison."""
        other_expr = self._to_expr(other)
        result = z3.ULT(self.z3_expr, other_expr)
        
        return SymbolicBool(
            name=f"{self.name}_lt_{hash(str(other_expr))}",
            z3_expr=result
        )
    
    def gt(self, other: Union[int, SymbolicInt]) -> SymbolicBool:
        """Unsigned greater than comparison."""
        other_expr = self._to_expr(other)
        result = z3.UGT(self.z3_expr, other_expr)
        
        return SymbolicBool(
            name=f"{self.name}_gt_{hash(str(other_expr))}",
            z3_expr=result
        )
    
    def slt(self, other: Union[int, SymbolicInt]) -> SymbolicBool:
        """Signed less than comparison."""
        other_expr = self._to_expr(other)
        result = z3.BVSLT(self.z3_expr, other_expr)
        
        return SymbolicBool(
            name=f"{self.name}_slt_{hash(str(other_expr))}",
            z3_expr=result
        )
    
    def sgt(self, other: Union[int, SymbolicInt]) -> SymbolicBool:
        """Signed greater than comparison."""
        other_expr = self._to_expr(other)
        result = z3.BVSGT(self.z3_expr, other_expr)
        
        return SymbolicBool(
            name=f"{self.name}_sgt_{hash(str(other_expr))}",
            z3_expr=result
        )
    
    def eq(self, other: Union[int, SymbolicInt]) -> SymbolicBool:
        """Equality comparison."""
        other_expr = self._to_expr(other)
        result = self.z3_expr == other_expr
        
        return SymbolicBool(
            name=f"{self.name}_eq_{hash(str(other_expr))}",
            z3_expr=result
        )
    
    def is_zero(self) -> SymbolicBool:
        """Check if value is zero."""
        return SymbolicBool(
            name=f"{self.name}_is_zero",
            z3_expr=self.z3_expr == 0
        )
    
    def bitwise_and(self, other: Union[int, SymbolicInt]) -> SymbolicInt:
        """Bitwise AND operation."""
        other_expr = self._to_expr(other)
        return SymbolicInt(
            name=f"{self.name}_and_{hash(str(other_expr))}",
            z3_expr=self.z3_expr & other_expr
        )
    
    def bitwise_or(self, other: Union[int, SymbolicInt]) -> SymbolicInt:
        """Bitwise OR operation."""
        other_expr = self._to_expr(other)
        return SymbolicInt(
            name=f"{self.name}_or_{hash(str(other_expr))}",
            z3_expr=self.z3_expr | other_expr
        )
    
    def bitwise_xor(self, other: Union[int, SymbolicInt]) -> SymbolicInt:
        """Bitwise XOR operation."""
        other_expr = self._to_expr(other)
        return SymbolicInt(
            name=f"{self.name}_xor_{hash(str(other_expr))}",
            z3_expr=self.z3_expr ^ other_expr
        )
    
    def bitwise_not(self) -> SymbolicInt:
        """Bitwise NOT operation."""
        return SymbolicInt(
            name=f"{self.name}_not",
            z3_expr=~self.z3_expr
        )
    
    def shift_left(self, bits: int) -> SymbolicInt:
        """Left shift operation."""
        return SymbolicInt(
            name=f"{self.name}_shl_{bits}",
            z3_expr=self.z3_expr << bits
        )
    
    def shift_right(self, bits: int) -> SymbolicInt:
        """Right shift operation."""
        return SymbolicInt(
            name=f"{self.name}_shr_{bits}",
            z3_expr=z3.LShR(self.z3_expr, bits)
        )
    
    def sign_extend(self, bytes_count: int) -> SymbolicInt:
        """Sign extend from bytes_count bytes."""
        return SymbolicInt(
            name=f"{self.name}_sext_{bytes_count}",
            z3_expr=z3.SignExt(256 - bytes_count * 8, self.z3_expr)
        )
    
    def zero_extend(self, bytes_count: int) -> SymbolicInt:
        """Zero extend from bytes_count bytes."""
        return SymbolicInt(
            name=f"{self.name}_zext_{bytes_count}",
            z3_expr=z3.ZeroExt(256 - bytes_count * 8, self.z3_expr)
        )
    
    def _to_expr(self, other: Union[int, SymbolicInt]) -> z3.ExprRef:
        """Convert other to Z3 expression."""
        if isinstance(other, int):
            return z3.BitVecVal(other, 256)
        elif isinstance(other, SymbolicInt):
            return other.z3_expr
        elif isinstance(other, SymbolicValue):
            return other.z3_expr
        else:
            return other


class SymbolicBool(SymbolicValue):
    """
    Symbolic boolean value.
    
    Extends SymbolicValue with boolean-specific operations.
    """
    
    def __init__(
        self,
        name: str,
        z3_expr: Optional[z3.ExprRef] = None,
        value_type: ValueType = ValueType.SYMBOLIC,
        constraints: list = None,
        source_info: Optional[str] = None
    ):
        # Ensure z3_expr is a Bool
        if z3_expr is None:
            z3_expr = z3.Bool(name)
        elif isinstance(z3_expr, z3.BitVecRef):
            # Convert bitvec to bool (non-zero = True)
            z3_expr = z3_expr != 0
        
        super().__init__(
            name=name,
            z3_expr=z3_expr,
            value_type=value_type,
            constraints=constraints or [],
            source_info=source_info
        )
    
    @classmethod
    def concrete(cls, value: bool, name: str = "") -> SymbolicBool:
        """Create a concrete symbolic boolean."""
        return cls(
            name=name or f"const_{value}",
            z3_expr=z3.BoolVal(value),
            value_type=ValueType.CONCRETE
        )
    
    @classmethod
    def symbolic(cls, name: str) -> SymbolicBool:
        """Create a fresh symbolic boolean."""
        return cls(
            name=name,
            z3_expr=z3.Bool(name),
            value_type=ValueType.SYMBOLIC
        )
    
    def and_(self, other: Union[bool, SymbolicBool]) -> SymbolicBool:
        """Logical AND."""
        other_expr = self._to_expr(other)
        return SymbolicBool(
            name=f"{self.name}_and_{hash(str(other_expr))}",
            z3_expr=z3.And(self.z3_expr, other_expr)
        )
    
    def or_(self, other: Union[bool, SymbolicBool]) -> SymbolicBool:
        """Logical OR."""
        other_expr = self._to_expr(other)
        return SymbolicBool(
            name=f"{self.name}_or_{hash(str(other_expr))}",
            z3_expr=z3.Or(self.z3_expr, other_expr)
        )
    
    def not_(self) -> SymbolicBool:
        """Logical NOT."""
        return SymbolicBool(
            name=f"{self.name}_not",
            z3_expr=z3.Not(self.z3_expr)
        )
    
    def xor(self, other: Union[bool, SymbolicBool]) -> SymbolicBool:
        """Logical XOR."""
        other_expr = self._to_expr(other)
        return SymbolicBool(
            name=f"{self.name}_xor_{hash(str(other_expr))}",
            z3_expr=z3.Xor(self.z3_expr, other_expr)
        )
    
    def implies(self, other: SymbolicBool) -> SymbolicBool:
        """Logical implication (self => other)."""
        return SymbolicBool(
            name=f"{self.name}_implies_{hash(str(other.z3_expr))}",
            z3_expr=z3.Implies(self.z3_expr, other.z3_expr)
        )
    
    def iff(self, other: SymbolicBool) -> SymbolicBool:
        """Logical iff (if and only if)."""
        return SymbolicBool(
            name=f"{self.name}_iff_{hash(str(other.z3_expr))}",
            z3_expr=self.z3_expr == other.z3_expr
        )
    
    def ite(self, then_val: Any, else_val: Any) -> SymbolicInt:
        """If-then-else as symbolic integer."""
        then_expr = then_val.z3_expr if hasattr(then_val, 'z3_expr') else z3.BitVecVal(then_val, 256)
        else_expr = else_val.z3_expr if hasattr(else_val, 'z3_expr') else z3.BitVecVal(else_val, 256)
        
        return SymbolicInt(
            name=f"ite_{self.name}",
            z3_expr=z3.If(self.z3_expr, then_expr, else_expr)
        )
    
    def _to_expr(self, other: Union[bool, SymbolicBool]) -> z3.ExprRef:
        """Convert other to Z3 boolean expression."""
        if isinstance(other, bool):
            return z3.BoolVal(other)
        elif isinstance(other, SymbolicBool):
            return other.z3_expr
        elif isinstance(other, SymbolicValue):
            return other.z3_expr != 0
        else:
            return other


class SymbolicAddress:
    """
    Symbolic address value (160 bits for EVM).
    
    Represents Ethereum addresses and other 160-bit values.
    """
    
    def __init__(
        self,
        name: str,
        z3_expr: Optional[z3.ExprRef] = None,
        constraints: list = None
    ):
        self.name = name
        self.z3_expr = z3_expr or z3.BitVec(name, 160)
        self.constraints = constraints or []
    
    @classmethod
    def symbolic(cls, name: str) -> SymbolicAddress:
        """Create a fresh symbolic address."""
        return cls(name=name, z3_expr=z3.BitVec(name, 160))
    
    @classmethod
    def concrete(cls, address: int) -> SymbolicAddress:
        """Create a concrete address."""
        return cls(
            name=f"addr_{address}",
            z3_expr=z3.BitVecVal(address, 160)
        )
    
    def eq(self, other: Union[int, SymbolicAddress]) -> SymbolicBool:
        """Check equality with another address."""
        if isinstance(other, int):
            other_expr = z3.BitVecVal(other, 160)
        else:
            other_expr = other.z3_expr
        return SymbolicBool(
            name=f"{self.name}_eq_{hash(str(other_expr))}",
            z3_expr=self.z3_expr == other_expr
        )


class SymbolicBytes:
    """
    Symbolic bytes/byte array value.
    
    Used for calldata, returndata, and arbitrary byte sequences.
    """
    
    def __init__(
        self,
        name: str,
        max_size: int = 256,
        constraints: list = None
    ):
        self.name = name
        self.max_size = max_size
        self.constraints = constraints or []
        # Represent as uninterpreted function for now
        self.z3_expr = z3.Function(name, z3.BitVecSort(256), z3.BitVecSort(8))
    
    @classmethod
    def symbolic(cls, name: str, size: Optional[int] = None) -> SymbolicBytes:
        """Create a fresh symbolic bytes value."""
        return cls(name=name, max_size=size or 256)
    
    def length(self) -> SymbolicInt:
        """Get the length of the bytes."""
        return SymbolicInt(
            name=f"{self.name}_len",
            z3_expr=z3.BitVec(f"{self.name}_len", 256)
        )
    
    def get_byte(self, index: SymbolicInt) -> SymbolicInt:
        """Get a byte at index."""
        return SymbolicInt(
            name=f"{self.name}_byte_{index.name}",
            z3_expr=self.z3_expr(index.z3_expr)
        )


class SymbolicArray:
    """
    Symbolic fixed-size array.
    
    For representing arrays in contract storage/memory.
    """
    
    def __init__(
        self,
        name: str,
        element_type: type,
        size: int
    ):
        self.name = name
        self.element_type = element_type
        self.size = size
        
        # Create array sort
        index_sort = z3.BitVecSort(256)
        if element_type == int:
            elem_sort = z3.BitVecSort(256)
        elif element_type == bool:
            elem_sort = z3.BoolSort()
        else:
            elem_sort = z3.BitVecSort(256)
        
        self.z3_expr = z3.Array(name, index_sort, elem_sort)
    
    def select(self, index: Union[int, SymbolicInt]) -> SymbolicValue:
        """Select element at index."""
        if isinstance(index, int):
            idx_expr = z3.BitVecVal(index, 256)
        else:
            idx_expr = index.z3_expr
        
        return SymbolicValue(
            name=f"{self.name}_sel_{hash(str(idx_expr))}",
            z3_expr=self.z3_expr[idx_expr]
        )
    
    def store(self, index: Union[int, SymbolicInt], value: SymbolicValue) -> SymbolicArray:
        """Store value at index, returning new array."""
        if isinstance(index, int):
            idx_expr = z3.BitVecVal(index, 256)
        else:
            idx_expr = index.z3_expr
        
        new_array = SymbolicArray(self.name, self.element_type, self.size)
        new_array.z3_expr = self.z3_expr[idx_expr == value.z3_expr]
        return new_array
