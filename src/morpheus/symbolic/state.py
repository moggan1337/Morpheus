"""
Symbolic State Management
=========================

This module defines the symbolic state abstractions used during
contract analysis, including memory, storage, and execution state.

Author: Morpheus Team
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any, Tuple, Union, Set
from dataclasses import dataclass, field
from enum import Enum, auto
import z3


class ValueType(Enum):
    """Types of symbolic values."""
    CONCRETE = auto()
    SYMBOLIC = auto()
    UNINITIALIZED = auto()


@dataclass
class SymbolicValue:
    """
    Represents a value in the symbolic execution state.
    
    Can be either concrete or symbolic, with tracking of constraints
    and provenance for debugging and counterexample generation.
    """
    name: str
    z3_expr: z3.ExprRef
    value_type: ValueType = ValueType.SYMBOLIC
    constraints: List[z3.ExprRef] = field(default_factory=list)
    source_info: Optional[str] = None
    
    def __post_init__(self):
        if self.z3_expr is None:
            self.z3_expr = z3.BitVec(self.name, 256)
    
    def is_concrete(self) -> bool:
        """Check if this is a concrete value."""
        return self.value_type == ValueType.CONCRETE
    
    def is_symbolic(self) -> bool:
        """Check if this is a symbolic value."""
        return self.value_type == ValueType.SYMBOLIC
    
    def simplify(self) -> z3.ExprRef:
        """Simplify the underlying Z3 expression."""
        return z3.simplify(self.z3_expr)
    
    def substitute(
        self,
        substitutions: Dict[z3.ExprRef, z3.ExprRef]
    ) -> SymbolicValue:
        """Apply substitutions to this value."""
        new_expr = z3.substitute(self.z3_expr, 
                                  [(k, v) for k, v in substitutions.items()])
        return SymbolicValue(
            name=self.name,
            z3_expr=new_expr,
            value_type=self.value_type,
            constraints=self.constraints.copy(),
            source_info=self.source_info
        )


@dataclass
class Memory:
    """
    Symbolic memory model.
    
    Implements a mapping from byte addresses to symbolic values,
    with support for word-aligned access (32 bytes).
    """
    _data: Dict[int, SymbolicValue] = field(default_factory=dict)
    _size: int = 0
    _max_size: int = 2**64  # EVM memory size limit
    
    def read_word(self, offset: int) -> SymbolicValue:
        """
        Read a 32-byte word from memory.
        
        Args:
            offset: Byte offset (must be word-aligned for efficiency)
            
        Returns:
            SymbolicValue containing the word
        """
        word_offset = offset // 32 * 32  # Word-align
        
        if word_offset in self._data:
            return self._data[word_offset]
        
        # Create new symbolic value for uninitialized memory
        value = SymbolicValue(
            name=f"mem_{word_offset}",
            z3_expr=z3.BitVec(f"mem_{word_offset}", 256),
            value_type=ValueType.SYMBOLIC
        )
        self._data[word_offset] = value
        return value
    
    def read_bytes(
        self,
        offset: int,
        length: int
    ) -> List[SymbolicValue]:
        """
        Read bytes from memory.
        
        Args:
            offset: Byte offset
            length: Number of bytes to read
            
        Returns:
            List of SymbolicValues
        """
        words = []
        for i in range(0, length, 32):
            word = self.read_word(offset + i)
            words.append(word)
        return words
    
    def write_word(self, offset: int, value: SymbolicValue) -> None:
        """
        Write a 32-byte word to memory.
        
        Args:
            offset: Byte offset
            value: Value to write
        """
        word_offset = offset // 32 * 32
        self._data[word_offset] = value
        
        # Update size tracking
        new_size = word_offset + 32
        if new_size > self._size:
            self._size = new_size
    
    def write_bytes(
        self,
        offset: int,
        values: List[SymbolicValue]
    ) -> None:
        """
        Write bytes to memory.
        
        Args:
            offset: Byte offset
            values: Values to write
        """
        current_offset = offset
        for value in values:
            self.write_word(current_offset, value)
            current_offset += 32
    
    def get_size(self) -> int:
        """Get the current memory size."""
        return self._size
    
    def extend(self, new_size: int) -> None:
        """
        Extend memory to new size.
        
        Args:
            new_size: New memory size in bytes
        """
        if new_size > self._max_size:
            raise ValueError(f"Memory size {new_size} exceeds maximum {self._max_size}")
        self._size = new_size
    
    def get_concrete_value(self, offset: int) -> Optional[int]:
        """
        Try to get a concrete value from memory.
        
        Args:
            offset: Byte offset
            
        Returns:
            Concrete integer value or None if symbolic
        """
        word_offset = offset // 32 * 32
        if word_offset in self._data:
            value = self._data[word_offset]
            if value.is_concrete():
                try:
                    return int(str(value.z3_expr))
                except (ValueError, TypeError):
                    pass
        return None


@dataclass
class Storage:
    """
    Symbolic storage model.
    
    Implements contract storage as a mapping from slot addresses
    to symbolic values, with support for mapping types.
    """
    _data: Dict[int, SymbolicValue] = field(default_factory=dict)
    _mapping_keys: Dict[int, List[z3.ExprRef]] = field(default_factory=dict)
    
    def read(self, slot: int) -> SymbolicValue:
        """
        Read a storage slot.
        
        Args:
            slot: Storage slot number
            
        Returns:
            SymbolicValue at the slot
        """
        if slot in self._data:
            return self._data[slot]
        
        # Create new symbolic value
        value = SymbolicValue(
            name=f"storage_{slot}",
            z3_expr=z3.BitVec(f"storage_{slot}", 256),
            value_type=ValueType.SYMBOLIC
        )
        self._data[slot] = value
        return value
    
    def read_mapping(
        self,
        base_slot: int,
        key: z3.ExprRef
    ) -> SymbolicValue:
        """
        Read from a mapping type storage slot.
        
        Args:
            base_slot: Base slot of the mapping
            key: Mapping key
            
        Returns:
            SymbolicValue at the mapping location
        """
        # Calculate actual storage slot for mapping
        actual_slot = self._mapping_slot(base_slot, key)
        
        if actual_slot not in self._data:
            value = SymbolicValue(
                name=f"storage_map_{base_slot}_{hash(str(key))}",
                z3_expr=z3.BitVec(f"storage_map_{base_slot}_{hash(str(key))}", 256),
                value_type=ValueType.SYMBOLIC
            )
            self._data[actual_slot] = value
        
        # Track the key for this mapping
        if base_slot not in self._mapping_keys:
            self._mapping_keys[base_slot] = []
        self._mapping_keys[base_slot].append(key)
        
        return self._data[actual_slot]
    
    def write(self, slot: int, value: SymbolicValue) -> None:
        """
        Write to a storage slot.
        
        Args:
            slot: Storage slot
            value: Value to write
        """
        self._data[slot] = value
    
    def write_mapping(
        self,
        base_slot: int,
        key: z3.ExprRef,
        value: SymbolicValue
    ) -> None:
        """
        Write to a mapping type storage slot.
        
        Args:
            base_slot: Base slot of the mapping
            key: Mapping key
            value: Value to write
        """
        actual_slot = self._mapping_slot(base_slot, key)
        self.write(actual_slot, value)
    
    def _mapping_slot(self, base_slot: int, key: z3.ExprRef) -> int:
        """
        Calculate storage slot for mapping access.
        
        Uses the EVM mapping storage layout:
        keccak256(key . slot) for mappings
        
        Args:
            base_slot: Base slot of the mapping
            key: Mapping key
            
        Returns:
            Actual storage slot
        """
        # Simplified: use hash for slot calculation
        import sha3
        keccak = sha3.keccak_256()
        
        # Concatenate key and slot
        if isinstance(key, z3.BitVecRef):
            key_bytes = key.as_long().to_bytes(32, 'big') if hasattr(key, 'as_long') else b'\x00' * 32
        else:
            key_bytes = str(key).encode()[:32].ljust(32, b'\x00')
        
        slot_bytes = base_slot.to_bytes(32, 'big')
        keccak.update(key_bytes + slot_bytes)
        
        return int.from_bytes(keccak.digest()[:32], 'big')
    
    def get_all_slots(self) -> Set[int]:
        """Get all storage slots that have been written."""
        return set(self._data.keys())
    
    def reset(self) -> None:
        """Reset storage to empty state."""
        self._data.clear()
        self._mapping_keys.clear()


@dataclass
class SymState:
    """
    Complete symbolic execution state.
    
    Encapsulates all mutable state during symbolic execution:
    - Stack
    - Memory
    - Storage
    - Call context
    - Gas tracking
    """
    stack: List[SymbolicValue] = field(default_factory=list)
    memory: Memory = field(default_factory=Memory)
    storage: Storage = field(default_factory=Storage)
    
    # Execution context
    contract_address: Optional[SymbolicValue] = None
    caller: Optional[SymbolicValue] = None
    origin: Optional[SymbolicValue] = None
    callvalue: Optional[SymbolicValue] = None
    calldata: Optional[SymbolicValue] = None
    gas: SymbolicValue = field(default_factory=lambda: SymbolicValue(
        name="gas",
        z3_expr=z3.BitVecVal(2**63 - 1, 256),  # Use max int as initial gas
        value_type=ValueType.SYMBOLIC
    ))
    
    # Return data
    return_data: Optional[SymbolicValue] = None
    
    # State flags
    reverted: bool = False
    stopped: bool = False
    valid: bool = True
    
    # Depth tracking
    call_depth: int = 0
    max_call_depth: int = 1024
    
    def push_stack(self, value: SymbolicValue) -> None:
        """
        Push a value onto the stack.
        
        Args:
            value: Value to push
            
        Raises:
            ValueError: If stack is full
        """
        if len(self.stack) >= 1024:  # EVM stack limit
            raise ValueError("Stack overflow")
        self.stack.append(value)
    
    def pop_stack(self) -> SymbolicValue:
        """
        Pop a value from the stack.
        
        Returns:
            Popped value
            
        Raises:
            ValueError: If stack is empty
        """
        if not self.stack:
            raise ValueError("Stack underflow")
        return self.stack.pop()
    
    def peek_stack(self, position: int = 0) -> SymbolicValue:
        """
        Peek at a stack value without removing it.
        
        Args:
            position: Position from top (0 = top)
            
        Returns:
            Value at position
        """
        if position >= len(self.stack):
            raise ValueError(f"Stack underflow at position {position}")
        return self.stack[-(position + 1)]
    
    def dup_stack(self, position: int) -> None:
        """
        Duplicate a stack value.
        
        Args:
            position: Position from top (1-indexed)
        """
        value = self.peek_stack(position - 1)
        self.push_stack(SymbolicValue(
            name=f"dup_{position}",
            z3_expr=value.z3_expr,
            value_type=value.value_type,
            constraints=value.constraints.copy()
        ))
    
    def swap_stack(self, position: int) -> None:
        """
        Swap top of stack with another position.
        
        Args:
            position: Position from top (0 = swap with self)
        """
        if position >= len(self.stack):
            raise ValueError(f"Stack too small for swap at position {position}")
        
        idx = -(position + 1)
        self.stack[-1], self.stack[idx] = self.stack[idx], self.stack[-1]
    
    def consume_gas(self, amount: int) -> bool:
        """
        Consume gas from the state.
        
        Args:
            amount: Amount of gas to consume
            
        Returns:
            True if enough gas available, False otherwise
        """
        if isinstance(self.gas.z3_expr, z3.BitVecNumRef):
            current = int(str(self.gas.z3_expr))
            if current < amount:
                self.reverted = True
                return False
            self.gas = SymbolicValue(
                name="gas",
                z3_expr=z3.BitVecVal(current - amount, 256),
                value_type=ValueType.CONCRETE
            )
        return True
    
    def copy(self) -> SymState:
        """
        Create a deep copy of this state.
        
        Returns:
            New SymState with copied data
        """
        new_state = SymState(
            stack=self.stack.copy(),
            memory=self.memory,
            storage=self.storage,
            contract_address=self.contract_address,
            caller=self.caller,
            origin=self.origin,
            callvalue=self.callvalue,
            calldata=self.calldata,
            gas=SymbolicValue(
                name=self.gas.name,
                z3_expr=self.gas.z3_expr,
                value_type=self.gas.value_type,
                constraints=self.gas.constraints.copy()
            ),
            return_data=self.return_data,
            reverted=self.reverted,
            stopped=self.stopped,
            valid=self.valid,
            call_depth=self.call_depth,
            max_call_depth=self.max_call_depth
        )
        return new_state
    
    def merge(self, other: SymState, condition: z3.ExprRef) -> SymState:
        """
        Merge two states with a condition.
        
        Used for path merging at join points in the control flow.
        
        Args:
            other: Another state to merge with
            condition: Branch condition
            
        Returns:
            Merged state
        """
        merged = SymState(
            stack=self.stack.copy(),
            memory=self.memory,
            storage=self.storage,
            call_depth=self.call_depth,
            max_call_depth=self.max_call_depth
        )
        
        # Merge symbolic values using ite (if-then-else)
        def merge_value(sv1: Optional[SymbolicValue], 
                       sv2: Optional[SymbolicValue]) -> SymbolicValue:
            if sv1 is None:
                return sv2
            if sv2 is None:
                return sv1
            merged_expr = z3.If(condition, sv1.z3_expr, sv2.z3_expr)
            return SymbolicValue(
                name=f"merged_{sv1.name}",
                z3_expr=merged_expr,
                value_type=ValueType.SYMBOLIC
            )
        
        merged.contract_address = merge_value(self.contract_address, other.contract_address)
        merged.caller = merge_value(self.caller, other.caller)
        merged.gas = merge_value(self.gas, other.gas)
        
        return merged
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert state to dictionary for debugging/exporting.
        
        Returns:
            Dictionary representation
        """
        return {
            "stack_depth": len(self.stack),
            "memory_size": self.memory.get_size(),
            "storage_slots": len(self.storage.get_all_slots()),
            "gas": str(self.gas.z3_expr),
            "reverted": self.reverted,
            "stopped": self.stopped,
            "call_depth": self.call_depth
        }


class CallContext:
    """
    Represents a call context in the execution trace.
    
    Used for tracking the call stack and return addresses.
    """
    
    def __init__(
        self,
        target: Union[str, int],
        call_type: str,
        gas: int,
        args: List[Any] = None,
        value: int = 0
    ):
        self.target = target
        self.call_type = call_type  # CALL, DELEGATECALL, STATICCALL, etc.
        self.gas = gas
        self.args = args or []
        self.value = value
        self.return_data: Optional[bytes] = None
        self.succeeded: Optional[bool] = None


class ExecutionTrace:
    """
    Tracks the execution trace for debugging and analysis.
    
    Records each step of symbolic execution including:
    - Opcode executed
    - Stack state
    - PC changes
    - Branch decisions
    """
    
    def __init__(self):
        self.steps: List[TraceStep] = []
        self.branches: List[BranchPoint] = []
        self.function_calls: List[FunctionCall] = []
    
    def add_step(self, step: TraceStep) -> None:
        """Add a step to the trace."""
        self.steps.append(step)
    
    def add_branch(self, branch: BranchPoint) -> None:
        """Add a branch point to the trace."""
        self.branches.append(branch)
    
    def add_function_call(self, call: FunctionCall) -> None:
        """Add a function call to the trace."""
        self.function_calls.append(call)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the trace."""
        return {
            "total_steps": len(self.steps),
            "branches": len(self.branches),
            "function_calls": len(self.function_calls),
            "branches_taken": sum(1 for b in self.branches if b.taken),
            "max_depth": max((b.depth for b in self.branches), default=0)
        }


@dataclass
class TraceStep:
    """Single step in the execution trace."""
    pc: int
    opcode: int
    stack_before: List[str]
    stack_after: List[str]
    gas_consumed: int
    description: str = ""


@dataclass 
class BranchPoint:
    """Represents a branch decision in the trace."""
    pc: int
    condition: str
    depth: int
    taken: bool
    path_id: str = ""


@dataclass
class FunctionCall:
    """Represents a function call in the trace."""
    name: str
    pc: int
    args: Dict[str, Any]
    return_value: Optional[Any] = None
    success: Optional[bool] = None
