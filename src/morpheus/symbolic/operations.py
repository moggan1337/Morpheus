"""
Symbolic Operations for EVM
============================

This module provides symbolic operation implementations for
Ethereum Virtual Machine opcodes.

Author: Morpheus Team
"""

from __future__ import annotations
from typing import Union, List, Optional, Tuple, Any
import z3
from morpheus.symbolic.values import SymbolicInt, SymbolicBool, SymbolicBytes, SymbolicAddress


class SymbolicOperations:
    """
    Provides symbolic implementations of EVM operations.
    
    Each method takes symbolic operands and returns a symbolic result,
    tracking all relevant constraints and potential violations.
    """
    
    # Precomputed constants
    WORD_SIZE = 256
    MAX_UINT256 = 2**256 - 1
    MAX_UINT160 = 2**160 - 1
    
    @staticmethod
    def add(a: SymbolicInt, b: SymbolicInt, track_overflow: bool = True) -> Tuple[SymbolicInt, Optional[SymbolicBool]]:
        """
        Symbolic ADD operation.
        
        Args:
            a: First operand
            b: Second operand
            track_overflow: Whether to track overflow condition
            
        Returns:
            Tuple of (result, overflow_flag if track_overflow)
        """
        result_expr = a.z3_expr + b.z3_expr
        
        overflow = None
        if track_overflow:
            # Check if result exceeds 256 bits
            overflow = SymbolicBool(
                name="add_overflow",
                z3_expr=z3.UGT(result_expr, SymbolicInt.Word(MAX_UINT256))
            )
        
        result = SymbolicInt(
            name=f"{a.name}_add_{b.name}",
            z3_expr=result_expr,
            constraints=a.constraints + b.constraints
        )
        
        return result, overflow
    
    @staticmethod
    def sub(a: SymbolicInt, b: SymbolicInt, track_underflow: bool = True) -> Tuple[SymbolicInt, Optional[SymbolicBool]]:
        """
        Symbolic SUB operation.
        
        Args:
            a: First operand
            b: Second operand
            track_underflow: Whether to track underflow condition
            
        Returns:
            Tuple of (result, underflow_flag if track_underflow)
        """
        result_expr = a.z3_expr - b.z3_expr
        
        underflow = None
        if track_underflow:
            underflow = SymbolicBool(
                name="sub_underflow",
                z3_expr=z3.UGT(b.z3_expr, a.z3_expr)
            )
        
        result = SymbolicInt(
            name=f"{a.name}_sub_{b.name}",
            z3_expr=result_expr,
            constraints=a.constraints + b.constraints
        )
        
        return result, underflow
    
    @staticmethod
    def mul(a: SymbolicInt, b: SymbolicInt, track_overflow: bool = True) -> Tuple[SymbolicInt, Optional[SymbolicBool]]:
        """
        Symbolic MUL operation.
        
        Args:
            a: First operand
            b: Second operand
            track_overflow: Whether to track overflow condition
            
        Returns:
            Tuple of (result, overflow_flag if track_overflow)
        """
        result_expr = a.z3_expr * b.z3_expr
        
        overflow = None
        if track_overflow:
            # For multiplication, check if a * b > MAX_UINT256
            overflow = SymbolicBool(
                name="mul_overflow",
                z3_expr=z3.UGT(result_expr, SymbolicInt.Word(MAX_UINT256))
            )
        
        result = SymbolicInt(
            name=f"{a.name}_mul_{b.name}",
            z3_expr=result_expr,
            constraints=a.constraints + b.constraints
        )
        
        return result, overflow
    
    @staticmethod
    def div(a: SymbolicInt, b: SymbolicInt) -> SymbolicInt:
        """
        Symbolic DIV (unsigned division) operation.
        
        Note: EVM DIV returns 0 when dividing by 0.
        
        Args:
            a: Dividend
            b: Divisor
            
        Returns:
            Result of a / b
        """
        result_expr = z3.UDiv(a.z3_expr, b.z3_expr)
        
        result = SymbolicInt(
            name=f"{a.name}_div_{b.name}",
            z3_expr=result_expr,
            constraints=a.constraints + b.constraints + [b.z3_expr != 0]
        )
        
        return result
    
    @staticmethod
    def sdiv(a: SymbolicInt, b: SymbolicInt) -> SymbolicInt:
        """
        Symbolic SDIV (signed division) operation.
        
        Args:
            a: Dividend
            b: Divisor
            
        Returns:
            Result of signed(a) / signed(b)
        """
        result_expr = z3.BVSDiv(a.z3_expr, b.z3_expr)
        
        result = SymbolicInt(
            name=f"{a.name}_sdiv_{b.name}",
            z3_expr=result_expr,
            constraints=a.constraints + b.constraints + [b.z3_expr != 0]
        )
        
        return result
    
    @staticmethod
    def mod(a: SymbolicInt, b: SymbolicInt) -> SymbolicInt:
        """
        Symbolic MOD (unsigned modulo) operation.
        
        Args:
            a: Dividend
            b: Divisor
            
        Returns:
            Result of a % b
        """
        result_expr = z3.URem(a.z3_expr, b.z3_expr)
        
        result = SymbolicInt(
            name=f"{a.name}_mod_{b.name}",
            z3_expr=result_expr,
            constraints=a.constraints + b.constraints + [b.z3_expr != 0]
        )
        
        return result
    
    @staticmethod
    def smod(a: SymbolicInt, b: SymbolicInt) -> SymbolicInt:
        """
        Symbolic SMOD (signed modulo) operation.
        
        Args:
            a: Dividend
            b: Divisor
            
        Returns:
            Result of signed(a) % signed(b)
        """
        result_expr = z3.BVSRem(a.z3_expr, b.z3_expr)
        
        result = SymbolicInt(
            name=f"{a.name}_smod_{b.name}",
            z3_expr=result_expr,
            constraints=a.constraints + b.constraints + [b.z3_expr != 0]
        )
        
        return result
    
    @staticmethod
    def addmod(a: SymbolicInt, b: SymbolicInt, c: SymbolicInt) -> SymbolicInt:
        """
        Symbolic ADDMOD operation: (a + b) % c.
        
        Args:
            a: First operand
            b: Second operand
            c: Modulus
            
        Returns:
            (a + b) % c
        """
        result_expr = z3.URem(a.z3_expr + b.z3_expr, c.z3_expr)
        
        result = SymbolicInt(
            name=f"{a.name}_addmod_{c.name}",
            z3_expr=result_expr,
            constraints=a.constraints + b.constraints + c.constraints + [c.z3_expr != 0]
        )
        
        return result
    
    @staticmethod
    def mulmod(a: SymbolicInt, b: SymbolicInt, c: SymbolicInt) -> SymbolicInt:
        """
        Symbolic MULMOD operation: (a * b) % c.
        
        Args:
            a: First operand
            b: Second operand
            c: Modulus
            
        Returns:
            (a * b) % c
        """
        result_expr = z3.URem(a.z3_expr * b.z3_expr, c.z3_expr)
        
        result = SymbolicInt(
            name=f"{a.name}_mulmod_{c.name}",
            z3_expr=result_expr,
            constraints=a.constraints + b.constraints + c.constraints + [c.z3_expr != 0]
        )
        
        return result
    
    @staticmethod
    def exp(base: SymbolicInt, exponent: SymbolicInt) -> SymbolicInt:
        """
        Symbolic EXP operation.
        
        Note: This is potentially expensive symbolically.
        
        Args:
            base: Base
            exponent: Exponent
            
        Returns:
            base ** exponent
        """
        # For symbolic exponentiation, we use uninterpreted function
        # In practice, this would be handled differently based on exponent nature
        result = SymbolicInt(
            name=f"{base.name}_exp_{exponent.name}",
            z3_expr=z3.BitVec(f"exp_{hash(str(base.z3_expr))}_{hash(str(exponent.z3_expr))}", 256)
        )
        
        return result
    
    @staticmethod
    def signextend(byte_count: SymbolicInt, value: SymbolicInt) -> SymbolicInt:
        """
        Symbolic SIGNEXTEND operation.
        
        Args:
            byte_count: Number of bytes to sign-extend from
            value: Value to extend
            
        Returns:
            Sign-extended value
        """
        if value.is_concrete() and byte_count.is_concrete():
            # Can compute concretely
            bc = int(str(byte_count.z3_expr))
            v = int(str(value.z3_expr))
            if bc >= 32:
                return value
            
            sign_bit = (v >> (bc * 8 - 1)) & 1
            if sign_bit:
                mask = (1 << (bc * 8)) - 1
                v = v | (~mask & ((1 << 256) - 1))
            else:
                mask = (1 << (bc * 8)) - 1
                v = v & mask
            
            return SymbolicInt.concrete(v)
        
        # Symbolic case
        result = SymbolicInt(
            name=f"{value.name}_sext_{byte_count.name}",
            z3_expr=z3.SignExt(256 - (byte_count.z3_expr + 1) * 8, value.z3_expr)
        )
        
        return result
    
    @staticmethod
    def lt(a: SymbolicInt, b: SymbolicInt) -> SymbolicBool:
        """
        Symbolic LT (unsigned less than) operation.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            a < b
        """
        result = SymbolicBool(
            name=f"{a.name}_lt_{b.name}",
            z3_expr=z3.ULT(a.z3_expr, b.z3_expr)
        )
        
        return result
    
    @staticmethod
    def gt(a: SymbolicInt, b: SymbolicInt) -> SymbolicBool:
        """
        Symbolic GT (unsigned greater than) operation.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            a > b
        """
        result = SymbolicBool(
            name=f"{a.name}_gt_{b.name}",
            z3_expr=z3.UGT(a.z3_expr, b.z3_expr)
        )
        
        return result
    
    @staticmethod
    def slt(a: SymbolicInt, b: SymbolicInt) -> SymbolicBool:
        """
        Symbolic SLT (signed less than) operation.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            signed(a) < signed(b)
        """
        result = SymbolicBool(
            name=f"{a.name}_slt_{b.name}",
            z3_expr=z3.BVSLT(a.z3_expr, b.z3_expr)
        )
        
        return result
    
    @staticmethod
    def sgt(a: SymbolicInt, b: SymbolicInt) -> SymbolicBool:
        """
        Symbolic SGT (signed greater than) operation.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            signed(a) > signed(b)
        """
        result = SymbolicBool(
            name=f"{a.name}_sgt_{b.name}",
            z3_expr=z3.BVSGT(a.z3_expr, b.z3_expr)
        )
        
        return result
    
    @staticmethod
    def eq(a: SymbolicInt, b: SymbolicInt) -> SymbolicBool:
        """
        Symbolic EQ operation.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            a == b
        """
        result = SymbolicBool(
            name=f"{a.name}_eq_{b.name}",
            z3_expr=a.z3_expr == b.z3_expr
        )
        
        return result
    
    @staticmethod
    def iszero(a: SymbolicInt) -> SymbolicBool:
        """
        Symbolic ISZERO operation.
        
        Args:
            a: Operand
            
        Returns:
            a == 0
        """
        result = SymbolicBool(
            name=f"{a.name}_iszero",
            z3_expr=a.z3_expr == 0
        )
        
        return result
    
    @staticmethod
    def and_(a: SymbolicInt, b: SymbolicInt) -> SymbolicInt:
        """
        Symbolic AND operation.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            a & b
        """
        result = SymbolicInt(
            name=f"{a.name}_and_{b.name}",
            z3_expr=a.z3_expr & b.z3_expr
        )
        
        return result
    
    @staticmethod
    def or_(a: SymbolicInt, b: SymbolicInt) -> SymbolicInt:
        """
        Symbolic OR operation.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            a | b
        """
        result = SymbolicInt(
            name=f"{a.name}_or_{b.name}",
            z3_expr=a.z3_expr | b.z3_expr
        )
        
        return result
    
    @staticmethod
    def xor(a: SymbolicInt, b: SymbolicInt) -> SymbolicInt:
        """
        Symbolic XOR operation.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            a ^ b
        """
        result = SymbolicInt(
            name=f"{a.name}_xor_{b.name}",
            z3_expr=a.z3_expr ^ b.z3_expr
        )
        
        return result
    
    @staticmethod
    def not_(a: SymbolicInt) -> SymbolicInt:
        """
        Symbolic NOT operation.
        
        Args:
            a: Operand
            
        Returns:
            ~a
        """
        result = SymbolicInt(
            name=f"{a.name}_not",
            z3_expr=~a.z3_expr
        )
        
        return result
    
    @staticmethod
    def byte(index: SymbolicInt, value: SymbolicInt) -> SymbolicInt:
        """
        Symbolic BYTE operation - extract byte from word.
        
        Args:
            index: Byte index (0 = most significant)
            value: Value to extract from
            
        Returns:
            The byte at index
        """
        # BYTE extracts the i-th byte from a 256-bit value
        # i=0 returns the most significant byte
        # Result is 0 if i >= 32
        
        if value.is_concrete() and index.is_concrete():
            idx = int(str(index.z3_expr))
            v = int(str(value.z3_expr))
            if idx < 32:
                return SymbolicInt.concrete((v >> (248 - idx * 8)) & 0xFF)
            else:
                return SymbolicInt.concrete(0)
        
        # Symbolic case: use extraction
        # For index 0, extract bits 248-255 (MSB)
        # For index 31, extract bits 0-7 (LSB)
        result = SymbolicInt(
            name=f"byte_{index.name}_{value.name}",
            z3_expr=z3.Extract(7, 0, value.z3_expr)  # Simplified
        )
        
        return result
    
    @staticmethod
    def shl(shift: SymbolicInt, value: SymbolicInt) -> SymbolicInt:
        """
        Symbolic SHL (left shift) operation.
        
        Args:
            shift: Number of bits to shift
            value: Value to shift
            
        Returns:
            value << shift
        """
        result = SymbolicInt(
            name=f"{value.name}_shl_{shift.name}",
            z3_expr=value.z3_expr << shift.z3_expr
        )
        
        return result
    
    @staticmethod
    def shr(shift: SymbolicInt, value: SymbolicInt) -> SymbolicInt:
        """
        Symbolic SHR (right shift) operation.
        
        Args:
            shift: Number of bits to shift
            value: Value to shift
            
        Returns:
            value >> shift (logical)
        """
        result = SymbolicInt(
            name=f"{value.name}_shr_{shift.name}",
            z3_expr=z3.LShR(value.z3_expr, shift.z3_expr)
        )
        
        return result
    
    @staticmethod
    def sar(shift: SymbolicInt, value: SymbolicInt) -> SymbolicInt:
        """
        Symbolic SAR (arithmetic right shift) operation.
        
        Args:
            shift: Number of bits to shift
            value: Value to shift
            
        Returns:
            value >> shift (arithmetic)
        """
        # For arithmetic right shift, we need to sign-extend
        # Z3's BVAShr does this automatically
        result = SymbolicInt(
            name=f"{value.name}_sar_{shift.name}",
            z3_expr=z3.BVAShr(value.z3_expr, shift.z3_expr)
        )
        
        return result
    
    # Address operations
    
    @staticmethod
    def address(addr: SymbolicAddress) -> SymbolicAddress:
        """Get current contract address."""
        return addr
    
    @staticmethod
    def balance(addr: SymbolicAddress) -> SymbolicInt:
        """Get balance of address."""
        return SymbolicInt(
            name=f"balance_{addr.name}",
            z3_expr=z3.BitVec(f"balance_{addr.name}", 256)
        )
    
    @staticmethod
    def origin() -> SymbolicAddress:
        """Get transaction origin."""
        return SymbolicAddress.symbolic("tx_origin")
    
    @staticmethod
    def caller() -> SymbolicAddress:
        """Get message sender."""
        return SymbolicAddress.symbolic("msg_sender")
    
    @staticmethod
    def callvalue() -> SymbolicInt:
        """Get msg.value."""
        return SymbolicInt.symbolic("msg_value")
    
    # Calldata operations
    
    @staticmethod
    def calldataload(offset: SymbolicInt) -> SymbolicBytes:
        """Load bytes from calldata."""
        return SymbolicBytes(
            name=f"calldata_{offset.name}",
            max_size=32
        )
    
    @staticmethod
    def calldatasize() -> SymbolicInt:
        """Get calldata size."""
        return SymbolicInt.symbolic("calldata_size")
    
    # Hash operations
    
    @staticmethod
    def keccak256(data: SymbolicBytes) -> SymbolicInt:
        """Compute keccak256 hash."""
        return SymbolicInt(
            name=f"keccak256_{data.name}",
            z3_expr=z3.BitVec(f"keccak256_{data.name}", 256)
        )
    
    # Control flow operations
    
    @staticmethod
    def jump(target: SymbolicInt, condition: SymbolicBool) -> bool:
        """
        Symbolic JUMPI operation.
        
        Returns:
            True if jump is taken, False otherwise
        """
        return condition.z3_expr
  
    # Memory operations
    
    @staticmethod
    def mload(offset: SymbolicInt, memory: dict) -> SymbolicInt:
        """Load from memory."""
        return SymbolicInt(
            name=f"mload_{offset.name}",
            z3_expr=z3.BitVec(f"mload_{offset.name}", 256)
        )
    
    @staticmethod
    def mstore(offset: SymbolicInt, value: SymbolicInt, memory: dict) -> None:
        """Store to memory."""
        memory[int(str(offset.z3_expr)) // 32] = value
    
    # Storage operations
    
    @staticmethod
    def sload(slot: SymbolicInt, storage: dict) -> SymbolicInt:
        """Load from storage."""
        slot_int = int(str(slot.z3_expr)) if slot.is_concrete else hash(str(slot.z3_expr))
        if slot_int in storage:
            return storage[slot_int]
        return SymbolicInt.symbolic(f"storage_{slot_int}")
    
    @staticmethod
    def sstore(slot: SymbolicInt, value: SymbolicInt, storage: dict) -> None:
        """Store to storage."""
        slot_int = int(str(slot.z3_expr)) if slot.is_concrete else hash(str(slot.z3_expr))
        storage[slot_int] = value
    
    # Block operations
    
    @staticmethod
    def blockhash(block_num: SymbolicInt) -> SymbolicInt:
        """Get block hash."""
        return SymbolicInt(
            name=f"blockhash_{block_num.name}",
            z3_expr=z3.BitVec(f"blockhash_{block_num.name}", 256)
        )
    
    @staticmethod
    def coinbase() -> SymbolicAddress:
        """Get block coinbase (miner address)."""
        return SymbolicAddress.symbolic("block_coinbase")
    
    @staticmethod
    def timestamp() -> SymbolicInt:
        """Get block timestamp."""
        return SymbolicInt.symbolic("block_timestamp")
    
    @staticmethod
    def number() -> SymbolicInt:
        """Get block number."""
        return SymbolicInt.symbolic("block_number")
    
    @staticmethod
    def difficulty() -> SymbolicInt:
        """Get block difficulty."""
        return SymbolicInt.symbolic("block_difficulty")
    
    @staticmethod
    def gaslimit() -> SymbolicInt:
        """Get block gas limit."""
        return SymbolicInt.symbolic("block_gaslimit")
    
    @staticmethod
    def chainid() -> SymbolicInt:
        """Get chain ID."""
        return SymbolicInt.symbolic("chain_id")
    
    @staticmethod
    def gasprice() -> SymbolicInt:
        """Get gas price."""
        return SymbolicInt.symbolic("tx_gasprice")
    
    # Contract creation/calls
    
    @staticmethod
    def create(value: SymbolicInt, code: SymbolicBytes) -> SymbolicAddress:
        """Create new contract."""
        return SymbolicAddress.symbolic("new_contract")
    
    @staticmethod
    def call(
        gas: SymbolicInt,
        addr: SymbolicAddress,
        value: SymbolicInt,
        args: SymbolicBytes
    ) -> Tuple[SymbolicBool, SymbolicBytes]:
        """Call another contract."""
        return (
            SymbolicBool.symbolic(f"call_success_{addr.name}"),
            SymbolicBytes.symbolic(f"call_return_{addr.name}")
        )
    
    @staticmethod
    def delegatecall(
        gas: SymbolicInt,
        addr: SymbolicAddress,
        args: SymbolicBytes
    ) -> SymbolicBool:
        """Delegate call."""
        return SymbolicBool.symbolic(f"delegatecall_success_{addr.name}")
    
    @staticmethod
    def staticcall(
        gas: SymbolicInt,
        addr: SymbolicAddress,
        args: SymbolicBytes
    ) -> Tuple[SymbolicBool, SymbolicBytes]:
        """Static call (cannot modify state)."""
        return (
            SymbolicBool.symbolic(f"staticcall_success_{addr.name}"),
            SymbolicBytes.symbolic(f"staticcall_return_{addr.name}")
        )
    
    @staticmethod
    def selfdestruct(addr: SymbolicAddress) -> None:
        """Self-destruct contract."""
        pass
    
    # Logging
    
    @staticmethod
    def log(topic_count: int, data: SymbolicBytes) -> None:
        """Emit log event."""
        pass


class OverflowDetector:
    """
    Detects and tracks arithmetic overflow conditions.
    
    Provides utilities for checking overflow conditions and
    generating appropriate constraints.
    """
    
    @staticmethod
    def check_add_overflow(a: z3.ExprRef, b: z3.ExprRef) -> z3.BoolRef:
        """
        Check if a + b would overflow.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            Z3 boolean indicating overflow condition
        """
        result = a + b
        return z3.UGT(result, z3.BitVecVal(2**256 - 1, 256))
    
    @staticmethod
    def check_sub_underflow(a: z3.ExprRef, b: z3.ExprRef) -> z3.BoolRef:
        """
        Check if a - b would underflow.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            Z3 boolean indicating underflow condition
        """
        return z3.UGT(b, a)
    
    @staticmethod
    def check_mul_overflow(a: z3.ExprRef, b: z3.ExprRef) -> z3.BoolRef:
        """
        Check if a * b would overflow.
        
        Args:
            a: First operand
            b: Second operand
            
        Returns:
            Z3 boolean indicating overflow condition
        """
        # Simplified: check if result > MAX_UINT256
        # For proper check, we'd need to verify a * b without overflow
        result = a * b
        return z3.UGT(result, z3.BitVecVal(2**256 - 1, 256))
    
    @staticmethod
    def check_div_zero(divisor: z3.ExprRef) -> z3.BoolRef:
        """Check if divisor is zero."""
        return divisor == 0
    
    @staticmethod
    def check_mod_zero(divisor: z3.ExprRef) -> z3.BoolRef:
        """Check if divisor is zero for modulo."""
        return divisor == 0


class GasCalculator:
    """
    Calculates gas consumption symbolically.
    
    Tracks minimum, maximum, and symbolic gas bounds.
    """
    
    # Base costs
    G_BASE = 2
    G_VERYLOW = 3
    G_LOW = 5
    G_MID = 8
    G_HIGH = 10
    G_JUMPDEST = 1
    G_SLOAD = 100
    G_SSTORE_SET = 20000
    G_SSTORE_RESET = 5000
    G_SSTORE_CLEAR_REFUND = 15000
    G_CALL = 700
    G_CALLVALUE = 9000
    G_CALLSTIPEND = 2300
    G_CREATE = 32000
    G_CREATE2 = 32000
    G_LOG = 375
    G_LOG_DATA = 8
    G_LOG_TOPIC = 375
    G_COPY = 3
    G_BLOCKHASH = 20
    G_EXPANSION = 200
    
    @classmethod
    def calculate_gas(
        cls,
        operation: str,
        operands: List[Any] = None
    ) -> Tuple[int, int]:
        """
        Calculate gas cost for an operation.
        
        Args:
            operation: Operation name
            operands: Operation operands
            
        Returns:
            Tuple of (min_gas, max_gas)
        """
        operands = operands or []
        
        base_costs = {
            'STOP': (0, 0),
            'ADD': (cls.G_VERYLOW, cls.G_VERYLOW),
            'MUL': (cls.G_LOW, cls.G_LOW),
            'SUB': (cls.G_VERYLOW, cls.G_VERYLOW),
            'DIV': (cls.G_LOW, cls.G_LOW),
            'SDIV': (cls.G_LOW, cls.G_LOW),
            'MOD': (cls.G_LOW, cls.G_LOW),
            'SMOD': (cls.G_LOW, cls.G_LOW),
            'ADDMOD': (cls.G_MID, cls.G_MID),
            'MULMOD': (cls.G_MID, cls.G_MID),
            'EXP': (cls.G_HIGH, cls.G_HIGH),  # + dynamic
            'SIGNEXTEND': (cls.G_LOW, cls.G_LOW),
            'LT': (cls.G_VERYLOW, cls.G_VERYLOW),
            'GT': (cls.G_VERYLOW, cls.G_VERYLOW),
            'SLT': (cls.G_VERYLOW, cls.G_VERYLOW),
            'SGT': (cls.G_VERYLOW, cls.G_VERYLOW),
            'EQ': (cls.G_VERYLOW, cls.G_VERYLOW),
            'ISZERO': (cls.G_VERYLOW, cls.G_VERYLOW),
            'AND': (cls.G_VERYLOW, cls.G_VERYLOW),
            'OR': (cls.G_VERYLOW, cls.G_VERYLOW),
            'XOR': (cls.G_VERYLOW, cls.G_VERYLOW),
            'NOT': (cls.G_VERYLOW, cls.G_VERYLOW),
            'BYTE': (cls.G_VERYLOW, cls.G_VERYLOW),
            'SHL': (cls.G_VERYLOW, cls.G_VERYLOW),
            'SHR': (cls.G_VERYLOW, cls.G_VERYLOW),
            'SAR': (cls.G_VERYLOW, cls.G_VERYLOW),
            'KECCAK256': (cls.G_HIGH, cls.G_HIGH),  # + dynamic
            'ADDRESS': (cls.G_BASE, cls.G_BASE),
            'BALANCE': (cls.G_BASE, cls.G_BASE),  # + cold access
            'ORIGIN': (cls.G_BASE, cls.G_BASE),
            'CALLER': (cls.G_BASE, cls.G_BASE),
            'CALLVALUE': (cls.G_BASE, cls.G_BASE),
            'CALLDATALOAD': (cls.G_VERYLOW, cls.G_VERYLOW),
            'CALLDATASIZE': (cls.G_VERYLOW, cls.G_VERYLOW),
            'CALLDATACOPY': (cls.G_VERYLOW, cls.G_VERYLOW),
            'CODESIZE': (cls.G_BASE, cls.G_BASE),
            'CODECOPY': (cls.G_VERYLOW, cls.G_VERYLOW),
            'EXTCODESIZE': (cls.G_BASE, cls.G_BASE),
            'EXTCODECOPY': (cls.G_HIGH, cls.G_HIGH),
            'EXTCODEHASH': (cls.G_BASE, cls.G_BASE),
            'RETURNDATASIZE': (cls.G_BASE, cls.G_BASE),
            'RETURNDATACOPY': (cls.G_VERYLOW, cls.G_VERYLOW),
            'POP': (cls.G_BASE, cls.G_BASE),
            'MLOAD': (cls.G_VERYLOW, cls.G_VERYLOW),
            'MSTORE': (cls.G_VERYLOW, cls.G_VERYLOW),
            'MSTORE8': (cls.G_VERYLOW, cls.G_VERYLOW),
            'SLOAD': (cls.G_SLOAD, cls.G_SLOAD),  # + cold access
            'SSTORE': (cls.G_SSTORE_SET, cls.G_SSTORE_RESET),
            'JUMP': (cls.G_MID, cls.G_MID),
            'JUMPI': (cls.G_HIGH, cls.G_HIGH),
            'JUMPDEST': (cls.G_JUMPDEST, cls.G_JUMPDEST),
            'PC': (cls.G_BASE, cls.G_BASE),
            'MSIZE': (cls.G_BASE, cls.G_BASE),
            'GAS': (cls.G_BASE, cls.G_BASE),
            'PUSH1': (cls.G_BASE, cls.G_BASE),
            'DUP1': (cls.G_VERYLOW, cls.G_VERYLOW),
            'SWAP1': (cls.G_VERYLOW, cls.G_VERYLOW),
            'LOG0': (cls.G_LOG, cls.G_LOG),
            'LOG1': (cls.G_LOG + cls.G_LOG_TOPIC, cls.G_LOG + cls.G_LOG_TOPIC),
            'LOG2': (cls.G_LOG + 2 * cls.G_LOG_TOPIC, cls.G_LOG + 2 * cls.G_LOG_TOPIC),
            'LOG3': (cls.G_LOG + 3 * cls.G_LOG_TOPIC, cls.G_LOG + 3 * cls.G_LOG_TOPIC),
            'LOG4': (cls.G_LOG + 4 * cls.G_LOG_TOPIC, cls.G_LOG + 4 * cls.G_LOG_TOPIC),
            'CREATE': (cls.G_CREATE, cls.G_CREATE),
            'CALL': (cls.G_CALL, cls.G_CALL),
            'CALLCODE': (cls.G_CALL, cls.G_CALL),
            'DELEGATECALL': (cls.G_CALL, cls.G_CALL),
            'STATICCALL': (cls.G_CALL, cls.G_CALL),
            'RETURN': (cls.G_BASE, cls.G_BASE),
            'REVERT': (cls.G_BASE, cls.G_BASE),
            'INVALID': (cls.G_BASE, cls.G_BASE),
            'SELFDESTRUCT': (cls.G_HIGH, cls.G_HIGH),
            'CREATE2': (cls.G_CREATE2, cls.G_CREATE2),
        }
        
        return base_costs.get(operation.upper(), (cls.G_BASE, cls.G_BASE))
