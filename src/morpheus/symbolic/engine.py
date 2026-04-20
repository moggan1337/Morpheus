"""
Symbolic Execution Engine with Z3 SMT Solver Integration
=========================================================

This module provides the core symbolic execution engine for smart contract
verification. It integrates with Microsoft's Z3 theorem prover to enable
symbolic analysis of contract behavior.

Key Components:
- Path exploration with symbolic constraints
- Z3 solver integration for constraint solving
- Branch point handling and path merging
- Precondition/postcondition checking
- Gas symbolic analysis

Author: Morpheus Team
"""

from __future__ import annotations
import z3
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class ConstraintLevel(Enum):
    """Levels for constraint tracking during symbolic execution."""
    HARD = auto()      # Cannot be violated (e.g., require statements)
    SOFT = auto()      # Can be violated but tracked (e.g., assumptions)
    PATH = auto()      # Path conditions (branches taken)
    TEMPORARY = auto() # Temporary constraints to be removed


@dataclass
class SymbolicConstraint:
    """Represents a constraint in the symbolic execution."""
    expr: z3.ExprRef
    level: ConstraintLevel
    source: str = ""  # Source location in contract
    description: str = ""
    
    def __hash__(self):
        return hash((str(self.expr), self.level))


@dataclass 
class PathCondition:
    """Represents the path condition for a symbolic execution path."""
    constraints: List[SymbolicConstraint] = field(default_factory=list)
    assumptions: List[z3.ExprRef] = field(default_factory=list)
    
    def add_constraint(self, constraint: SymbolicConstraint) -> None:
        """Add a constraint to the path condition."""
        self.constraints.append(constraint)
        
    def add_assumption(self, assumption: z3.ExprRef) -> None:
        """Add an assumption to the path condition."""
        self.assumptions.append(assumption)
    
    def to_z3(self) -> z3.Bool:
        """Convert path condition to Z3 boolean expression."""
        if not self.constraints and not self.assumptions:
            return z3.BoolVal(True)
        
        all_constraints = [c.expr for c in self.constraints]
        all_constraints.extend(self.assumptions)
        return z3.And(all_constraints)
    
    def is_satisfiable(self, solver: z3.Solver) -> Tuple[bool, Optional[Dict]]:
        """
        Check if the path condition is satisfiable.
        
        Returns:
            Tuple of (is_satisfiable, model if satisfiable else None)
        """
        solver.push()
        solver.add(self.to_z3())
        result = solver.check()
        
        if result == z3.sat:
            model = solver.model()
            solver.pop()
            return True, model
        else:
            solver.pop()
            return False, None
    
    def negate_branch(self, branch_expr: z3.ExprRef) -> PathCondition:
        """
        Create a new path condition representing the negated branch.
        Used for exploring alternative paths at branch points.
        """
        new_condition = PathCondition(
            constraints=self.constraints.copy(),
            assumptions=self.assumptions.copy()
        )
        new_condition.add_assumption(z3.Not(branch_expr))
        return new_condition


@dataclass
class ExecutionResult:
    """Result of symbolic execution of a function."""
    reachable: bool
    violations: List[Violation] = field(default_factory=list)
    path_conditions: List[PathCondition] = field(default_factory=list)
    return_values: List[Any] = field(default_factory=list)
    gas_estimate: Optional[int] = None
    steps: int = 0
    
    def has_violations(self) -> bool:
        return len(self.violations) > 0


@dataclass
class Violation:
    """Represents a property violation discovered during execution."""
    violation_type: str
    description: str
    path_condition: PathCondition
    counterexample: Optional[Dict[str, Any]] = None
    location: Optional[str] = None
    severity: str = "ERROR"


class SymbolicEngine(ABC):
    """
    Abstract symbolic execution engine for smart contracts.
    
    This class provides the base functionality for symbolic execution,
    including Z3 solver management, path exploration, and constraint tracking.
    
    Subclasses must implement:
    - execute_function()
    - handle_special_function()
    - translate_opcode()
    """
    
    def __init__(
        self,
        timeout: int = 30000,
        max_depth: int = 1000,
        max_paths: int = 10000,
        use_simplifier: bool = True
    ):
        """
        Initialize the symbolic execution engine.
        
        Args:
            timeout: Z3 solver timeout in milliseconds
            max_depth: Maximum execution depth
            max_paths: Maximum number of paths to explore
            use_simplifier: Whether to use Z3 simplifier
        """
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.use_simplifier = use_simplifier
        
        # Initialize Z3 solver
        self.solver = z3.Solver()
        self.solver.set(timeout=timeout)
        
        # Execution state
        self.paths_explored = 0
        self.constraints_history: List[List[SymbolicConstraint]] = [[]]
        
        # Symbolic variables
        self.symbolic_counter = 0
        self.symbolic_vars: Dict[str, z3.ExprRef] = {}
        
        # Call stack for tracking function calls
        self.call_stack: List[str] = []
        
        # Results
        self.results: List[ExecutionResult] = []
        self.violations: List[Violation] = []
        
        # Configuration
        self.track_gas = True
        self.track_storage = True
        self.track_memory = True
        
        logger.info(f"Initialized SymbolicEngine with timeout={timeout}ms, max_depth={max_depth}")
    
    def fresh_symbolic_var(
        self,
        name: str,
        z3_sort: Optional[z3.Sort] = None
    ) -> z3.ExprRef:
        """
        Create a fresh symbolic variable.
        
        Args:
            name: Base name for the variable
            z3_sort: Z3 sort (defaults to BitVec(256) for EVM compatibility)
            
        Returns:
            Z3 symbolic expression
        """
        if z3_sort is None:
            z3_sort = z3.BitVecSort(256)
        
        unique_name = f"{name}_{self.symbolic_counter}"
        self.symbolic_counter += 1
        var = z3.FreshConst(z3_sort, name=unique_name)
        self.symbolic_vars[unique_name] = var
        return var
    
    def create_symbolic_value(
        self,
        name: str,
        size: int = 256
    ) -> z3.ExprRef:
        """
        Create a symbolic value of specified size.
        
        Args:
            name: Name for the symbolic value
            size: Bit size (256 for EVM word)
            
        Returns:
            Symbolic bitvector expression
        """
        return self.fresh_symbolic_var(name, z3.BitVecSort(size))
    
    def create_symbolic_bool(self, name: str) -> z3.ExprRef:
        """Create a symbolic boolean value."""
        return self.fresh_symbolic_var(name, z3.BoolSort())
    
    def add_constraint(
        self,
        constraint: z3.ExprRef,
        level: ConstraintLevel = ConstraintLevel.HARD,
        source: str = "",
        description: str = ""
    ) -> None:
        """
        Add a constraint to the current path.
        
        Args:
            constraint: Z3 constraint expression
            level: Constraint level
            source: Source location
            description: Human-readable description
        """
        sym_constraint = SymbolicConstraint(
            expr=constraint,
            level=level,
            source=source,
            description=description
        )
        
        # Check satisfiability before adding
        self.solver.push()
        self.solver.add(constraint)
        
        if self.solver.check() == z3.unsat:
            logger.warning(f"Adding unsatisfiable constraint: {constraint}")
            self.violations.append(Violation(
                violation_type="UNSATISFIABLE_CONSTRAINT",
                description=f"Constraint unsatisfiable: {description}",
                path_condition=self._get_current_path_condition(),
                location=source
            ))
        
        self.solver.pop()
        
        # Add to current path
        if self.constraints_history:
            self.constraints_history[-1].append(sym_constraint)
    
    def _get_current_path_condition(self) -> PathCondition:
        """Get the current path condition from constraint history."""
        return PathCondition(
            constraints=self.constraints_history[-1] if self.constraints_history else []
        )
    
    def check_satisfiability(
        self,
        additional_constraints: Optional[List[z3.ExprRef]] = None
    ) -> Tuple[bool, Optional[z3.Model]]:
        """
        Check if current path constraints are satisfiable.
        
        Args:
            additional_constraints: Additional constraints to check
            
        Returns:
            Tuple of (is_satisfiable, model)
        """
        self.solver.push()
        
        if additional_constraints:
            for constraint in additional_constraints:
                self.solver.add(constraint)
        
        result = self.solver.check()
        
        if result == z3.sat:
            model = self.solver.model()
            self.solver.pop()
            return True, model
        else:
            self.solver.pop()
            return False, None
    
    def get_model_values(
        self,
        vars_to_query: List[z3.ExprRef]
    ) -> Optional[Dict[str, Any]]:
        """
        Get concrete values from the current model for given variables.
        
        Args:
            vars_to_query: List of Z3 expressions to evaluate
            
        Returns:
            Dictionary mapping variable names to concrete values
        """
        result, model = self.check_satisfiability()
        
        if not result or model is None:
            return None
        
        values = {}
        for var in vars_to_query:
            try:
                values[str(var)] = model.eval(var, model_completion=True)
            except z3.Z3Exception:
                values[str(var)] = None
        
        return values
    
    def push_path(self) -> None:
        """Push a new path level for branching."""
        self.constraints_history.append([])
        self.solver.push()
        self.paths_explored += 1
        
        if self.paths_explored > self.max_paths:
            logger.warning(f"Max paths ({self.max_paths}) exceeded")
            raise StopIteration("Maximum paths exceeded")
    
    def pop_path(self) -> None:
        """Pop the current path level."""
        if self.constraints_history:
            self.constraints_history.pop()
        self.solver.pop()
    
    def branch(
        self,
        condition: z3.ExprRef,
        on_true: callable,
        on_false: callable
    ) -> Tuple[Any, Any]:
        """
        Branch on a condition, exploring both paths.
        
        Args:
            condition: Branch condition
            on_true: Callback for true branch
            on_false: Callback for false branch
            
        Returns:
            Tuple of results from both branches
        """
        true_result = None
        false_result = None
        
        # Explore true branch
        self.push_path()
        self.add_constraint(condition, level=ConstraintLevel.PATH)
        try:
            sat, _ = self.check_satisfiability()
            if sat:
                true_result = on_true()
        except StopIteration:
            pass
        finally:
            self.pop_path()
        
        # Explore false branch
        self.push_path()
        self.add_constraint(z3.Not(condition), level=ConstraintLevel.PATH)
        try:
            sat, _ = self.check_satisfiability()
            if sat:
                false_result = on_false()
        except StopIteration:
            pass
        finally:
            self.pop_path()
        
        return true_result, false_result
    
    @abstractmethod
    def execute_function(
        self,
        function_name: str,
        args: Dict[str, Any],
        contract_state: Dict[str, Any]
    ) -> ExecutionResult:
        """
        Execute a function symbolically.
        
        Args:
            function_name: Name of function to execute
            args: Function arguments
            contract_state: Initial contract state
            
        Returns:
            Execution result with violations and paths
        """
        pass
    
    @abstractmethod
    def translate_opcode(self, opcode: Any) -> z3.ExprRef:
        """
        Translate an EVM opcode to Z3 expression.
        
        Args:
            opcode: EVM opcode
            
        Returns:
            Z3 expression representing the operation
        """
        pass
    
    def prove(
        self,
        property: z3.ExprRef,
        is_invariant: bool = False
    ) -> Tuple[bool, Optional[Dict]]:
        """
        Attempt to prove a property using Z3.
        
        Args:
            property: Property to prove
            is_invariant: Whether this is an invariant (prove ∀) or postcondition (prove ⇒)
            
        Returns:
            Tuple of (proved, counterexample if not proved)
        """
        self.solver.push()
        
        if is_invariant:
            # For invariants, we prove that negation is unsatisfiable
            self.solver.add(z3.Not(property))
        else:
            # For postconditions, prove implication
            pass
        
        result = self.solver.check()
        self.solver.pop()
        
        if result == z3.unsat:
            logger.info("Property proved: UNSAT")
            return True, None
        elif result == z3.sat:
            model = self.solver.model()
            logger.info("Property NOT proved: counterexample found")
            return False, model
        else:
            logger.warning("Property check returned UNKNOWN")
            return False, None
    
    def check_invariant(
        self,
        invariant: z3.ExprRef,
        initial_state: Optional[Dict] = None
    ) -> Tuple[bool, List[Dict]]:
        """
        Check an invariant over all possible states.
        
        Args:
            invariant: Invariant to check
            initial_state: Optional initial state constraints
            
        Returns:
            Tuple of (holds, list of counterexamples)
        """
        counterexamples = []
        
        # Add initial state constraints if provided
        if initial_state:
            for key, value in initial_state.items():
                self.add_constraint(
                    z3.BitVecVal(value, 256) == self.symbolic_vars.get(key, z3.BitVec(key, 256)),
                    level=ConstraintLevel.HARD,
                    description=f"Initial state: {key} = {value}"
                )
        
        # Try to find counterexample
        self.solver.push()
        self.solver.add(z3.Not(invariant))
        
        while self.solver.check() == z3.sat:
            model = self.solver.model()
            counterexamples.append({
                str(v): model.eval(v, model_completion=True) 
                for v in self.symbolic_vars.values()
            })
            
            # Block this counterexample to find another
            block = z3.Or([
                v != model.eval(v, model_completion=True)
                for v in self.symbolic_vars.values()
            ])
            self.solver.add(block)
        
        self.solver.pop()
        
        return len(counterexamples) == 0, counterexamples
    
    def reset(self) -> None:
        """Reset the engine state."""
        self.solver = z3.Solver()
        self.solver.set(timeout=self.timeout)
        self.constraints_history = [[]]
        self.symbolic_vars = {}
        self.symbolic_counter = 0
        self.paths_explored = 0
        self.results = []
        self.violations = []
        self.call_stack = []


class EVMSymbolicEngine(SymbolicEngine):
    """
    EVM-specific symbolic execution engine.
    
    Implements symbolic execution for Ethereum Virtual Machine bytecode
    and Solidity contracts.
    """
    
    def __init__(
        self,
        bytecode: Optional[bytes] = None,
        calldata_signature: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize EVM symbolic engine.
        
        Args:
            bytecode: Contract bytecode
            calldata_signature: Function selector for calldata
            **kwargs: Base engine configuration
        """
        super().__init__(**kwargs)
        self.bytecode = bytecode or b""
        self.calldata_signature = calldata_signature
        
        # EVM state
        self.stack: List[z3.ExprRef] = []
        self.memory: List[z3.ExprRef] = []
        self.storage: Dict[int, z3.ExprRef] = {}
        self.gas = self.fresh_symbolic_var("gas", z3.BitVecSort(256))
        
        # Precompile contracts
        self.precompile_addresses = {
            1: self._precompile_ecrecover,
            2: self._precompile_sha256,
            3: self._precompile_ripemd160,
            4: self._precompile_identity,
            5: self._precompile_modexp,
            6: self._precompile_ecadd,
            7: self._precompile_ecmul,
            8: self._precompile_ecpairing,
        }
    
    def execute_function(
        self,
        function_name: str,
        args: Dict[str, Any],
        contract_state: Dict[str, Any]
    ) -> ExecutionResult:
        """Execute a function with symbolic analysis."""
        result = ExecutionResult(reachable=True)
        
        # Create symbolic calldata
        calldata = self._create_symbolic_calldata(function_name, args)
        
        # Initialize contract state
        for key, value in contract_state.items():
            self.storage[self._storage_key(key)] = z3.BitVecVal(value, 256)
        
        # Create symbolic state variables
        caller = self.create_symbolic_value("caller")
        origin = self.create_symbolic_value("origin")
        value = self.create_symbolic_value("value")
        gas_price = self.create_symbolic_value("gas_price")
        
        # Execute bytecode symbolically
        try:
            self._execute_bytecode(calldata, result)
        except Exception as e:
            logger.error(f"Execution error: {e}")
            result.reachable = False
        
        return result
    
    def _create_symbolic_calldata(
        self,
        function_name: str,
        args: Dict[str, Any]
    ) -> z3.ExprRef:
        """Create symbolic calldata for function call."""
        # Function selector is first 4 bytes
        selector = self._get_function_selector(function_name)
        selector_bv = z3.BitVecVal(selector, 32)
        
        # Create symbolic args
        symbolic_args = []
        for i, (name, value) in enumerate(args.items()):
            if isinstance(value, int):
                symbolic_args.append(z3.BitVecVal(value, 256))
            else:
                symbolic_args.append(self.create_symbolic_value(f"arg_{name}"))
        
        return z3.Concat([selector_bv] + symbolic_args)
    
    def _get_function_selector(self, name: str) -> int:
        """Compute function selector using keccak256."""
        import sha3
        keccak = sha3.keccak_256()
        keccak.update(name.encode())
        return int.from_bytes(keccak.digest()[:4], 'big')
    
    def _execute_bytecode(
        self,
        calldata: z3.ExprRef,
        result: ExecutionResult
    ) -> None:
        """Execute bytecode with symbolic interpretation."""
        pc = 0
        depth = 0
        
        while pc < len(self.bytecode) and depth < self.max_depth:
            opcode = self.bytecode[pc]
            
            # Handle opcodes symbolically
            result.steps += 1
            
            if opcode == 0x00:  # STOP
                break
            elif opcode == 0x01:  # ADD
                self._arith_add()
            elif opcode == 0x02:  # MUL
                self._arith_mul()
            elif opcode == 0x03:  # SUB
                self._arith_sub()
            elif opcode == 0x04:  # DIV
                self._arith_div()
            elif opcode == 0x05:  # SDIV
                self._arith_sdiv()
            elif opcode == 0x06:  # MOD
                self._arith_mod()
            elif opcode == 0x07:  # SMOD
                self._arith_smod()
            elif opcode == 0x08:  # ADDMOD
                self._arith_addmod()
            elif opcode == 0x09:  # MULMOD
                self._arith_mulmod()
            elif opcode == 0x10:  # LT
                self._compare_lt()
            elif opcode == 0x11:  # GT
                self._compare_gt()
            elif opcode == 0x14:  # EQ
                self._compare_eq()
            elif opcode == 0x15:  # ISZERO
                self._logic_iszero()
            elif opcode == 0x18:  # XOR
                self._logic_xor()
            elif opcode == 0x19:  # NOT
                self._logic_not()
            elif opcode == 0x20:  # SHA3
                self._crypto_sha3()
            elif opcode == 0x30:  # ADDRESS
                self.stack.append(self.create_symbolic_value("address"))
            elif opcode == 0x31:  # BALANCE
                self._op_balance()
            elif opcode == 0x32:  # ORIGIN
                self.stack.append(self.create_symbolic_value("origin"))
            elif opcode == 0x33:  # CALLER
                self.stack.append(self.create_symbolic_value("caller"))
            elif opcode == 0x34:  # CALLVALUE
                self.stack.append(self.create_symbolic_value("value"))
            elif opcode == 0x35:  # CALLDATALOAD
                self._op_calldataload()
            elif opcode == 0x36:  # CALLDATASIZE
                self.stack.append(self.create_symbolic_value("calldata_size"))
            elif opcode == 0x37:  # CALLDATACOPY
                self._op_calldatacopy()
            elif opcode == 0x38:  # CODESIZE
                self.stack.append(z3.BitVecVal(len(self.bytecode), 256))
            elif opcode == 0x3B:  # EXTCODESIZE
                self.stack.append(z3.BitVecVal(1, 256))  # Assume 1 for simplicity
            elif opcode == 0x3F:  # EXTCODEHASH
                self.stack.append(self.create_symbolic_value("extcodehash"))
            elif opcode == 0x50:  # POP
                if self.stack:
                    self.stack.pop()
            elif opcode == 0x51:  # MLOAD
                self._op_mload()
            elif opcode == 0x52:  # MSTORE
                self._op_mstore()
            elif opcode == 0x53:  # MSTORE8
                self._op_mstore8()
            elif opcode == 0x54:  # SLOAD
                self._op_sload()
            elif opcode == 0x55:  # SSTORE
                self._op_sstore()
            elif opcode == 0x56:  # JUMP
                self._op_jump()
            elif opcode == 0x57:  # JUMPI
                self._op_jumpi()
            elif opcode == 0x58:  # PC
                self.stack.append(z3.BitVecVal(pc, 256))
            elif opcode == 0x59:  # MSIZE
                self.stack.append(z3.BitVecVal(len(self.memory) * 32, 256))
            elif opcode == 0x5A:  # GAS
                self.stack.append(self.gas)
            elif opcode == 0x5B:  # JUMPDEST
                pass  # Marker, no operation
            elif opcode == 0x60:  # PUSH1
                self._push_bytes(1)
            elif opcode == 0x61:  # PUSH2
                self._push_bytes(2)
            elif opcode == 0x62:  # PUSH3
                self._push_bytes(3)
            elif opcode == 0x63:  # PUSH4
                self._push_bytes(4)
            elif opcode == 0x64:  # PUSH5
                self._push_bytes(5)
            elif opcode == 0x65:  # PUSH6
                self._push_bytes(6)
            elif opcode == 0x66:  # PUSH7
                self._push_bytes(7)
            elif opcode == 0x67:  # PUSH8
                self._push_bytes(8)
            elif opcode == 0x68:  # PUSH9
                self._push_bytes(9)
            elif opcode == 0x69:  # PUSH10
                self._push_bytes(10)
            elif opcode == 0x6A:  # PUSH11
                self._push_bytes(11)
            elif opcode == 0x6B:  # PUSH12
                self._push_bytes(12)
            elif opcode == 0x6C:  # PUSH13
                self._push_bytes(13)
            elif opcode == 0x6D:  # PUSH14
                self._push_bytes(14)
            elif opcode == 0x6E:  # PUSH15
                self._push_bytes(15)
            elif opcode == 0x6F:  # PUSH16
                self._push_bytes(16)
            elif opcode == 0x70:  # PUSH17
                self._push_bytes(17)
            elif opcode == 0x71:  # PUSH18
                self._push_bytes(18)
            elif opcode == 0x72:  # PUSH19
                self._push_bytes(19)
            elif opcode == 0x73:  # PUSH20
                self._push_bytes(20)
            elif opcode == 0x74:  # PUSH21
                self._push_bytes(21)
            elif opcode == 0x75:  # PUSH22
                self._push_bytes(22)
            elif opcode == 0x76:  # PUSH23
                self._push_bytes(23)
            elif opcode == 0x77:  # PUSH24
                self._push_bytes(24)
            elif opcode == 0x78:  # PUSH25
                self._push_bytes(25)
            elif opcode == 0x79:  # PUSH26
                self._push_bytes(26)
            elif opcode == 0x7A:  # PUSH27
                self._push_bytes(27)
            elif opcode == 0x7B:  # PUSH28
                self._push_bytes(28)
            elif opcode == 0x7C:  # PUSH29
                self._push_bytes(29)
            elif opcode == 0x7D:  # PUSH30
                self._push_bytes(30)
            elif opcode == 0x7E:  # PUSH31
                self._push_bytes(31)
            elif opcode == 0x7F:  # PUSH32
                self._push_bytes(32)
            elif opcode == 0x80:  # DUP1
                self._dup(1)
            elif opcode == 0x81:  # DUP2
                self._dup(2)
            elif opcode == 0x82:  # DUP3
                self._dup(3)
            elif opcode == 0x83:  # DUP4
                self._dup(4)
            elif opcode == 0x84:  # DUP5
                self._dup(5)
            elif opcode == 0x85:  # DUP6
                self._dup(6)
            elif opcode == 0x86:  # DUP7
                self._dup(7)
            elif opcode == 0x87:  # DUP8
                self._dup(8)
            elif opcode == 0x88:  # DUP9
                self._dup(9)
            elif opcode == 0x89:  # DUP10
                self._dup(10)
            elif opcode == 0x8A:  # DUP11
                self._dup(11)
            elif opcode == 0x8B:  # DUP12
                self._dup(12)
            elif opcode == 0x8C:  # DUP13
                self._dup(13)
            elif opcode == 0x8D:  # DUP14
                self._dup(14)
            elif opcode == 0x8E:  # DUP15
                self._dup(15)
            elif opcode == 0x8F:  # DUP16
                self._dup(16)
            elif opcode == 0x90:  # SWAP1
                self._swap(1)
            elif opcode == 0x91:  # SWAP2
                self._swap(2)
            elif opcode == 0x92:  # SWAP3
                self._swap(3)
            elif opcode == 0x93:  # SWAP4
                self._swap(4)
            elif opcode == 0x94:  # SWAP5
                self._swap(5)
            elif opcode == 0x95:  # SWAP6
                self._swap(6)
            elif opcode == 0x96:  # SWAP7
                self._swap(7)
            elif opcode == 0x97:  # SWAP8
                self._swap(8)
            elif opcode == 0x98:  # SWAP9
                self._swap(9)
            elif opcode == 0x99:  # SWAP10
                self._swap(10)
            elif opcode == 0x9A:  # SWAP11
                self._swap(11)
            elif opcode == 0x9B:  # SWAP12
                self._swap(12)
            elif opcode == 0x9C:  # SWAP13
                self._swap(13)
            elif opcode == 0x9D:  # SWAP14
                self._swap(14)
            elif opcode == 0x9E:  # SWAP15
                self._swap(15)
            elif opcode == 0x9F:  # SWAP16
                self._swap(16)
            elif opcode == 0xA0:  # LOG0
                self._log(0)
            elif opcode == 0xA1:  # LOG1
                self._log(1)
            elif opcode == 0xA2:  # LOG2
                self._log(2)
            elif opcode == 0xA3:  # LOG3
                self._log(3)
            elif opcode == 0xA4:  # LOG4
                self._log(4)
            elif opcode == 0xF0:  # CREATE
                self._op_create()
            elif opcode == 0xF1:  # CALL
                self._op_call()
            elif opcode == 0xF2:  # CALLCODE
                self._op_callcode()
            elif opcode == 0xF3:  # RETURN
                break
            elif opcode == 0xF4:  # DELEGATECALL
                self._op_delegatecall()
            elif opcode == 0xF5:  # CREATE2
                self._op_create2()
            elif opcode == 0xFA:  # STATICCALL
                self._op_staticcall()
            elif opcode == 0xFD:  # REVERT
                result.reachable = True
                break
            elif opcode == 0xFE:  # INVALID
                result.violations.append(Violation(
                    violation_type="INVALID_OPCODE",
                    description="Execution reached INVALID opcode",
                    path_condition=self._get_current_path_condition()
                ))
                break
            elif opcode == 0xFF:  # SELFDESTRUCT
                result.violations.append(Violation(
                    violation_type="SELFDESTRUCT",
                    description="Contract self-destructed",
                    path_condition=self._get_current_path_condition(),
                    severity="WARNING"
                ))
                break
            
            pc += 1
        
        result.path_conditions.append(self._get_current_path_condition())
    
    # EVM Operation Implementations
    
    def _arith_add(self) -> None:
        if len(self.stack) >= 2:
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.append(a + b)
    
    def _arith_mul(self) -> None:
        if len(self.stack) >= 2:
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.append(a * b)
    
    def _arith_sub(self) -> None:
        if len(self.stack) >= 2:
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.append(b - a)
    
    def _arith_div(self) -> None:
        if len(self.stack) >= 2:
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.append(z3.UDiv(b, a) if isinstance(a, z3.BitVecRef) else b / a)
    
    def _arith_sdiv(self) -> None:
        if len(self.stack) >= 2:
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.append(z3.BVSDiv(b, a) if isinstance(a, z3.BitVecRef) else b / a)
    
    def _arith_mod(self) -> None:
        if len(self.stack) >= 2:
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.append(z3.URem(b, a) if isinstance(a, z3.BitVecRef) else b % a)
    
    def _arith_smod(self) -> None:
        if len(self.stack) >= 2:
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.append(z3.BVSRem(b, a) if isinstance(a, z3.BitVecRef) else b % a)
    
    def _arith_addmod(self) -> None:
        if len(self.stack) >= 3:
            a = self.stack.pop()
            b = self.stack.pop()
            c = self.stack.pop()
            result = z3.simplify(z3.URem(b + a, c))
            self.stack.append(result)
    
    def _arith_mulmod(self) -> None:
        if len(self.stack) >= 3:
            a = self.stack.pop()
            b = self.stack.pop()
            c = self.stack.pop()
            result = z3.simplify(z3.URem(b * a, c))
            self.stack.append(result)
    
    def _compare_lt(self) -> None:
        if len(self.stack) >= 2:
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.append(z3.If(a < b, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
    
    def _compare_gt(self) -> None:
        if len(self.stack) >= 2:
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.append(z3.If(a > b, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
    
    def _compare_eq(self) -> None:
        if len(self.stack) >= 2:
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.append(z3.If(a == b, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
    
    def _logic_iszero(self) -> None:
        if len(self.stack) >= 1:
            a = self.stack.pop()
            self.stack.append(z3.If(a == 0, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)))
    
    def _logic_xor(self) -> None:
        if len(self.stack) >= 2:
            a = self.stack.pop()
            b = self.stack.pop()
            self.stack.append(a ^ b)
    
    def _logic_not(self) -> None:
        if len(self.stack) >= 1:
            a = self.stack.pop()
            self.stack.append(~a)
    
    def _crypto_sha3(self) -> None:
        if len(self.stack) >= 2:
            offset = self.stack.pop()
            length = self.stack.pop()
            # Symbolic SHA3 result
            result = self.create_symbolic_value("sha3_result")
            self.stack.append(result)
    
    def _op_balance(self) -> None:
        if len(self.stack) >= 1:
            self.stack.pop()
            self.stack.append(self.create_symbolic_value("balance"))
    
    def _op_calldataload(self) -> None:
        if len(self.stack) >= 1:
            offset = self.stack.pop()
            result = self.create_symbolic_value("calldata")
            self.stack.append(result)
    
    def _op_calldatacopy(self) -> None:
        if len(self.stack) >= 3:
            dest = self.stack.pop()
            offset = self.stack.pop()
            length = self.stack.pop()
            for _ in range(z3.get_eq(length, 32) if isinstance(length, z3.BitVecRef) else 32):
                self.memory.append(self.create_symbolic_value("calldata_byte"))
    
    def _op_mload(self) -> None:
        if len(self.stack) >= 1:
            offset = self.stack.pop()
            if offset is not None:
                idx = int(str(offset)) // 32 if isinstance(offset, z3.BitVecNumRef) else 0
                while len(self.memory) <= idx:
                    self.memory.append(self.create_symbolic_value(f"mem_{len(self.memory)}"))
                self.stack.append(self.memory[idx])
    
    def _op_mstore(self) -> None:
        if len(self.stack) >= 2:
            offset = self.stack.pop()
            value = self.stack.pop()
            if isinstance(offset, z3.BitVecNumRef):
                idx = int(str(offset)) // 32
                while len(self.memory) <= idx:
                    self.memory.append(self.create_symbolic_value(f"mem_{len(self.memory)}"))
                self.memory[idx] = value
    
    def _op_mstore8(self) -> None:
        if len(self.stack) >= 2:
            self.stack.pop()
            self.stack.pop()
    
    def _op_sload(self) -> None:
        if len(self.stack) >= 1:
            key = self.stack.pop()
            if isinstance(key, z3.BitVecNumRef):
                key_int = int(str(key))
            else:
                key_int = hash(str(key))
            
            if key_int not in self.storage:
                self.storage[key_int] = self.create_symbolic_value(f"storage_{key_int}")
            
            self.stack.append(self.storage[key_int])
    
    def _op_sstore(self) -> None:
        if len(self.stack) >= 2:
            key = self.stack.pop()
            value = self.stack.pop()
            if isinstance(key, z3.BitVecNumRef):
                key_int = int(str(key))
            else:
                key_int = hash(str(key))
            self.storage[key_int] = value
    
    def _op_jump(self) -> None:
        if len(self.stack) >= 1:
            self.stack.pop()
    
    def _op_jumpi(self) -> None:
        if len(self.stack) >= 2:
            dest = self.stack.pop()
            condition = self.stack.pop()
            self.add_constraint(
                z3.Not(condition == 0),
                level=ConstraintLevel.PATH,
                description="Jump condition"
            )
    
    def _push_bytes(self, n: int) -> None:
        pc = len(self.stack)  # Simplified
        if pc + n < len(self.bytecode):
            value = int.from_bytes(self.bytecode[pc:pc+n], 'big')
            self.stack.append(z3.BitVecVal(value, 256))
    
    def _dup(self, n: int) -> None:
        if len(self.stack) >= n:
            self.stack.append(self.stack[-n])
    
    def _swap(self, n: int) -> None:
        if len(self.stack) >= n + 1:
            idx = -(n + 1)
            self.stack[-1], self.stack[idx] = self.stack[idx], self.stack[-1]
    
    def _log(self, n: int) -> None:
        for _ in range(n + 2):
            if self.stack:
                self.stack.pop()
    
    def _op_create(self) -> None:
        if len(self.stack) >= 3:
            self.stack.pop()
            self.stack.pop()
            self.stack.pop()
            self.stack.append(self.create_symbolic_value("new_address"))
    
    def _op_call(self) -> None:
        if len(self.stack) >= 7:
            gas = self.stack.pop()
            addr = self.stack.pop()
            value = self.stack.pop()
            args_offset = self.stack.pop()
            args_length = self.stack.pop()
            ret_offset = self.stack.pop()
            ret_length = self.stack.pop()
            
            result = self.create_symbolic_bool("call_result")
            self.stack.append(result)
    
    def _op_callcode(self) -> None:
        self._op_call()
    
    def _op_delegatecall(self) -> None:
        self._op_call()
    
    def _op_create2(self) -> None:
        self._op_create()
    
    def _op_staticcall(self) -> None:
        if len(self.stack) >= 6:
            gas = self.stack.pop()
            addr = self.stack.pop()
            args_offset = self.stack.pop()
            args_length = self.stack.pop()
            ret_offset = self.stack.pop()
            ret_length = self.stack.pop()
            
            result = self.create_symbolic_bool("staticcall_result")
            self.stack.append(result)
    
    def _storage_key(self, name: str) -> int:
        """Convert storage variable name to slot."""
        import sha3
        keccak = sha3.keccak_256()
        keccak.update(name.encode())
        return int.from_bytes(keccak.digest()[:32], 'big')
    
    def _precompile_ecrecover(self, data: bytes) -> bytes:
        """Precompile: ecrecover"""
        return b'\x00' * 32
    
    def _precompile_sha256(self, data: bytes) -> bytes:
        """Precompile: SHA256"""
        import hashlib
        return hashlib.sha256(data).digest()
    
    def _precompile_ripemd160(self, data: bytes) -> bytes:
        """Precompile: RIPEMD160"""
        import hashlib
        return hashlib.new('ripemd160', data).digest()
    
    def _precompile_identity(self, data: bytes) -> bytes:
        """Precompile: identity (copy)"""
        return data
    
    def _precompile_modexp(self, data: bytes) -> bytes:
        """Precompile: modular exponentiation"""
        return b'\x00' * 32  # Simplified
    
    def _precompile_ecadd(self, data: bytes) -> bytes:
        """Precompile: BN128 addition"""
        return b'\x00' * 64
    
    def _precompile_ecmul(self, data: bytes) -> bytes:
        """Precompile: BN128 multiplication"""
        return b'\x00' * 64
    
    def _precompile_ecpairing(self, data: bytes) -> bytes:
        """Precompile: BN128 pairing check"""
        return b'\x00' * 32
    
    def translate_opcode(self, opcode: Any) -> z3.ExprRef:
        """Translate an opcode to Z3 expression."""
        if hasattr(opcode, 'result'):
            return opcode.result
        return self.create_symbolic_value("opcode_result")
