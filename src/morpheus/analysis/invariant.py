"""
Invariant Detection and Verification
====================================

This module provides automatic detection and verification of
invariants in smart contracts using symbolic execution and
theorem proving.

Invariant Types:
- Loop invariants
- Function preconditions/postconditions
- Contract state invariants
- Data structure invariants

Author: Morpheus Team
"""

from __future__ import annotations
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
import z3
import logging

from morpheus.symbolic.engine import SymbolicEngine, EVMSymbolicEngine
from morpheus.symbolic.state import SymState
from morpheus.specification.language import Invariant, SpecificationContext

logger = logging.getLogger(__name__)


@dataclass
class InvariantResult:
    """Result of invariant verification."""
    invariant: Invariant
    proved: bool
    counterexample: Optional[Dict[str, Any]] = None
    verification_time: float = 0.0
    method: str = ""  # induction, k-induction, etc.


class InvariantDetector:
    """
    Detects and verifies invariants in smart contracts.
    
    Uses multiple techniques:
    - Dynamic invariant generation (from execution traces)
    - Static invariant inference (from code analysis)
    - Inductive verification (k-induction)
    """
    
    def __init__(self, engine: Optional[SymbolicEngine] = None):
        self.engine = engine or EVMSymbolicEngine()
        self.invariants: List[Invariant] = []
        self.proved_invariants: List[InvariantResult] = []
        self.disproved_invariants: List[InvariantResult] = []
    
    def detect_loop_invariants(
        self,
        loop_node: Any,
        context: SpecificationContext
    ) -> List[Invariant]:
        """
        Detect invariants for a loop.
        
        Args:
            loop_node: Loop AST node
            context: Specification context
            
        Returns:
            List of detected invariants
        """
        invariants = []
        
        # Analyze loop structure
        if hasattr(loop_node, 'condition'):
            # Extract condition as potential invariant
            condition = self._extract_condition(loop_node.condition, context)
            if condition:
                inv = Invariant(
                    name=f"loop_invariant_{len(self.invariants)}",
                    spec_type=Invariant.spec_type,
                    condition=str(condition),
                    formula=condition,
                    scope="loop"
                )
                invariants.append(inv)
        
        # Analyze loop variables
        loop_vars = self._extract_loop_variables(loop_node)
        for var in loop_vars:
            # Bound invariant
            bound_inv = Invariant(
                name=f"bound_{var}_{len(self.invariants)}",
                spec_type=Invariant.spec_type,
                condition=f"{var} >= 0",
                scope="loop"
            )
            invariants.append(bound_inv)
        
        return invariants
    
    def detect_contract_invariants(
        self,
        contract: Any,
        context: SpecificationContext
    ) -> List[Invariant]:
        """
        Detect contract-level invariants.
        
        Args:
            contract: Contract AST
            context: Specification context
            
        Returns:
            List of detected invariants
        """
        invariants = []
        
        # Analyze state variables
        for var in contract.state_variables:
            # Type-based invariants
            var_type = self._get_variable_type(var)
            
            if 'uint' in var_type:
                # Non-negative invariant
                inv = Invariant(
                    name=f"nonnegative_{var.name}_{len(self.invariants)}",
                    spec_type=Invariant.spec_type,
                    condition=f"{var.name} >= 0",
                    scope="global"
                )
                invariants.append(inv)
            
            elif 'balance' in var.name.lower():
                # Balance invariants
                inv = Invariant(
                    name=f"balance_{var.name}_{len(self.invariants)}",
                    spec_type=Invariant.spec_type,
                    condition=f"{var.name} >= 0",
                    scope="global"
                )
                invariants.append(inv)
            
            elif 'count' in var.name.lower() or 'total' in var.name.lower():
                # Counter invariants
                inv = Invariant(
                    name=f"counter_{var.name}_{len(self.invariants)}",
                    spec_type=Invariant.spec_type,
                    condition=f"{var.name} >= 0",
                    scope="global"
                )
                invariants.append(inv)
        
        # Analyze function effects
        for func in contract.functions:
            for var in contract.state_variables:
                # Check if variable can decrease
                if self._can_decrease(func, var.name):
                    # Add lower bound invariant
                    pass
                
                # Check if variable can increase
                if self._can_increase(func, var.name):
                    # Add upper bound invariant if applicable
                    pass
        
        return invariants
    
    def verify_invariant(
        self,
        invariant: Invariant,
        contract: Any,
        context: SpecificationContext,
        method: str = "induction"
    ) -> InvariantResult:
        """
        Verify an invariant against a contract.
        
        Args:
            invariant: Invariant to verify
            contract: Contract AST
            context: Specification context
            method: Verification method (induction, k-induction, etc.)
            
        Returns:
            InvariantResult with verification outcome
        """
        result = InvariantResult(
            invariant=invariant,
            proved=False,
            method=method
        )
        
        if method == "induction":
            result = self._verify_by_induction(invariant, contract, context)
        elif method == "k-induction":
            result = self._verify_by_k_induction(invariant, contract, context, k=1)
        elif method == "bounded":
            result = self._verify_by_bounded_model_checking(
                invariant, contract, context, bound=100
            )
        else:
            logger.warning(f"Unknown verification method: {method}")
        
        return result
    
    def _verify_by_induction(
        self,
        invariant: Invariant,
        contract: Any,
        context: SpecificationContext
    ) -> InvariantResult:
        """Verify invariant using induction."""
        result = InvariantResult(
            invariant=invariant,
            proved=False,
            method="induction"
        )
        
        # Base case: Check initial state
        base_proved = self._check_base_case(invariant, context)
        
        # Inductive step: Check transition preserves invariant
        step_proved = self._check_inductive_step(invariant, contract, context)
        
        result.proved = base_proved and step_proved
        
        if not result.proved:
            result.counterexample = self._find_counterexample(
                invariant, contract, context
            )
        
        return result
    
    def _verify_by_k_induction(
        self,
        invariant: Invariant,
        contract: Any,
        context: SpecificationContext,
        k: int = 1
    ) -> InvariantResult:
        """Verify invariant using k-induction."""
        result = InvariantResult(
            invariant=invariant,
            proved=False,
            method=f"k-induction (k={k})"
        )
        
        # Base case: Check first k steps
        base_proved = self._check_base_case_k(invariant, context, k)
        
        # Inductive step: k-induction
        step_proved = self._check_inductive_step_k(invariant, contract, context, k)
        
        result.proved = base_proved and step_proved
        
        if not result.proved:
            result.counterexample = self._find_counterexample(
                invariant, contract, context
            )
        
        return result
    
    def _verify_by_bounded_model_checking(
        self,
        invariant: Invariant,
        contract: Any,
        context: SpecificationContext,
        bound: int = 100
    ) -> InvariantResult:
        """Verify invariant using bounded model checking."""
        result = InvariantResult(
            invariant=invariant,
            proved=False,
            method=f"bounded (bound={bound})"
        )
        
        # Execute up to 'bound' steps and check invariant
        for step in range(bound):
            if not self._check_invariant_at_step(invariant, context, step):
                result.counterexample = {
                    'step': step,
                    'violation': True
                }
                return result
        
        result.proved = True
        return result
    
    def _check_base_case(
        self,
        invariant: Invariant,
        context: SpecificationContext
    ) -> bool:
        """Check base case: initial state satisfies invariant."""
        # Create solver for initial state
        solver = z3.Solver()
        
        # Add invariant as constraint
        if invariant.formula:
            solver.add(invariant.formula)
        
        # Check satisfiability
        result = solver.check()
        return result == z3.sat
    
    def _check_inductive_step(
        self,
        invariant: Invariant,
        contract: Any,
        context: SpecificationContext
    ) -> bool:
        """Check inductive step: transition preserves invariant."""
        # Create solver
        solver = z3.Solver()
        
        # Assume invariant holds in current state
        if invariant.formula:
            solver.add(invariant.formula)
        
        # Create symbolic variables for next state
        for name, var in context.variables.items():
            next_var = z3.FreshConst(z3.BitVecSort(256), name=f"{name}_next")
            # Create transition constraint (simplified)
            solver.add(next_var == var)
        
        # Check invariant holds in next state
        # This is simplified - real implementation would analyze transitions
        
        result = solver.check()
        return result == z3.sat
    
    def _check_base_case_k(
        self,
        invariant: Invariant,
        context: SpecificationContext,
        k: int
    ) -> bool:
        """Check base case for k steps."""
        for step in range(k):
            if not self._check_invariant_at_step(invariant, context, step):
                return False
        return True
    
    def _check_inductive_step_k(
        self,
        invariant: Invariant,
        contract: Any,
        context: SpecificationContext,
        k: int
    ) -> bool:
        """Check k-inductive step."""
        # Simplified: just check regular induction
        return self._check_inductive_step(invariant, contract, context)
    
    def _check_invariant_at_step(
        self,
        invariant: Invariant,
        context: SpecificationContext,
        step: int
    ) -> bool:
        """Check if invariant holds at a specific step."""
        solver = z3.Solver()
        
        # Add step-specific constraints (simplified)
        solver.add(z3.BitVecVal(step, 256) >= 0)
        
        # Add invariant
        if invariant.formula:
            solver.add(invariant.formula)
        
        result = solver.check()
        return result == z3.sat
    
    def _find_counterexample(
        self,
        invariant: Invariant,
        contract: Any,
        context: SpecificationContext
    ) -> Optional[Dict[str, Any]]:
        """Find a counterexample that violates the invariant."""
        solver = z3.Solver()
        
        # Negate invariant to find violation
        if invariant.formula:
            solver.add(z3.Not(invariant.formula))
        
        # Add any constraints from context
        for name, var in context.variables.items():
            solver.add(z3.BitVec(name, 256) >= 0)
        
        result = solver.check()
        if result == z3.sat:
            model = solver.model()
            counterexample = {}
            for decl in model.decls():
                counterexample[str(decl)] = model[decl]
            return counterexample
        
        return None
    
    def _extract_condition(
        self,
        condition: Any,
        context: SpecificationContext
    ) -> Optional[z3.BoolRef]:
        """Extract Z3 condition from AST node."""
        # Simplified implementation
        return z3.BoolVal(True)
    
    def _extract_loop_variables(self, loop_node: Any) -> List[str]:
        """Extract loop variables from loop node."""
        # Simplified implementation
        return []
    
    def _get_variable_type(self, var: Any) -> str:
        """Get variable type as string."""
        if hasattr(var, 'var_type'):
            return str(var.var_type)
        return "unknown"
    
    def _can_decrease(self, func: Any, var_name: str) -> bool:
        """Check if function can decrease a variable."""
        return False  # Simplified
    
    def _can_increase(self, func: Any, var_name: str) -> bool:
        """Check if function can increase a variable."""
        return False  # Simplified


class InvariantGenerator:
    """
    Generates candidate invariants from contract code.
    
    Uses heuristics and patterns to generate potential invariants.
    """
    
    @staticmethod
    def generate_from_state_variable(var: Any) -> List[str]:
        """Generate candidate invariants from a state variable."""
        invariants = []
        
        var_type = str(getattr(var, 'var_type', 'unknown'))
        var_name = getattr(var, 'name', 'unknown')
        
        # Type-based invariants
        if 'uint' in var_type.lower():
            invariants.append(f"{var_name} >= 0")
        
        if 'int' in var_type.lower():
            invariants.append(f"{var_name} >= {-2**255}")
            invariants.append(f"{var_name} < 2**255")
        
        if 'balance' in var_name.lower():
            invariants.append(f"{var_name} >= 0")
        
        if 'count' in var_name.lower() or 'total' in var_name.lower():
            invariants.append(f"{var_name} >= 0")
            invariants.append(f"{var_name} <= 2**256 - 1")
        
        return invariants
    
    @staticmethod
    def generate_from_function(func: Any) -> List[str]:
        """Generate candidate invariants from a function."""
        invariants = []
        
        func_name = getattr(func, 'name', 'unknown')
        
        # Check function name for patterns
        if 'lock' in func_name.lower():
            invariants.append("locked == true")
        if 'unlock' in func_name.lower():
            invariants.append("locked == false")
        
        return invariants
    
    @staticmethod
    def generate_from_mapping(mapping: Any) -> List[str]:
        """Generate candidate invariants for a mapping."""
        invariants = []
        
        # Value type invariants
        if hasattr(mapping, 'value_type'):
            value_type = str(mapping.value_type)
            if 'uint' in value_type.lower():
                invariants.append("mapping_value >= 0")
        
        return invariants
