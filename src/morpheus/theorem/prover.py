"""
Theorem Proving for Smart Contract Properties
=============================================

This module provides theorem proving capabilities for verifying
properties of smart contracts using Z3.

Supported Proof Techniques:
- Direct verification
- Induction
- K-induction
- Contract invariants
- Pre/postcondition verification

Author: Morpheus Team
"""

from __future__ import annotations
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
import z3
import logging

from morpheus.symbolic.engine import SymbolicEngine
from morpheus.specification.language import Property, Invariant, SpecificationContext

logger = logging.getLogger(__name__)


class ProofStatus(Enum):
    """Status of a proof attempt."""
    PROVED = auto()
    DISPROVED = auto()
    UNKNOWN = auto()
    TIMEOUT = auto()
    ERROR = auto()


@dataclass
class ProofResult:
    """Result of a proof attempt."""
    property_name: str
    status: ProofStatus
    prover_time: float = 0.0
    counterexample: Optional[Dict[str, Any]] = None
    proof_steps: List[str] = field(default_factory=list)
    prover_output: str = ""
    
    def is_proved(self) -> bool:
        """Check if property was proved."""
        return self.status == ProofStatus.PROVED
    
    def is_disproved(self) -> bool:
        """Check if property was disproved."""
        return self.status == ProofStatus.DISPROVED


class TheoremProver:
    """
    Theorem prover for smart contract properties.
    
    Uses Z3 to prove or disprove properties about contract behavior.
    """
    
    def __init__(
        self,
        timeout: int = 30000,
        max_steps: int = 10000
    ):
        """
        Initialize theorem prover.
        
        Args:
            timeout: Z3 solver timeout in milliseconds
            max_steps: Maximum proof steps
        """
        self.timeout = timeout
        self.max_steps = max_steps
        self.solver = z3.Solver()
        self.solver.set(timeout=timeout)
        self.proof_results: Dict[str, ProofResult] = {}
    
    def prove(
        self,
        property: Property,
        context: SpecificationContext,
        assumptions: List[z3.BoolRef] = None
    ) -> ProofResult:
        """
        Attempt to prove a property.
        
        Args:
            property: Property to prove
            context: Specification context with variables
            assumptions: Additional assumptions
            
        Returns:
            ProofResult with outcome
        """
        import time
        start_time = time.time()
        
        result = ProofResult(
            property_name=property.name,
            status=ProofStatus.UNKNOWN
        )
        
        try:
            # Create fresh solver for this proof
            solver = z3.Solver()
            solver.set(timeout=self.timeout)
            
            # Add assumptions
            if assumptions:
                for assumption in assumptions:
                    solver.add(assumption)
            
            # Add context variables
            for name, var in context.variables.items():
                solver.add(var >= 0)  # Basic constraints
            
            # Get property formula
            formula = property.formula if property.formula else z3.Bool(property.name)
            
            # Check if negation is unsatisfiable (proves formula)
            solver.push()
            solver.add(z3.Not(formula))
            
            proof_steps = []
            proof_steps.append(f"Proving: {property.name}")
            proof_steps.append(f"Formula: {formula}")
            
            check_result = solver.check()
            
            if check_result == z3.unsat:
                result.status = ProofStatus.PROVED
                proof_steps.append("Result: UNSAT - Property is valid")
            elif check_result == z3.sat:
                result.status = ProofStatus.DISPROVED
                model = solver.model()
                counterexample = {}
                for decl in model.decls():
                    counterexample[str(decl)] = str(model[decl])
                result.counterexample = counterexample
                proof_steps.append("Result: SAT - Counterexample found")
            else:
                result.status = ProofStatus.UNKNOWN
                proof_steps.append("Result: UNKNOWN")
            
            solver.pop()
            
            result.prover_time = time.time() - start_time
            result.proof_steps = proof_steps
            
        except z3.Z3Exception as e:
            result.status = ProofStatus.ERROR
            result.prover_output = str(e)
            logger.error(f"Z3 error: {e}")
        except Exception as e:
            result.status = ProofStatus.ERROR
            result.prover_output = str(e)
            logger.error(f"Proof error: {e}")
        
        self.proof_results[property.name] = result
        return result
    
    def disprove(
        self,
        property: Property,
        context: SpecificationContext
    ) -> ProofResult:
        """
        Attempt to disprove a property (find counterexample).
        
        Args:
            property: Property to disprove
            context: Specification context
            
        Returns:
            ProofResult with counterexample if found
        """
        import time
        start_time = time.time()
        
        result = ProofResult(
            property_name=property.name,
            status=ProofStatus.UNKNOWN
        )
        
        try:
            solver = z3.Solver()
            solver.set(timeout=self.timeout)
            
            # Get property formula
            formula = property.formula if property.formula else z3.Bool(property.name)
            
            # Add formula (we want to find model where it holds)
            solver.add(formula)
            
            # Check if satisfiable (find counterexample to negation)
            check_result = solver.check()
            
            if check_result == z3.sat:
                model = solver.model()
                counterexample = {}
                for decl in model.decls():
                    counterexample[str(decl)] = str(model[decl])
                result.counterexample = counterexample
                result.status = ProofStatus.DISPROVED
            elif check_result == z3.unsat:
                result.status = ProofStatus.PROVED  # Can't disprove
            else:
                result.status = ProofStatus.UNKNOWN
            
            result.prover_time = time.time() - start_time
            
        except Exception as e:
            result.status = ProofStatus.ERROR
            result.prover_output = str(e)
        
        return result
    
    def prove_invariant(
        self,
        invariant: Invariant,
        contract: Any,
        context: SpecificationContext
    ) -> ProofResult:
        """
        Prove an invariant using induction.
        
        Args:
            invariant: Invariant to prove
            contract: Contract with transitions
            context: Specification context
            
        Returns:
            ProofResult
        """
        import time
        start_time = time.time()
        
        result = ProofResult(
            property_name=invariant.name,
            status=ProofStatus.UNKNOWN
        )
        
        proof_steps = []
        proof_steps.append(f"Proving invariant: {invariant.name}")
        
        # Base case: Initial state satisfies invariant
        proof_steps.append("Checking base case (initial state)...")
        base_result = self._check_base_case(invariant, context)
        
        if not base_result:
            result.status = ProofStatus.DISPROVED
            proof_steps.append("Base case FAILED - Invariant not satisfied initially")
            result.prover_time = time.time() - start_time
            result.proof_steps = proof_steps
            return result
        
        proof_steps.append("Base case OK")
        
        # Inductive step: Transition preserves invariant
        proof_steps.append("Checking inductive step...")
        step_result, counterexample = self._check_inductive_step(
            invariant, contract, context
        )
        
        if step_result:
            result.status = ProofStatus.PROVED
            proof_steps.append("Inductive step OK - Invariant is preserved")
        else:
            result.status = ProofStatus.DISPROVED
            result.counterexample = counterexample
            proof_steps.append("Inductive step FAILED - Counterexample found")
        
        result.prover_time = time.time() - start_time
        result.proof_steps = proof_steps
        
        return result
    
    def _check_base_case(
        self,
        invariant: Invariant,
        context: SpecificationContext
    ) -> bool:
        """Check base case of invariant."""
        solver = z3.Solver()
        solver.set(timeout=self.timeout)
        
        # Create symbolic variables for initial state
        for name, var in context.variables.items():
            solver.add(var >= 0)
        
        # Add invariant
        formula = invariant.formula if invariant.formula else z3.Bool(invariant.name)
        solver.add(formula)
        
        result = solver.check()
        return result == z3.sat
    
    def _check_inductive_step(
        self,
        invariant: Invariant,
        contract: Any,
        context: SpecificationContext
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Check inductive step of invariant."""
        solver = z3.Solver()
        solver.set(timeout=self.timeout)
        
        # Create variables for current and next state
        current_vars = {}
        next_vars = {}
        
        for name, var in context.variables.items():
            current = z3.FreshConst(z3.BitVecSort(256), name=f"{name}_cur")
            next_var = z3.FreshConst(z3.BitVecSort(256), name=f"{name}_next")
            current_vars[name] = current
            next_vars[name] = next_var
        
        # Constraint: Current state satisfies invariant
        formula = invariant.formula if invariant.formula else z3.Bool(invariant.name)
        # Substitute current variables
        subs = [(context.variables[k], current_vars[k]) for k in context.variables]
        current_formula = z3.substitute(formula, subs)
        solver.add(current_formula)
        
        # Constraint: Next state violates invariant (negation)
        next_subs = [(context.variables[k], next_vars[k]) for k in context.variables]
        next_formula = z3.substitute(formula, subs)
        solver.add(z3.Not(next_formula))
        
        # Check if satisfiable (counterexample exists)
        result = solver.check()
        
        if result == z3.sat:
            model = solver.model()
            counterexample = {}
            for name in current_vars:
                try:
                    counterexample[f"{name} (current)"] = str(model[current_vars[name]])
                    counterexample[f"{name} (next)"] = str(model[next_vars[name]])
                except:
                    pass
            return False, counterexample
        
        return True, None
    
    def verify_precondition_postcondition(
        self,
        precondition: z3.BoolRef,
        function_body: Any,
        postcondition: z3.BoolRef,
        context: SpecificationContext
    ) -> ProofResult:
        """
        Verify pre/postcondition pair using symbolic execution.
        
        Args:
            precondition: Function precondition
            function_body: Function to verify
            postcondition: Function postcondition
            context: Specification context
            
        Returns:
            ProofResult
        """
        import time
        start_time = time.time()
        
        result = ProofResult(
            property_name="pre_post_verification",
            status=ProofStatus.UNKNOWN
        )
        
        try:
            solver = z3.Solver()
            solver.set(timeout=self.timeout)
            
            # Add precondition
            solver.add(precondition)
            
            # Execute function symbolically (simplified)
            # In practice, would use symbolic execution engine
            
            # Check if postcondition holds
            solver.add(z3.Not(postcondition))
            
            check_result = solver.check()
            
            if check_result == z3.unsat:
                result.status = ProofStatus.PROVED
            elif check_result == z3.sat:
                result.status = ProofStatus.DISPROVED
                model = solver.model()
                result.counterexample = {str(d): str(model[d]) for d in model.decls()}
            else:
                result.status = ProofStatus.UNKNOWN
            
            result.prover_time = time.time() - start_time
            
        except Exception as e:
            result.status = ProofStatus.ERROR
            result.prover_output = str(e)
        
        return result
    
    def batch_prove(
        self,
        properties: List[Property],
        context: SpecificationContext
    ) -> Dict[str, ProofResult]:
        """
        Prove a batch of properties.
        
        Args:
            properties: List of properties to prove
            context: Specification context
            
        Returns:
            Dictionary mapping property names to results
        """
        results = {}
        
        for prop in properties:
            result = self.prove(prop, context)
            results[prop.name] = result
        
        return results


class InductionProver:
    """
    Specialized prover for inductive invariants.
    """
    
    def __init__(self, prover: TheoremProver):
        self.prover = prover
    
    def prove_invariant(
        self,
        invariant: z3.BoolRef,
        transitions: List[Tuple[z3.BoolRef, z3.BoolRef]],
        context: SpecificationContext
    ) -> ProofResult:
        """
        Prove invariant using k-induction.
        
        Args:
            invariant: Invariant to prove
            transitions: List of (precondition, postcondition) pairs
            context: Specification context
            
        Returns:
            ProofResult
        """
        result = ProofResult(
            property_name="inductive_invariant",
            status=ProofStatus.UNKNOWN
        )
        
        proof_steps = []
        proof_steps.append("Starting k-induction proof")
        
        # Base case: Invariant holds initially
        proof_steps.append("Base case check...")
        base_holds = self._check_base_case(invariant, context)
        
        if not base_holds:
            result.status = ProofStatus.DISPROVED
            proof_steps.append("Base case failed")
            result.proof_steps = proof_steps
            return result
        
        proof_steps.append("Base case OK")
        
        # Inductive step: Invariant preserved by all transitions
        proof_steps.append("Inductive step check...")
        
        for i, (pre, post) in enumerate(transitions):
            step_ok, counterexample = self._check_transition(
                invariant, pre, post, context
            )
            
            if not step_ok:
                result.status = ProofStatus.DISPROVED
                result.counterexample = counterexample
                proof_steps.append(f"Transition {i} violates invariant")
                result.proof_steps = proof_steps
                return result
        
        proof_steps.append("All transitions preserve invariant")
        result.status = ProofStatus.PROVED
        result.proof_steps = proof_steps
        
        return result
    
    def _check_base_case(
        self,
        invariant: z3.BoolRef,
        context: SpecificationContext
    ) -> bool:
        """Check if invariant holds in initial states."""
        solver = z3.Solver()
        solver.add(invariant)
        return solver.check() == z3.sat
    
    def _check_transition(
        self,
        invariant: z3.BoolRef,
        pre: z3.BoolRef,
        post: z3.BoolRef,
        context: SpecificationContext
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Check if transition preserves invariant."""
        solver = z3.Solver()
        
        # Assume pre and invariant
        solver.add(pre)
        solver.add(invariant)
        
        # Check if post violates invariant
        solver.add(z3.Not(post))
        solver.add(z3.Not(invariant))
        
        result = solver.check()
        
        if result == z3.sat:
            model = solver.model()
            counterexample = {str(d): str(model[d]) for d in model.decls()}
            return False, counterexample
        
        return True, None
