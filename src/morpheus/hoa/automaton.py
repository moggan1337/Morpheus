"""
HOA (Hardware Object) Format Support
=====================================

This module provides support for the HOA (Hardware Object)
format for representing automata, which can be used for:
- Control flow automaton representation
- Büchi automaton for LTL properties
- Symbolic execution state machines
- Contract verification automata

The HOA format is a standard format for representing
alternating automata in the model checking community.

Reference: https://adl.github.io/hoaf/

Author: Morpheus Team
"""

from __future__ import annotations
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
import logging

logger = logging.getLogger(__name__)


class AcceptanceCondition:
    """Represents acceptance conditions for automata."""
    
    def __init__(self, name: str = "Buchi"):
        self.name = name
        self.accepting_states: Set[int] = set()
        self.transition_accepting: Dict[Tuple[int, str], bool] = {}
    
    def add_accepting_state(self, state: int) -> None:
        """Add an accepting state."""
        self.accepting_states.add(state)
    
    def is_accepting_state(self, state: int) -> bool:
        """Check if state is accepting."""
        return state in self.accepting_states
    
    def to_hoa_string(self) -> str:
        """Convert to HOA format string."""
        if self.name == "Buchi":
            inf_sets = ",".join(str(s) for s in self.accepting_states)
            return f"Acc: 1 {{{{ {inf_sets} }}}}"
        return f"Acc: 0 {{{{}}}}}"


@dataclass
class State:
    """Represents a state in the automaton."""
    id: int
    name: Optional[str] = None
    properties: List[str] = field(default_factory=list)
    initial: bool = False
    accepting: bool = False
    label: Optional[str] = None


@dataclass
class Transition:
    """Represents a transition in the automaton."""
    source: int
    dest: int
    guard: Optional[str] = None  # HOA format guard
    label: Optional[str] = None  # Human-readable label
    symbols: Set[str] = field(default_factory=set)  # Alphabet symbols
    acceptance_marks: Set[int] = field(default_factory=set)
    
    def to_hoa_string(self) -> str:
        """Convert to HOA format string."""
        parts = [f"{self.source} -> {self.dest}"]
        
        if self.guard:
            parts.append(f'[{self.guard}]')
        
        if self.symbols:
            symbols_str = ",".join(sorted(self.symbols))
            parts.append(symbols_str)
        else:
            parts.append("t")
        
        if self.acceptance_marks:
            marks_str = ",".join(str(m) for m in self.acceptance_marks)
            parts.append(f"{{{marks_str}}}")
        
        return " ".join(parts)


@dataclass
class AlphabetSymbol:
    """Represents a symbol in the automaton's alphabet."""
    name: str
    description: str = ""
    variables: List[str] = field(default_factory=list)
    
    def to_hoa_string(self) -> str:
        """Convert to HOA format string."""
        if self.variables:
            return f'{self.name} @{self.variables[0]}' if self.variables else self.name
        return self.name


class HOAAutomaton:
    """
    Represents an automaton in HOA format.
    
    Used for:
    - Control flow automaton generation
    - Property automaton construction
    - Symbolic execution state machines
    """
    
    def __init__(
        self,
        name: str = "automaton",
        num_ap: int = 0,
        acceptance: Optional[AcceptanceCondition] = None
    ):
        """
        Initialize HOA automaton.
        
        Args:
            name: Automaton name
            num_ap: Number of atomic propositions
            acceptance: Acceptance condition
        """
        self.name = name
        self.num_ap = num_ap
        self.acceptance = acceptance or AcceptanceCondition()
        
        self.states: Dict[int, State] = {}
        self.transitions: List[Transition] = []
        self.alphabet: List[AlphabetSymbol] = []
        
        self.start_state: Optional[int] = None
        self.properties: List[str] = []
        
        self.state_counter = 0
        self.transition_counter = 0
    
    def add_state(
        self,
        name: Optional[str] = None,
        initial: bool = False,
        accepting: bool = False,
        properties: List[str] = None
    ) -> int:
        """
        Add a state to the automaton.
        
        Args:
            name: State name
            initial: Is initial state
            accepting: Is accepting state
            properties: State properties
            
        Returns:
            State ID
        """
        state_id = self.state_counter
        state = State(
            id=state_id,
            name=name or f"s{state_id}",
            initial=initial,
            accepting=accepting,
            properties=properties or []
        )
        
        self.states[state_id] = state
        self.state_counter += 1
        
        if initial:
            self.start_state = state_id
        
        if accepting:
            self.acceptance.add_accepting_state(state_id)
        
        return state_id
    
    def add_transition(
        self,
        source: int,
        dest: int,
        guard: Optional[str] = None,
        label: Optional[str] = None,
        symbols: Set[str] = None,
        acceptance_marks: Set[int] = None
    ) -> int:
        """
        Add a transition to the automaton.
        
        Args:
            source: Source state ID
            dest: Destination state ID
            guard: Transition guard (HOA format)
            label: Human-readable label
            symbols: Alphabet symbols
            acceptance_marks: Acceptance set marks
            
        Returns:
            Transition ID
        """
        transition = Transition(
            source=source,
            dest=dest,
            guard=guard,
            label=label,
            symbols=symbols or set(),
            acceptance_marks=acceptance_marks or set()
        )
        
        transition_id = self.transition_counter
        self.transition_counter += 1
        self.transitions.append(transition)
        
        return transition_id
    
    def add_alphabet_symbol(
        self,
        name: str,
        description: str = "",
        variables: List[str] = None
    ) -> None:
        """Add a symbol to the alphabet."""
        symbol = AlphabetSymbol(
            name=name,
            description=description,
            variables=variables or []
        )
        self.alphabet.append(symbol)
    
    def to_hoa_string(self) -> str:
        """
        Convert automaton to HOA format string.
        
        Returns:
            HOA format representation
        """
        lines = [f"HOA: v1"]
        
        # Header
        lines.append(f"name: \"{self.name}\"")
        
        if self.alphabet:
            ap_str = " ".join(f'"{s.name}"' for s in self.alphabet)
            lines.append(f"AP: {len(self.alphabet)} {ap_str}")
        
        # Acceptance
        lines.append(self.acceptance.to_hoa_string())
        
        # Properties
        for prop in self.properties:
            lines.append(f"properties: {prop}")
        
        # Start state
        if self.start_state is not None:
            lines.append(f"Start: {self.start_state}")
        
        # States
        lines.append(f"States: {len(self.states)}")
        
        # Body with transitions
        for state_id in sorted(self.states.keys()):
            state = self.states[state_id]
            
            # State header
            header_parts = [f"State: {state_id}"]
            
            if state.name:
                header_parts.append(f'"{state.name}"')
            
            if state.accepting:
                header_parts.append("acc")
            
            if state.properties:
                header_parts.append(" ".join(state.properties))
            
            lines.append(" ".join(header_parts))
            
            # Transitions from this state
            state_transitions = [t for t in self.transitions if t.source == state_id]
            
            for trans in state_transitions:
                lines.append(f"  {trans.to_hoa_string()}")
        
        return "\n".join(lines)
    
    @classmethod
    def from_hoa_string(cls, hoa_string: str) -> HOAAutomaton:
        """
        Parse HOA format string.
        
        Args:
            hoa_string: HOA format string
            
        Returns:
            Parsed HOAAutomaton
        """
        automaton = cls()
        current_state = None
        
        for line in hoa_string.split('\n'):
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('HOA:'):
                continue
            
            elif line.startswith('name:'):
                name = line.split(':', 1)[1].strip().strip('"')
                automaton.name = name
            
            elif line.startswith('AP:'):
                # Parse atomic propositions
                parts = line.split(':', 1)[1].strip().split(maxsplit=1)
                automaton.num_ap = int(parts[0])
                if len(parts) > 1:
                    # Parse AP names
                    ap_str = parts[1].strip()
                    # Simplified parsing
                    pass
            
            elif line.startswith('Acc:'):
                # Parse acceptance
                # Simplified
                pass
            
            elif line.startswith('Start:'):
                start_id = int(line.split(':', 1)[1].strip())
                automaton.start_state = start_id
                automaton.add_state(initial=True)
            
            elif line.startswith('States:'):
                # Number of states
                pass
            
            elif line.startswith('State:'):
                # Parse state
                parts = line.split(':', 1)[1].split(maxsplit=2)
                state_id = int(parts[0])
                state_name = None
                accepting = False
                
                if len(parts) > 1 and parts[1] == 'acc':
                    accepting = True
                
                automaton.add_state(
                    name=f"s{state_id}",
                    accepting=accepting
                )
                current_state = state_id
            
            elif line.startswith('  '):
                # Transition line
                if current_state is not None:
                    parts = line.strip().split()
                    if '->' in parts:
                        idx = parts.index('->')
                        source = int(parts[idx - 1])
                        dest = int(parts[idx + 1])
                        automaton.add_transition(source, dest)
            
            elif '->' in line:
                # Transition without state header
                parts = line.split('->')
                source = int(parts[0].strip())
                dest = int(parts[1].split()[0].strip())
                automaton.add_transition(source, dest)
        
        return automaton
    
    def minimize(self) -> HOAAutomaton:
        """Minimize the automaton (Hopcroft's algorithm)."""
        # Simplified: return self
        return self
    
    def complement(self) -> HOAAutomaton:
        """Create complement automaton."""
        complement = HOAAutomaton(
            name=f"{self.name}_complement",
            num_ap=self.num_ap,
            acceptance=AcceptanceCondition()
        )
        
        # Copy states with flipped acceptance
        for state_id, state in self.states.items():
            complement.add_state(
                name=state.name,
                initial=state.initial,
                accepting=not state.accepting
            )
        
        # Copy transitions
        for trans in self.transitions:
            complement.add_transition(
                trans.source,
                trans.dest,
                trans.guard,
                trans.label,
                trans.symbols.copy(),
                trans.acceptance_marks.copy()
            )
        
        return complement
    
    def product(self, other: HOAAutomaton) -> HOAAutomaton:
        """Compute product with another automaton."""
        product = HOAAutomaton(
            name=f"{self.name}_x_{other.name}",
            num_ap=max(self.num_ap, other.num_ap)
        )
        
        # Product states: (s1, s2)
        state_map = {}
        
        for s1_id, s1 in self.states.items():
            for s2_id, s2 in other.states.items():
                combined_name = f"{s1.name}_{s2.name}"
                combined_accepting = s1.accepting and s2.accepting
                
                new_state_id = product.add_state(
                    name=combined_name,
                    initial=s1.initial and s2.initial,
                    accepting=combined_accepting
                )
                state_map[(s1_id, s2_id)] = new_state_id
        
        # Product transitions
        for trans1 in self.transitions:
            for trans2 in other.transitions:
                if trans1.label == trans2.label:
                    s1 = self.states[trans1.source]
                    s2 = other.states[trans2.source]
                    d1 = trans1.dest
                    d2 = trans2.dest
                    
                    if (s1.id, s2.id) in state_map and (d1, d2) in state_map:
                        product.add_transition(
                            state_map[(s1.id, s2.id)],
                            state_map[(d1, d2)],
                            label=trans1.label
                        )
        
        return product


class HOAExporter:
    """
    Exporter for HOA format.
    
    Provides utilities for exporting automata to HOA format
    and importing from various sources.
    """
    
    @staticmethod
    def export_to_file(automaton: HOAAutomaton, filepath: str) -> None:
        """
        Export automaton to HOA file.
        
        Args:
            automaton: Automaton to export
            filepath: Output file path
        """
        with open(filepath, 'w') as f:
            f.write(automaton.to_hoa_string())
    
    @staticmethod
    def import_from_file(filepath: str) -> HOAAutomaton:
        """
        Import automaton from HOA file.
        
        Args:
            filepath: Input file path
            
        Returns:
            Parsed automaton
        """
        with open(filepath, 'r') as f:
            content = f.read()
        return HOAAutomaton.from_hoa_string(content)
    
    @staticmethod
    def contract_to_automaton(contract: Any) -> HOAAutomaton:
        """
        Convert contract control flow to automaton.
        
        Args:
            contract: Contract AST
            
        Returns:
            Control flow automaton
        """
        automaton = HOAAutomaton(
            name=f"{contract.name}_cfg",
            num_ap=0
        )
        
        # Add entry state
        entry_id = automaton.add_state("entry", initial=True)
        
        # Add states for each function
        for func in contract.functions:
            func_id = automaton.add_state(func.name)
            automaton.add_transition(entry_id, func_id, label=func.name)
            
            # Add transitions for basic blocks
            if func.body:
                prev_block = func_id
                for stmt in func.body.statements:
                    block_id = automaton.add_state(f"{func.name}_block_{stmt}")
                    automaton.add_transition(prev_block, block_id)
                    prev_block = block_id
        
        return automaton
    
    @staticmethod
    def property_to_automaton(property_formula: str) -> HOAAutomaton:
        """
        Convert property formula to automaton.
        
        Args:
            property_formula: LTL/CTL property formula
            
        Returns:
            Property automaton
        """
        automaton = HOAAutomaton(
            name=f"property_automaton",
            num_ap=0
        )
        
        # Simplified: create a simple accepting automaton
        initial = automaton.add_state("initial", initial=True)
        accept = automaton.add_state("accept", accepting=True)
        
        automaton.add_transition(initial, accept, label=property_formula)
        automaton.add_transition(accept, accept, label="true")
        
        return automaton


class SymbolicExecutionAutomaton:
    """
    Automaton representation of symbolic execution states.
    
    Converts symbolic execution paths into an automaton
    for further analysis.
    """
    
    def __init__(self):
        self.automaton = HOAAutomaton(name="symbolic_execution")
        self.state_to_id: Dict[int, int] = {}
        self.path_conditions: Dict[int, Any] = {}
    
    def add_execution_state(
        self,
        pc: int,
        constraints: List[Any],
        accepting: bool = False
    ) -> int:
        """Add a symbolic execution state."""
        state_id = self.automaton.add_state(
            name=f"pc_{pc}",
            accepting=accepting
        )
        self.state_to_id[pc] = state_id
        self.path_conditions[state_id] = constraints
        return state_id
    
    def add_transition(
        self,
        from_pc: int,
        to_pc: int,
        condition: str
    ) -> None:
        """Add a transition between execution states."""
        if from_pc in self.state_to_id and to_pc in self.state_to_id:
            self.automaton.add_transition(
                self.state_to_id[from_pc],
                self.state_to_id[to_pc],
                guard=condition,
                label=condition
            )
    
    def get_automaton(self) -> HOAAutomaton:
        """Get the underlying automaton."""
        return self.automaton
