"""
Morpheus - Formal Verification Engine for Smart Contracts
===========================================================

A comprehensive formal verification framework for analyzing and proving
properties of Solidity and Vyper smart contracts.

Features:
- Symbolic execution with Z3 SMT solver
- Invariant detection and proving
- Theorem proving for contract properties
- Counterexample generation
- Reentrancy, integer overflow proofs
- DeFi vulnerability detection
- Formal specification language
- Taint analysis for exploits
- HOA (Hardware Object) format support

Author: Morpheus Team
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Morpheus Team"

from morpheus.symbolic.engine import SymbolicEngine
from morpheus.symbolic.state import SymState, Memory, Storage
from morpheus.symbolic.values import SymbolicValue, SymbolicInt, SymbolicBool
from morpheus.symbolic.operations import SymbolicOperations
from morpheus.parser.solidity import SolidityParser
from morpheus.parser.vyper import VyperParser
from morpheus.parser.ast import (
    Contract, Function, Statement, Expression,
    Identifier, BinaryOp, UnaryOp, Assignment
)
from morpheus.specification.language import SpecificationLanguage, Property, Invariant
from morpheus.specification.grammar import SpecificationGrammar
from morpheus.analysis.invariant import InvariantDetector
from morpheus.analysis.taint import TaintAnalyzer
from morpheus.vulnerability.detector import VulnerabilityDetector
from morpheus.vulnerability.patterns import VulnerabilityPatterns
from morpheus.theorem.prover import TheoremProver
from morpheus.theorem.counterexample import CounterexampleGenerator
from morpheus.hoa.automaton import HOAAutomaton, HOAExporter
from morpheus.analysis.defi import DeFiAnalyzer

__all__ = [
    # Core symbolic execution
    "SymbolicEngine",
    "SymState", "Memory", "Storage",
    "SymbolicValue", "SymbolicInt", "SymbolicBool",
    "SymbolicOperations",
    # Parsers
    "SolidityParser", "VyperParser",
    "Contract", "Function", "Statement", "Expression",
    "Identifier", "BinaryOp", "UnaryOp", "Assignment",
    # Specification
    "SpecificationLanguage", "Property", "Invariant",
    "SpecificationGrammar",
    # Analysis
    "InvariantDetector", "TaintAnalyzer", "DeFiAnalyzer",
    # Vulnerability
    "VulnerabilityDetector", "VulnerabilityPatterns",
    # Theorem proving
    "TheoremProver", "CounterexampleGenerator",
    # HOA
    "HOAAutomaton", "HOAExporter",
]
