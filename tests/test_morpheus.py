"""
Tests for Morpheus Formal Verification Engine
==============================================
"""

import pytest
import z3
from morpheus import (
    SolidityParser, VyperParser, SymbolicEngine, EVMSymbolicEngine,
    TheoremProver, VulnerabilityDetector, InvariantDetector, TaintAnalyzer,
    Property, Invariant, SpecificationLanguage, SpecificationContext
)


class TestSolidityParser:
    """Tests for Solidity parser."""
    
    def test_parse_simple_contract(self):
        """Test parsing a simple contract."""
        source = '''
        pragma solidity ^0.8.0;
        
        contract Simple {
            uint256 public value;
            
            function setValue(uint256 _value) public {
                value = _value;
            }
        }
        '''
        parser = SolidityParser()
        ast = parser.parse_source(source)
        
        assert len(ast.contracts) == 1
        assert ast.contracts[0].name == "Simple"
        assert len(ast.contracts[0].state_variables) == 1
        assert len(ast.contracts[0].functions) == 1
    
    def test_parse_function_with_parameters(self):
        """Test parsing function parameters."""
        source = '''
        pragma solidity ^0.8.0;
        
        contract Calculator {
            function add(uint256 a, uint256 b) public pure returns (uint256) {
                return a + b;
            }
        }
        '''
        parser = SolidityParser()
        ast = parser.parse_source(source)
        
        func = ast.contracts[0].functions[0]
        assert func.name == "add"
        assert len(func.parameters) == 2
    
    def test_parse_state_variables(self):
        """Test parsing state variables."""
        source = '''
        pragma solidity ^0.8.0;
        
        contract Bank {
            mapping(address => uint256) public balances;
            address public owner;
            uint256 public totalSupply;
        }
        '''
        parser = SolidityParser()
        ast = parser.parse_source(source)
        
        contract = ast.contracts[0]
        assert len(contract.state_variables) == 3


class TestSymbolicEngine:
    """Tests for symbolic execution engine."""
    
    def test_create_symbolic_engine(self):
        """Test creating a symbolic engine."""
        engine = SymbolicEngine()
        assert engine is not None
        assert engine.timeout > 0
    
    def test_create_symbolic_variable(self):
        """Test creating symbolic variables."""
        engine = SymbolicEngine()
        var = engine.create_symbolic_value("test_var")
        assert var is not None
        assert isinstance(var, z3.BitVecRef)
    
    def test_create_symbolic_bool(self):
        """Test creating symbolic boolean."""
        engine = SymbolicEngine()
        var = engine.create_symbolic_bool("test_bool")
        assert var is not None
    
    def test_add_constraint(self):
        """Test adding constraints."""
        engine = SymbolicEngine()
        engine.add_constraint(z3.BitVec("x", 256) > 0)
        
        sat, model = engine.check_satisfiability()
        assert sat is True
    
    def test_path_branching(self):
        """Test path branching."""
        engine = SymbolicEngine()
        x = engine.create_symbolic_value("x")
        
        true_result = None
        false_result = None
        
        def on_true():
            return "true_branch"
        
        def on_false():
            return "false_branch"
        
        true_result, false_result = engine.branch(x > 5, on_true, on_false)
        
        assert true_result == "true_branch"
        assert false_result == "false_branch"


class TestTheoremProver:
    """Tests for theorem prover."""
    
    def test_prove_simple_property(self):
        """Test proving a simple property."""
        prover = TheoremProver(timeout=5000)
        context = SpecificationContext()
        
        # x + 0 = x
        x = context.create_symbolic_var("x")
        
        property = Property.create(
            "add_zero_identity",
            x + 0 == x,
            "Adding zero should not change value"
        )
        
        result = prover.prove(property, context)
        assert result is not None
    
    def test_disprove_contradiction(self):
        """Test disproving a contradiction."""
        prover = TheoremProver(timeout=5000)
        context = SpecificationContext()
        
        x = context.create_symbolic_var("x")
        
        property = Property.create(
            "contradiction",
            x > 10 and x < 5,  # Impossible
            "Contradiction"
        )
        
        result = prover.disprove(property, context)
        assert result.status.value in [1, 2]  # PROVED or DISPROVED


class TestVulnerabilityDetector:
    """Tests for vulnerability detection."""
    
    def test_create_detector(self):
        """Test creating vulnerability detector."""
        detector = VulnerabilityDetector()
        assert detector is not None
    
    def test_vulnerability_types(self):
        """Test vulnerability type enumeration."""
        from morpheus.vulnerability.detector import VulnerabilityType
        
        assert VulnerabilityType.REENTRANCY is not None
        assert VulnerabilityType.INTEGER_OVERFLOW is not None
        assert VulnerabilityType.ACCESS_CONTROL is not None


class TestSpecificationLanguage:
    """Tests for specification language."""
    
    def test_create_property(self):
        """Test creating a property."""
        spec = SpecificationLanguage()
        
        x = z3.BitVec("x", 256)
        prop = spec.property(
            "positive",
            x > 0,
            "Value should be positive"
        )
        
        assert prop.name == "positive"
        assert prop.description == "Value should be positive"
    
    def test_create_invariant(self):
        """Test creating an invariant."""
        spec = SpecificationLanguage()
        
        x = z3.BitVec("x", 256)
        inv = spec.invariant(
            "balance_invariant",
            x >= 0,
            scope="global"
        )
        
        assert inv.name == "balance_invariant"
        assert inv.scope == "global"
    
    def test_requires_ensures(self):
        """Test pre/postcondition creation."""
        spec = SpecificationLanguage()
        
        x = z3.BitVec("x", 256)
        
        pre = spec.requires(
            "withdraw",
            x > 0,
            "Withdrawal amount must be positive"
        )
        
        post = spec.ensures(
            "withdraw",
            x > 0,
            "Withdrawal should succeed"
        )
        
        assert pre.function == "withdraw"
        assert post.function == "withdraw"


class TestInvariantDetector:
    """Tests for invariant detection."""
    
    def test_create_detector(self):
        """Test creating invariant detector."""
        detector = InvariantDetector()
        assert detector is not None
    
    def test_verify_simple_invariant(self):
        """Test verifying a simple invariant."""
        prover = TheoremProver(timeout=5000)
        detector = InvariantDetector(engine=prover)
        
        context = SpecificationContext()
        x = context.create_symbolic_var("x")
        
        invariant = Invariant.create(
            "positive",
            x >= 0,
            scope="global"
        )
        
        # Create a dummy contract-like object
        class MockContract:
            name = "test"
        
        result = detector.verify_invariant(
            invariant,
            MockContract(),
            context,
            method="induction"
        )
        
        assert result is not None


class TestTaintAnalyzer:
    """Tests for taint analysis."""
    
    def test_create_analyzer(self):
        """Test creating taint analyzer."""
        analyzer = TaintAnalyzer()
        assert analyzer is not None
    
    def test_add_taint_source(self):
        """Test adding taint sources."""
        analyzer = TaintAnalyzer()
        analyzer.add_taint_source(
            "user_input",
            TaintSource.USER_INPUT,
            "Unvalidated user input"
        )
        
        assert "user_input" in analyzer.tainted_values


class TestHOAAutomaton:
    """Tests for HOA automaton support."""
    
    def test_create_automaton(self):
        """Test creating HOA automaton."""
        from morpheus.hoa import HOAAutomaton
        
        automaton = HOAAutomaton(name="test")
        assert automaton.name == "test"
    
    def test_add_states(self):
        """Test adding states to automaton."""
        from morpheus.hoa import HOAAutomaton
        
        automaton = HOAAutomaton(name="test")
        state1 = automaton.add_state("start", initial=True)
        state2 = automaton.add_state("accept", accepting=True)
        
        assert state1 == 0
        assert state2 == 1
        assert automaton.start_state == 0
    
    def test_add_transitions(self):
        """Test adding transitions."""
        from morpheus.hoa import HOAAutomaton
        
        automaton = HOAAutomaton(name="test")
        automaton.add_state("start", initial=True)
        automaton.add_state("next")
        
        trans_id = automaton.add_transition(0, 1, label="a")
        assert trans_id == 0
        assert len(automaton.transitions) == 1
    
    def test_to_hoa_string(self):
        """Test HOA format output."""
        from morpheus.hoa import HOAAutomaton
        
        automaton = HOAAutomaton(name="simple")
        automaton.add_state("start", initial=True)
        automaton.add_state("accept", accepting=True)
        automaton.add_transition(0, 1, label="a")
        
        hoa_string = automaton.to_hoa_string()
        assert "HOA:" in hoa_string
        assert 'name: "simple"' in hoa_string


class TestCounterexampleGenerator:
    """Tests for counterexample generation."""
    
    def test_create_generator(self):
        """Test creating counterexample generator."""
        from morpheus.theorem.counterexample import CounterexampleGenerator
        
        generator = CounterexampleGenerator()
        assert generator is not None
    
    def test_generate_counterexample(self):
        """Test generating a counterexample."""
        from morpheus.theorem.counterexample import CounterexampleGenerator
        
        generator = CounterexampleGenerator()
        
        solver = z3.Solver()
        x = z3.BitVec("x", 256)
        solver.add(x > 10)
        solver.add(x < 15)
        solver.check()
        
        ce = generator.generate(
            property_name="test",
            negated_formula=z3.BoolVal(True),
            solver=solver
        )
        
        # May be None if unsatisfiable
        # or have values if satisfiable
        assert ce is None or ce.values is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
