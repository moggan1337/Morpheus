# Morpheus - Formal Verification Engine for Smart Contracts

<div align="center">

![Morpheus Logo](https://img.shields.io/badge/Morpheus-Verification-4B0082?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A comprehensive formal verification framework for analyzing and proving properties of Solidity and Vyper smart contracts.**

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## 🎬 Demo
![Morpheus Demo](demo.gif)

*Formal verification of smart contracts*

## Screenshots
| Component | Preview |
|-----------|---------|
| Contract Analysis | ![analysis](screenshots/contract-analysis.png) |
| Proof Viewer | ![proof](screenshots/proof-viewer.png) |
| Vulnerability Report | ![vulns](screenshots/vulns.png) |

## Visual Description
Contract analysis shows parsed Solidity with control flow graph. Proof viewer displays formal specifications and verification results. Vulnerability report lists found issues with severity.

---


## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Architecture](#architecture)
6. [Formal Methods Overview](#formal-methods-overview)
7. [Specification Language](#specification-language)
8. [Vulnerability Detection](#vulnerability-detection)
9. [Symbolic Execution](#symbolic-execution)
10. [Theorem Proving](#theorem-proving)
11. [DeFi Analysis](#defi-analysis)
12. [API Reference](#api-reference)
13. [Examples](#examples)
14. [Configuration](#configuration)
15. [Best Practices](#best-practices)
16. [Troubleshooting](#troubleshooting)
17. [Roadmap](#roadmap)
18. [Contributing](#contributing)
19. [License](#license)
20. [Acknowledgments](#acknowledgments)

---

## Introduction

Morpheus is a state-of-the-art formal verification engine designed specifically for Ethereum smart contracts. Named after the Greek god of dreams who could shape reality, Morpheus provides developers and security researchers with powerful tools to mathematically prove the correctness of their smart contract code.

### Why Formal Verification?

Smart contracts manage billions of dollars in digital assets and operate on immutable blockchain infrastructure. Unlike traditional software, bugs in smart contracts cannot be easily patched once deployed. Formal verification provides mathematical guarantees about contract behavior, going beyond traditional testing which can only check specific inputs.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Traditional Testing vs Formal Verification   │
├─────────────────────────────────────────────────────────────────┤
│  Testing:                                                       │
│    - Checks specific inputs                                     │
│    - Cannot guarantee absence of bugs                          │
│    - May miss edge cases                                        │
│                                                                 │
│  Formal Verification:                                          │
│    - Proves properties for ALL inputs                          │
│    - Guarantees absence of certain bugs                         │
│    - Provides mathematical proof                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

### Core Verification Engine

- **Symbolic Execution Engine**: Full Z3 SMT solver integration for symbolic analysis
- **Theorem Proving**: Complete proof system for contract property verification
- **Invariant Detection**: Automatic detection and verification of loop and state invariants
- **Counterexample Generation**: Concrete input examples when properties fail

### Language Support

- **Solidity**: Full Solidity parser supporting versions 0.4.x through 0.8.x
- **Vyper**: Vyper smart contract parsing and analysis

### Security Analysis

- **Reentrancy Detection**: Single-function, cross-function, and read-only reentrancy
- **Integer Overflow/Underflow**: Proving arithmetic safety
- **Access Control**: Missing access control and privilege escalation
- **Front-Running**: Transaction ordering vulnerability detection
- **Denial of Service**: Unbounded operations and blocking patterns

### DeFi-Specific Analysis

- **Flash Loan Attack Detection**: Vulnerability patterns in DeFi protocols
- **Price Oracle Manipulation**: Spot price vs TWAP analysis
- **Liquidity Pool Security**: Swap arithmetic and reentrancy in AMMs
- **Yield Farming Exploits**: Deposit/withdraw vulnerability patterns

### Advanced Features

- **Taint Analysis**: Track potentially dangerous data flows
- **HOA Automaton Support**: Integration with model checking tools
- **Formal Specification Language**: DSL for writing verification conditions
- **Test Case Generation**: Automatic generation of failing test cases from counterexamples

---

## Installation

### Prerequisites

- Python 3.10 or higher
- Z3 SMT Solver (installed automatically)
- Git

### Using pip

```bash
pip install morpheus
```

### From Source

```bash
# Clone the repository
git clone https://github.com/moggan1337/Morpheus.git
cd Morpheus

# Install dependencies
pip install -e .

# Or install dev dependencies
pip install -e ".[dev]"
```

### Verify Installation

```python
import morpheus
print(morpheus.__version__)
```

---

## Quick Start

### Basic Verification

```python
from morpheus import SolidityParser, SymbolicEngine, TheoremProver
from morpheus.specification.language import Property, SpecificationLanguage

# Parse a contract
parser = SolidityParser()
contract = parser.parse_source('''
    contract SafeBank {
        mapping(address => uint256) public balances;
        address public owner;
        
        constructor() {
            owner = msg.sender;
        }
        
        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }
        
        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount);
            balances[msg.sender] -= amount;
            msg.sender.transfer(amount);
        }
    }
''')

# Create symbolic engine
engine = SymbolicEngine()

# Verify properties
prover = TheoremProver()
property = Property.create(
    "balance_conservation",
    "balances[msg.sender] >= 0",
    "Balances should never underflow"
)

result = prover.prove(property, context)
print(f"Proved: {result.is_proved()}")
```

### Vulnerability Detection

```python
from morpheus import SolidityParser, VulnerabilityDetector

# Parse and analyze
parser = SolidityParser()
contract = parser.parse_source('''
    contract VulnerableToken {
        mapping(address => uint256) balances;
        
        function transfer(address to, uint256 amount) public {
            // VULNERABLE: No checks-effects-interactions pattern
            balances[msg.sender] -= amount;  // Could underflow
            balances[to] += amount;          // External call could reenter
            payable(to).transfer(amount);    // External call
        }
    }
''')

# Detect vulnerabilities
detector = VulnerabilityDetector()
result = detector.analyze_contract(contract)

for vuln in result.vulnerabilities:
    print(f"[{vuln.severity}] {vuln.title}")
    print(f"  Function: {vuln.function}")
    print(f"  Recommendation: {vuln.recommendation}")
```

### Using the Specification Language

```solidity
// bank.mspec - Morpheus Specification File

# Define properties
property balance_non_negative: balances[sender] >= 0
property owner_only_withdraw: implies(msg.sender == owner, canWithdraw)
property transfer_amount_match: old(balances[sender]) - balances[sender] == amount

# Define invariants
invariant conservation: totalSupply == sum(balances)
invariant non_negative_balances: forall a . balances[a] >= 0

# Define function contracts
requires withdraw(amount): balances[msg.sender] >= amount
ensures withdraw(amount): old(balances[msg.sender]) == balances[msg.sender] + amount
```

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Morpheus Architecture                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────────┐   │
│  │   Source    │────▶│   Parser    │────▶│      AST        │   │
│  │   Code      │     │   (Solidity │     │   (Abstract     │   │
│  │             │     │   / Vyper)  │     │   Syntax Tree)  │   │
│  └─────────────┘     └─────────────┘     └────────┬────────┘   │
│                                                   │              │
│  ┌────────────────────────────────────────────────┴────────┐    │
│  │                   Analysis Layer                       │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │    │
│  │  │ Vulnerability│  │  Invariant  │  │     Taint       │ │    │
│  │  │  Detector   │  │  Detector   │  │    Analyzer     │ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘ │    │
│  └───────────────────────────────────────────────────────┘    │
│                           │                                      │
│  ┌────────────────────────┴────────────────────────────────┐    │
│  │              Symbolic Execution Engine                  │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │    │
│  │  │     Z3      │  │    Path     │  │    Constraint   │ │    │
│  │  │   Solver    │  │  Explorer   │  │     Manager     │ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘ │    │
│  └───────────────────────────────────────────────────────┘    │
│                           │                                      │
│  ┌────────────────────────┴────────────────────────────────┐    │
│  │                   Theorem Prover                        │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │    │
│  │  │   Proof     │  │   Counter   │  │   Specification │ │    │
│  │  │   Engine    │  │  Example    │  │     Language    │ │    │
│  │  └─────────────┘  │  Generator  │  └─────────────────┘ │    │
│  │                   └─────────────┘                       │    │
│  └───────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Module Structure

```
morpheus/
├── __init__.py              # Main package exports
├── symbolic/                # Symbolic execution engine
│   ├── engine.py           # Core symbolic execution
│   ├── state.py            # State management
│   ├── values.py           # Symbolic value types
│   └── operations.py       # EVM operations
├── parser/                  # Language parsers
│   ├── ast.py              # AST node definitions
│   ├── solidity.py         # Solidity parser
│   └── vyper.py            # Vyper parser
├── specification/           # Formal specifications
│   ├── language.py         # Specification DSL
│   └── grammar.py          # Grammar parser
├── analysis/                # Analysis modules
│   ├── invariant.py        # Invariant detection
│   ├── taint.py            # Taint analysis
│   └── defi.py             # DeFi-specific analysis
├── vulnerability/           # Vulnerability detection
│   ├── detector.py         # Main vulnerability detector
│   └── patterns.py         # Vulnerability patterns
├── theorem/                 # Theorem proving
│   ├── prover.py           # Theorem prover
│   └── counterexample.py   # Counterexample generation
└── hoa/                     # HOA format support
    └── automaton.py        # Automaton representation
```

---

## Formal Methods Overview

### What is Formal Verification?

Formal verification is the act of proving or disproving the correctness of algorithms or systems with respect to a formal specification. For smart contracts, this means mathematically proving that a contract behaves according to its specification.

### Verification Techniques in Morpheus

#### 1. Symbolic Execution

Symbolic execution analyzes a program by representing inputs as symbolic values rather than concrete values. This allows reasoning about all possible execution paths simultaneously.

```python
# Symbolic execution concept
from morpheus.symbolic import SymbolicEngine, SymbolicInt

# Create symbolic input
x = SymbolicInt.symbolic("input")
y = SymbolicInt.symbolic("input")

# Execute symbolically
result = x + y  # Represents all possible sums

# Query with Z3
solver = z3.Solver()
solver.add(result > 100)
# Can determine: "Does there exist inputs where result > 100?"
```

#### 2. Model Checking

Model checking exhaustively explores the state space of a system to verify properties. Morpheus uses HOA automata for state machine representation.

```
State Space Example:
    ┌─────────┐      ┌─────────┐      ┌─────────┐
    │  Init   │─────▶│ State 1 │─────▶│ State 2 │
    └─────────┘      └─────────┘      └─────────┘
                          │                │
                          ▼                ▼
                    ┌─────────┐      ┌─────────┐
                    │ Error   │      │ Accept  │
                    └─────────┘      └─────────┘
```

#### 3. Theorem Proving

Theorem proving uses logical inference to prove properties. Morpheus leverages Z3's theorem prover for this purpose.

```python
# Theorem proving example
from morpheus.theorem import TheoremProver
from morpheus.specification import Property

# Define property to prove
property = Property.create(
    name="transfer_safety",
    condition="balances[sender] >= amount => balances[sender] == old(balances[sender]) - amount"
)

# Attempt to prove
prover = TheoremProver()
result = prover.prove(property, context)

if result.is_proved():
    print("Property mathematically verified!")
else:
    print(f"Counterexample: {result.counterexample}")
```

### Key Formal Methods Concepts

| Concept | Description | Morpheus Implementation |
|---------|-------------|------------------------|
| **Precondition** | Conditions required before execution | `requires` in specs |
| **Postcondition** | Conditions guaranteed after execution | `ensures` in specs |
| **Invariant** | Conditions that always hold | `invariant` in specs |
| **Hoare Triple** | {P} program {Q} | Automatic via prover |
| **Induction** | Proving base case + step | `InvariantDetector` |
| **K-Induction** | Extended induction | `TheoremProver` |

---

## Specification Language

### Morpheus Specification Format (.mspec)

Morpheus includes a domain-specific language for writing formal specifications:

```mspec
# Bank Contract Specification

# Properties - General assertions
property transfer_amounts_match:
    implies(
        transfer(amount),
        old(balances[sender]) - balances[sender] == amount
    )

property no_unauthorized_transfers:
    forall address a . 
        implies(
            a != owner,
            cannot decrease balances[owner]
        )

# Invariants - Always true
invariant conservation_of_value:
    sum(balances) == initial_supply + total_deposited - total_withdrawn

invariant non_negative_balances:
    forall address a . balances[a] >= 0

invariant owner_always_has_access:
    balances[owner] >= 0

# Function Contracts
requires deposit():
    msg.value > 0

ensures deposit():
    balances[msg.sender] == old(balances[msg.sender]) + msg.value

requires withdraw(amount):
    balances[msg.sender] >= amount

ensures withdraw(amount):
    balances[msg.sender] == old(balances[msg.sender]) - amount
    msg.sender.balance == old(msg.sender.balance) + amount
```

### Specification Syntax

| Keyword | Description | Example |
|---------|-------------|---------|
| `property` | Define a verification property | `property name: condition` |
| `invariant` | Define an invariant | `invariant name: formula` |
| `requires` | Precondition for function | `requires func(): condition` |
| `ensures` | Postcondition for function | `ensures func(): condition` |
| `axiom` | Global assumption | `axiom name: formula` |
| `forall` | Universal quantification | `forall x . P(x)` |
| `exists` | Existential quantification | `exists x . P(x)` |
| `implies` | Logical implication | `implies(A, B)` |
| `old()` | Reference pre-state value | `old(balance)` |

---

## Vulnerability Detection

### Supported Vulnerability Types

| Category | Vulnerabilities | Severity |
|----------|-----------------|----------|
| **Reentrancy** | Single-function, Cross-function, Read-only | HIGH |
| **Arithmetic** | Overflow, Underflow, Division by zero | MEDIUM |
| **Access Control** | Missing modifiers, Privilege escalation | HIGH |
| **External Calls** | Unchecked returns, Unsafe delegates | MEDIUM |
| **Front-Running** | MEV, Transaction ordering | MEDIUM |
| **DoS** | Unbounded loops, Blocked operations | HIGH |
| **Time** | Timestamp dependence, Block number reliance | LOW |
| **Authentication** | tx.origin usage | MEDIUM |
| **Initialization** | Uninitialized storage | HIGH |
| **Self-destruct** | Unauthorized destruction | CRITICAL |

### Detection Examples

#### Reentrancy Detection

```python
from morpheus.vulnerability import VulnerabilityDetector

# The detector identifies:
# 1. External calls before state updates
# 2. State modifications after calls
# 3. Missing reentrancy guards

vuln = Vulnerability(
    vuln_type=VulnerabilityType.REENTRANCY,
    severity="HIGH",
    title="Reentrancy Vulnerability",
    description="Function makes external call before state update",
    function="withdraw",
    recommendation="Apply checks-effects-interactions pattern"
)
```

#### Overflow Detection

```python
# Proving arithmetic safety
from morpheus.symbolic import SymbolicInt, SymbolicOperations

# Create symbolic values
a = SymbolicInt.symbolic("a")
b = SymbolicInt.symbolic("b")

# Execute operation with overflow tracking
result, overflow = SymbolicOperations.add(a, b, track_overflow=True)

# Query: Is overflow possible?
solver = z3.Solver()
solver.add(overflow.z3_expr == True)
is_possible = solver.check() == z3.sat

print(f"Overflow possible: {is_possible}")
```

---

## Symbolic Execution

### How Symbolic Execution Works

1. **Symbolic Input**: Replace concrete inputs with symbolic variables
2. **Path Exploration**: Explore all possible execution paths
3. **Constraint Collection**: Track path conditions (branches taken)
4. **Query Solving**: Use Z3 to determine path feasibility
5. **Violation Detection**: Find inputs that cause violations

### Key Components

#### SymbolicEngine

```python
from morpheus.symbolic import SymbolicEngine

engine = SymbolicEngine(
    timeout=30000,      # Z3 timeout (ms)
    max_depth=1000,    # Maximum execution depth
    max_paths=10000    # Maximum paths to explore
)

# Execute function symbolically
result = engine.execute_function(
    function_name="withdraw",
    args={"amount": symbolic_amount},
    contract_state=initial_storage
)

# Check for violations
for violation in result.violations:
    print(f"Vulnerability: {violation.description}")
```

#### Symbolic Values

```python
from morpheus.symbolic import SymbolicInt, SymbolicBool, SymbolicAddress

# Create symbolic values
amount = SymbolicInt.symbolic("withdrawal_amount")
sender = SymbolicAddress.symbolic("caller")
is_owner = SymbolicBool.symbolic("is_owner")

# Perform symbolic operations
new_balance = current_balance - amount
is_valid = is_owner & (current_balance >= amount)
```

---

## Theorem Proving

### Proof Methods

#### Direct Verification

```python
# Verify a property directly
result = prover.verify_precondition_postcondition(
    precondition=balances[sender] >= amount,
    function_body=withdraw_code,
    postcondition=balances[sender] == old_balance - amount,
    context=context
)
```

#### Induction Proof

```python
# Prove invariant by induction
result = prover.prove_invariant(
    invariant=balances[sender] >= 0,
    contract=contract,
    context=context,
    method="induction"  # or "k-induction"
)

# Result includes:
# - Base case verification
# - Inductive step verification
# - Counterexample if failed
```

### Proof Result Types

| Status | Meaning |
|--------|---------|
| `PROVED` | Property mathematically verified |
| `DISPROVED` | Counterexample found |
| `UNKNOWN` | Solver could not determine |
| `TIMEOUT` | Exceeded time limit |
| `ERROR` | Internal error occurred |

---

## DeFi Analysis

### DeFi-Specific Vulnerabilities

Morpheus includes specialized analysis for DeFi protocols:

```python
from morpheus.analysis import DeFiAnalyzer

analyzer = DeFiAnalyzer()

# Detect flash loan vulnerabilities
analyzer._detect_flash_loan_vulnerabilities(contract)

# Detect oracle manipulation
analyzer._detect_oracle_manipulation(contract)

# Detect liquidity pool issues
analyzer._detect_liquidity_vulnerabilities(contract)
```

### Supported DeFi Patterns

- **Flash Loan Attacks**: State manipulation via flash loans
- **Price Oracle Manipulation**: Spot price vs TWAP
- **Impermanent Loss**: AMM liquidity provider losses
- **Token Approval Bugs**: Unsafe approve patterns
- **Liquidity Drain**: Reentrancy in AMM operations
- **Yield Exploits**: Reward calculation issues
- **Sandwich Attacks**: MEV in DEX operations

---

## API Reference

### Core Classes

#### SymbolicEngine

```python
class SymbolicEngine:
    def execute_function(
        self,
        function_name: str,
        args: Dict[str, Any],
        contract_state: Dict[str, Any]
    ) -> ExecutionResult
    
    def prove(
        self,
        property: z3.ExprRef,
        is_invariant: bool = False
    ) -> Tuple[bool, Optional[Dict]]
    
    def check_invariant(
        self,
        invariant: z3.ExprRef,
        initial_state: Optional[Dict] = None
    ) -> Tuple[bool, List[Dict]]
```

#### TheoremProver

```python
class TheoremProver:
    def prove(
        self,
        property: Property,
        context: SpecificationContext,
        assumptions: List[z3.BoolRef] = None
    ) -> ProofResult
    
    def disprove(
        self,
        property: Property,
        context: SpecificationContext
    ) -> ProofResult
    
    def prove_invariant(
        self,
        invariant: Invariant,
        contract: Contract,
        context: SpecificationContext
    ) -> ProofResult
```

#### VulnerabilityDetector

```python
class VulnerabilityDetector:
    def analyze_contract(
        self,
        contract: Contract,
        bytecode: Optional[bytes] = None
    ) -> DetectionResult
```

---

## Examples

### Example 1: Basic Property Verification

```python
from morpheus import SolidityParser, TheoremProver
from morpheus.specification import Property, SpecificationContext

# Parse contract
source = '''
pragma solidity ^0.8.0;
contract Simple {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
}
'''
parser = SolidityParser()
ast = parser.parse_source(source)

# Create context
context = SpecificationContext()
context.add_variable("a", z3.BitVec("a", 256))
context.add_variable("b", z3.BitVec("b", 256))

# Define property: sum should not overflow (Solidity 0.8+ handles this)
property = Property.create(
    "add_no_overflow",
    "a + b >= a && a + b >= b",
    "Addition should not overflow"
)

# Prove
prover = TheoremProver()
result = prover.prove(property, context)

print(f"Proved: {result.is_proved()}")
```

### Example 2: Reentrancy Analysis

```python
from morpheus import SolidityParser, VulnerabilityDetector

source = '''
pragma solidity ^0.7.0;
contract VulnerableBank {
    mapping(address => uint256) balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public {
        // VULNERABLE: External call before state update
        msg.sender.transfer(amount);
        balances[msg.sender] -= amount;
    }
}
'''

parser = SolidityParser()
contract = parser.parse_source(source)

detector = VulnerabilityDetector()
result = detector.analyze_contract(contract)

for vuln in result.vulnerabilities:
    if "reentrancy" in vuln.vuln_type.name.lower():
        print(f"[{vuln.severity}] {vuln.title}")
```

### Example 3: Counterexample Generation

```python
from morpheus import TheoremProver
from morpheus.specification import Property
from morpheus.counterexample import CounterexampleGenerator

# Create a failing property
property = Property.create(
    "impossible_property",
    "x > 10 && x < 5"  # Contradiction
)

prover = TheoremProver()
generator = CounterexampleGenerator()

# Get counterexample
counterexample = generator.generate(
    property_name="impossible_property",
    negated_formula=z3.Not(property.formula),
    solver=prover.solver
)

if counterexample:
    print(f"Counterexample: {counterexample.values}")
    print(counterexample.to_test_case("python"))
```

---

## Configuration

### Configuration File

Create `morpheus.yaml`:

```yaml
# Morpheus Configuration

verification:
  timeout: 30000           # Z3 solver timeout (ms)
  max_depth: 1000          # Maximum symbolic execution depth
  max_paths: 10000         # Maximum paths to explore
  use_simplifier: true     # Use Z3 simplifier

vulnerability:
  check_reentrancy: true
  check_overflow: true
  check_access_control: true
  check_external_calls: true
  check_front_running: true
  check_dos: true
  check_time_manipulation: true

output:
  format: json             # Output format (json, yaml, text)
  verbose: false
  include_counterexamples: true
  generate_tests: true
```

### Environment Variables

```bash
# Set Z3 timeout
export MORPHEUS_TIMEOUT=60000

# Enable verbose output
export MORPHEUS_VERBOSE=1

# Use parallel verification
export MORPHEUS_PARALLEL=4
```

---

## Best Practices

### Writing Verifiable Contracts

1. **Keep Functions Small**: Easier to verify
2. **Use Clear State Updates**: Follow checks-effects-interactions
3. **Avoid Assembly**: Harder to verify symbolically
4. **Use Fixed Types**: uint256 instead of uint8
5. **Document Invariants**: Comment what should always hold

### Specification Writing

1. **Start with Invariants**: What must always be true?
2. **Add Function Contracts**: Pre/post conditions
3. **Be Specific**: Avoid vague specifications
4. **Test Specifications**: Verify with known counterexamples
5. **Iterate**: Refine based on verification results

### Integration into Development

```bash
# Add to CI/CD pipeline
morpheus verify contract.sol --spec contract.mspec

# Git pre-commit hook
morpheus check --exit-code
```

---

## Troubleshooting

### Common Issues

#### "Solver timeout exceeded"

```python
# Increase timeout
prover = TheoremProver(timeout=60000)
```

#### "Too many paths explored"

```python
# Limit path exploration
engine = SymbolicEngine(max_paths=1000)
```

#### "Property too complex"

Break down into smaller lemmas:
```mspec
# Instead of:
property complex: A && B && C && D

# Write:
property part1: A && B
property part2: C && D
```

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable trace output
engine = SymbolicEngine()
engine.trace_enabled = True
```

---

## Roadmap

### Version 1.1 (Planned)
- [ ] Yul intermediate representation support
- [ ] Improved DeFi analysis
- [ ] VS Code extension

### Version 1.2 (Planned)
- [ ] WebAssembly bytecode analysis
- [ ] Multi-contract verification
- [ ] Composability analysis

### Future Ideas
- [ ] EVM formal specification
- [ ] Interactive proof assistant integration
- [ ] Machine learning for pattern detection

---

## Contributing

Contributions are welcome! Please read our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Write tests for new features
4. Ensure all tests pass
5. Submit a pull request

### Development Setup

```bash
# Clone and install
git clone https://github.com/moggan1337/Morpheus.git
cd Morpheus
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run with coverage
pytest --cov=morpheus tests/
```

---

## License

Morpheus is released under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- **Z3 Theorem Prover**: Microsoft Research for the excellent SMT solver
- **EVM Specification**: Ethereum Foundation for the detailed EVM specification
- **Formal Methods Community**: For the foundational work in program verification
- **OpenZeppelin**: For security patterns and smart contract best practices

---

<div align="center">

**Morpheus: Seeing Through Smart Contract Reality**

*"In dreams, we find truth about the waking world."*

</div>
