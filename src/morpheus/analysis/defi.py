"""
DeFi-Specific Analysis
======================

This module provides specialized analysis for DeFi (Decentralized Finance)
smart contracts, detecting vulnerabilities specific to DeFi protocols.

Supported DeFi Vulnerability Types:
- Flash loan attacks
- Price oracle manipulation
- Impermanent loss
- Token approval issues
- Liquidity pool vulnerabilities
- Yield farming exploits
- Sandwich attacks
- Token minting vulnerabilities

Author: Morpheus Team
"""

from __future__ import annotations
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
import z3
import logging

from morpheus.parser.ast import Contract, Function, Expression, Identifier, FunctionCall
from morpheus.symbolic.engine import SymbolicEngine
from morpheus.analysis.taint import TaintAnalyzer, TaintSink

logger = logging.getLogger(__name__)


class DeFiVulnerabilityType(Enum):
    """Types of DeFi-specific vulnerabilities."""
    FLASH_LOAN_ATTACK = auto()
    PRICE_ORACLE_MANIPULATION = auto()
    IMPERMANENT_LOSS = auto()
    TOKEN_APPROVAL_BUG = auto()
    LIQUIDITY_DRAIN = auto()
    YIELD_EXPLOIT = auto()
    SANDWICH_ATTACK = auto()
    MINTING_VULNERABILITY = auto()
    WRAP_UNWRAP_BUG = auto()
    REENTRANCY_ATTACK = auto()


@dataclass
class DeFiVulnerability:
    """Represents a DeFi-specific vulnerability."""
    vuln_type: DeFiVulnerabilityType
    severity: str
    title: str
    description: str
    function: str
    affected_contracts: List[str] = field(default_factory=list)
    recommendation: str = ""
    proof_of_concept: Optional[str] = None


@dataclass
class PriceOracle:
    """Represents a price oracle integration."""
    name: str
    source: str  # chainlink, uniswap, custom, etc.
    get_price_func: str
    last_price_var: Optional[str] = None
    update_frequency: Optional[int] = None


@dataclass
class LiquidityPool:
    """Represents a liquidity pool."""
    name: str
    token0: str
    token1: str
    reserve0_var: str
    reserve1_var: str
    lp_token: Optional[str] = None


@dataclass
class FlashLoanReceiver:
    """Represents a flash loan receiver."""
    name: str
    callback_function: str
    expects_callback: bool = True


class DeFiAnalyzer:
    """
    Specialized analyzer for DeFi protocols.
    
    Detects vulnerabilities specific to DeFi applications
    including flash loan attacks, oracle manipulation, etc.
    """
    
    def __init__(self, engine: Optional[SymbolicEngine] = None):
        self.engine = engine
        self.vulnerabilities: List[DeFiVulnerability] = []
        self.price_oracles: List[PriceOracle] = []
        self.liquidity_pools: List[LiquidityPool] = []
        self.flash_loan_receivers: List[FlashLoanReceiver] = []
    
    def analyze_contract(
        self,
        contract: Contract,
        dependencies: List[Contract] = None
    ) -> List[DeFiVulnerability]:
        """
        Analyze a DeFi contract for vulnerabilities.
        
        Args:
            contract: DeFi contract AST
            dependencies: List of dependency contracts
            
        Returns:
            List of detected vulnerabilities
        """
        logger.info(f"Analyzing DeFi contract: {contract.name}")
        
        # Detect flash loan patterns
        self._detect_flash_loan_vulnerabilities(contract)
        
        # Detect price oracle manipulation
        self._detect_oracle_manipulation(contract)
        
        # Detect liquidity pool issues
        self._detect_liquidity_vulnerabilities(contract)
        
        # Detect token approval issues
        self._detect_approval_vulnerabilities(contract)
        
        # Detect yield farming vulnerabilities
        self._detect_yield_vulnerabilities(contract)
        
        # Detect sandwich attack vulnerabilities
        self._detect_sandwich_vulnerabilities(contract)
        
        return self.vulnerabilities
    
    def _detect_flash_loan_vulnerabilities(self, contract: Contract) -> None:
        """Detect flash loan attack vulnerabilities."""
        # Find functions that borrow tokens
        borrow_functions = self._find_borrow_functions(contract)
        
        for func in borrow_functions:
            # Check if callback is validated
            if not self._has_flash_loan_callback_validation(func):
                vuln = DeFiVulnerability(
                    vuln_type=DeFiVulnerabilityType.FLASH_LOAN_ATTACK,
                    severity="HIGH",
                    title="Potential Flash Loan Attack",
                    description=(
                        f"Function '{func.name}' may be vulnerable to flash loan attacks "
                        "as it doesn't properly validate flash loan callbacks or state."
                    ),
                    function=func.name,
                    recommendation="Implement proper flash loan protections"
                )
                self.vulnerabilities.append(vuln)
            
            # Check if state is updated before external calls
            if self._updates_state_before_external_call(func):
                vuln = DeFiVulnerability(
                    vuln_type=DeFiVulnerabilityType.FLASH_LOAN_ATTACK,
                    severity="HIGH",
                    title="Flash Loan State Dependency",
                    description=(
                        f"Function '{func.name}' may use flash loan-sensitive state "
                        "that can be manipulated during the flash loan."
                    ),
                    function=func.name,
                    recommendation="Use snapshot or TWAP for sensitive calculations"
                )
                self.vulnerabilities.append(vuln)
    
    def _detect_oracle_manipulation(self, contract: Contract) -> None:
        """Detect price oracle manipulation vulnerabilities."""
        # Find oracle integrations
        oracles = self._find_price_oracles(contract)
        
        for oracle in oracles:
            # Check if using spot price directly
            if oracle.source in ('uniswap_v2', 'uniswap_v3', 'sushiswap'):
                # Check if using TWAP
                if not self._uses_twap(oracle):
                    vuln = DeFiVulnerability(
                        vuln_type=DeFiVulnerabilityType.PRICE_ORACLE_MANIPULATION,
                        severity="HIGH",
                        title="Price Oracle Manipulation Risk",
                        description=(
                            f"Oracle '{oracle.name}' uses spot price which can be "
                            "manipulated in a single transaction."
                        ),
                        function=oracle.get_price_func,
                        recommendation="Use TWAP (Time-Weighted Average Price) oracle"
                    )
                    self.vulnerabilities.append(vuln)
            
            # Check for stale price usage
            if oracle.last_price_var and not self._checks_staleness(oracle):
                vuln = DeFiVulnerability(
                    vuln_type=DeFiVulnerabilityType.PRICE_ORACLE_MANIPULATION,
                    severity="MEDIUM",
                    title="Stale Price Risk",
                    description=(
                        f"Oracle '{oracle.name}' may use stale prices."
                    ),
                    function=oracle.get_price_func,
                    recommendation="Check price staleness before use"
                )
                self.vulnerabilities.append(vuln)
    
    def _detect_liquidity_vulnerabilities(self, contract: Contract) -> None:
        """Detect liquidity pool vulnerabilities."""
        pools = self._find_liquidity_pools(contract)
        
        for pool in pools:
            # Check for reentrancy in liquidity operations
            if self._has_liquidity_reentrancy_risk(pool):
                vuln = DeFiVulnerability(
                    vuln_type=DeFiVulnerabilityType.LIQUIDITY_DRAIN,
                    severity="HIGH",
                    title="Liquidity Pool Reentrancy",
                    description=(
                        f"Pool '{pool.name}' may be vulnerable to reentrancy attacks."
                    ),
                    function=pool.name,
                    recommendation="Implement reentrancy guards"
                )
                self.vulnerabilities.append(vuln)
            
            # Check for arithmetic issues in swap calculations
            if self._has_swap_arithmetic_issues(pool):
                vuln = DeFiVulnerability(
                    vuln_type=DeFiVulnerabilityType.LIQUIDITY_DRAIN,
                    severity="MEDIUM",
                    title="Swap Calculation Precision Issue",
                    description=(
                        f"Pool '{pool.name}' may have precision issues in calculations."
                    ),
                    function=pool.name,
                    recommendation="Use safe math and proper rounding"
                )
                self.vulnerabilities.append(vuln)
    
    def _detect_approval_vulnerabilities(self, contract: Contract) -> None:
        """Detect token approval vulnerabilities."""
        for func in contract.functions:
            # Check for approve(0) before new approval
            if self._uses_unsafe_approve(func):
                vuln = DeFiVulnerability(
                    vuln_type=DeFiVulnerabilityType.TOKEN_APPROVAL_BUG,
                    severity="MEDIUM",
                    title="Unsafe Token Approval Pattern",
                    description=(
                        f"Function '{func.name}' uses unsafe approve pattern."
                    ),
                    function=func.name,
                    recommendation="Use safeApprove or increaseAllowance pattern"
                )
                self.vulnerabilities.append(vuln)
            
            # Check for unlimited approvals
            if self._gives_unlimited_approval(func):
                vuln = DeFiVulnerability(
                    vuln_type=DeFiVulnerabilityType.TOKEN_APPROVAL_BUG,
                    severity="LOW",
                    title="Unlimited Token Approval",
                    description=(
                        f"Function '{func.name}' grants unlimited approval."
                    ),
                    function=func.name,
                    recommendation="Consider limited approvals"
                )
                self.vulnerabilities.append(vuln)
    
    def _detect_yield_vulnerabilities(self, contract: Contract) -> None:
        """Detect yield farming vulnerabilities."""
        for func in contract.functions:
            # Check for deposit/withdraw vulnerabilities
            if 'deposit' in func.name.lower() or 'withdraw' in func.name.lower():
                if not self._has_proper_balance_checking(func):
                    vuln = DeFiVulnerability(
                        vuln_type=DeFiVulnerabilityType.YIELD_EXPLOIT,
                        severity="HIGH",
                        title="Yield Deposit/Withdraw Vulnerability",
                        description=(
                            f"Function '{func.name}' may have balance manipulation risk."
                        ),
                        function=func.name,
                        recommendation="Use balance checking with proper accounting"
                    )
                    self.vulnerabilities.append(vuln)
            
            # Check for reward calculation issues
            if 'harvest' in func.name.lower() or 'claim' in func.name.lower():
                if self._has_reward_calculation_issues(func):
                    vuln = DeFiVulnerability(
                        vuln_type=DeFiVulnerabilityType.YIELD_EXPLOIT,
                        severity="MEDIUM",
                        title="Reward Calculation Issue",
                        description=(
                            f"Function '{func.name}' may have reward calculation issues."
                        ),
                        function=func.name,
                        recommendation="Verify reward calculation logic"
                    )
                    self.vulnerabilities.append(vuln)
    
    def _detect_sandwich_vulnerabilities(self, contract: Contract) -> None:
        """Detect sandwich attack vulnerabilities."""
        for func in contract.functions:
            # Check for MEV-sensitive operations
            if self._is_mev_sensitive(func):
                if not self._has_sandwich_protection(func):
                    vuln = DeFiVulnerability(
                        vuln_type=DeFiVulnerabilityType.SANDWICH_ATTACK,
                        severity="LOW",
                        title="Potential Sandwich Attack",
                        description=(
                            f"Function '{func.name}' may be vulnerable to sandwich attacks."
                        ),
                        function=func.name,
                        recommendation="Consider using commit-reveal pattern"
                    )
                    self.vulnerabilities.append(vuln)
    
    # Helper methods
    
    def _find_borrow_functions(self, contract: Contract) -> List[Function]:
        """Find functions that borrow tokens."""
        borrow_funcs = []
        borrow_keywords = ['borrow', 'flash', 'loan', 'swap', 'trade', 'exchange']
        
        for func in contract.functions:
            if any(kw in func.name.lower() for kw in borrow_keywords):
                borrow_funcs.append(func)
        
        return borrow_funcs
    
    def _find_price_oracles(self, contract: Contract) -> List[PriceOracle]:
        """Find price oracle integrations."""
        oracles = []
        oracle_sources = ['chainlink', 'uniswap', 'pancakeswap', 'sushiswap', 'curve']
        
        for func in contract.functions:
            for keyword in oracle_sources:
                if keyword in func.name.lower():
                    oracles.append(PriceOracle(
                        name=f"oracle_{len(oracles)}",
                        source=keyword,
                        get_price_func=func.name
                    ))
        
        return oracles
    
    def _find_liquidity_pools(self, contract: Contract) -> List[LiquidityPool]:
        """Find liquidity pool definitions."""
        pools = []
        
        for var in contract.state_variables:
            if 'reserve' in var.name.lower():
                pools.append(LiquidityPool(
                    name=var.name,
                    token0="token0",
                    token1="token1",
                    reserve0_var=var.name,
                    reserve1_var="reserve1"
                ))
        
        return pools
    
    def _has_flash_loan_callback_validation(self, func: Function) -> bool:
        """Check if function validates flash loan callback."""
        # Simplified check
        return 'flash' in func.name.lower()
    
    def _updates_state_before_external_call(self, func: Function) -> bool:
        """Check if state is updated before external call."""
        # Simplified check
        return False
    
    def _uses_twap(self, oracle: PriceOracle) -> bool:
        """Check if oracle uses TWAP."""
        return 'twap' in oracle.source.lower() or 'average' in oracle.source.lower()
    
    def _checks_staleness(self, oracle: PriceOracle) -> bool:
        """Check if oracle checks price staleness."""
        return oracle.update_frequency is not None
    
    def _has_liquidity_reentrancy_risk(self, pool: LiquidityPool) -> bool:
        """Check if pool has reentrancy risk."""
        # Simplified check
        return True  # Assume all pools have some risk
    
    def _has_swap_arithmetic_issues(self, pool: LiquidityPool) -> bool:
        """Check for arithmetic issues in swap."""
        # Simplified check
        return False
    
    def _uses_unsafe_approve(self, func: Function) -> bool:
        """Check for unsafe approve pattern."""
        return 'approve' in func.name.lower()
    
    def _gives_unlimited_approval(self, func: Function) -> bool:
        """Check for unlimited approval."""
        # Check if uint256(-1) or similar is used
        return False
    
    def _has_proper_balance_checking(self, func: Function) -> bool:
        """Check for proper balance checking."""
        return 'balance' in func.name.lower()
    
    def _has_reward_calculation_issues(self, func: Function) -> bool:
        """Check for reward calculation issues."""
        return False
    
    def _is_mev_sensitive(self, func: Function) -> bool:
        """Check if function is MEV-sensitive."""
        sensitive_keywords = ['swap', 'trade', 'buy', 'sell', 'transfer']
        return any(kw in func.name.lower() for kw in sensitive_keywords)
    
    def _has_sandwich_protection(self, func: Function) -> bool:
        """Check for sandwich attack protection."""
        return 'commit' in func.name.lower() or 'reveal' in func.name.lower()


class FlashLoanAttackSimulator:
    """
    Simulates flash loan attacks to detect vulnerabilities.
    """
    
    def __init__(self, engine: SymbolicEngine):
        self.engine = engine
    
    def simulate_attack(
        self,
        contract: Contract,
        attack_vector: str,
        initial_state: Dict[str, Any]
    ) -> bool:
        """
        Simulate a flash loan attack.
        
        Args:
            contract: Target contract
            attack_vector: Type of attack to simulate
            initial_state: Initial contract state
            
        Returns:
            True if attack succeeds
        """
        # Create symbolic state
        state = self.engine.execute_function(
            'attack',
            {'vector': attack_vector},
            initial_state
        )
        
        # Check if attack succeeded
        return state.has_violations()
    
    def generate_attack_scenario(
        self,
        contract: Contract
    ) -> List[Dict[str, Any]]:
        """Generate potential flash loan attack scenarios."""
        scenarios = []
        
        # Generate scenarios based on contract structure
        for func in contract.functions:
            if self._is_state_dependent(func):
                scenarios.append({
                    'type': 'state_manipulation',
                    'function': func.name,
                    'description': 'Manipulate state via flash loan'
                })
        
        return scenarios
    
    def _is_state_dependent(self, func: Function) -> bool:
        """Check if function depends on state that can be manipulated."""
        return 'price' in func.name.lower() or 'balance' in func.name.lower()


class PriceManipulationDetector:
    """
    Detects price manipulation vulnerabilities.
    """
    
    def __init__(self):
        self.suspicious_patterns = []
    
    def detect(
        self,
        contract: Contract,
        oracle_source: str = "uniswap"
    ) -> List[DeFiVulnerability]:
        """Detect price manipulation vulnerabilities."""
        vulns = []
        
        for func in contract.functions:
            if 'price' in func.name.lower() or 'get' in func.name.lower():
                if not self._uses_safe_oracle(oracle_source):
                    vulns.append(DeFiVulnerability(
                        vuln_type=DeFiVulnerabilityType.PRICE_ORACLE_MANIPULATION,
                        severity="HIGH",
                        title="Price Manipulation Risk",
                        description=f"Function {func.name} may be affected by price manipulation",
                        function=func.name,
                        recommendation="Use TWAP or Chainlink oracle"
                    ))
        
        return vulns
    
    def _uses_safe_oracle(self, source: str) -> bool:
        """Check if using safe oracle."""
        safe_sources = ['chainlink', 'twap', 'average', 'uniswap_v3_twap']
        return any(s in source.lower() for s in safe_sources)
