import re
from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

@dataclass
class Vulnerability:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    line: int
    function: str
    code_snippet: str
    recommendation: str
    fixed_code: str = ""

class SolidityAuditor:
    def __init__(self):
        self.vulnerabilities = []
        self.recommendations = []
        
    def analyze_contract(self, contract_code: str) -> Dict[str, Any]:
        """Main analysis function that runs all vulnerability checks"""
        self.vulnerabilities = []
        self.recommendations = []
        
        lines = contract_code.split('\n')
        
        # Run all vulnerability detection methods
        self._detect_reentrancy(contract_code, lines)
        self._detect_tx_origin_usage(contract_code, lines)
        self._detect_overflow_underflow(contract_code, lines)
        self._detect_unchecked_calls(contract_code, lines)
        self._detect_timestamp_dependence(contract_code, lines)
        self._detect_gas_limit_dos(contract_code, lines)
        self._detect_front_running(contract_code, lines)
        self._detect_missing_events(contract_code, lines)
        self._detect_unsafe_delegatecall(contract_code, lines)
        self._detect_unprotected_selfdestruct(contract_code, lines)
        self._detect_weak_randomness(contract_code, lines)
        self._detect_unhandled_exceptions(contract_code, lines)
        
        # Generate recommendations
        self._generate_recommendations()
        
        # Calculate security score
        security_score = self._calculate_security_score()
        
        return {
            "summary": {
                "totalIssues": len(self.vulnerabilities),
                "criticalIssues": sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL),
                "highIssues": sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH),
                "mediumIssues": sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM),
                "lowIssues": sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW),
                "securityScore": security_score,
                "recommendation": self._get_overall_recommendation(security_score)
            },
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "category": v.category,
                    "description": v.description,
                    "line": v.line,
                    "function": v.function,
                    "codeSnippet": v.code_snippet,
                    "recommendation": v.recommendation,
                    "fixedCode": v.fixed_code
                }
                for v in self.vulnerabilities
            ],
            "recommendations": self.recommendations
        }
    
    def _detect_reentrancy(self, code: str, lines: List[str]):
        """Detect reentrancy vulnerabilities"""
        # Look for external calls before state changes
        function_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*[^{]*\{'
        external_call_patterns = [
            r'\.call\s*\{',
            r'\.send\s*\(',
            r'\.transfer\s*\(',
            r'\.call\s*\('
        ]
        
        current_function = ""
        brace_count = 0
        in_function = False
        external_call_line = -1
        state_change_line = -1
        
        for i, line in enumerate(lines):
            line_clean = line.strip()
            
            # Track function boundaries
            func_match = re.search(function_pattern, line_clean)
            if func_match:
                current_function = func_match.group(1)
                in_function = True
                brace_count = line_clean.count('{') - line_clean.count('}')
                external_call_line = -1
                state_change_line = -1
                continue
            
            if in_function:
                brace_count += line_clean.count('{') - line_clean.count('}')
                
                # Check for external calls
                for pattern in external_call_patterns:
                    if re.search(pattern, line_clean) and external_call_line == -1:
                        external_call_line = i + 1
                
                # Check for state changes after external call
                if (external_call_line != -1 and 
                    re.search(r'\w+\s*\[\s*\w+\s*\]\s*[-+*/]?=', line_clean) and
                    state_change_line == -1):
                    state_change_line = i + 1
                
                # If we found both patterns in wrong order, it's a vulnerability
                if external_call_line != -1 and state_change_line != -1 and external_call_line < state_change_line:
                    self.vulnerabilities.append(Vulnerability(
                        id="REEN_001",
                        title="Reentrancy Attack Vulnerability",
                        severity=Severity.CRITICAL,
                        category="Reentrancy",
                        description="External call is made before state changes, allowing potential reentrancy attacks where malicious contracts can recursively call back.",
                        line=external_call_line,
                        function=current_function,
                        code_snippet=lines[external_call_line-1:state_change_line],
                        recommendation="Follow the Checks-Effects-Interactions pattern. Update state before making external calls, or use a reentrancy guard.",
                        fixed_code=f"""// Use reentrancy guard and update state first
function {current_function}(...) public nonReentrant {{
    require(condition);
    // Update state first
    balances[msg.sender] -= amount;
    // Then make external call
    (bool success, ) = msg.sender.call{{value: amount}}("");
    require(success, "Transfer failed");
}}"""
                    ))
                    break
                
                if brace_count == 0:
                    in_function = False
    
    def _detect_tx_origin_usage(self, code: str, lines: List[str]):
        """Detect tx.origin usage for authentication"""
        pattern = r'tx\.origin'
        for i, line in enumerate(lines):
            if re.search(pattern, line):
                function_name = self._get_function_name(lines, i)
                self.vulnerabilities.append(Vulnerability(
                    id="PRIV_001",
                    title="Privilege Escalation via tx.origin",
                    severity=Severity.CRITICAL,
                    category="Access Control",
                    description="Using tx.origin for authorization allows privilege escalation attacks. A malicious contract can trick users into performing unauthorized actions.",
                    line=i + 1,
                    function=function_name,
                    code_snippet=line.strip(),
                    recommendation="Use msg.sender instead of tx.origin for authorization checks.",
                    fixed_code=line.replace('tx.origin', 'msg.sender')
                ))
    
    def _detect_overflow_underflow(self, code: str, lines: List[str]):
        """Detect potential integer overflow/underflow"""
        # Check Solidity version first
        version_match = re.search(r'pragma\s+solidity\s+[\^<>=]*([0-9]+\.[0-9]+)', code)
        if version_match:
            version = float(version_match.group(1))
            if version >= 0.8:
                return  # Solidity 0.8+ has built-in overflow protection
        
        # Look for arithmetic operations without SafeMath
        unsafe_patterns = [
            r'\w+\s*\+=\s*\w+',
            r'\w+\s*-=\s*\w+',
            r'\w+\s*\*=\s*\w+',
            r'\w+\s*=\s*\w+\s*[\+\-\*]\s*\w+'
        ]
        
        for i, line in enumerate(lines):
            line_clean = line.strip()
            # Skip if SafeMath is used
            if 'SafeMath' in line_clean or 'safe' in line_clean.lower():
                continue
                
            for pattern in unsafe_patterns:
                if re.search(pattern, line_clean):
                    function_name = self._get_function_name(lines, i)
                    self.vulnerabilities.append(Vulnerability(
                        id="OVER_001",
                        title="Integer Overflow/Underflow Risk",
                        severity=Severity.HIGH,
                        category="Arithmetic",
                        description="Arithmetic operations without overflow protection can lead to integer overflow/underflow vulnerabilities.",
                        line=i + 1,
                        function=function_name,
                        code_snippet=line_clean,
                        recommendation="Use Solidity 0.8.0+ with built-in overflow checks or implement SafeMath library for older versions.",
                        fixed_code=f"// Upgrade to Solidity 0.8+ or use SafeMath\n{line_clean.replace('+=', '= SafeMath.add(balances[msg.sender],').replace('-=', '= SafeMath.sub(balances[msg.sender],')}"
                    ))
                    break
    
    def _detect_unchecked_calls(self, code: str, lines: List[str]):
        """Detect unchecked low-level calls"""
        call_patterns = [
            r'\.call\s*\([^)]*\)\s*;',
            r'\.send\s*\([^)]*\)\s*;',
            r'\.delegatecall\s*\([^)]*\)\s*;'
        ]
        
        for i, line in enumerate(lines):
            line_clean = line.strip()
            for pattern in call_patterns:
                if re.search(pattern, line_clean):
                    # Check if return value is checked in the same line or next few lines
                    is_checked = False
                    for j in range(max(0, i-2), min(len(lines), i+3)):
                        if re.search(r'(bool|require|assert|if\s*\()', lines[j]):
                            is_checked = True
                            break
                    
                    if not is_checked:
                        function_name = self._get_function_name(lines, i)
                        self.vulnerabilities.append(Vulnerability(
                            id="CALL_001",
                            title="Unchecked Low-Level Call",
                            severity=Severity.HIGH,
                            category="Error Handling",
                            description="Low-level call return value is not checked, which can lead to silent failures and unexpected behavior.",
                            line=i + 1,
                            function=function_name,
                            code_snippet=line_clean,
                            recommendation="Always check the return value of low-level calls and handle failures appropriately.",
                            fixed_code=f"(bool success, ) = {line_clean.split('.')[0]}.call(...);\nrequire(success, \"Call failed\");"
                        ))
                        break
    
    def _detect_timestamp_dependence(self, code: str, lines: List[str]):
        """Detect timestamp dependence vulnerabilities"""
        timestamp_patterns = [
            r'block\.timestamp',
            r'now\b'
        ]
        
        for i, line in enumerate(lines):
            line_clean = line.strip()
            for pattern in timestamp_patterns:
                if re.search(pattern, line_clean):
                    function_name = self._get_function_name(lines, i)
                    self.vulnerabilities.append(Vulnerability(
                        id="TIME_001",
                        title="Timestamp Dependence",
                        severity=Severity.MEDIUM,
                        category="Temporal",
                        description="Contract logic depends on block.timestamp which can be manipulated by miners within a ~15 second window.",
                        line=i + 1,
                        function=function_name,
                        code_snippet=line_clean,
                        recommendation="Avoid using block.timestamp for critical logic. Use block numbers or implement additional security measures.",
                        fixed_code=line_clean.replace('block.timestamp', 'block.number').replace('now', 'block.number')
                    ))
                    break
    
    def _detect_gas_limit_dos(self, code: str, lines: List[str]):
        """Detect potential gas limit DoS attacks"""
        loop_patterns = [
            r'for\s*\([^)]*\.length[^)]*\)',
            r'while\s*\([^)]*\.length[^)]*\)'
        ]
        
        for i, line in enumerate(lines):
            line_clean = line.strip()
            for pattern in loop_patterns:
                if re.search(pattern, line_clean):
                    function_name = self._get_function_name(lines, i)
                    self.vulnerabilities.append(Vulnerability(
                        id="GAS_001",
                        title="Gas Limit DoS Attack Risk",
                        severity=Severity.MEDIUM,
                        category="Gas Optimization",
                        description="Unbounded loop over dynamic array can cause gas limit issues and potential denial of service attacks.",
                        line=i + 1,
                        function=function_name,
                        code_snippet=line_clean,
                        recommendation="Implement pagination or batch processing to avoid gas limit issues.",
                        fixed_code=f"// Implement pagination\nfunction {function_name}(uint start, uint end) public {{\n    require(end <= array.length, \"Invalid range\");\n    for(uint i = start; i < end; i++) {{\n        // Process item\n    }}\n}}"
                    ))
                    break
    
    def _detect_front_running(self, code: str, lines: List[str]):
        """Detect front-running vulnerabilities"""
        vulnerable_patterns = [
            r'getCurrentPrice\(\)',
            r'getPrice\(\)',
            r'msg\.value\s*/\s*price'
        ]
        
        for i, line in enumerate(lines):
            line_clean = line.strip()
            for pattern in vulnerable_patterns:
                if re.search(pattern, line_clean):
                    function_name = self._get_function_name(lines, i)
                    self.vulnerabilities.append(Vulnerability(
                        id="FRONT_001",
                        title="Front-Running Vulnerability",
                        severity=Severity.MEDIUM,
                        category="MEV",
                        description="Transaction ordering dependence allows front-running attacks where miners can reorder transactions for profit.",
                        line=i + 1,
                        function=function_name,
                        code_snippet=line_clean,
                        recommendation="Implement commit-reveal schemes or use price oracles with slippage protection.",
                        fixed_code=f"function {function_name}(uint maxPrice) public payable {{\n    uint price = getCurrentPrice();\n    require(price <= maxPrice, \"Price too high\");\n    // Continue with transaction\n}}"
                    ))
                    break
    
    def _detect_missing_events(self, code: str, lines: List[str]):
        """Detect missing event emissions for critical state changes"""
        state_change_patterns = [
            r'owner\s*=',
            r'admin\s*=',
            r'paused\s*=',
            r'stopped\s*='
        ]
        
        for i, line in enumerate(lines):
            line_clean = line.strip()
            for pattern in state_change_patterns:
                if re.search(pattern, line_clean):
                    # Check if there's an emit statement nearby
                    has_emit = False
                    for j in range(max(0, i-3), min(len(lines), i+4)):
                        if re.search(r'emit\s+\w+', lines[j]):
                            has_emit = True
                            break
                    
                    if not has_emit:
                        function_name = self._get_function_name(lines, i)
                        self.vulnerabilities.append(Vulnerability(
                            id="EVENT_001",
                            title="Missing Event Emission",
                            severity=Severity.LOW,
                            category="Transparency",
                            description="Critical state changes are not logged with events, making it difficult to track contract activity.",
                            line=i + 1,
                            function=function_name,
                            code_snippet=line_clean,
                            recommendation="Emit events for all critical state changes to improve transparency and enable off-chain monitoring.",
                            fixed_code=f"event StateChanged(address indexed user, uint256 timestamp);\n\n{line_clean}\nemit StateChanged(msg.sender, block.timestamp);"
                        ))
                        break
    
    def _detect_unsafe_delegatecall(self, code: str, lines: List[str]):
        """Detect unsafe delegatecall usage"""
        for i, line in enumerate(lines):
            if 'delegatecall' in line:
                function_name = self._get_function_name(lines, i)
                self.vulnerabilities.append(Vulnerability(
                    id="DELEG_001",
                    title="Unsafe Delegatecall",
                    severity=Severity.HIGH,
                    category="Proxy Security",
                    description="Delegatecall can be dangerous as it executes code in the context of the calling contract, potentially allowing attackers to modify storage.",
                    line=i + 1,
                    function=function_name,
                    code_snippet=line.strip(),
                    recommendation="Ensure delegatecall targets are trusted and implement proper access controls.",
                    fixed_code="// Add whitelist check\nrequire(trustedContracts[target], \"Untrusted target\");\n" + line.strip()
                ))
    
    def _detect_unprotected_selfdestruct(self, code: str, lines: List[str]):
        """Detect unprotected selfdestruct calls"""
        for i, line in enumerate(lines):
            if 'selfdestruct' in line or 'suicide' in line:
                # Check if there's access control
                has_protection = False
                for j in range(max(0, i-5), i):
                    if re.search(r'(require|modifier|onlyOwner|msg\.sender)', lines[j]):
                        has_protection = True
                        break
                
                if not has_protection:
                    function_name = self._get_function_name(lines, i)
                    self.vulnerabilities.append(Vulnerability(
                        id="DEST_001",
                        title="Unprotected Selfdestruct",
                        severity=Severity.CRITICAL,
                        category="Access Control",
                        description="Selfdestruct function lacks proper access control, allowing anyone to destroy the contract.",
                        line=i + 1,
                        function=function_name,
                        code_snippet=line.strip(),
                        recommendation="Add proper access control to selfdestruct functions.",
                        fixed_code=f"modifier onlyOwner() {{ require(msg.sender == owner); _; }}\n\nfunction {function_name}() public onlyOwner {{\n    {line.strip()}\n}}"
                    ))
    
    def _detect_weak_randomness(self, code: str, lines: List[str]):
        """Detect weak randomness sources"""
        weak_random_patterns = [
            r'block\.timestamp',
            r'block\.difficulty',
            r'block\.number',
            r'blockhash\(',
            r'keccak256\(abi\.encodePacked\(block\.'
        ]
        
        for i, line in enumerate(lines):
            line_clean = line.strip()
            if any(re.search(pattern, line_clean) for pattern in weak_random_patterns):
                if 'random' in line_clean.lower() or 'seed' in line_clean.lower():
                    function_name = self._get_function_name(lines, i)
                    self.vulnerabilities.append(Vulnerability(
                        id="RAND_001",
                        title="Weak Randomness Source",
                        severity=Severity.HIGH,
                        category="Randomness",
                        description="Using predictable blockchain data for randomness can be exploited by miners and other actors.",
                        line=i + 1,
                        function=function_name,
                        code_snippet=line_clean,
                        recommendation="Use Chainlink VRF or similar oracle services for secure randomness.",
                        fixed_code="// Use Chainlink VRF for secure randomness\n// requestRandomness(keyHash, fee);"
                    ))
    
    def _detect_unhandled_exceptions(self, code: str, lines: List[str]):
        """Detect unhandled exceptions in external calls"""
        for i, line in enumerate(lines):
            if '.call(' in line and 'try' not in line and 'require' not in line:
                function_name = self._get_function_name(lines, i)
                self.vulnerabilities.append(Vulnerability(
                    id="EXC_001",
                    title="Unhandled Exception",
                    severity=Severity.MEDIUM,
                    category="Error Handling",
                    description="External call doesn't handle potential exceptions, which could lead to unexpected contract behavior.",
                    line=i + 1,
                    function=function_name,
                    code_snippet=line.strip(),
                    recommendation="Use try-catch blocks or check return values for external calls.",
                    fixed_code=f"try externalContract.call() {{\n    // Handle success\n}} catch {{\n    // Handle failure\n}}"
                ))
    
    def _get_function_name(self, lines: List[str], current_line: int) -> str:
        """Extract function name from context"""
        for i in range(current_line, -1, -1):
            match = re.search(r'function\s+(\w+)', lines[i])
            if match:
                return match.group(1)
        return "unknown"
    
    def _generate_recommendations(self):
        """Generate general security recommendations"""
        self.recommendations = [
            {
                "category": "General Security",
                "description": "Implement comprehensive test suite including edge cases and attack scenarios."
            },
            {
                "category": "Access Control",
                "description": "Use OpenZeppelin's AccessControl for role-based permissions instead of simple owner checks."
            },
            {
                "category": "Upgrades",
                "description": "Consider using proxy patterns for upgradeable contracts, but implement proper access controls."
            },
            {
                "category": "External Dependencies",
                "description": "Audit all external contracts and libraries. Pin specific versions to avoid supply chain attacks."
            },
            {
                "category": "Gas Optimization",
                "description": "Optimize gas usage by using appropriate data types and avoiding unnecessary storage operations."
            },
            {
                "category": "Emergency Procedures",
                "description": "Implement emergency pause functionality and clear incident response procedures."
            }
        ]
    
    def _calculate_security_score(self) -> int:
        """Calculate security score based on vulnerabilities found"""
        base_score = 100
        
        for vuln in self.vulnerabilities:
            if vuln.severity == Severity.CRITICAL:
                base_score -= 25
            elif vuln.severity == Severity.HIGH:
                base_score -= 15
            elif vuln.severity == Severity.MEDIUM:
                base_score -= 8
            elif vuln.severity == Severity.LOW:
                base_score -= 3
        
        return max(0, base_score)
    
    def _get_overall_recommendation(self, score: int) -> str:
        """Get overall security recommendation based on score"""
        if score >= 90:
            return "Excellent security posture. Minor improvements recommended."
        elif score >= 70:
            return "Good security with some areas for improvement."
        elif score >= 50:
            return "Moderate security risks detected. Address high priority issues."
        elif score >= 30:
            return "Significant security vulnerabilities found. Immediate attention required."
        else:
            return "Critical security vulnerabilities detected. Do not deploy without fixes."