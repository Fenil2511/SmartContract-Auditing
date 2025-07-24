export const mockAuditResults = {
  summary: {
    totalIssues: 8,
    criticalIssues: 2,
    highIssues: 3,
    mediumIssues: 2,
    lowIssues: 1,
    securityScore: 35,
    recommendation: "Critical vulnerabilities detected. Immediate remediation required before deployment."
  },
  vulnerabilities: [
    {
      id: "REEN_001",
      title: "Reentrancy Attack Vulnerability",
      severity: "Critical",
      category: "Reentrancy",
      description: "The contract is vulnerable to reentrancy attacks. External calls are made before state changes, allowing malicious contracts to recursively call back and drain funds.",
      line: 45,
      function: "withdraw()",
      codeSnippet: `function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount; // State change after external call
}`,
      recommendation: "Follow the Checks-Effects-Interactions pattern. Update state before making external calls, or use a reentrancy guard.",
      fixedCode: `function withdraw(uint amount) public nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount; // State change first
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}`
    },
    {
      id: "PRIV_001",
      title: "Privilege Escalation via tx.origin",
      severity: "Critical",
      category: "Access Control",
      description: "Using tx.origin for authorization allows privilege escalation attacks. A malicious contract can trick users into performing unauthorized actions.",
      line: 23,
      function: "onlyOwner modifier",
      codeSnippet: `modifier onlyOwner() {
    require(tx.origin == owner, "Not owner");
    _;
}`,
      recommendation: "Use msg.sender instead of tx.origin for authorization checks.",
      fixedCode: `modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}`
    },
    {
      id: "OVER_001",
      title: "Integer Overflow/Underflow",
      severity: "High",
      category: "Arithmetic",
      description: "Arithmetic operations without SafeMath or built-in overflow checks can lead to integer overflow/underflow vulnerabilities.",
      line: 67,
      function: "transfer()",
      codeSnippet: `function transfer(address to, uint amount) public {
    balances[msg.sender] -= amount; // Potential underflow
    balances[to] += amount; // Potential overflow
}`,
      recommendation: "Use Solidity 0.8.0+ with built-in overflow checks or implement SafeMath library for older versions.",
      fixedCode: `function transfer(address to, uint amount) public {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    require(balances[to] + amount >= balances[to], "Overflow detected");
    balances[msg.sender] -= amount;
    balances[to] += amount;
}`
    },
    {
      id: "CALL_001",
      title: "Unchecked Low-Level Call",
      severity: "High",
      description: "Low-level calls (.call, .send, .delegatecall) return values are not checked, which can lead to silent failures.",
      line: 91,
      function: "sendEther()",
      codeSnippet: `function sendEther(address payable recipient, uint amount) public {
    recipient.call{value: amount}(""); // Return value not checked
}`,
      recommendation: "Always check the return value of low-level calls and handle failures appropriately.",
      fixedCode: `function sendEther(address payable recipient, uint amount) public {
    (bool success, ) = recipient.call{value: amount}("");
    require(success, "Transfer failed");
}`
    },
    {
      id: "TIME_001",
      title: "Timestamp Dependence",
      severity: "High",
      description: "Contract logic depends on block.timestamp which can be manipulated by miners within a ~15 second window.",
      line: 112,
      function: "timeLock()",
      codeSnippet: `function timeLock() public {
    require(block.timestamp > unlockTime, "Still locked");
    // Critical logic here
}`,
      recommendation: "Avoid using block.timestamp for critical logic. Use block numbers or implement additional security measures.",
      fixedCode: `function timeLock() public {
    require(block.number > unlockBlock, "Still locked");
    // Or add buffer time
    require(block.timestamp > unlockTime + 1 hours, "Still locked");
}`
    },
    {
      id: "GAS_001",
      title: "Gas Limit DoS Attack",
      severity: "Medium",
      description: "Unbounded loop can cause gas limit issues and potential denial of service attacks.",
      line: 134,
      function: "distributeFunds()",
      codeSnippet: `function distributeFunds() public {
    for(uint i = 0; i < beneficiaries.length; i++) {
        beneficiaries[i].transfer(amount);
    }
}`,
      recommendation: "Implement pagination or batch processing to avoid gas limit issues.",
      fixedCode: `function distributeFunds(uint start, uint end) public {
    require(end <= beneficiaries.length, "Invalid range");
    for(uint i = start; i < end; i++) {
        (bool success, ) = beneficiaries[i].call{value: amount}("");
        // Handle individual failures gracefully
    }
}`
    },
    {
      id: "FRONT_001",
      title: "Front-Running Vulnerability",
      severity: "Medium",
      description: "Transaction ordering dependence allows front-running attacks where miners can reorder transactions for profit.",
      line: 156,
      function: "buyTokens()",
      codeSnippet: `function buyTokens() public payable {
    uint price = getCurrentPrice(); // Price can change
    uint tokens = msg.value / price;
    mint(msg.sender, tokens);
}`,
      recommendation: "Implement commit-reveal schemes or use oracles with price feeds to prevent front-running.",
      fixedCode: `function buyTokens(uint maxPrice) public payable {
    uint price = getCurrentPrice();
    require(price <= maxPrice, "Price too high");
    uint tokens = msg.value / price;
    mint(msg.sender, tokens);
}`
    },
    {
      id: "INFO_001",
      title: "Missing Event Emission",
      severity: "Low",
      description: "Critical state changes are not logged with events, making it difficult to track contract activity.",
      line: 178,
      function: "changeOwner()",
      codeSnippet: `function changeOwner(address newOwner) public onlyOwner {
    owner = newOwner; // No event emitted
}`,
      recommendation: "Emit events for all critical state changes to improve transparency and enable off-chain monitoring.",
      fixedCode: `event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

function changeOwner(address newOwner) public onlyOwner {
    address oldOwner = owner;
    owner = newOwner;
    emit OwnershipTransferred(oldOwner, newOwner);
}`
    }
  ],
  recommendations: [
    {
      category: "General Security",
      description: "Implement a comprehensive test suite including edge cases and attack scenarios."
    },
    {
      category: "Access Control",
      description: "Use OpenZeppelin's AccessControl for role-based permissions instead of simple owner checks."
    },
    {
      category: "Upgrades",
      description: "Consider using proxy patterns for upgradeable contracts, but implement proper access controls."
    },
    {
      category: "External Dependencies",
      description: "Audit all external contracts and libraries. Pin specific versions to avoid supply chain attacks."
    },
    {
      category: "Gas Optimization",
      description: "Optimize gas usage by using appropriate data types and avoiding unnecessary storage operations."
    },
    {
      category: "Emergency Procedures",
      description: "Implement emergency pause functionality and clear incident response procedures."
    }
  ]
};