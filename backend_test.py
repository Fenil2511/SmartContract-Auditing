#!/usr/bin/env python3
"""
Comprehensive Backend Testing for Smart Contract Auditing Toolkit
Tests all vulnerability detection algorithms, API endpoints, and database integration
"""

import requests
import json
import time
import os
from pathlib import Path

# Get backend URL from frontend .env file
def get_backend_url():
    frontend_env_path = Path("/app/frontend/.env")
    if frontend_env_path.exists():
        with open(frontend_env_path, 'r') as f:
            for line in f:
                if line.startswith('REACT_APP_BACKEND_URL='):
                    return line.split('=', 1)[1].strip()
    return "http://localhost:8001"

BASE_URL = get_backend_url() + "/api"
print(f"Testing backend at: {BASE_URL}")

# Test Solidity contracts with known vulnerabilities
TEST_CONTRACTS = {
    "reentrancy_vulnerable": """
pragma solidity ^0.7.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable: external call before state change
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount; // State change after external call
    }
}
""",
    
    "tx_origin_vulnerable": """
pragma solidity ^0.7.0;

contract VulnerableAuth {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner, "Not authorized"); // Vulnerable: using tx.origin
        owner = newOwner;
    }
}
""",
    
    "overflow_vulnerable": """
pragma solidity ^0.7.0;

contract VulnerableToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount; // Potential underflow
        balances[to] += amount; // Potential overflow
    }
    
    function mint(uint256 amount) public {
        totalSupply += amount; // Potential overflow
        balances[msg.sender] += amount; // Potential overflow
    }
}
""",
    
    "unchecked_call_vulnerable": """
pragma solidity ^0.7.0;

contract VulnerablePayment {
    function sendPayment(address payable recipient, uint256 amount) public {
        recipient.call{value: amount}(""); // Unchecked call
    }
    
    function sendMultiple(address[] memory recipients, uint256[] memory amounts) public {
        for(uint i = 0; i < recipients.length; i++) {
            recipients[i].call{value: amounts[i]}(""); // Unchecked call
        }
    }
}
""",
    
    "timestamp_vulnerable": """
pragma solidity ^0.7.0;

contract VulnerableLottery {
    uint256 public lastWinner;
    
    function playLottery() public payable {
        require(msg.value >= 1 ether, "Minimum bet is 1 ether");
        
        // Vulnerable: using block.timestamp for randomness
        if (block.timestamp % 2 == 0) {
            lastWinner = block.timestamp;
            payable(msg.sender).transfer(address(this).balance);
        }
    }
    
    function isTimeToPlay() public view returns (bool) {
        return now > lastWinner + 1 hours; // Vulnerable: using now
    }
}
""",
    
    "gas_limit_vulnerable": """
pragma solidity ^0.7.0;

contract VulnerableAuction {
    address[] public bidders;
    mapping(address => uint256) public bids;
    
    function refundAll() public {
        // Vulnerable: unbounded loop
        for(uint i = 0; i < bidders.length; i++) {
            payable(bidders[i]).transfer(bids[bidders[i]]);
        }
    }
    
    function getAllBidders() public view returns (address[] memory) {
        return bidders; // Vulnerable: can grow unbounded
    }
}
""",
    
    "front_running_vulnerable": """
pragma solidity ^0.7.0;

contract VulnerableExchange {
    uint256 public currentPrice = 100;
    
    function getCurrentPrice() public view returns (uint256) {
        return currentPrice;
    }
    
    function buyTokens() public payable {
        uint256 price = getCurrentPrice(); // Vulnerable to front-running
        uint256 tokens = msg.value / price;
        // Transfer tokens logic
    }
}
""",
    
    "missing_events_vulnerable": """
pragma solidity ^0.7.0;

contract VulnerableGovernance {
    address public owner;
    bool public paused;
    
    function transferOwnership(address newOwner) public {
        require(msg.sender == owner, "Not authorized");
        owner = newOwner; // Missing event emission
    }
    
    function setPaused(bool _paused) public {
        require(msg.sender == owner, "Not authorized");
        paused = _paused; // Missing event emission
    }
}
""",
    
    "unsafe_delegatecall_vulnerable": """
pragma solidity ^0.7.0;

contract VulnerableProxy {
    address public implementation;
    
    function upgrade(address newImplementation) public {
        implementation = newImplementation;
    }
    
    fallback() external payable {
        // Vulnerable: unsafe delegatecall
        implementation.delegatecall(msg.data);
    }
}
""",
    
    "unprotected_selfdestruct_vulnerable": """
pragma solidity ^0.7.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function destroy() public {
        selfdestruct(payable(msg.sender)); // Unprotected selfdestruct
    }
}
""",
    
    "weak_randomness_vulnerable": """
pragma solidity ^0.7.0;

contract VulnerableRandom {
    uint256 public randomSeed;
    
    function generateRandom() public {
        // Vulnerable: weak randomness sources
        randomSeed = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
    }
    
    function lottery() public view returns (bool) {
        uint256 random = uint256(keccak256(abi.encodePacked(block.number, msg.sender)));
        return random % 2 == 0;
    }
}
""",
    
    "unhandled_exceptions_vulnerable": """
pragma solidity ^0.7.0;

interface ExternalContract {
    function riskyCall() external returns (bool);
}

contract VulnerableHandler {
    ExternalContract external_contract;
    
    function makeCall() public {
        external_contract.call(abi.encodeWithSignature("riskyCall()")); // Unhandled exception
    }
    
    function anotherCall() public {
        external_contract.riskyCall(); // No try-catch
    }
}
""",
    
    "multiple_vulnerabilities": """
pragma solidity ^0.7.0;

contract MultipleVulnerabilities {
    address public owner;
    mapping(address => uint256) public balances;
    address[] public users;
    
    constructor() {
        owner = msg.sender;
    }
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Reentrancy vulnerability
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }
    
    function changeOwner(address newOwner) public {
        require(tx.origin == owner, "Not authorized"); // tx.origin vulnerability
        owner = newOwner; // Missing event
    }
    
    function addBalance(uint256 amount) public {
        balances[msg.sender] += amount; // Overflow vulnerability
    }
    
    function refundAll() public {
        for(uint i = 0; i < users.length; i++) { // Gas limit DoS
            payable(users[i]).call{value: balances[users[i]]}(""); // Unchecked call
        }
    }
    
    function destroy() public {
        selfdestruct(payable(msg.sender)); // Unprotected selfdestruct
    }
    
    function randomWinner() public view returns (address) {
        uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp))); // Weak randomness
        return users[random % users.length];
    }
}
"""
}

def test_api_root():
    """Test the root API endpoint"""
    print("\n=== Testing API Root Endpoint ===")
    try:
        response = requests.get(f"{BASE_URL}/")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_contract_analysis():
    """Test contract analysis endpoint with various vulnerable contracts"""
    print("\n=== Testing Contract Analysis Endpoint ===")
    results = {}
    
    for contract_name, contract_code in TEST_CONTRACTS.items():
        print(f"\nTesting {contract_name}...")
        try:
            payload = {
                "contract_code": contract_code,
                "filename": f"{contract_name}.sol"
            }
            
            response = requests.post(f"{BASE_URL}/analyze", json=payload)
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"Analysis ID: {result.get('id')}")
                print(f"Security Score: {result['summary']['securityScore']}")
                print(f"Total Issues: {result['summary']['totalIssues']}")
                print(f"Critical Issues: {result['summary']['criticalIssues']}")
                print(f"High Issues: {result['summary']['highIssues']}")
                print(f"Medium Issues: {result['summary']['mediumIssues']}")
                print(f"Low Issues: {result['summary']['lowIssues']}")
                
                # Verify vulnerabilities detected
                vulnerabilities = result.get('vulnerabilities', [])
                print(f"Vulnerabilities found: {len(vulnerabilities)}")
                for vuln in vulnerabilities:
                    print(f"  - {vuln['title']} ({vuln['severity']}) at line {vuln['line']}")
                
                results[contract_name] = {
                    "success": True,
                    "vulnerabilities_count": len(vulnerabilities),
                    "security_score": result['summary']['securityScore']
                }
            else:
                print(f"Error: {response.text}")
                results[contract_name] = {"success": False, "error": response.text}
                
        except Exception as e:
            print(f"Error testing {contract_name}: {e}")
            results[contract_name] = {"success": False, "error": str(e)}
    
    return results

def test_file_upload():
    """Test file upload endpoint"""
    print("\n=== Testing File Upload Endpoint ===")
    
    # Create a temporary .sol file
    test_contract = TEST_CONTRACTS["reentrancy_vulnerable"]
    temp_file_path = "/tmp/test_contract.sol"
    
    try:
        with open(temp_file_path, 'w') as f:
            f.write(test_contract)
        
        # Test valid .sol file upload
        with open(temp_file_path, 'rb') as f:
            files = {'file': ('test_contract.sol', f, 'text/plain')}
            response = requests.post(f"{BASE_URL}/analyze-file", files=files)
        
        print(f"Valid file upload - Status Code: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"Analysis successful: {result.get('id')}")
            print(f"Filename: {result.get('filename')}")
            print(f"Vulnerabilities: {len(result.get('vulnerabilities', []))}")
        else:
            print(f"Error: {response.text}")
        
        # Test invalid file extension
        with open(temp_file_path, 'rb') as f:
            files = {'file': ('test_contract.txt', f, 'text/plain')}
            response = requests.post(f"{BASE_URL}/analyze-file", files=files)
        
        print(f"Invalid file extension - Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        # Clean up
        os.remove(temp_file_path)
        
        return True
        
    except Exception as e:
        print(f"Error in file upload test: {e}")
        return False

def test_audit_history():
    """Test audit history endpoints"""
    print("\n=== Testing Audit History Endpoints ===")
    
    try:
        # First, create some audit records by analyzing contracts
        audit_ids = []
        for i, (name, code) in enumerate(list(TEST_CONTRACTS.items())[:3]):
            payload = {"contract_code": code, "filename": f"{name}.sol"}
            response = requests.post(f"{BASE_URL}/analyze", json=payload)
            if response.status_code == 200:
                audit_ids.append(response.json()['id'])
        
        time.sleep(1)  # Give database time to process
        
        # Test getting audit history
        response = requests.get(f"{BASE_URL}/history")
        print(f"History endpoint - Status Code: {response.status_code}")
        
        if response.status_code == 200:
            history = response.json()
            print(f"History records: {len(history.get('history', []))}")
            for record in history.get('history', [])[:3]:
                print(f"  - ID: {record['id']}, File: {record['filename']}, Vulnerabilities: {record['vulnerabilities_count']}")
        else:
            print(f"Error: {response.text}")
        
        # Test getting specific audit details
        if audit_ids:
            test_id = audit_ids[0]
            response = requests.get(f"{BASE_URL}/history/{test_id}")
            print(f"Specific audit details - Status Code: {response.status_code}")
            
            if response.status_code == 200:
                details = response.json()
                print(f"Audit details for {test_id}:")
                print(f"  - Filename: {details.get('filename')}")
                print(f"  - Vulnerabilities: {len(details.get('vulnerabilities', []))}")
                print(f"  - Security Score: {details['summary']['securityScore']}")
            else:
                print(f"Error: {response.text}")
        
        # Test non-existent audit ID
        response = requests.get(f"{BASE_URL}/history/non-existent-id")
        print(f"Non-existent ID - Status Code: {response.status_code}")
        
        return True
        
    except Exception as e:
        print(f"Error in audit history test: {e}")
        return False

def test_audit_statistics():
    """Test audit statistics endpoint"""
    print("\n=== Testing Audit Statistics Endpoint ===")
    
    try:
        response = requests.get(f"{BASE_URL}/stats")
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            stats = response.json()
            print(f"Statistics:")
            print(f"  - Total Audits: {stats.get('total_audits')}")
            print(f"  - Total Vulnerabilities: {stats.get('total_vulnerabilities')}")
            print(f"  - Average Vulnerabilities per Audit: {stats.get('average_vulnerabilities_per_audit')}")
            
            breakdown = stats.get('vulnerability_breakdown', {})
            print(f"  - Critical: {breakdown.get('critical', 0)}")
            print(f"  - High: {breakdown.get('high', 0)}")
            print(f"  - Medium: {breakdown.get('medium', 0)}")
            print(f"  - Low: {breakdown.get('low', 0)}")
            
            return True
        else:
            print(f"Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"Error in statistics test: {e}")
        return False

def test_vulnerability_detection_accuracy():
    """Test accuracy of vulnerability detection algorithms"""
    print("\n=== Testing Vulnerability Detection Accuracy ===")
    
    expected_vulnerabilities = {
        "reentrancy_vulnerable": ["REEN_001"],
        "tx_origin_vulnerable": ["PRIV_001"],
        "overflow_vulnerable": ["OVER_001"],
        "unchecked_call_vulnerable": ["CALL_001"],
        "timestamp_vulnerable": ["TIME_001"],
        "gas_limit_vulnerable": ["GAS_001"],
        "front_running_vulnerable": ["FRONT_001"],
        "missing_events_vulnerable": ["EVENT_001"],
        "unsafe_delegatecall_vulnerable": ["DELEG_001"],
        "unprotected_selfdestruct_vulnerable": ["DEST_001"],
        "weak_randomness_vulnerable": ["RAND_001"],
        "unhandled_exceptions_vulnerable": ["EXC_001"]
    }
    
    detection_results = {}
    
    for contract_name, expected_ids in expected_vulnerabilities.items():
        print(f"\nTesting {contract_name} for {expected_ids}...")
        
        try:
            payload = {
                "contract_code": TEST_CONTRACTS[contract_name],
                "filename": f"{contract_name}.sol"
            }
            
            response = requests.post(f"{BASE_URL}/analyze", json=payload)
            
            if response.status_code == 200:
                result = response.json()
                found_ids = [vuln['id'] for vuln in result.get('vulnerabilities', [])]
                
                detected = []
                missed = []
                
                for expected_id in expected_ids:
                    if expected_id in found_ids:
                        detected.append(expected_id)
                    else:
                        missed.append(expected_id)
                
                detection_results[contract_name] = {
                    "detected": detected,
                    "missed": missed,
                    "extra": [id for id in found_ids if id not in expected_ids]
                }
                
                print(f"  Detected: {detected}")
                print(f"  Missed: {missed}")
                print(f"  Extra: {detection_results[contract_name]['extra']}")
                
            else:
                print(f"  Error: {response.text}")
                detection_results[contract_name] = {"error": response.text}
                
        except Exception as e:
            print(f"  Error: {e}")
            detection_results[contract_name] = {"error": str(e)}
    
    return detection_results

def test_error_handling():
    """Test API error handling"""
    print("\n=== Testing Error Handling ===")
    
    test_cases = [
        {
            "name": "Empty contract code",
            "payload": {"contract_code": "", "filename": "empty.sol"},
            "expected_status": 400
        },
        {
            "name": "Missing contract code",
            "payload": {"filename": "missing.sol"},
            "expected_status": 422
        },
        {
            "name": "Invalid JSON",
            "payload": "invalid json",
            "expected_status": 422
        }
    ]
    
    results = {}
    
    for test_case in test_cases:
        print(f"\nTesting: {test_case['name']}")
        try:
            if isinstance(test_case['payload'], str):
                response = requests.post(f"{BASE_URL}/analyze", data=test_case['payload'])
            else:
                response = requests.post(f"{BASE_URL}/analyze", json=test_case['payload'])
            
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            
            results[test_case['name']] = {
                "status_code": response.status_code,
                "expected": test_case['expected_status'],
                "passed": response.status_code == test_case['expected_status']
            }
            
        except Exception as e:
            print(f"Error: {e}")
            results[test_case['name']] = {"error": str(e), "passed": False}
    
    return results

def run_comprehensive_tests():
    """Run all backend tests"""
    print("=" * 80)
    print("SMART CONTRACT AUDITING TOOLKIT - COMPREHENSIVE BACKEND TESTING")
    print("=" * 80)
    
    test_results = {}
    
    # Test 1: API Root
    test_results['api_root'] = test_api_root()
    
    # Test 2: Contract Analysis
    test_results['contract_analysis'] = test_contract_analysis()
    
    # Test 3: File Upload
    test_results['file_upload'] = test_file_upload()
    
    # Test 4: Audit History
    test_results['audit_history'] = test_audit_history()
    
    # Test 5: Statistics
    test_results['statistics'] = test_audit_statistics()
    
    # Test 6: Vulnerability Detection Accuracy
    test_results['vulnerability_detection'] = test_vulnerability_detection_accuracy()
    
    # Test 7: Error Handling
    test_results['error_handling'] = test_error_handling()
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    total_tests = 0
    passed_tests = 0
    
    for test_name, result in test_results.items():
        if isinstance(result, bool):
            total_tests += 1
            if result:
                passed_tests += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        elif isinstance(result, dict):
            if test_name == 'contract_analysis':
                for contract, data in result.items():
                    total_tests += 1
                    if data.get('success', False):
                        passed_tests += 1
                        print(f"✅ {test_name} - {contract}: PASSED ({data.get('vulnerabilities_count', 0)} vulnerabilities)")
                    else:
                        print(f"❌ {test_name} - {contract}: FAILED")
            elif test_name == 'vulnerability_detection':
                for contract, data in result.items():
                    total_tests += 1
                    if 'error' not in data and not data.get('missed', []):
                        passed_tests += 1
                        print(f"✅ {test_name} - {contract}: PASSED")
                    else:
                        print(f"❌ {test_name} - {contract}: FAILED")
            elif test_name == 'error_handling':
                for case, data in result.items():
                    total_tests += 1
                    if data.get('passed', False):
                        passed_tests += 1
                        print(f"✅ {test_name} - {case}: PASSED")
                    else:
                        print(f"❌ {test_name} - {case}: FAILED")
    
    print(f"\nOVERALL RESULTS: {passed_tests}/{total_tests} tests passed ({(passed_tests/total_tests)*100:.1f}%)")
    
    return test_results

if __name__ == "__main__":
    results = run_comprehensive_tests()