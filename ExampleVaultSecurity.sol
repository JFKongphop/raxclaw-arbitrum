// MultiVault — Demo contract with multiple intentional vulnerabilities
// for RAXC Autonomous Security Audit demonstration
//
// Vulnerabilities present:
//   ❌ Reentrancy: withdraw() calls external before state update
//   ❌ Access Control: no onlyOwner on critical functions
//   ❌ Flash Loan: spot price oracle, manipulable in single tx
//   ❌ Unchecked Return: send() return value ignored
//   ❌ Integer Overflow: Solidity <0.8 arithmetic
//   ❌ tx.origin auth: vulnerable to phishing
//   ❌ Timestamp manipulation: block.timestamp for randomness
//   ❌ Gas: array.length in loop, string memory param

pragma solidity ^0.7.0;

contract MultiVault {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    address[] public depositors;
    address public owner;
    bool private initialized;
    uint256 public lastDistribution;

    // ❌ AccessControl: no initializer guard — callable by anyone, multiple times
    function initialize(address _owner) external {
        owner = _owner;
    }

    // ❌ AccessControl: setOwner has no onlyOwner guard
    function setOwner(address _newOwner) external {
        owner = _newOwner;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        depositors.push(msg.sender);
    }

    // ❌ Reentrancy: external call BEFORE state update (violates CEI)
    // ❌ AccessControl: no onlyOwner — anyone can call withdraw
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0;
    }

    // ❌ FlashLoan: spot price oracle via getReserves — manipulable in one tx
    function getPrice() external view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = IUniswapPair(address(this))
            .getReserves();
        return (uint256(reserve0) * 1e18) / uint256(reserve1);
    }

    // ❌ FlashLoan: callback with no reentrancy guard
    function executeOperation(uint256 amount) external {
        uint256 price = this.getPrice();
        balances[msg.sender] += price * amount;
    }

    // ❌ FlashLoan: borrow + swap in same tx, no atomicity guard
    function flashArbitrage(address token, uint256 amount) external {
        IFlashLender(token).borrow(amount);
        uint256 profit = this.getPrice();
        balances[msg.sender] += profit;
    }

    // ❌ Unchecked Return: send() return value not checked
    function distributeReward(address recipient) external {
        uint256 reward = rewards[recipient];
        // BUG: send() can fail silently — 2300 gas may not be enough
        payable(recipient).send(reward);
        rewards[recipient] = 0;
    }

    // ❌ tx.origin: vulnerable to phishing attacks
    function emergencyWithdraw() external {
        require(tx.origin == owner, "Not owner");
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "Transfer failed");
    }

    // ❌ Timestamp manipulation: block.timestamp for "randomness"
    function luckyReward() external returns (uint256) {
        uint256 random = uint256(
            keccak256(abi.encodePacked(block.timestamp, msg.sender))
        );
        uint256 reward = random % 100;
        if (reward > 90) {
            balances[msg.sender] += 10 ether;
        }
        return reward;
    }

    // ❌ Integer Overflow (pre-0.8): no SafeMath
    function batchTransfer(
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amounts[i];
            balances[msg.sender] -= amounts[i];
        }
    }

    // ❌ Gas: array.length in loop, string memory param
    function distributeRewards(string memory label) external {
        for (uint i = 0; i < depositors.length; i++) {
            balances[depositors[i]] += 100;
        }
        lastDistribution = block.timestamp;
    }

    // ❌ selfdestruct without onlyOwner
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}

interface IUniswapPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IFlashLender {
    function borrow(uint256 amount) external;
}
