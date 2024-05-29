const ethers = require('ethers');

const provider = new ethers.providers.JsonRpcProvider('https://avalanche.public-rpc.com');
const signer = new ethers.Wallet("0x9bbc62adcf6aae6f3295e88dc0219f83b3900bc1fb90f458b91404e1381d178e", provider);

const VOUCHER_CONTRACT = '0xbB740E17f3c177172CaAcCef2F472DB41b9b1d19';
const LOCK_TOKEN = "0xf3E0915319b33445AAF9Ea4c6D3c4f7fB2875081";
const ABI = [{ "type": "function", "name": "createBatch", "inputs": [{ "name": "tokenAddress", "type": "address", "internalType": "address" }, { "name": "batch", "type": "tuple", "internalType": "struct BatchVesting", "components": [{ "name": "vesting", "type": "tuple", "internalType": "struct Vesting", "components": [{ "name": "balance", "type": "uint256", "internalType": "uint256" }, { "name": "schedules", "type": "tuple[]", "internalType": "struct VestingSchedule[]", "components": [{ "name": "amount", "type": "uint256", "internalType": "uint256" }, { "name": "vestingType", "type": "uint8", "internalType": "uint8" }, { "name": "linearType", "type": "uint8", "internalType": "uint8" }, { "name": "startTimestamp", "type": "uint256", "internalType": "uint256" }, { "name": "endTimestamp", "type": "uint256", "internalType": "uint256" }, { "name": "isVested", "type": "uint8", "internalType": "uint8" }, { "name": "remainingAmount", "type": "uint256", "internalType": "uint256" }] }, { "name": "fee", "type": "tuple", "internalType": "struct VestingFee", "components": [{ "name": "isFee", "type": "uint8", "internalType": "uint8" }, { "name": "feeTokenAddress", "type": "address", "internalType": "address" }, { "name": "receiverAddress", "type": "address", "internalType": "address" }, { "name": "totalFee", "type": "uint256", "internalType": "uint256" }, { "name": "remainingFee", "type": "uint256", "internalType": "uint256" }] }] }, { "name": "quantity", "type": "uint256", "internalType": "uint256" }, { "name": "tokenUris", "type": "string[]", "internalType": "string[]" }] }, { "name": "royaltyRate", "type": "uint96", "internalType": "uint96" }], "outputs": [{ "name": "", "type": "address", "internalType": "address" }, { "name": "", "type": "uint256", "internalType": "uint256" }, { "name": "", "type": "uint256", "internalType": "uint256" }], "stateMutability": "nonpayable" }];

const ERC20ABI = [{ "constant": true, "inputs": [], "name": "name", "outputs": [{ "name": "", "type": "string" }], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": false, "inputs": [{ "name": "_spender", "type": "address" }, { "name": "_value", "type": "uint256" }], "name": "approve", "outputs": [{ "name": "", "type": "bool" }], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": true, "inputs": [], "name": "totalSupply", "outputs": [{ "name": "", "type": "uint256" }], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": false, "inputs": [{ "name": "_from", "type": "address" }, { "name": "_to", "type": "address" }, { "name": "_value", "type": "uint256" }], "name": "transferFrom", "outputs": [{ "name": "", "type": "bool" }], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": true, "inputs": [], "name": "decimals", "outputs": [{ "name": "", "type": "uint8" }], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [{ "name": "_owner", "type": "address" }], "name": "balanceOf", "outputs": [{ "name": "balance", "type": "uint256" }], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "symbol", "outputs": [{ "name": "", "type": "string" }], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": false, "inputs": [{ "name": "_to", "type": "address" }, { "name": "_value", "type": "uint256" }], "name": "transfer", "outputs": [{ "name": "", "type": "bool" }], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": true, "inputs": [{ "name": "_owner", "type": "address" }, { "name": "_spender", "type": "address" }], "name": "allowance", "outputs": [{ "name": "", "type": "uint256" }], "payable": false, "stateMutability": "view", "type": "function" }, { "payable": true, "stateMutability": "payable", "type": "fallback" }, { "anonymous": false, "inputs": [{ "indexed": true, "name": "owner", "type": "address" }, { "indexed": true, "name": "spender", "type": "address" }, { "indexed": false, "name": "value", "type": "uint256" }], "name": "Approval", "type": "event" }, { "anonymous": false, "inputs": [{ "indexed": true, "name": "from", "type": "address" }, { "indexed": true, "name": "to", "type": "address" }, { "indexed": false, "name": "value", "type": "uint256" }], "name": "Transfer", "type": "event" }];

const contract = new ethers.Contract(VOUCHER_CONTRACT, ABI, signer);
const erc20Contract = new ethers.Contract(0xf3E0915319b33445AAF9Ea4c6D3c4f7fB2875081, ERC20ABI, signer);

async function createBatch() {
    // approve the token to contract first
    await erc20Contract.approve(VOUCHER_CONTRACT, 999999999);

    // do the real batch
    await contract.createBatch(
        LOCK_TOKEN,
        {
            vesting: {
                balance: 1000,
                schedules: [
                    {
                        amount: 500,
                        vestingType: 1,
                        linearType: 1,
                        startTimestamp: 1633039123,
                        endTimestamp: 1664575123,
                        isVested: 0,
                        remainingAmount: 500
                    }
                ],
                fee: {
                    isFee: 0,
                    feeTokenAddress: "0x0000000000000000000000000000000000000000",
                    receiverAddress: "0x0000000000000000000000000000000000000000",
                    totalFee: 0,
                    remainingFee: 0
                }
            },
            quantity: 1000,
            tokenUris: ["http://example.com/token/1", "http://example.com/token/2"],
        }, 500);
}


createBatch();

