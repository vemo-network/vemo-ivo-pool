## Vemo Pools
Type of pools using in Vemo ecosystem, IVO pool, staking pool

## Documentation
Deployment on Avax
| Contract Name | Address | Commit |
| --- | --- | --- |
| VoucherFactory | 0xbB740E17f3c177172CaAcCef2F472DB41b9b1d19 |  |
| Vemo Vesting Factory | 0x296d2C371D4Be8A5368f5E541Bc62926051E92CC | |
| Vemo Vesting Factory Impl | 0xbF907b4ff56E6EF9E648B4831aBF526cF5494896 | |

-----------------------------------
Deployment on bnb mainnet 
| Contract Name | Address | Commit |
| --- | --- | --- |
| VoucherFactory | 0x9869524fd160fe3adDA6218883B6526c0977D3a5 |  |
| Vemo Vesting Factory | 0x29f118a2Eb3c7754847a104ABeDF7776Ee5D4C80 |  |
| Vemo Vesting Factory Impl | 0x79CC5d5Fb0E876C9A81FC5b47B2E978D0Bb33c94 |  |

-------------------------------------------------------
avax testnet
| Contract Name | Address |
| --- | --- |
| Voucher Factory Proxy | 0x65B903D7903d277bE600B8524a759aBEa3CC7e1A |
| VoucherFactory Imp | 0x8b8950E6efb667895B60827c6c121358A02B77FD |
| Vemo Vesting Factory | 0x5ef5D34bcbCefdFa6442aD7672a4147A98C08698 |
| PoolImplManager | 0x2ADCeA67791c01a0264BF2A0d396a432acd18567 |
| PoolImplManager Proxy | 0x5c98e85e7FCC7998A5071092aafa4C2ae093338d |
| VemoFixedStakingPool | 0x94f79aFA223ba6E7647F3d5D3f67E85108f71dE5 |

-------------------------------------------------------
Deployment on bnb testnet
| Contract Name | Address |
| --- | --- |
| VoucherFactory | 0xD0901C6fE9FA1A8D56D2250Db272D65391117dfc |
| VoucherFactory Imp | 0xA2a89a309bb061a7ab4B21D4F99545701C57E994 |
| Vemo Vesting Factory | 0x38BE5E3f75C7D5F67558FC47c75c010783a28Cc9 |
| Vemo Vesting Factory Impl | 0x21b2E6c9805871743aeAD44c65bAb6cb9F0f1c60 |


## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>

forge clean && forge build && forge script script/VemoVestingPoolFactoryUpgrade.s.sol  --rpc-url https://avalanche-fuji-c-chain-rpc.publicnode.com  --verifier-url 'https://api.routescan.io/v2/network/mainnet/evm/43113/etherscan' --etherscan-api-key  "1VYRT81XHNBY8BC2X88N9ZF4XRBXUJDYKQ" --ffi --broadcast
```

### 

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
