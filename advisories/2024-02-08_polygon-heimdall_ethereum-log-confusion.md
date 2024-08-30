# Polygon Heimdall - Ethereum Log Confusion

## Introduction

In this blog post, we describe a vulnerability in Heimdall, the validator software of the [Polygon Proof-of-Stake (PoS)](https://polygon.technology/polygon-pos) blockchain. This flaw, if exploited, could have allowed a rogue or compromised validator to take over the Heimdall consensus layer and inject fraudulent events into the StakeSync mechanism, a critical component of the Polygon PoS bridge, putting over $2B of crypto assets in the bridge at risk.   

We privately disclosed the vulnerability through the [Polygon Immunefi Bug Bounty](https://immunefi.com/bounty/polygon/) program and the issue has been patched. No malicious exploitation took place and no user funds were lost.

## Polygon PoS and Heimdall

The Polygon PoS network is the most popular Ethereum sidechain averaging more than 3 million daily transactions and roughly $3B worth of crypto assets locked in its two Ethereum bridges, "PoS Bridge" and "Plasma".

The network relies on three different layers for its operation:

* Firstly, a set of smart contracts on the Ethereum mainnet for managing staking, checkpoints and validator rewards. 

* Secondly, the consensus layer, which is based on a Proof-of-Stake network of Heimdall validators, which monitor the Ethereum contract state, coordinate block producer selection and push new snapshots of the chain state known as checkpoints back to Ethereum. 

* Lastly, the execution layer, which uses Bor, a fork of geth and is responsible for producing new blocks.

As is often the case, the security vulnerability we want to highlight lies in the boundaries between these different layers. Specifically, the vulnerability resides in the interface between the Heimdall network and the Ethereum smart contracts.

The Heimdall consensus layer is a proof-of-stake network, based on a forked version of Cosmos and Tendermint, in which the voting power is dependent on the amount of MATIC stake owned or delegated to each validator.

In contrast to most other PoS chains, staking isn’t implemented natively but relies on a set of Ethereum contracts, which are responsible for managing stake, validator selection and reward distributions. 

The two relevant contracts for this blog post are:

* [StakeManager](https://github.com/maticnetwork/contracts/blob/main/contracts/staking/stakeManager/StakeManager.sol), which as its name implies is responsible for stake and validator management.
* [StakingInfo](https://github.com/maticnetwork/contracts/blob/f15e4be8712a74f353c6b1f44ed542f6c0c1708e/contracts/staking/StakingInfo.sol), a lightweight logging contract that emits the relevant log events when called by the manager contract.

If a relevant event, such as a new stake delegation, is emitted by the `StakingInfo` contract, the information has to be pushed to the Heimdall network to be processed:

First, the event will be picked up by a component called [bridge](https://github.com/maticnetwork/heimdall/blob/master/bridge/README.md), which listens for all relevant log events emitted on the Ethereum mainnet. Based on the event type, the bridge creates a Cosmos message describing the event and submits it to the Heimdall network. 

For example, a `StakeUpdate` event will be turned into a `MsgStakeUpdate` Heimdall message as shown below:

```solidity
// contracts/staking/StakingInfo.sol#L121
event StakeUpdate(
        uint256 indexed validatorId,
        uint256 indexed nonce,
        uint256 indexed newAmount
    );
```

```golang
// staking/types/msg.go#L127
// MsgStakeUpdate represents stake update
type MsgStakeUpdate struct {
	From        hmTypes.HeimdallAddress json:"from"
	ID          hmTypes.ValidatorID     json:"id"
	NewAmount   sdk.Int                 json:"amount"
	TxHash      hmTypes.HeimdallHash    json:"tx_hash"
	LogIndex    uint64                  json:"log_index"
	BlockNumber uint64                  json:"block_number"
	Nonce       uint64                  json:"nonce"
}
```

The `ID`, `NewAmount` and `Nonce` fields of the `MsgStakeUpdate` struct correspond to the indexed event fields. Obviously, a rogue validator could just submit a fake `MsgStakeUpdate` to increase their own stake. To protect against this, Heimdall uses "side handlers" to verify that the event really was emitted.

## Side Handlers

An example of such a side handler is shown below:

```golang
// staking/side_handler.go#L150
// SideHandleMsgStakeUpdate handles stake update message
func SideHandleMsgStakeUpdate(ctx sdk.Context, msg types.MsgStakeUpdate, k Keeper, contractCaller helper.IContractCaller) (result abci.ResponseDeliverSideTx) {
	
	[...]
	// get main tx receipt
	receipt, err := contractCaller.GetConfirmedTxReceipt(msg.TxHash.EthHash(), params.MainchainTxConfirmations) ** A **
	if err != nil || receipt == nil {
		return hmCommon.ErrorSideTx(k.Codespace(), common.CodeErrDecodeEvent)
	}

	eventLog, err := contractCaller.DecodeValidatorStakeUpdateEvent(chainParams.StakingInfoAddress.EthAddress(), receipt, msg.LogIndex) ** B **
	if err != nil || eventLog == nil {
		k.Logger(ctx).Error("Error fetching log from txhash")
		return hmCommon.ErrorSideTx(k.Codespace(), common.CodeInvalidMsg)
	}

	if receipt.BlockNumber.Uint64() != msg.BlockNumber {
		[..]
		return hmCommon.ErrorSideTx(k.Codespace(), common.CodeInvalidMsg)
	}

	if eventLog.ValidatorId.Uint64() != msg.ID.Uint64() {
		[..]
		return hmCommon.ErrorSideTx(k.Codespace(), common.CodeInvalidMsg)
	}

	// check Amount
	if eventLog.NewAmount.Cmp(msg.NewAmount.BigInt()) != 0 {
		[..]
		return hmCommon.ErrorSideTx(k.Codespace(), common.CodeInvalidMsg)
	}

	// check nonce
	if eventLog.Nonce.Uint64() != msg.Nonce {
		[..]
		return hmCommon.ErrorSideTx(k.Codespace(), common.CodeInvalidMsg)
	}

	k.Logger(ctx).Debug("✅ Successfully validated External call for stake update msg")

	result.Result = abci.SideTxResultType_Yes

	return
}
```

`SideHandleMsgStakeUpdate` is the verification function for `StakeUpdate` events. The function uses the `TxHash` field of the incoming message to fetch the transaction receipt of the Ethereum transaction in (**A**)  and calls `DecodeValidatorStakeUpdateEvent` in (**B**) to parse the log at `LogIndex` as a `StakeUpdate` event. If this succeeds, all fields in the event are compared to the corresponding field in the incoming message and only if they are equal the function returns a success result. 

Off chain verification code like this can suffer from a number of issues. The two most common ones are equality checks that don’t verify all message fields and insecure parsing of Ethereum log messages. In this case, all event fields are correctly verified but let’s take a closer look at the event decoding performed by the line `contractCaller.DecodeValidatorStakeUpdateEvent(chainParams.StakingInfoAddress.EthAddress(), receipt, msg.LogIndex)`:

```golang
// helper/call.go#L618
// DecodeValidatorStakeUpdateEvent represents validator stake update event
func (c *ContractCaller) DecodeValidatorStakeUpdateEvent(contractAddress common.Address, receipt *ethTypes.Receipt, logIndex uint64) (*stakinginfo.StakinginfoStakeUpdate, error) {
	var (
		event = new(stakinginfo.StakinginfoStakeUpdate)
		found = false
	)

	for _, vLog := range receipt.Logs {
		if uint64(vLog.Index) == logIndex && bytes.Equal(vLog.Address.Bytes(), contractAddress.Bytes()) {
			found = true

			if err := UnpackLog(&c.StakingInfoABI, event, stakeUpdateEvent, vLog); err != nil { ** C ** 
				return nil, err
			}

			break
		}
	}

	if !found {
		return nil, errors.New("event not found")
	}

	return event, nil
}
```

`DecodeValidatorStakeUpdateEvent` performs a simple loop over all logs in the transaction receipt and searches for a log with the correct index, while ensuring that it was emitted by the `StakingInfo` contract. The log is then passed to the `UnpackLog` function in (**C**).

## UnpackLog Typeconfusion

```golang
// helper/unpack.go#L22
func UnpackLog(abiObject *abi.ABI, out interface{}, event string, log *types.Log) error {
	if len(log.Data) > 0 {
		if err := abiObject.UnpackIntoInterface(out, event, log.Data); err != nil {
			return err
		}
	}

	var indexed abi.Arguments

	for _, arg := range abiObject.Events[event].Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}

	return parseTopics(out, indexed, log.Topics[1:])
}
```

`UnpackLog` is responsible for converting an Ethereum log event into a Golang struct based on the ABI and event name arguments.

However, looking closer reveals a critical vulnerability: There is no check that the parsed log event is of the right type. Event types in Ethereum can be uniquely identified by checking the first topic in the log entry (`log.Topic[0]`) and for all `StakeUpdate` events this topic should be `0x35af9eea1f0e7b300b0a14fae90139a072470e44daa3f14b5069bebbc1265bda` (the keccak hash of the event definition). 

However the first topic is never verified and instead `UnpackLog` will happily parse any event as long as it has the same number of indexed arguments as the expected one. A malicious validator could have abused this vulnerability by tricking Heimdall into misparsing a real confirmed log event as a different type - a type confusion bug.

While our analysis only looked at the `StakeUpdate` case, all other events are also parsed by `UnpackLog` and can be targeted in a similar way. However, `StakeUpdate` is the most interesting attack vector as fake update events can be used to arbitrarily increase the stake of an attacker. This makes it possible to take over Heimdall's consensus layer.

## SignerChange vs StakeUpdate

```solidity
//contracts/staking/StakingInfo.sol#L121 
event StakeUpdate(
        uint256 indexed validatorId,
        uint256 indexed nonce,
        uint256 indexed newAmount
    );
```

To exploit this issue we need to find an event type emitted by the `StakingInfo.sol` contract that can be confused with a `StakeUpdate` event and that allows us to control the `validatorId`, `nonce` and `newAmount` fields. 

While there are a number of events that have the right number of indexed arguments, only one gives an attacker the necessary control to increase their own stake: The `SignerChange` event.

```solidity
// contracts/staking/StakingInfo.sol#L87    
/// @dev Emitted when the validator public key is updated in 'updateSigner()'.
    /// @param validatorId unique integer to identify a validator.
    /// @param nonce to synchronize the events in heimdal.
    /// @param oldSigner old address of the validator.
    /// @param newSigner new address of the validator.
    /// @param signerPubkey public key of the validator.
    event SignerChange(
        uint256 indexed validatorId,
        uint256 nonce,
        address indexed oldSigner,
        address indexed newSigner,
        bytes signerPubkey
    );
```

As the comment explains, this event is emitted whenever a validator changes their public key using the `updateSigner` method in `StakeManager.sol`. Looking at the indexed arguments, we can see that `validatorId` matches in both events. `oldSigner` corresponds to the `nonce` field in the `StakeUpdate` event and `newSigner` corresponds to `newAmount`. As a random address interpreted as `newAmount` will lead to an extremely high increase in validator stake, the only field an attacker would need to be concerned with is the `oldSigner` or `nonce` field.

`oldSigner` corresponds to the address used by the Heimdall validator before the call to `updateSigner`. This means that it has to be a valid Ethereum address and the validator needs to be in possession of its private key. `nonce` on the other hand is a simple per validator count, that is strictly increased by 1 for each event triggered for a validator such as delegations, restakes or signer changes. Coming up with an `oldSigner` address that also equals the expected nonce at the time of the event emissions seems impossible at first glance.

However, it turns out to be a feasible attack due to an integer truncation in Heimdall. If we go back and look at `nonce` check in the `SideHandleMsgStakeUpdate` side handler, we can see that Heimdall truncates the uint256 `nonce` field of the event to a uint64 before comparing it with the `msg.Nonce`. `msg.Nonce` is later validated to be equal to the current validator nonce.

```golang
// check nonce
if eventLog.Nonce.Uint64() != msg.Nonce {
	[..]
	return hmCommon.ErrorSideTx(k.Codespace(), common.CodeInvalidMsg)
}
```

This means that as long as an attacker can generate a valid Ethereum pubkey whose last 8 bytes are a valid nonce they could exploit this vulnerability.

The truncated `oldSigner` address and the validator nonce need to match exactly for the attack to work, but an attacker has a direct influence over the nonce of their own validator, by triggering events such as `StakeUpdates` (for example through delegation). Looking at the existing set of validators on mainnet we can see that nonces around ~5000 are not unusual, but most validators are below that so to simplify our calculations we assume that an attacker can increment their nonce to around 0xFFF (4095) before executing the attack. This means the `oldSigner` address has to have the following format: `0x........0000000000000XXX` where X can be arbitrary. Generating an Ethereum address with 13 zero digits at the end is difficult, but turns out to be surprisingly feasible.

One different but related example in the wild are MEV bots, which often use addresses with leading zeroes to reduce gas costs. Interestingly, the MEV bot [06f65](https://etherscan.io/address/0x000000000000006f6502b7f2bbac8c30a3f67e9a) uses an address that starts with 14 zero digits, which means it was 16 times as difficult to generate as an address that fits our target set.

An attacker will need to generate around 2**51 addresses for a 50% chance of a hit. With ETH address generation speed being mostly bounded by keccak256 performance, tools like [Profanity2](https://github.com/1inch/profanity2) can generate around 200MH/s on a single personal computer. This would mean an average of around 21 years of computation time before an attacker will find a working address. This is obviously infeasible.  However, an attacker isn’t restricted to their own hardware and modern GPUs optimised for AI workloads have an extreme amount of computing power.

Extrapolating based on publicly available benchmark numbers (e.g 125 BH/s for SHA256 on an EC2 P5 instance with 8 Nvidia H100 GPUs), the cost of creating a valid Ethereum address that matches our requirements lies between 50k$ and 100k$. While this puts the attack out of the reach of most hobbyists, it’s obviously not a big issue for well resourced attackers.

With all these requirements met, an attack by a rogue or compromised validator would look like the following:

1. Bruteforce an Ethereum address with a suffix of `0000000000000XXX`. The last three digits have to be larger than the validator's current nonce.
2. Change the signing key of your validator to this address by invoking the `updateSigner` method and wait for the cooldown period (roughly an hour) to end.
3. Increase the nonce of your validator until `nonce+1 == XXX`, by changing your stake either directly or through delegations.
4. Perform a signer change to a new address under your control and use the generated event to process a fake `MsgStakeUpdate`.


Once the fake `MsgStakeUpdate` is accepted, the [PostHandleMsgStakeUpdate](https://github.com/maticnetwork/heimdall/blob/249aa798c2f23c533d2421f2101127c11684c76e/staking/side_handler.go#L412C6-L412C30) method would have been triggered to calculate the validator's new voting power. Due to the large amount of faked stake added when the new signer address is interpreted as a newly staked MATIC amount, the malicious validator will earn a super majority of Heimdall stake, taking over the Heimdall consensus. 

Interestingly, this does not directly lead to a loss of funds or a full Polygon PoS takeover: As the smart contracts on Ethereum mainnet still track the true voting power of the malicious validator, a validator can't just push malicious checkpoints back to L1 to withdraw funds locked in the Polygon PoS bridges. 

Instead, the attacker can use their inflated voting power to manipulate another side handler mechanism: The state-sync module.

## Attacking State-Sync

[State-Sync](https://github.com/maticnetwork/heimdall/tree/master/clerk) is a mechanism used by Polygon PoS to push events from the Ethereum L1 to the Polygon network. It’s implemented on top of a StateSender contract deployed on Ethereum and a `StateReceiver` contract deployed on the Bor execution layer. State-Sync is implemented on top of the side handler mechanism described above: Every time a message is sent through the `StateSender` contract, a log event is emitted. This event will get picked up by the Heimdall bridge module, triggering the creation and processing of a [MsgEventRecord](https://github.com/maticnetwork/heimdall/blob/249aa798c2f23c533d2421f2101127c11684c76e/clerk/types/msg.go#L12C1-L22C2) message. If the message is validated and confirmed by its corresponding [side handler](https://github.com/maticnetwork/heimdall/blob/249aa798c2f23c533d2421f2101127c11684c76e/clerk/side_handler.go#L47C6-L47C30), an Event record is stored on the Heimdall chain. These events are later picked up by Bor nodes, which will invoke the `StateReceiver` contract's [commitState](https://github.com/maticnetwork/genesis-contracts/blob/96a19dd75502ee75d59469e5d40257aa5e33371f/contracts/StateReceiver.sol#L15C17-L15C17) method to push the state update to the target contract.

State-Sync is an interesting attack surface, because it is used to process all incoming transfers for the Polygon PoS bridge and Polygon Plasma bridge. This means that an attacker with the ability to inject fake state sync events, can mint arbitrary amounts of tokens on Polygon PoS. By withdrawing these fake deposits back to L1, all tokens locked in the Polygon PoS bridge could be stolen. While the State-Sync side handler uses the same vulnerable `UnpackLog` function as the Staking module, it can’t be directly attacked through this issue. There are no interesting event types emitted by the `StateSender` contract that would lead to an exploitable type confusion. 

However, an attacker can use their inflated voting power on Heimdall to achieve the same result due to way the consensus mechanism for side handlers works. When we talked about side handlers earlier in this post, we claimed that messages are only processed if the side handler validation method executes successfully. This was a bit of a simplification and the real process is slightly more complex: When a new message that requires a side handler is sent to Heimdall, each validator runs the validation method (`SideHandleMsgEventRecord` in the case of State Sync). If it succeeds, the validator votes to process the actual message in the next block. At the start of each block, the [BeginSideBlocker](https://github.com/maticnetwork/heimdall/blob/249aa798c2f23c533d2421f2101127c11684c76e/app/side_tx_processor.go#L41) function is executed. It iterates through all open side transactions and counts all positive validator votes:

```golang
for _, sigObj := range sideTxResult.Sigs {
		// get validator by sig address
		if i := getValidatorIndexByAddress(sigObj.Address, validators); i != -1 {
			// check if validator already voted on tx
			if _, ok := usedValidator[i]; !ok {
				signedPower[sigObj.Result] = signedPower[sigObj.Result] + validators[i].Power
				usedValidator[i] = true
			}
		}
	}

	var result sdk.Result

	// check vote majority
	if signedPower[abci.SideTxResultType_Yes] >= (totalPower*2/3 + 1) {
		// approved
		logger.Debug("[sidechannel] Approved side-tx", "txHash", hex.EncodeToString(tx.Hash()))

		// execute tx with yes
		result = app.runTx(ctx, tx, abci.SideTxResultType_Yes)
```

If more than 2/3 of voting power confirmed a side transaction, the message is processed by all validators and included in the Heimdall consensus. This is a useful feature, because it makes consensus less brittle in the case of an RPC outage: Even if a validator can't confirm an event on its own when their Ethereum RPC is down, they will still be able to participate in Heimdall consensus as long as a super majority of validators agree on the validity of the event. In our case, the greater reliability comes at a cost: By using the inflated voting power of the rogue validator, an attacker can approve completely fake side messages regardless of the Ethereum L1 state.

This means, they can forge arbitrary deposit events to the Polygon PoS chain and trick other validators into accepting them, leading to an infinite mint on the Polygon PoS network. As withdrawals for the Polygon PoS bridge on Ethereum are not limited or delayed, bridging those funds back to Ethereum would potentially allow a theft of all tokens locked in the Polygon PoS bridge contract (roughly $2B at the time of our report).

## Conclusion

This bug is another example of a critical vulnerability in a cross-chain integration, demonstrating that these features can carry risk. While the Polygon PoS ecosystem has a mature security program and a highly successful bug bounty program, this issue existed since the earliest version of Heimdall and was not discovered for 5 years. 

As an industry we need to come to terms with the fact that vulnerabilities like this will continue to exist and that even a software system that was launched with a well resourced security program won’t have a 100% success rate. However, a focus on defense-in-depth capabilities could have severely limited the impact of an attack:

* **Time locks and withdrawal delays**: Polygon PoS supports two native bridges, but only “Plasma” uses a withdrawal delay mechanism. If both bridges would have limited withdrawals for a certain amount of time, an attacker’s ability to steal tokens locked on Ethereum would have been significantly reduced. Similarly, Heimdall could be hardened further by introducing time delays for changes in voting power, giving the operators the chance to detect and block attacks before they can do any damage.

* **Transfer limits**: While unrestricted flow of funds is great from a usability perspective, it exposes protocols and their users to unbounded risk. Adding transfer limits that are high enough to allow for normal usage, but delay malicious attacks can turn an existential billion dollar hack into a recoverable incident. 

* **Invariant checking**: Large parts of the presented attack chain depend on the fact that implied invariants aren’t enforced through the codebase. Silent truncation on a nonce value allowed the malicious type confusion. Staking amounts are not compared to a sane upper limit and there is no enforcement that a single validator should never hold a super majority of voting power. Sprinkling defensive checks and assertions through the core parts of your code base can turn high impact vulnerabilities into simple Denial-of-Service issues and is essentially free for off-chain code that does not need to optimise for gas costs.

We would like to thank everyone involved for their professionalism in handling this issue. A patch was released to fix the underlying Type Confusion issue and the contributors spent a lot of time and effort assessing the security implications of the issues mentioned above. Please take a look at [their writeup](https://forum.polygon.technology/t/heimdall-security-bug-fix-review/13537) on this finding in the Polygon forum for further information.