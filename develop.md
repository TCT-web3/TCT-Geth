## Feature 1: add TCT hypothesis hash (hypo_hash)
First, I want to add `hypo_hash` into `Transaction` struct. The analysis is as follows:

In the new version, geth uses [`NewTx`](core/types/transaction.go#L62) to create a new transaction, the rest (such as `NewContractCreation`) have been deprecated.
```go
// NewTx creates a new transaction.
// core/types/transaction.go
func NewTx(inner TxData) *Transaction {
	tx := new(Transaction)
	tx.setDecoded(inner.copy(), 0)
	return tx
}
```
and this is the struct of [`Transaction`](core/types/transaction.go#L51):
```go
// Transaction is an Ethereum transaction.
// core/types/transaction.go
type Transaction struct {
	inner TxData    // Consensus contents of a transaction
	time  time.Time // Time first seen locally (spam avoidance)

	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}
```
entering the [`TxData`](core/types/transaction.go#L71) struct:
```go
// TxData is the underlying data of a transaction.
// This is implemented by DynamicFeeTx, LegacyTx, BlobTx and AccessListTx.
// core/types/transaction.go
type TxData interface {
	txType() byte // returns the type ID
	copy() TxData // creates a deep copy and initializes all fields

	chainID() *big.Int
	accessList() AccessList
	data() []byte
	gas() uint64
	gasPrice() *big.Int
	gasTipCap() *big.Int
	gasFeeCap() *big.Int
	value() *big.Int
	nonce() uint64
	to() *common.Address
	blobGas() uint64
	blobGasFeeCap() *big.Int
	blobHashes() []common.Hash

	rawSignatureValues() (v, r, s *big.Int)
	setSignatureValues(chainID, v, r, s *big.Int)

	// effectiveGasPrice computes the gas price paid by the transaction, given
	// the inclusion block baseFee.
	// Unlike other TxData methods, the returned *big.Int should be an independent
	// copy of the computed value, i.e. callers are allowed to mutate the result.
	// Method implementations can use 'dst' to store the result.
	effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int
}
```

Therefore, we have to add a member variable `hypo_hash` into four struct: `DynamicFeeTx, LegacyTx, BlobTx and AccessListTx`.
- [`AccessListTx`](core/types/tx_access_list.go#L48)
- [`BlobTx`](core/types/tx_blob.go#L32)
- [`LegacyTx`](core/types/tx_legacy.go#L27)
- [`DynamicFeeTx`](core/types/tx_dynamic_fee.go#L28)

Finally, simplistic `hypoHash` is added before a transaction is executed in evm which is in `applyTransaction` function and `Hypohash` is carried with transaction in [`transaction.go`](core/types/transaction.go#L51). More details can be found in [retrieveHypoHash](core/state_processor.go#L354). Future plan is that we might deploy a hypothesis service on IPFS/Infura and retireve from IPFS/Infura.

## Feature 2: get value of var in contract while interacting
Given the hypothesis file [here](https://github.com/TCT-web3/demo/tree/aug2023/web-demo/uploads), for example, in file `theorem_reentrancy.json`:
```json
{
	"entry-for-test":"MultiVulnToken::clear(address)",
	"entry-for-real":"0x88c436e4a975ef5e5788f97e86d80fde29ddd13d::0x3d0a4061",
	"def-vars": {
		"totalSupply": ["", "this.totalSupply", "uint256"]
	},
	"hypothesis": [
		"totalSupply < TwoE256 && tx_origin != _to"
	],
	"path-hash-for-test": "*",
	"path-hash-for-real": "the real hash (not implemented yet)",
	"numerical-type": "int"
}
```
sometimes, we have to access state variables (such as `this.totalSupply`) in the contract we are interacting with.

First, we could know the storage layout of contract given [this](https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html). When we know the offset and slot of the specific variable, we could use [`eth_getstorageat()`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getstorageat) to get the value of particular variable. More details about how to get state variable and mapping struct are [referred here](https://medium.com/@dariusdev/how-to-read-ethereum-contract-storage-44252c8af925).

since `applyTransaction()` is the entry point right before a tx is executed by evm, we implement feature 2 [here](core/state_processor.go#L114).

## Feature 3: path hash
To get the hash of evm code execution trace in geth client. We first get the hash of each opcode type and then concat them as the final path hash.

Specifically, we add `opTrace []byte // Code trace` in [`EVMInterpreter` struct](core/vm/interpreter.go#L43). and we set several `interpreter.opTrace = append(interpreter.opTrace, toAddr[:]...) //For TCT`in `instruction.go`.