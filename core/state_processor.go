// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"encoding/binary"
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	var (
		context = NewEVMBlockContext(header, p.bc, nil)
		vmenv   = vm.NewEVM(context, vm.TxContext{}, statedb, p.config, cfg)
		signer  = types.MakeSigner(p.config, header.Number, header.Time)
	)
	if beaconRoot := block.BeaconRoot(); beaconRoot != nil {
		ProcessBeaconBlockRoot(*beaconRoot, vmenv, statedb)
	}
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		msg, err := TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.SetTxContext(tx.Hash(), i)
		receipt, err := applyTransaction(msg, p.config, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Fail if Shanghai not enabled and len(withdrawals) is non-zero.
	withdrawals := block.Withdrawals()
	if len(withdrawals) > 0 && !p.config.IsShanghai(block.Number(), block.Time()) {
		return nil, nil, 0, errors.New("withdrawals before shanghai")
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), withdrawals)

	return receipts, allLogs, *usedGas, nil
}

func applyTransaction(msg *Message, config *params.ChainConfig, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (*types.Receipt, error) {
	var start_time, end_time time.Time
	if msg.To != nil {
		log.Warn("msg.Data=", hex.EncodeToString(msg.Data))
		function_selector := binary.BigEndian.Uint32(msg.Data[0:4])
		if function_selector == transferProxy_selector {
			checkHypo_transferProxy(msg, statedb)
		} else if function_selector == swapExactTokensForTokens_selector {
			checkHypo_swapExactTokensForTokens(msg, statedb)
		}
	}

	// TCT: get hypothesis given hypoHash
	// example like this: hypoHash := common.Hash{0x1}
	hypoHash := tx.HypoHash // transaction carries the hash
	hypothesis, err := retrieveHypoHash(hypoHash)
	if err != nil {
		log.Warn("The hypothesis does not find given ", hypoHash)
	}
	fmt.Println("hypothesis is ", hypothesis)

	start_time = time.Now()
	log.Warn(fmt.Sprintf("start_time=%d", start_time.UnixNano()))

	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	receipt.BlobGasUsed = uint64(len(tx.BlobHashes()) * params.BlobTxBlobGasPerBlob)
	receipt.BlobGasPrice = tx.BlobGasFeeCap()

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())

	// TCT: path hash
	if msg.To != nil {
		end_time = time.Now()
		var pathHash common.Hash
		time1 := time.Now()
		for i := 0; i < 1000000; i++ {
			pathHash = evm.Interpreter().ComputePathHash()
		}
		log.Warn(fmt.Sprintf("pathHash*1000000=%d", time.Now().UnixNano()-time1.UnixNano()))
		log.Warn("pathHash=", common.BytesToHash(pathHash[:]).Hex())
		//tx_apply_time := time.Since(checking_end_time).Nanoseconds()
		total_time := end_time.UnixNano() - start_time.UnixNano()
		log.Warn(fmt.Sprintf("end_time=%d", end_time.UnixNano()))
		log.Warn(fmt.Sprintf("total_time=%d", total_time))
		//log.Warn(fmt.Sprintf("total_time=%d  tx_apply_time=%d foo=%d", total_time, tx_apply_time, 1))
	}
	return receipt, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{BlobHashes: tx.BlobHashes()}, statedb, config, cfg)
	return applyTransaction(msg, config, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv)
}

// ProcessBeaconBlockRoot applies the EIP-4788 system call to the beacon block root
// contract. This method is exported to be used in tests.
func ProcessBeaconBlockRoot(beaconRoot common.Hash, vmenv *vm.EVM, statedb *state.StateDB) {
	// If EIP-4788 is enabled, we need to invoke the beaconroot storage contract with
	// the new root
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  30_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &params.BeaconRootsStorageAddress,
		Data:      beaconRoot[:],
	}
	vmenv.Reset(NewEVMTxContext(msg), statedb)
	statedb.AddAddressToAccessList(params.BeaconRootsStorageAddress)
	_, _, _ = vmenv.Call(vm.AccountRef(msg.From), *msg.To, msg.Data, 30_000_000, common.Big0)
	statedb.Finalise(true)
}

/*  TCT: get value of particular variable with interacting contract */
var transferProxy_selector = binary.BigEndian.Uint32([]byte{0xcf, 0x05, 0x3d, 0x9d})            // 0xcf053d9d
var swapExactTokensForTokens_selector = binary.BigEndian.Uint32([]byte{0x47, 0x2b, 0x43, 0xf3}) // 0x472b43f3
var TwoE255 = new(big.Int).Lsh(common.Big1, 255)

func checkHypo_transferProxy(msg *Message, statedb *state.StateDB) {
	var satisfied bool
	var start_time time.Time
	var arg_value, arg_fee, this_totalSupply common.Hash
	//Hypothesis: "0 <= _value && _value < TwoE255 && 0<= _fee && _fee < TwoE255 && this.totalSupply < TwoE255"
	slot := common.BytesToHash([]byte{0x01})
	this_totalSupply = statedb.GetState(*msg.To, slot)
	start_time = time.Now()
	for i := 0; i < 1000000; i++ {
		arg_value = common.BytesToHash(msg.Data[4+32*2 : 4+32*3])
		_value := new(big.Int).SetBytes(arg_value[:])
		arg_fee = common.BytesToHash(msg.Data[4+32*3 : 4+32*4])
		_fee := new(big.Int).SetBytes(arg_fee[:])
		this_totalSupply = statedb.GetState(*msg.To, slot)
		_this_totalSupply := new(big.Int).SetBytes(this_totalSupply[:])
		satisfied = _value.Cmp(TwoE255) < 0 && _fee.Cmp(TwoE255) < 0 && _this_totalSupply.Cmp(TwoE255) < 0
	}
	checking_end_time := time.Now()
	log.Warn(fmt.Sprintf("checking_time*1000000=%d satisfied=%v", checking_end_time.UnixNano()-start_time.UnixNano(), satisfied))
	log.Warn("_value=", arg_value.Hex())
	log.Warn("_fee=", arg_fee.Hex())
	log.Warn("this.totalSupply=", this_totalSupply.Hex())
}

func checkHypo_swapExactTokensForTokens(msg *Message, statedb *state.StateDB) {
	var satisfied bool
	var start_time time.Time
	// "to != pair", "tx_origin != pair", "pair.reserve0 == tokenB.balanceOf[pair]", "pair.reserve1 == tokenA.balanceOf[pair]",
	// "tokenB.totalSupply < TwoE255", "tokenA.totalSupply < TwoE255", "pair.token0 == tokenB", "pair.token1 == tokenA"
	slot_of_getPair := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	slot_of_balanceOf := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	arg_tokenA := msg.Data[0xa4:0xc4]
	arg_tokenB := msg.Data[0xc4:0xe4]
	slot := common.BytesToHash([]byte{0x00}) // slot of _factory
	this_factory := statedb.GetState(*msg.To, slot)
	_this_factory := new(big.Int).SetBytes(this_factory[:])
	slot = crypto.Keccak256Hash(arg_tokenA, slot_of_getPair)
	slot = crypto.Keccak256Hash(arg_tokenB, slot[:])
	pair := statedb.GetState(common.BytesToAddress(_this_factory.Bytes()), slot)
	tx_origin := new(big.Int).SetBytes(msg.From[:])
	_to := new(big.Int).SetBytes(msg.Data[0x64:0x84][:])
	slot = common.BytesToHash([]byte{0x06}) // slot of token0
	pair_token0 := statedb.GetState(common.BytesToAddress(pair.Bytes()), slot)
	slot = common.BytesToHash([]byte{0x07}) // slot of token1
	pair_token1 := statedb.GetState(common.BytesToAddress(pair.Bytes()), slot)
	slot = common.BytesToHash([]byte{0x08}) // slot of reserve0
	pair_reserve0 := statedb.GetState(common.BytesToAddress(pair.Bytes()), slot)
	slot = common.BytesToHash([]byte{0x09}) // slot of reserve1
	pair_reserve1 := statedb.GetState(common.BytesToAddress(pair.Bytes()), slot)
	slot = crypto.Keccak256Hash(pair[:], slot_of_balanceOf)
	tokenA_bal_pair := statedb.GetState(common.BytesToAddress(arg_tokenA), slot)
	tokenB_bal_pair := statedb.GetState(common.BytesToAddress(arg_tokenB), slot)
	slot = common.BytesToHash([]byte{0x00}) // slot of totalSupply
	tokenA_totalSupply := statedb.GetState(common.BytesToAddress(arg_tokenA), slot)
	tokenB_totalSupply := statedb.GetState(common.BytesToAddress(arg_tokenB), slot)

	start_time = time.Now()
	for i := 0; i < 1000000; i++ {
		arg_tokenA := msg.Data[0xa4:0xc4]
		arg_tokenB := msg.Data[0xc4:0xe4]
		slot := common.BytesToHash([]byte{0x00}) // slot of _factory
		this_factory := statedb.GetState(*msg.To, slot)
		_this_factory := new(big.Int).SetBytes(this_factory[:])
		slot = crypto.Keccak256Hash(arg_tokenA, slot_of_getPair)
		slot = crypto.Keccak256Hash(arg_tokenB, slot[:])
		pair := statedb.GetState(common.BytesToAddress(_this_factory.Bytes()), slot)
		tx_origin = new(big.Int).SetBytes(msg.From[:])
		_to = new(big.Int).SetBytes(msg.Data[0x64:0x84][:])
		slot = common.BytesToHash([]byte{0x06}) // slot of token0
		pair_token0 = statedb.GetState(common.BytesToAddress(pair.Bytes()), slot)
		slot = common.BytesToHash([]byte{0x07}) // slot of token1
		pair_token1 = statedb.GetState(common.BytesToAddress(pair.Bytes()), slot)
		slot = common.BytesToHash([]byte{0x08}) // slot of reserve0
		pair_reserve0 = statedb.GetState(common.BytesToAddress(pair.Bytes()), slot)
		slot = common.BytesToHash([]byte{0x09}) // slot of reserve1
		pair_reserve1 = statedb.GetState(common.BytesToAddress(pair.Bytes()), slot)
		slot = crypto.Keccak256Hash(pair[:], slot_of_balanceOf)
		tokenA_bal_pair = statedb.GetState(common.BytesToAddress(arg_tokenA), slot)
		tokenB_bal_pair = statedb.GetState(common.BytesToAddress(arg_tokenB), slot)
		slot = common.BytesToHash([]byte{0x00}) // slot of totalSupply
		tokenA_totalSupply = statedb.GetState(common.BytesToAddress(arg_tokenA), slot)
		tokenB_totalSupply = statedb.GetState(common.BytesToAddress(arg_tokenB), slot)

		bigIntPair := new(big.Int).SetBytes(pair[:])
		bigInt_tokenA_totalSupply := new(big.Int).SetBytes(tokenA_totalSupply[:])
		bigInt_tokenB_totalSupply := new(big.Int).SetBytes(tokenB_totalSupply[:])
		satisfied = _to.Cmp(bigIntPair) != 0 && tx_origin.Cmp(bigIntPair) != 0 &&
			pair_reserve0.Cmp(tokenB_bal_pair) == 0 && pair_reserve1.Cmp(tokenA_bal_pair) == 0 &&
			bigInt_tokenA_totalSupply.Cmp(TwoE255) < 0 && bigInt_tokenB_totalSupply.Cmp(TwoE255) < 0 &&
			pair_token0.Cmp(common.BytesToHash(arg_tokenB[:])) == 0 && pair_token1.Cmp(common.BytesToHash(arg_tokenA[:])) == 0
	}
	checking_end_time := time.Now()
	log.Warn(fmt.Sprintf("checking_time*1000000=%d satisfied=%v", checking_end_time.UnixNano()-start_time.UnixNano(), satisfied))
	log.Warn("tx_origin=", common.BytesToHash(tx_origin.Bytes()).Hex())
	log.Warn("_to=", common.BytesToHash(_to.Bytes()).Hex())
	log.Warn("pair_token0=", common.BytesToHash(pair_token0[:]).Hex())
	log.Warn("pair_token1=", common.BytesToHash(pair_token1[:]).Hex())
	log.Warn("pair_reserve0=", common.BytesToHash(pair_reserve0[:]).Hex())
	log.Warn("pair_reserve1=", common.BytesToHash(pair_reserve1[:]).Hex())
	log.Warn("tokenA.balanceOf[pair]=", common.BytesToHash(tokenA_bal_pair[:]).Hex())
	log.Warn("tokenB.balanceOf[pair]=", common.BytesToHash(tokenB_bal_pair[:]).Hex())
	log.Warn(fmt.Sprintf("tokenA.totalSupply=%d  tokenB.totalSupply=%d", tokenA_totalSupply, tokenB_totalSupply))
	log.Warn("this_factory=", this_factory.Hex())
	log.Warn("pair=", common.BytesToHash(pair[:]).Hex())
	log.Warn(fmt.Sprintf("satisfied=%v", satisfied))
}

func retrieveHypoHash(hypoHash common.Hash) ([]byte, error) {
	// TODO: might use IPFS to get the hypothesis given hash
	// set a temporary hash set here
	hypoHashset := map[common.Hash][]byte{
		common.Hash{0x1}: []byte(`tokenA != tokenB,
								tx_origin != pair,
								tokenA.balanceOf[pair] > Zero,
								tokenB.balanceOf[pair] > Zero,
								pair.totalSupply > Zero,
								tokenA.totalSupply < TwoE255,
								tokenB.totalSupply < TwoE255,
								pair.reserve0 == tokenB.balanceOf[pair],
								pair.reserve1 == tokenA.balanceOf[pair],
								pair.token0 == tokenB,
								pair.token1 == tokenA`), // theorem_addLiquidity.json
		common.Hash{0x2}: []byte(`Zero <= _value,
								_value < TwoE255,
								Zero <= _fee,
								_fee < TwoE255,
								totalSupply < TwoE255`), // theorem_integerOverflow.json
	}

	// Retrieve the value from the map
	value, exists := hypoHashset[hypoHash]
	if !exists {
		// If the value does not exist, return an error
		log.Error("Hypothesis not found for hash %x", hypoHash)
		return nil, fmt.Errorf("Hypothesis not found for hash %x", hypoHash)
	}

	// If the value exists, return it
	return value, nil
}
