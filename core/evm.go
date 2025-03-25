// Copyright 2016 The go-ethereum Authors
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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// ChainContext supports retrieving headers and consensus parameters from the
// current blockchain to be used during transaction processing.
// ChainContext 支持从当前区块链中检索头部和共识参数，
// 用于交易处理过程中。
type ChainContext interface {
	// Engine retrieves the chain's consensus engine.
	// Engine 检索链的共识引擎。
	Engine() consensus.Engine

	// GetHeader returns the header corresponding to the hash/number argument pair.
	// GetHeader 返回与哈希/编号参数对应的区块头。
	GetHeader(common.Hash, uint64) *types.Header

	// Config returns the chain's configuration.
	// Config 返回链的配置。
	Config() *params.ChainConfig
}

// NewEVMBlockContext creates a new context for use in the EVM.
// NewEVMBlockContext 创建一个新的上下文，用于EVM中。
func NewEVMBlockContext(header *types.Header, chain ChainContext, author *common.Address) vm.BlockContext {
	var (
		beneficiary common.Address
		baseFee     *big.Int
		blobBaseFee *big.Int
		random      *common.Hash
	)

	// If we don't have an explicit author (i.e. not mining), extract from the header
	// 如果我们没有一个明确的作者（即不是挖矿），从头部提取
	if author == nil {
		beneficiary, _ = chain.Engine().Author(header) // Ignore error, we're past header validation // 忽略错误，我们已经通过了头部验证
	} else {
		beneficiary = *author
	}
	if header.BaseFee != nil {
		baseFee = new(big.Int).Set(header.BaseFee)
	}
	if header.ExcessBlobGas != nil {
		blobBaseFee = eip4844.CalcBlobFee(chain.Config(), header)
	}
	if header.Difficulty.Sign() == 0 {
		random = &header.MixDigest
	}
	return vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     GetHashFn(header, chain),
		Coinbase:    beneficiary,
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        header.Time,
		Difficulty:  new(big.Int).Set(header.Difficulty),
		BaseFee:     baseFee,
		BlobBaseFee: blobBaseFee,
		GasLimit:    header.GasLimit,
		Random:      random,
	}
}

// NewEVMTxContext creates a new transaction context for a single transaction.
// NewEVMTxContext 为单个交易创建一个新的交易上下文。
func NewEVMTxContext(msg *Message) vm.TxContext {
	ctx := vm.TxContext{
		Origin:     msg.From,
		GasPrice:   new(big.Int).Set(msg.GasPrice),
		BlobHashes: msg.BlobHashes,
	}
	if msg.BlobGasFeeCap != nil {
		ctx.BlobFeeCap = new(big.Int).Set(msg.BlobGasFeeCap)
	}
	return ctx
}

// GetHashFn returns a GetHashFunc which retrieves header hashes by number
// GetHashFn 返回一个GetHashFunc，通过编号检索区块头哈希
func GetHashFn(ref *types.Header, chain ChainContext) func(n uint64) common.Hash {
	// Cache will initially contain [refHash.parent],
	// Then fill up with [refHash.p, refHash.pp, refHash.ppp, ...]
	// 缓存最初将包含[refHash.parent]，
	// 然后填充[refHash.p, refHash.pp, refHash.ppp, ...]
	var cache []common.Hash

	return func(n uint64) common.Hash {
		if ref.Number.Uint64() <= n {
			// This situation can happen if we're doing tracing and using
			// block overrides.
			// 如果我们正在进行追踪并使用区块覆盖，这种情况可能会发生。
			return common.Hash{}
		}
		// If there's no hash cache yet, make one
		// 如果还没有哈希缓存，创建一个
		if len(cache) == 0 {
			cache = append(cache, ref.ParentHash)
		}
		if idx := ref.Number.Uint64() - n - 1; idx < uint64(len(cache)) {
			return cache[idx]
		}
		// No luck in the cache, but we can start iterating from the last element we already know
		// 缓存中没有找到，但我们可以从已知的最后一个元素开始迭代
		lastKnownHash := cache[len(cache)-1]
		lastKnownNumber := ref.Number.Uint64() - uint64(len(cache))

		for {
			header := chain.GetHeader(lastKnownHash, lastKnownNumber)
			if header == nil {
				break
			}
			cache = append(cache, header.ParentHash)
			lastKnownHash = header.ParentHash
			lastKnownNumber = header.Number.Uint64() - 1
			if n == lastKnownNumber {
				return lastKnownHash
			}
		}
		return common.Hash{}
	}
}

// CanTransfer checks whether there are enough funds in the address' account to make a transfer.
// This does not take the necessary gas in to account to make the transfer valid.
// CanTransfer 检查地址账户中是否有足够的资金进行转账。
// 这并不考虑使转账有效所需的必要gas。
func CanTransfer(db vm.StateDB, addr common.Address, amount *uint256.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

// Transfer subtracts amount from sender and adds amount to recipient using the given Db
// Transfer 使用给定的DB从发送者中减去金额并将金额添加到接收者
func Transfer(db vm.StateDB, sender, recipient common.Address, amount *uint256.Int) {
	db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
	db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
}
