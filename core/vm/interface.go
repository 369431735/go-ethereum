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

package vm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
)

// StateDB is an EVM database for full state querying.
// StateDB 是用于完整状态查询的EVM数据库。
type StateDB interface {
	// CreateAccount 创建一个新账户
	CreateAccount(common.Address)
	// CreateContract 创建一个新合约
	CreateContract(common.Address)

	// SubBalance 从账户余额中减去指定金额，并返回操作前的余额
	SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int
	// AddBalance 向账户余额中添加指定金额，并返回操作前的余额
	AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int
	// GetBalance 获取账户余额
	GetBalance(common.Address) *uint256.Int

	// GetNonce 获取账户的nonce值
	GetNonce(common.Address) uint64
	// SetNonce 设置账户的nonce值
	SetNonce(common.Address, uint64, tracing.NonceChangeReason)

	// GetCodeHash 获取账户代码的哈希值
	GetCodeHash(common.Address) common.Hash
	// GetCode 获取账户的代码
	GetCode(common.Address) []byte

	// SetCode sets the new code for the address, and returns the previous code, if any.
	// SetCode 为地址设置新代码，并返回之前的代码（如果有）
	SetCode(common.Address, []byte) []byte
	// GetCodeSize 获取账户代码的大小
	GetCodeSize(common.Address) int

	// AddRefund 添加退款金额
	AddRefund(uint64)
	// SubRefund 减少退款金额
	SubRefund(uint64)
	// GetRefund 获取退款金额
	GetRefund() uint64

	// GetCommittedState 获取已提交的状态
	GetCommittedState(common.Address, common.Hash) common.Hash
	// GetState 获取状态
	GetState(common.Address, common.Hash) common.Hash
	// SetState 设置状态，并返回之前的状态
	SetState(common.Address, common.Hash, common.Hash) common.Hash
	// GetStorageRoot 获取存储根
	GetStorageRoot(addr common.Address) common.Hash

	// GetTransientState 获取临时状态
	GetTransientState(addr common.Address, key common.Hash) common.Hash
	// SetTransientState 设置临时状态
	SetTransientState(addr common.Address, key, value common.Hash)

	// SelfDestruct 自毁合约，并返回合约余额
	SelfDestruct(common.Address) uint256.Int
	// HasSelfDestructed 检查合约是否已自毁
	HasSelfDestructed(common.Address) bool

	// SelfDestruct6780 is post-EIP6780 selfdestruct, which means that it's a
	// send-all-to-beneficiary, unless the contract was created in this same
	// transaction, in which case it will be destructed.
	// This method returns the prior balance, along with a boolean which is
	// true iff the object was indeed destructed.
	// SelfDestruct6780 是EIP6780后的自毁操作，这意味着它会将所有余额发送给受益人，
	// 除非合约是在同一交易中创建的，这种情况下它将被销毁。
	// 此方法返回先前的余额，以及一个布尔值，当且仅当对象确实被销毁时，该布尔值为true。
	SelfDestruct6780(common.Address) (uint256.Int, bool)

	// Exist reports whether the given account exists in state.
	// Notably this should also return true for self-destructed accounts.
	// Exist 报告给定账户是否存在于状态中。
	// 值得注意的是，对于自毁账户，这也应该返回true。
	Exist(common.Address) bool
	// Empty returns whether the given account is empty. Empty
	// is defined according to EIP161 (balance = nonce = code = 0).
	// Empty 返回给定账户是否为空。空
	// 根据EIP161定义（余额 = nonce = 代码 = 0）。
	Empty(common.Address) bool

	// AddressInAccessList 检查地址是否在访问列表中
	AddressInAccessList(addr common.Address) bool
	// SlotInAccessList 检查地址和槽位是否在访问列表中
	SlotInAccessList(addr common.Address, slot common.Hash) (addressOk bool, slotOk bool)
	// AddAddressToAccessList adds the given address to the access list. This operation is safe to perform
	// even if the feature/fork is not active yet
	// AddAddressToAccessList 将给定地址添加到访问列表。即使功能/分叉尚未激活，
	// 也可以安全地执行此操作。
	AddAddressToAccessList(addr common.Address)
	// AddSlotToAccessList adds the given (address,slot) to the access list. This operation is safe to perform
	// even if the feature/fork is not active yet
	// AddSlotToAccessList 将给定的（地址，槽位）添加到访问列表。即使功能/分叉尚未激活，
	// 也可以安全地执行此操作。
	AddSlotToAccessList(addr common.Address, slot common.Hash)

	// PointCache returns the point cache used in computations
	// PointCache 返回计算中使用的点缓存
	PointCache() *utils.PointCache

	// Prepare 为交易执行准备状态
	Prepare(rules params.Rules, sender, coinbase common.Address, dest *common.Address, precompiles []common.Address, txAccesses types.AccessList)

	// RevertToSnapshot 恢复到快照
	RevertToSnapshot(int)
	// Snapshot 创建当前状态的快照
	Snapshot() int

	// AddLog 添加日志
	AddLog(*types.Log)
	// AddPreimage 添加原像
	AddPreimage(common.Hash, []byte)

	// Witness 返回见证数据
	Witness() *stateless.Witness

	// AccessEvents 返回访问事件
	AccessEvents() *state.AccessEvents

	// Finalise must be invoked at the end of a transaction
	// Finalise 必须在交易结束时调用
	Finalise(bool)
}
