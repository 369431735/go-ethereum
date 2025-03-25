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

// Package ethereum defines interfaces for interacting with Ethereum.
// 包ethereum定义了与以太坊交互的接口。
package ethereum

import (
	"context"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// NotFound is returned by API methods if the requested item does not exist.
// NotFound 在API方法中当请求的项目不存在时返回。
var NotFound = errors.New("not found")

// Subscription represents an event subscription where events are
// delivered on a data channel.
// Subscription 表示事件订阅，其中事件通过数据通道传递。
type Subscription interface {
	// Unsubscribe cancels the sending of events to the data channel
	// and closes the error channel.
	// Unsubscribe 取消向数据通道发送事件并关闭错误通道。
	Unsubscribe()
	// Err returns the subscription error channel. The error channel receives
	// a value if there is an issue with the subscription (e.g. the network connection
	// delivering the events has been closed). Only one value will ever be sent.
	// The error channel is closed by Unsubscribe.
	// Err 返回订阅错误通道。如果订阅出现问题（例如，传递事件的网络连接已关闭），
	// 错误通道会接收一个值。该通道只会发送一个值。错误通道由Unsubscribe关闭。
	Err() <-chan error
}

// ChainReader provides access to the blockchain. The methods in this interface access raw
// data from either the canonical chain (when requesting by block number) or any
// blockchain fork that was previously downloaded and processed by the node. The block
// number argument can be nil to select the latest canonical block. Reading block headers
// should be preferred over full blocks whenever possible.
//
// The returned error is NotFound if the requested item does not exist.
// ChainReader 提供对区块链的访问。此接口中的方法可以访问来自规范链（通过区块号请求时）
// 或节点先前下载并处理的任何区块链分叉的原始数据。区块号参数可以为nil以选择最新的规范区块。
// 在可能的情况下，应优先读取区块头而不是完整区块。
//
// 如果请求的项目不存在，则返回错误NotFound。
type ChainReader interface {
	// BlockByHash 通过哈希获取区块
	BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error)
	// BlockByNumber 通过区块号获取区块
	BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error)
	// HeaderByHash 通过哈希获取区块头
	HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error)
	// HeaderByNumber 通过区块号获取区块头
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	// TransactionCount 获取指定区块中的交易数量
	TransactionCount(ctx context.Context, blockHash common.Hash) (uint, error)
	// TransactionInBlock 获取指定区块中的指定索引的交易
	TransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, error)

	// This method subscribes to notifications about changes of the head block of
	// the canonical chain.
	// 此方法订阅有关规范链头区块变化的通知。
	SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (Subscription, error)
}

// TransactionReader provides access to past transactions and their receipts.
// Implementations may impose arbitrary restrictions on the transactions and receipts that
// can be retrieved. Historic transactions may not be available.
//
// Avoid relying on this interface if possible. Contract logs (through the LogFilterer
// interface) are more reliable and usually safer in the presence of chain
// reorganisations.
//
// The returned error is NotFound if the requested item does not exist.
// TransactionReader 提供对过去交易及其收据的访问。
// 实现可能对可检索的交易和收据施加任意限制。历史交易可能不可用。
//
// 如果可能，避免依赖此接口。合约日志（通过LogFilterer接口）在链重组存在时更可靠且通常更安全。
//
// 如果请求的项目不存在，则返回错误NotFound。
type TransactionReader interface {
	// TransactionByHash checks the pool of pending transactions in addition to the
	// blockchain. The isPending return value indicates whether the transaction has been
	// mined yet. Note that the transaction may not be part of the canonical chain even if
	// it's not pending.
	// TransactionByHash 除了区块链外，还检查待处理交易池。
	// isPending返回值表示交易是否已被挖掘。请注意，即使交易不是待处理的，它也可能不是规范链的一部分。
	TransactionByHash(ctx context.Context, txHash common.Hash) (tx *types.Transaction, isPending bool, err error)
	// TransactionReceipt returns the receipt of a mined transaction. Note that the
	// transaction may not be included in the current canonical chain even if a receipt
	// exists.
	// TransactionReceipt 返回已挖掘交易的收据。请注意，即使存在收据，
	// 交易也可能不包含在当前规范链中。
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
}

// ChainStateReader wraps access to the state trie of the canonical blockchain. Note that
// implementations of the interface may be unable to return state values for old blocks.
// In many cases, using CallContract can be preferable to reading raw contract storage.
// ChainStateReader 包装对规范区块链状态树的访问。请注意，
// 接口的实现可能无法返回旧区块的状态值。
// 在许多情况下，使用CallContract比读取原始合约存储更可取。
type ChainStateReader interface {
	// BalanceAt 获取指定账户在指定区块的余额
	BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error)
	// StorageAt 获取指定账户在指定区块的存储数据
	StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error)
	// CodeAt 获取指定账户在指定区块的代码
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
	// NonceAt 获取指定账户在指定区块的nonce值
	NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error)
}

// SyncProgress gives progress indications when the node is synchronising with
// the Ethereum network.
// SyncProgress 在节点与以太坊网络同步时提供进度指示。
type SyncProgress struct {
	StartingBlock uint64 // Block number where sync began // 同步开始的区块号
	CurrentBlock  uint64 // Current block number where sync is at // 当前同步到的区块号
	HighestBlock  uint64 // Highest alleged block number in the chain // 链中最高声称的区块号

	// "fast sync" fields. These used to be sent by geth, but are no longer used
	// since version v1.10.
	// "快速同步"字段。这些曾经由geth发送，但自v1.10版本以来不再使用。
	PulledStates uint64 // Number of state trie entries already downloaded // 已下载的状态树条目数
	KnownStates  uint64 // Total number of state trie entries known about // 已知的状态树条目总数

	// "snap sync" fields.
	// "快照同步"字段。
	SyncedAccounts      uint64 // Number of accounts downloaded // 已下载的账户数
	SyncedAccountBytes  uint64 // Number of account trie bytes persisted to disk // 持久化到磁盘的账户树字节数
	SyncedBytecodes     uint64 // Number of bytecodes downloaded // 已下载的字节码数
	SyncedBytecodeBytes uint64 // Number of bytecode bytes downloaded // 已下载的字节码字节数
	SyncedStorage       uint64 // Number of storage slots downloaded // 已下载的存储槽数
	SyncedStorageBytes  uint64 // Number of storage trie bytes persisted to disk // 持久化到磁盘的存储树字节数

	HealedTrienodes     uint64 // Number of state trie nodes downloaded // 已下载的状态树节点数
	HealedTrienodeBytes uint64 // Number of state trie bytes persisted to disk // 持久化到磁盘的状态树字节数
	HealedBytecodes     uint64 // Number of bytecodes downloaded // 已下载的字节码数
	HealedBytecodeBytes uint64 // Number of bytecodes persisted to disk // 持久化到磁盘的字节码数

	HealingTrienodes uint64 // Number of state trie nodes pending // 待处理的状态树节点数
	HealingBytecode  uint64 // Number of bytecodes pending // 待处理的字节码数

	// "transaction indexing" fields
	// "交易索引"字段
	TxIndexFinishedBlocks  uint64 // Number of blocks whose transactions are already indexed // 已为其交易建立索引的区块数
	TxIndexRemainingBlocks uint64 // Number of blocks whose transactions are not indexed yet // 尚未为其交易建立索引的区块数
}

// Done returns the indicator if the initial sync is finished or not.
// Done 返回指示初始同步是否完成的指标。
func (prog SyncProgress) Done() bool {
	if prog.CurrentBlock < prog.HighestBlock {
		return false
	}
	return prog.TxIndexRemainingBlocks == 0
}

// ChainSyncReader wraps access to the node's current sync status. If there's no
// sync currently running, it returns nil.
// ChainSyncReader 包装对节点当前同步状态的访问。如果当前没有运行同步，则返回nil。
type ChainSyncReader interface {
	// SyncProgress 获取同步进度
	SyncProgress(ctx context.Context) (*SyncProgress, error)
}

// CallMsg contains parameters for contract calls.
// CallMsg 包含合约调用的参数。
type CallMsg struct {
	From      common.Address  // the sender of the 'transaction' // 交易的发送者
	To        *common.Address // the destination contract (nil for contract creation) // 目标合约（合约创建时为nil）
	Gas       uint64          // if 0, the call executes with near-infinite gas // 如果为0，调用将使用接近无限的gas
	GasPrice  *big.Int        // wei <-> gas exchange ratio // wei <-> gas 兑换比率
	GasFeeCap *big.Int        // EIP-1559 fee cap per gas. // EIP-1559 每单位gas的费用上限
	GasTipCap *big.Int        // EIP-1559 tip per gas. // EIP-1559 每单位gas的小费
	Value     *big.Int        // amount of wei sent along with the call // 随调用发送的wei数量
	Data      []byte          // input data, usually an ABI-encoded contract method invocation // 输入数据，通常是ABI编码的合约方法调用

	AccessList types.AccessList // EIP-2930 access list. // EIP-2930 访问列表

	// For BlobTxType
	// 用于BlobTxType
	BlobGasFeeCap *big.Int      // Blob gas fee cap // Blob gas费用上限
	BlobHashes    []common.Hash // Blob hashes // Blob哈希列表
}

// A ContractCaller provides contract calls, essentially transactions that are executed by
// the EVM but not mined into the blockchain. ContractCall is a low-level method to
// execute such calls. For applications which are structured around specific contracts,
// the abigen tool provides a nicer, properly typed way to perform calls.
// ContractCaller 提供合约调用，本质上是由EVM执行但不被挖掘到区块链中的交易。
// ContractCall是执行此类调用的低级方法。对于围绕特定合约构建的应用程序，
// abigen工具提供了一种更好的、类型正确的方式来执行调用。
type ContractCaller interface {
	// CallContract 调用合约
	CallContract(ctx context.Context, call CallMsg, blockNumber *big.Int) ([]byte, error)
}

// FilterQuery contains options for contract log filtering.
// FilterQuery 包含合约日志过滤的选项。
type FilterQuery struct {
	BlockHash *common.Hash     // used by eth_getLogs, return logs only from block with this hash // 由eth_getLogs使用，仅返回具有此哈希的区块中的日志
	FromBlock *big.Int         // beginning of the queried range, nil means genesis block // 查询范围的开始，nil表示创世区块
	ToBlock   *big.Int         // end of the range, nil means latest block // 范围的结束，nil表示最新区块
	Addresses []common.Address // restricts matches to events created by specific contracts // 将匹配限制为由特定合约创建的事件

	// The Topic list restricts matches to particular event topics. Each event has a list
	// of topics. Topics matches a prefix of that list. An empty element slice matches any
	// topic. Non-empty elements represent an alternative that matches any of the
	// contained topics.
	//
	// Examples:
	// {} or nil          matches any topic list
	// {{A}}              matches topic A in first position
	// {{}, {B}}          matches any topic in first position AND B in second position
	// {{A}, {B}}         matches topic A in first position AND B in second position
	// {{A, B}, {C, D}}   matches topic (A OR B) in first position AND (C OR D) in second position
	// Topic列表将匹配限制为特定的事件主题。每个事件都有一个主题列表。
	// Topics匹配该列表的前缀。空元素切片匹配任何主题。
	// 非空元素表示与包含的任何主题匹配的替代方案。
	//
	// 示例：
	// {} 或 nil          匹配任何主题列表
	// {{A}}              匹配第一位置的主题A
	// {{}, {B}}          匹配第一位置的任何主题和第二位置的B
	// {{A}, {B}}         匹配第一位置的主题A和第二位置的B
	// {{A, B}, {C, D}}   匹配第一位置的主题(A或B)和第二位置的(C或D)
	Topics [][]common.Hash
}

// LogFilterer provides access to contract log events using a one-off query or continuous
// event subscription.
//
// Logs received through a streaming query subscription may have Removed set to true,
// indicating that the log was reverted due to a chain reorganisation.
// LogFilterer 使用一次性查询或连续事件订阅提供对合约日志事件的访问。
//
// 通过流式查询订阅接收的日志可能将Removed设置为true，
// 表示由于链重组而撤销了该日志。
type LogFilterer interface {
	// FilterLogs 过滤日志
	FilterLogs(ctx context.Context, q FilterQuery) ([]types.Log, error)
	// SubscribeFilterLogs 订阅过滤日志
	SubscribeFilterLogs(ctx context.Context, q FilterQuery, ch chan<- types.Log) (Subscription, error)
}

// TransactionSender wraps transaction sending. The SendTransaction method injects a
// signed transaction into the pending transaction pool for execution. If the transaction
// was a contract creation, the TransactionReceipt method can be used to retrieve the
// contract address after the transaction has been mined.
//
// The transaction must be signed and have a valid nonce to be included. Consumers of the
// API can use package accounts to maintain local private keys and need can retrieve the
// next available nonce using PendingNonceAt.
// TransactionSender 包装交易发送。SendTransaction方法将签名交易注入待处理交易池以执行。
// 如果交易是合约创建，则可以使用TransactionReceipt方法在交易被挖掘后检索合约地址。
//
// 交易必须签名并具有有效的nonce才能包含在内。API的消费者可以使用accounts包来维护本地私钥，
// 并需要使用PendingNonceAt检索下一个可用的nonce。
type TransactionSender interface {
	// SendTransaction 发送交易
	SendTransaction(ctx context.Context, tx *types.Transaction) error
}

// GasPricer wraps the gas price oracle, which monitors the blockchain to determine the
// optimal gas price given current fee market conditions.
// GasPricer 包装gas价格预言机，其监控区块链以根据当前费用市场条件确定最佳gas价格。
type GasPricer interface {
	// SuggestGasPrice 建议gas价格
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
}

// GasPricer1559 provides access to the EIP-1559 gas price oracle.
// GasPricer1559 提供对EIP-1559 gas价格预言机的访问。
type GasPricer1559 interface {
	// SuggestGasTipCap 建议gas小费上限
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
}

// FeeHistoryReader provides access to the fee history oracle.
// FeeHistoryReader 提供对费用历史预言机的访问。
type FeeHistoryReader interface {
	// FeeHistory 获取费用历史
	FeeHistory(ctx context.Context, blockCount uint64, lastBlock *big.Int, rewardPercentiles []float64) (*FeeHistory, error)
}

// FeeHistory provides recent fee market data that consumers can use to determine
// a reasonable maxPriorityFeePerGas value.
// FeeHistory 提供最近的费用市场数据，消费者可以使用这些数据来确定
// 合理的maxPriorityFeePerGas值。
type FeeHistory struct {
	OldestBlock  *big.Int     // block corresponding to first response value // 对应于第一个响应值的区块
	Reward       [][]*big.Int // list every txs priority fee per block // 列出每个区块中所有交易的优先费用
	BaseFee      []*big.Int   // list of each block's base fee // 每个区块的基础费用列表
	GasUsedRatio []float64    // ratio of gas used out of the total available limit // 已使用gas占总可用限制的比率
}

// A PendingStateReader provides access to the pending state, which is the result of all
// known executable transactions which have not yet been included in the blockchain. It is
// commonly used to display the result of 'unconfirmed' actions (e.g. wallet value
// transfers) initiated by the user. The PendingNonceAt operation is a good way to
// retrieve the next available transaction nonce for a specific account.
// PendingStateReader 提供对待处理状态的访问，这是所有已知的可执行交易但尚未包含在区块链中的结果。
// 它通常用于显示用户发起的"未确认"操作（例如钱包价值转移）的结果。
// PendingNonceAt操作是检索特定账户的下一个可用交易nonce的好方法。
type PendingStateReader interface {
	// PendingBalanceAt 获取待处理状态中指定账户的余额
	PendingBalanceAt(ctx context.Context, account common.Address) (*big.Int, error)
	// PendingStorageAt 获取待处理状态中指定账户的存储数据
	PendingStorageAt(ctx context.Context, account common.Address, key common.Hash) ([]byte, error)
	// PendingCodeAt 获取待处理状态中指定账户的代码
	PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error)
	// PendingNonceAt 获取待处理状态中指定账户的nonce值
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	// PendingTransactionCount 获取待处理状态中的交易数量
	PendingTransactionCount(ctx context.Context) (uint, error)
}

// PendingContractCaller can be used to perform calls against the pending state.
// PendingContractCaller 可用于对待处理状态执行调用。
type PendingContractCaller interface {
	// PendingCallContract 在待处理状态上调用合约
	PendingCallContract(ctx context.Context, call CallMsg) ([]byte, error)
}

// PendingTransactionSender wraps the sending of transactions to a backend and
// allows waiting for inclusion on the pending state.
// PendingTransactionSender 包装向后端发送交易，并允许等待包含在待处理状态中。
type PendingTransactionSender interface {
	TransactionSender
}

// GasEstimator wraps EstimateGas, which tries to estimate the gas needed to execute a
// specific transaction based on the pending state. There is no guarantee that this is the
// true gas limit requirement as other transactions may be added or removed by miners, but
// it should provide a basis for setting a reasonable default.
// GasEstimator 包装EstimateGas，尝试根据待处理状态估计执行特定交易所需的gas。
// 不能保证这是真正的gas限制要求，因为矿工可能会添加或删除其他交易，
// 但它应该提供设置合理默认值的基础。
type GasEstimator interface {
	// EstimateGas 估计执行交易所需的gas
	EstimateGas(ctx context.Context, call CallMsg) (uint64, error)
}

// PendingStateEventer provides access to real time notifications about changes to the
// pending state.
// PendingStateEventer 提供对待处理状态变化的实时通知的访问。
type PendingStateEventer interface {
	// SubscribePendingTransactions 订阅待处理交易
	SubscribePendingTransactions(ctx context.Context, ch chan<- *types.Transaction) (Subscription, error)
}

// BlockNumberReader wraps GetBlockByNumber, which returns the most recent block number.
// BlockNumberReader 包装GetBlockByNumber，返回最新的区块号。
type BlockNumberReader interface {
	// BlockNumber 获取当前区块号
	BlockNumber(ctx context.Context) (uint64, error)
}

// ChainIDReader wraps ChainID which returns the current chain ID.
// ChainIDReader 包装ChainID，返回当前链ID。
type ChainIDReader interface {
	// ChainID 获取链ID
	ChainID(ctx context.Context) (*big.Int, error)
}
