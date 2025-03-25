// Copyright 2014 The go-ethereum Authors
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
	"errors"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

type (
	// CanTransferFunc is the signature of a transfer guard function
	// CanTransferFunc 是转账守卫函数的签名
	CanTransferFunc func(StateDB, common.Address, *uint256.Int) bool
	// TransferFunc is the signature of a transfer function
	// TransferFunc 是转账函数的签名
	TransferFunc func(StateDB, common.Address, common.Address, *uint256.Int)
	// GetHashFunc returns the n'th block hash in the blockchain
	// and is used by the BLOCKHASH EVM op code.
	// GetHashFunc 返回区块链中第n个区块的哈希
	// 用于BLOCKHASH EVM操作码。
	GetHashFunc func(uint64) common.Hash
)

// precompile 检查一个地址是否是预编译合约
func (evm *EVM) precompile(addr common.Address) (PrecompiledContract, bool) {
	p, ok := evm.precompiles[addr]
	return p, ok
}

// BlockContext provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
// BlockContext 为EVM提供辅助信息。一旦提供，
// 就不应该修改。
type BlockContext struct {
	// CanTransfer returns whether the account contains
	// sufficient ether to transfer the value
	// CanTransfer 返回账户是否包含
	// 足够的以太币来转移价值
	CanTransfer CanTransferFunc
	// Transfer transfers ether from one account to the other
	// Transfer 将以太币从一个账户转移到另一个账户
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n
	// GetHash 返回对应于n的哈希
	GetHash GetHashFunc

	// Block information
	// 区块信息
	Coinbase    common.Address // Provides information for COINBASE // 提供COINBASE的信息
	GasLimit    uint64         // Provides information for GASLIMIT // 提供GASLIMIT的信息
	BlockNumber *big.Int       // Provides information for NUMBER // 提供NUMBER的信息
	Time        uint64         // Provides information for TIME // 提供TIME的信息
	Difficulty  *big.Int       // Provides information for DIFFICULTY // 提供DIFFICULTY的信息
	BaseFee     *big.Int       // Provides information for BASEFEE (0 if vm runs with NoBaseFee flag and 0 gas price) // 提供BASEFEE的信息（如果vm使用NoBaseFee标志和0 gas价格运行，则为0）
	BlobBaseFee *big.Int       // Provides information for BLOBBASEFEE (0 if vm runs with NoBaseFee flag and 0 blob gas price) // 提供BLOBBASEFEE的信息（如果vm使用NoBaseFee标志和0 blob gas价格运行，则为0）
	Random      *common.Hash   // Provides information for PREVRANDAO // 提供PREVRANDAO的信息
}

// TxContext provides the EVM with information about a transaction.
// All fields can change between transactions.
// TxContext 为EVM提供有关交易的信息。
// 所有字段都可以在交易之间更改。
type TxContext struct {
	// Message information
	// 消息信息
	Origin       common.Address      // Provides information for ORIGIN // 提供ORIGIN的信息
	GasPrice     *big.Int            // Provides information for GASPRICE (and is used to zero the basefee if NoBaseFee is set) // 提供GASPRICE的信息（如果设置了NoBaseFee，则用于将basefee置零）
	BlobHashes   []common.Hash       // Provides information for BLOBHASH // 提供BLOBHASH的信息
	BlobFeeCap   *big.Int            // Is used to zero the blobbasefee if NoBaseFee is set // 如果设置了NoBaseFee，则用于将blobbasefee置零
	AccessEvents *state.AccessEvents // Capture all state accesses for this tx // 捕获此交易的所有状态访问
}

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.
// EVM是以太坊虚拟机基础对象，提供
// 在给定状态下运行合约所需的工具，
// 具有提供的上下文。应该注意的是，任何错误
// 通过任何调用生成的都应该被视为
// 回滚状态并消耗所有gas的操作，不应该
// 对特定错误执行任何检查。解释器确保
// 任何生成的错误都被视为有缺陷的代码。
//
// EVM不应该被重用，并且不是线程安全的。
type EVM struct {
	// Context provides auxiliary blockchain related information
	// Context提供辅助区块链相关信息
	Context BlockContext
	TxContext

	// StateDB gives access to the underlying state
	// StateDB提供对底层状态的访问
	StateDB StateDB

	// depth is the current call stack
	// depth是当前调用栈
	depth int

	// chainConfig contains information about the current chain
	// chainConfig包含有关当前链的信息
	chainConfig *params.ChainConfig

	// chain rules contains the chain rules for the current epoch
	// chain rules包含当前纪元的链规则
	chainRules params.Rules

	// virtual machine configuration options used to initialise the evm
	// 用于初始化evm的虚拟机配置选项
	Config Config

	// global (to this context) ethereum virtual machine used throughout
	// the execution of the tx
	// 在整个tx执行过程中使用的全局（对此上下文）以太坊虚拟机
	interpreter *EVMInterpreter

	// abort is used to abort the EVM calling operations
	// abort用于中止EVM调用操作
	abort atomic.Bool

	// callGasTemp holds the gas available for the current call. This is needed because the
	// available gas is calculated in gasCall* according to the 63/64 rule and later
	// applied in opCall*.
	// callGasTemp保存当前调用可用的gas。这是必需的，因为
	// 可用gas根据63/64规则在gasCall*中计算，稍后
	// 在opCall*中应用。
	callGasTemp uint64

	// precompiles holds the precompiled contracts for the current epoch
	// precompiles保存当前纪元的预编译合约
	precompiles map[common.Address]PrecompiledContract

	// jumpDests is the aggregated result of JUMPDEST analysis made through
	// the life cycle of EVM.
	// jumpDests是通过EVM生命周期进行的JUMPDEST分析的汇总结果。
	jumpDests map[common.Hash]bitvec
}

// NewEVM constructs an EVM instance with the supplied block context, state
// database and several configs. It meant to be used throughout the entire
// state transition of a block, with the transaction context switched as
// needed by calling evm.SetTxContext.
// NewEVM构建一个EVM实例，具有提供的区块上下文、状态
// 数据库和几个配置。它旨在整个区块的状态转换中使用，
// 根据需要通过调用evm.SetTxContext切换交易上下文。
func NewEVM(blockCtx BlockContext, statedb StateDB, chainConfig *params.ChainConfig, config Config) *EVM {
	evm := &EVM{
		Context:     blockCtx,
		StateDB:     statedb,
		Config:      config,
		chainConfig: chainConfig,
		chainRules:  chainConfig.Rules(blockCtx.BlockNumber, blockCtx.Random != nil, blockCtx.Time),
		jumpDests:   make(map[common.Hash]bitvec),
	}
	evm.precompiles = activePrecompiledContracts(evm.chainRules)
	evm.interpreter = NewEVMInterpreter(evm)
	return evm
}

// SetPrecompiles sets the precompiled contracts for the EVM.
// This method is only used through RPC calls.
// It is not thread-safe.
// SetPrecompiles设置EVM的预编译合约。
// 此方法仅通过RPC调用使用。
// 它不是线程安全的。
func (evm *EVM) SetPrecompiles(precompiles PrecompiledContracts) {
	evm.precompiles = precompiles
}

// SetTxContext resets the EVM with a new transaction context.
// This is not threadsafe and should only be done very cautiously.
// SetTxContext使用新的交易上下文重置EVM。
// 这不是线程安全的，应该非常谨慎地进行。
func (evm *EVM) SetTxContext(txCtx TxContext) {
	if evm.chainRules.IsEIP4762 {
		txCtx.AccessEvents = state.NewAccessEvents(evm.StateDB.PointCache())
	}
	evm.TxContext = txCtx
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
// Cancel取消任何正在运行的EVM操作。这可以并发调用，
// 并且多次调用是安全的。
func (evm *EVM) Cancel() {
	evm.abort.Store(true)
}

// Cancelled returns true if Cancel has been called
// Cancelled返回Cancel是否已被调用
func (evm *EVM) Cancelled() bool {
	return evm.abort.Load()
}

// Interpreter returns the current interpreter
// Interpreter返回当前解释器
func (evm *EVM) Interpreter() *EVMInterpreter {
	return evm.interpreter
}

// isSystemCall returns true if the caller is system address
// isSystemCall如果调用者是系统地址则返回true
func isSystemCall(caller common.Address) bool {
	return caller == params.SystemAddress
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
// Call执行与给定输入作为参数的addr相关联的合约。
// 它还处理任何必要的价值转移，并采取必要的步骤
// 创建账户，并在执行错误或价值转移失败的情况下
// 恢复状态。
func (evm *EVM) Call(caller common.Address, addr common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, leftOverGas uint64, err error) {
	// Capture the tracer start/end events in debug mode
	// 在调试模式下捕获跟踪器开始/结束事件
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, CALL, caller, addr, input, gas, value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Fail if we're trying to execute above the call depth limit
	// 如果我们尝试在调用深度限制之上执行，则失败
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	// 如果我们尝试转移超过可用余额，则失败
	if !value.IsZero() && !evm.Context.CanTransfer(evm.StateDB, caller, value) {
		return nil, gas, ErrInsufficientBalance
	}
	snapshot := evm.StateDB.Snapshot()
	p, isPrecompile := evm.precompile(addr)

	if !evm.StateDB.Exist(addr) {
		if !isPrecompile && evm.chainRules.IsEIP4762 && !isSystemCall(caller) {
			// add proof of absence to witness
			// 将不存在证明添加到见证
			wgas := evm.AccessEvents.AddAccount(addr, false)
			if gas < wgas {
				evm.StateDB.RevertToSnapshot(snapshot)
				return nil, 0, ErrOutOfGas
			}
			gas -= wgas
		}

		if !isPrecompile && evm.chainRules.IsEIP158 && value.IsZero() {
			// Calling a non-existing account, don't do anything.
			// 调用不存在的账户，不做任何事情。
			return nil, gas, nil
		}
		evm.StateDB.CreateAccount(addr)
	}
	evm.Context.Transfer(evm.StateDB, caller, addr, value)

	if isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		// Initialise a new contract and set the code that is to be used by the EVM.
		// 初始化一个新合约，并设置EVM将使用的代码。
		code := evm.resolveCode(addr)
		if len(code) == 0 {
			ret, err = nil, nil // gas is unchanged // gas保持不变
		} else {
			// The contract is a scoped environment for this execution context only.
			// 合约是仅适用于此执行上下文的作用域环境。
			contract := NewContract(caller, addr, value, gas, evm.jumpDests)
			contract.IsSystemCall = isSystemCall(caller)
			contract.SetCallCode(evm.resolveCodeHash(addr), code)
			ret, err = evm.interpreter.Run(contract, input, false)
			gas = contract.Gas
		}
	}
	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally,
	// when we're in homestead this also counts for code storage gas errors.
	// 当EVM返回错误或在设置创建代码时
	// 我们恢复到快照并消耗剩余的任何gas。此外，
	// 当我们在homestead中时，这也适用于代码存储gas错误。
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}

			gas = 0
		}
		// TODO: consider clearing up unused snapshots:
		//} else {
		//	evm.StateDB.DiscardSnapshot(snapshot)
	}
	return ret, gas, err
}

// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
// CallCode执行与给定输入作为参数的addr相关联的合约。
// 它还处理任何必要的价值转移，并采取必要的步骤
// 创建账户，并在执行错误或价值转移失败的情况下
// 恢复状态。
//
// CallCode与Call的不同之处在于，它以调用者作为上下文
// 执行给定地址的代码。
func (evm *EVM) CallCode(caller common.Address, addr common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, leftOverGas uint64, err error) {
	// Invoke tracer hooks that signal entering/exiting a call frame
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, CALLCODE, caller, addr, input, gas, value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	// Note although it's noop to transfer X ether to caller itself. But
	// if caller doesn't have enough balance, it would be an error to allow
	// over-charging itself. So the check here is necessary.
	if !evm.Context.CanTransfer(evm.StateDB, caller, value) {
		return nil, gas, ErrInsufficientBalance
	}
	var snapshot = evm.StateDB.Snapshot()

	// It is allowed to call precompiles, even via delegatecall
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		contract := NewContract(caller, caller, value, gas, evm.jumpDests)
		contract.SetCallCode(evm.resolveCodeHash(addr), evm.resolveCode(addr))
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}
			gas = 0
		}
	}
	return ret, gas, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
// DelegateCall执行与给定输入作为参数的addr相关联的合约。
// 它在执行错误的情况下恢复状态。
//
// DelegateCall与CallCode的不同之处在于，它以调用者作为上下文
// 执行给定地址的代码，并且调用者被设置为调用者的调用者。
func (evm *EVM) DelegateCall(originCaller common.Address, caller common.Address, addr common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, leftOverGas uint64, err error) {
	// Invoke tracer hooks that signal entering/exiting a call frame
	if evm.Config.Tracer != nil {
		// DELEGATECALL inherits value from parent call
		evm.captureBegin(evm.depth, DELEGATECALL, caller, addr, input, gas, value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	var snapshot = evm.StateDB.Snapshot()

	// It is allowed to call precompiles, even via delegatecall
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		// Initialise a new contract and make initialise the delegate values
		//
		// Note: The value refers to the original value from the parent call.
		contract := NewContract(originCaller, caller, value, gas, evm.jumpDests)
		contract.SetCallCode(evm.resolveCodeHash(addr), evm.resolveCode(addr))
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}
			gas = 0
		}
	}
	return ret, gas, err
}

// StaticCall executes the contract associated with the addr with the given input
// as parameters while discarding the output. It reverses the state in case of an
// execution error.
// StaticCall执行与给定输入作为参数的addr相关联的合约，
// 同时丢弃输出。它在执行错误的情况下恢复状态。
func (evm *EVM) StaticCall(caller common.Address, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// Invoke tracer hooks that signal entering/exiting a call frame
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, STATICCALL, caller, addr, input, gas, nil)
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// We take a snapshot here. This is a bit counter-intuitive, and could probably be skipped.
	// However, even a staticcall is considered a 'touch'. On mainnet, static calls were introduced
	// after all empty accounts were deleted, so this is not required. However, if we omit this,
	// then certain tests start failing; stRevertTest/RevertPrecompiledTouchExactOOG.json.
	// We could change this, but for now it's left for legacy reasons
	var snapshot = evm.StateDB.Snapshot()

	// We do an AddBalance of zero here, just in order to trigger a touch.
	// This doesn't matter on Mainnet, where all empties are gone at the time of Byzantium,
	// but is the correct thing to do and matters on other networks, in tests, and potential
	// future scenarios
	evm.StateDB.AddBalance(addr, new(uint256.Int), tracing.BalanceChangeTouchAccount)

	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		contract := NewContract(caller, addr, new(uint256.Int), gas, evm.jumpDests)
		contract.SetCallCode(evm.resolveCodeHash(addr), evm.resolveCode(addr))

		// When an error was returned by the EVM or when setting the creation code
		// above we revert to the snapshot and consume any gas remaining. Additionally
		// when we're in Homestead this also counts for code storage gas errors.
		ret, err = evm.interpreter.Run(contract, input, true)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}

			gas = 0
		}
	}
	return ret, gas, err
}

// create creates a new contract using the code with the given deployment arguments.
// create使用具有给定部署参数的代码创建一个新合约。
func (evm *EVM) create(caller common.Address, code []byte, gas uint64, value *uint256.Int, address common.Address, typ OpCode) (ret []byte, createAddress common.Address, leftOverGas uint64, err error) {
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, typ, caller, address, code, gas, value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.Context.CanTransfer(evm.StateDB, caller, value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller)
	if nonce+1 < nonce {
		return nil, common.Address{}, gas, ErrNonceUintOverflow
	}
	evm.StateDB.SetNonce(caller, nonce+1, tracing.NonceChangeContractCreator)

	// Charge the contract creation init gas in verkle mode
	if evm.chainRules.IsEIP4762 {
		statelessGas := evm.AccessEvents.ContractCreatePreCheckGas(address)
		if statelessGas > gas {
			return nil, common.Address{}, 0, ErrOutOfGas
		}
		if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
			evm.Config.Tracer.OnGasChange(gas, gas-statelessGas, tracing.GasChangeWitnessContractCollisionCheck)
		}
		gas = gas - statelessGas
	}

	// We add this to the access list _before_ taking a snapshot. Even if the
	// creation fails, the access-list change should not be rolled back.
	if evm.chainRules.IsEIP2929 {
		evm.StateDB.AddAddressToAccessList(address)
	}
	// Ensure there's no existing contract already at the designated address.
	// Account is regarded as existent if any of these three conditions is met:
	// - the nonce is non-zero
	// - the code is non-empty
	// - the storage is non-empty
	contractHash := evm.StateDB.GetCodeHash(address)
	storageRoot := evm.StateDB.GetStorageRoot(address)
	if evm.StateDB.GetNonce(address) != 0 ||
		(contractHash != (common.Hash{}) && contractHash != types.EmptyCodeHash) || // non-empty code
		(storageRoot != (common.Hash{}) && storageRoot != types.EmptyRootHash) { // non-empty storage
		if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
			evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
		}
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// Create a new account on the state only if the object was not present.
	// It might be possible the contract code is deployed to a pre-existent
	// account with non-zero balance.
	snapshot := evm.StateDB.Snapshot()
	if !evm.StateDB.Exist(address) {
		evm.StateDB.CreateAccount(address)
	}
	// CreateContract means that regardless of whether the account previously existed
	// in the state trie or not, it _now_ becomes created as a _contract_ account.
	// This is performed _prior_ to executing the initcode,  since the initcode
	// acts inside that account.
	evm.StateDB.CreateContract(address)

	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1, tracing.NonceChangeNewContract)
	}
	// Charge the contract creation init gas in verkle mode
	if evm.chainRules.IsEIP4762 {
		statelessGas := evm.AccessEvents.ContractCreateInitGas(address)
		if statelessGas > gas {
			return nil, common.Address{}, 0, ErrOutOfGas
		}
		if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
			evm.Config.Tracer.OnGasChange(gas, gas-statelessGas, tracing.GasChangeWitnessContractInit)
		}
		gas = gas - statelessGas
	}
	evm.Context.Transfer(evm.StateDB, caller, address, value)

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, address, value, gas, evm.jumpDests)

	// Explicitly set the code to a null hash to prevent caching of jump analysis
	// for the initialization code.
	contract.SetCallCode(common.Hash{}, code)
	contract.IsDeployment = true

	ret, err = evm.initNewContract(contract, address)
	if err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			contract.UseGas(contract.Gas, evm.Config.Tracer, tracing.GasChangeCallFailedExecution)
		}
	}
	return ret, address, contract.Gas, err
}

// initNewContract prepares a contract call for execution and initializes contract logic.
// initNewContract准备合约调用以执行并初始化合约逻辑。
func (evm *EVM) initNewContract(contract *Contract, address common.Address) ([]byte, error) {
	ret, err := evm.interpreter.Run(contract, nil, false)
	if err != nil {
		return ret, err
	}

	// Check whether the max code size has been exceeded, assign err if the case.
	if evm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize {
		return ret, ErrMaxCodeSizeExceeded
	}

	// Reject code starting with 0xEF if EIP-3541 is enabled.
	if len(ret) >= 1 && ret[0] == 0xEF && evm.chainRules.IsLondon {
		return ret, ErrInvalidCode
	}

	if !evm.chainRules.IsEIP4762 {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if !contract.UseGas(createDataGas, evm.Config.Tracer, tracing.GasChangeCallCodeStorage) {
			return ret, ErrCodeStoreOutOfGas
		}
	} else {
		if len(ret) > 0 && !contract.UseGas(evm.AccessEvents.CodeChunksRangeGas(address, 0, uint64(len(ret)), uint64(len(ret)), true), evm.Config.Tracer, tracing.GasChangeWitnessCodeChunk) {
			return ret, ErrCodeStoreOutOfGas
		}
	}

	evm.StateDB.SetCode(address, ret)
	return ret, nil
}

// Create creates a new contract using the provided code, storing in contractAddr. contractAddr is determined from transaction logs or provided senderAddress + nonce.
// Create使用提供的代码创建一个新的合约，存储在contractAddr中。contractAddr由交易日志或提供的senderAddress + nonce确定。
func (evm *EVM) Create(caller common.Address, code []byte, gas uint64, value *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller, evm.StateDB.GetNonce(caller))
	return evm.create(caller, code, gas, value, contractAddr, CREATE)
}

// Create2 creates a new contract using the provided code with a salt-derived address. Salt is a byte32 value.
// Create2使用提供的代码和派生自盐值的地址创建一个新的合约。盐是一个byte32值。
func (evm *EVM) Create2(caller common.Address, code []byte, gas uint64, endowment *uint256.Int, salt *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress2(caller, salt.Bytes32(), crypto.Keccak256(code))
	return evm.create(caller, code, gas, endowment, contractAddr, CREATE2)
}

// resolveCode reads the code of a specified account for execution. If addr is a predeploy, the cached code, if available, is returned. Otherwise, the bytecode stored at the account's address is fetched.
// resolveCode读取指定账户的代码以执行。如果addr是预部署的，返回缓存的代码（如果可用）。否则，获取存储在账户地址的字节码。
func (evm *EVM) resolveCode(addr common.Address) []byte {
	code := evm.StateDB.GetCode(addr)
	if !evm.chainRules.IsPrague {
		return code
	}
	if target, ok := types.ParseDelegation(code); ok {
		// Note we only follow one level of delegation.
		return evm.StateDB.GetCode(target)
	}
	return code
}

// resolveCodeHash returns the codeHash of the specified account. Return emptyCodeHash if empty.
// resolveCodeHash返回指定账户的codeHash。如果为空，则返回emptyCodeHash。
func (evm *EVM) resolveCodeHash(addr common.Address) common.Hash {
	if evm.chainRules.IsPrague {
		code := evm.StateDB.GetCode(addr)
		if target, ok := types.ParseDelegation(code); ok {
			// Note we only follow one level of delegation.
			return evm.StateDB.GetCodeHash(target)
		}
	}
	return evm.StateDB.GetCodeHash(addr)
}

// ChainConfig returns the environment's chain configuration
// ChainConfig返回环境的链配置
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }

// captureBegin captures the beginning of an EVM call. Only used if tracing is enabled.
// captureBegin捕获EVM调用的开始。仅在启用跟踪时使用。
func (evm *EVM) captureBegin(depth int, typ OpCode, from common.Address, to common.Address, input []byte, startGas uint64, value *big.Int) {
	tracer := evm.Config.Tracer
	if tracer.OnEnter != nil {
		tracer.OnEnter(depth, byte(typ), from, to, input, startGas, value)
	}
	if tracer.OnGasChange != nil {
		tracer.OnGasChange(0, startGas, tracing.GasChangeCallInitialBalance)
	}
}

// captureEnd captures the end of an EVM call. Only used if tracing is enabled.
// captureEnd捕获EVM调用的结束。仅在启用跟踪时使用。
func (evm *EVM) captureEnd(depth int, startGas uint64, leftOverGas uint64, ret []byte, err error) {
	tracer := evm.Config.Tracer
	if leftOverGas != 0 && tracer.OnGasChange != nil {
		tracer.OnGasChange(leftOverGas, 0, tracing.GasChangeCallLeftOverReturned)
	}
	var reverted bool
	if err != nil {
		reverted = true
	}
	if !evm.chainRules.IsHomestead && errors.Is(err, ErrCodeStoreOutOfGas) {
		reverted = false
	}
	if tracer.OnExit != nil {
		tracer.OnExit(depth, ret, startGas-leftOverGas, VMErrorFromErr(err), reverted)
	}
}

// GetVMContext returns the context for tracing the current VM execution.
// GetVMContext返回用于跟踪当前VM执行的上下文。
func (evm *EVM) GetVMContext() *tracing.VMContext {
	return &tracing.VMContext{
		Coinbase:    evm.Context.Coinbase,
		BlockNumber: evm.Context.BlockNumber,
		Time:        evm.Context.Time,
		Random:      evm.Context.Random,
		BaseFee:     evm.Context.BaseFee,
		StateDB:     evm.StateDB,
	}
}
