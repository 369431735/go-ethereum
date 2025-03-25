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

// Package types contains data types related to Ethereum consensus.
// 包types包含与以太坊共识相关的数据类型。
package types

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

var (
	ErrInvalidSig           = errors.New("invalid transaction v, r, s values")                               // 无效的交易v、r、s值
	ErrUnexpectedProtection = errors.New("transaction type does not supported EIP-155 protected signatures") // 交易类型不支持EIP-155保护的签名
	ErrInvalidTxType        = errors.New("transaction type not valid in this context")                       // 在此上下文中交易类型无效
	ErrTxTypeNotSupported   = errors.New("transaction type not supported")                                   // 不支持的交易类型
	ErrGasFeeCapTooLow      = errors.New("fee cap less than base fee")                                       // 费用上限低于基础费用
	errShortTypedTx         = errors.New("typed transaction too short")                                      // 类型化交易太短
	errInvalidYParity       = errors.New("'yParity' field must be 0 or 1")                                   // 'yParity'字段必须为0或1
	errVYParityMismatch     = errors.New("'v' and 'yParity' fields do not match")                            // 'v'和'yParity'字段不匹配
	errVYParityMissing      = errors.New("missing 'yParity' or 'v' field in transaction")                    // 交易中缺少'yParity'或'v'字段
)

// Transaction types.
// 交易类型。
const (
	LegacyTxType     = 0x00 // 传统交易类型
	AccessListTxType = 0x01 // 访问列表交易类型
	DynamicFeeTxType = 0x02 // 动态费用交易类型
	BlobTxType       = 0x03 // Blob交易类型
	SetCodeTxType    = 0x04 // 设置代码交易类型
)

// Transaction is an Ethereum transaction.
// Transaction是一个以太坊交易。
type Transaction struct {
	inner TxData    // Consensus contents of a transaction // 交易的共识内容
	time  time.Time // Time first seen locally (spam avoidance) // 本地首次看到的时间（避免垃圾信息）

	// caches
	// 缓存
	hash atomic.Pointer[common.Hash] // 交易哈希的原子指针
	size atomic.Uint64               // 交易大小的原子计数器
	from atomic.Pointer[sigCache]    // 签名缓存的原子指针
}

// NewTx creates a new transaction.
// NewTx创建一个新交易。
func NewTx(inner TxData) *Transaction {
	tx := new(Transaction)
	tx.setDecoded(inner.copy(), 0)
	return tx
}

// TxData is the underlying data of a transaction.
//
// This is implemented by DynamicFeeTx, LegacyTx and AccessListTx.
// TxData是交易的底层数据。
//
// 这由DynamicFeeTx、LegacyTx和AccessListTx实现。
type TxData interface {
	txType() byte // returns the type ID // 返回类型ID
	copy() TxData // creates a deep copy and initializes all fields // 创建深拷贝并初始化所有字段

	chainID() *big.Int      // 链ID
	accessList() AccessList // 访问列表
	data() []byte           // 数据
	gas() uint64            // gas限制
	gasPrice() *big.Int     // gas价格
	gasTipCap() *big.Int    // gas小费上限
	gasFeeCap() *big.Int    // gas费用上限
	value() *big.Int        // 交易值
	nonce() uint64          // 交易序号
	to() *common.Address    // 接收地址

	rawSignatureValues() (v, r, s *big.Int)       // 原始签名值
	setSignatureValues(chainID, v, r, s *big.Int) // 设置签名值

	// effectiveGasPrice computes the gas price paid by the transaction, given
	// the inclusion block baseFee.
	//
	// Unlike other TxData methods, the returned *big.Int should be an independent
	// copy of the computed value, i.e. callers are allowed to mutate the result.
	// Method implementations can use 'dst' to store the result.
	// effectiveGasPrice计算交易支付的gas价格，给定
	// 包含区块的基础费用。
	//
	// 与其他TxData方法不同，返回的*big.Int应该是计算值的
	// 独立副本，即调用者可以修改结果。
	// 方法实现可以使用'dst'来存储结果。
	effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int

	encode(*bytes.Buffer) error // 编码
	decode([]byte) error        // 解码

	// sigHash returns the hash of the transaction that is ought to be signed
	// sigHash返回需要签名的交易哈希
	sigHash(*big.Int) common.Hash
}

// EncodeRLP implements rlp.Encoder
// EncodeRLP实现rlp.Encoder接口
func (tx *Transaction) EncodeRLP(w io.Writer) error {
	if tx.Type() == LegacyTxType {
		return rlp.Encode(w, tx.inner)
	}
	// It's an EIP-2718 typed TX envelope.
	// 这是一个EIP-2718类型的TX封装。
	buf := encodeBufferPool.Get().(*bytes.Buffer)
	defer encodeBufferPool.Put(buf)
	buf.Reset()
	if err := tx.encodeTyped(buf); err != nil {
		return err
	}
	return rlp.Encode(w, buf.Bytes())
}

// encodeTyped writes the canonical encoding of a typed transaction to w.
// encodeTyped将类型化交易的规范编码写入w。
func (tx *Transaction) encodeTyped(w *bytes.Buffer) error {
	w.WriteByte(tx.Type())
	return tx.inner.encode(w)
}

// MarshalBinary returns the canonical encoding of the transaction.
// For legacy transactions, it returns the RLP encoding. For EIP-2718 typed
// transactions, it returns the type and payload.
// MarshalBinary返回交易的规范编码。
// 对于传统交易，它返回RLP编码。对于EIP-2718类型的
// 交易，它返回类型和载荷。
func (tx *Transaction) MarshalBinary() ([]byte, error) {
	if tx.Type() == LegacyTxType {
		return rlp.EncodeToBytes(tx.inner)
	}
	var buf bytes.Buffer
	err := tx.encodeTyped(&buf)
	return buf.Bytes(), err
}

// DecodeRLP implements rlp.Decoder
// DecodeRLP实现rlp.Decoder接口
func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	kind, size, err := s.Kind()
	switch {
	case err != nil:
		return err
	case kind == rlp.List:
		// It's a legacy transaction.
		// 这是一个传统交易。
		var inner LegacyTx
		err := s.Decode(&inner)
		if err == nil {
			tx.setDecoded(&inner, rlp.ListSize(size))
		}
		return err
	case kind == rlp.Byte:
		return errShortTypedTx
	default:
		// It's an EIP-2718 typed TX envelope.
		// 这是一个EIP-2718类型的TX封装。
		// First read the tx payload bytes into a temporary buffer.
		// 首先将tx载荷字节读入临时缓冲区。
		b, buf, err := getPooledBuffer(size)
		if err != nil {
			return err
		}
		defer encodeBufferPool.Put(buf)
		if err := s.ReadBytes(b); err != nil {
			return err
		}
		// Now decode the inner transaction.
		// 现在解码内部交易。
		inner, err := tx.decodeTyped(b)
		if err == nil {
			tx.setDecoded(inner, size)
		}
		return err
	}
}

// UnmarshalBinary decodes the canonical encoding of transactions.
// It supports legacy RLP transactions and EIP-2718 typed transactions.
// UnmarshalBinary解码交易的规范编码。
// 它支持传统的RLP交易和EIP-2718类型的交易。
func (tx *Transaction) UnmarshalBinary(b []byte) error {
	if len(b) > 0 && b[0] > 0x7f {
		// It's a legacy transaction.
		// 这是一个传统交易。
		var data LegacyTx
		err := rlp.DecodeBytes(b, &data)
		if err != nil {
			return err
		}
		tx.setDecoded(&data, uint64(len(b)))
		return nil
	}
	// It's an EIP-2718 typed transaction envelope.
	// 这是一个EIP-2718类型的交易封装。
	inner, err := tx.decodeTyped(b)
	if err != nil {
		return err
	}
	tx.setDecoded(inner, uint64(len(b)))
	return nil
}

// decodeTyped decodes a typed transaction from the canonical format.
// decodeTyped从规范格式解码类型化交易。
func (tx *Transaction) decodeTyped(b []byte) (TxData, error) {
	if len(b) <= 1 {
		return nil, errShortTypedTx
	}
	var inner TxData
	switch b[0] {
	case AccessListTxType:
		inner = new(AccessListTx)
	case DynamicFeeTxType:
		inner = new(DynamicFeeTx)
	case BlobTxType:
		inner = new(BlobTx)
	case SetCodeTxType:
		inner = new(SetCodeTx)
	default:
		return nil, ErrTxTypeNotSupported
	}
	err := inner.decode(b[1:])
	return inner, err
}

// setDecoded sets the inner transaction and size after decoding.
// setDecoded在解码后设置内部交易和大小。
func (tx *Transaction) setDecoded(inner TxData, size uint64) {
	tx.inner = inner
	tx.time = time.Now()
	if size > 0 {
		tx.size.Store(size)
	}
}

// sanityCheckSignature checks that the V, R, S values are valid.
// sanityCheckSignature检查V、R、S值是否有效。
func sanityCheckSignature(v *big.Int, r *big.Int, s *big.Int, maybeProtected bool) error {
	if isProtectedV(v) && !maybeProtected {
		return ErrUnexpectedProtection
	}

	var plainV byte
	if isProtectedV(v) {
		chainID := deriveChainId(v).Uint64()
		plainV = byte(v.Uint64() - 35 - 2*chainID)
	} else if maybeProtected {
		// Only EIP-155 signatures can be optionally protected. Since
		// we determined this v value is not protected, it must be a
		// raw 27 or 28.
		// 只有EIP-155签名可以可选地受到保护。由于
		// 我们确定这个v值未受保护，它必须是
		// 原始的27或28。
		plainV = byte(v.Uint64() - 27)
	} else {
		// If the signature is not optionally protected, we assume it
		// must already be equal to the recovery id.
		// 如果签名不是可选保护的，我们假设它
		// 必须已经等于恢复ID。
		plainV = byte(v.Uint64())
	}
	if !crypto.ValidateSignatureValues(plainV, r, s, false) {
		return ErrInvalidSig
	}

	return nil
}

// isProtectedV checks if V is greater than 1.
// It assumes V is not nil.
// isProtectedV检查V是否大于1。
// 它假设V不为nil。
func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28 && v != 1 && v != 0
	}
	// anything not 27 or 28 is considered protected
	// 任何不是27或28的值都被视为受保护的
	return true
}

// deriveChainId derives the chain id from the given v parameter.
// deriveChainId从给定的v参数派生链ID。
func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 8 {
		v := v.Uint64()
		if v == 28 {
			return big.NewInt(1)
		}
		if v == 27 || v == 29 {
			return big.NewInt(0)
		}
	}
	return nil
}

// Protected says whether the transaction is replay-protected.
// Protected表示交易是否防重放保护。
func (tx *Transaction) Protected() bool {
	switch tx := tx.inner.(type) {
	case *LegacyTx:
		return tx.V != nil && isProtectedV(tx.V)
	default:
		return true
	}
}

// Type returns the transaction type.
// Type返回交易类型。
func (tx *Transaction) Type() uint8 {
	return tx.inner.txType()
}

// ChainId returns the EIP155 chain ID of the transaction. The return value will always be
// non-nil. For legacy transactions which are not replay-protected, the return value is
// zero.
// ChainId返回交易的EIP155链ID。返回值始终为
// 非空。对于不受重放保护的旧式交易，返回值为零。
func (tx *Transaction) ChainId() *big.Int {
	return tx.inner.chainID()
}

// Data returns the input data of the transaction.
// Data返回交易的输入数据。
func (tx *Transaction) Data() []byte { return tx.inner.data() }

// AccessList returns the access list of the transaction.
// AccessList返回交易的访问列表。
func (tx *Transaction) AccessList() AccessList { return tx.inner.accessList() }

// Gas returns the gas limit of the transaction.
// Gas返回交易的gas限制。
func (tx *Transaction) Gas() uint64 { return tx.inner.gas() }

// GasPrice returns the gas price of the transaction.
// GasPrice返回交易的gas价格。
func (tx *Transaction) GasPrice() *big.Int { return new(big.Int).Set(tx.inner.gasPrice()) }

// GasTipCap returns the gasTipCap per gas of the transaction.
// GasTipCap返回交易的每gas小费上限。
func (tx *Transaction) GasTipCap() *big.Int { return new(big.Int).Set(tx.inner.gasTipCap()) }

// GasFeeCap returns the fee cap per gas of the transaction.
// GasFeeCap返回交易的每gas费用上限。
func (tx *Transaction) GasFeeCap() *big.Int { return new(big.Int).Set(tx.inner.gasFeeCap()) }

// Value returns the ether amount of the transaction.
// Value返回交易的以太币金额。
func (tx *Transaction) Value() *big.Int { return new(big.Int).Set(tx.inner.value()) }

// Nonce returns the sender account nonce of the transaction.
// Nonce返回交易的发送方账户nonce。
func (tx *Transaction) Nonce() uint64 { return tx.inner.nonce() }

// To returns the recipient address of the transaction.
// For contract-creation transactions, To returns nil.
// To返回交易的接收方地址。
// 对于创建合约的交易，To返回nil。
func (tx *Transaction) To() *common.Address {
	return copyAddressPtr(tx.inner.to())
}

// Cost returns (gas * gasPrice) + (blobGas * blobGasPrice) + value.
// Cost返回 (gas * gasPrice) + (blobGas * blobGasPrice) + value。
func (tx *Transaction) Cost() *big.Int {
	total := new(big.Int).Mul(tx.GasPrice(), new(big.Int).SetUint64(tx.Gas()))
	if tx.Type() == BlobTxType {
		total.Add(total, new(big.Int).Mul(tx.BlobGasFeeCap(), new(big.Int).SetUint64(tx.BlobGas())))
	}
	total.Add(total, tx.Value())
	return total
}

// RawSignatureValues returns the V, R, S signature values of the transaction.
// The return values should not be modified by the caller.
// The return values may be nil or zero, if the transaction is unsigned.
// RawSignatureValues返回交易的V、R、S签名值。
// 返回值不应被调用者修改。
// 如果交易未签名，返回值可能为nil或零。
func (tx *Transaction) RawSignatureValues() (v, r, s *big.Int) {
	return tx.inner.rawSignatureValues()
}

// GasFeeCapCmp比较两个交易的费用上限。
func (tx *Transaction) GasFeeCapCmp(other *Transaction) int {
	return tx.inner.gasFeeCap().Cmp(other.inner.gasFeeCap())
}

// GasFeeCapIntCmp比较交易的费用上限与给定的费用上限。
func (tx *Transaction) GasFeeCapIntCmp(other *big.Int) int {
	return tx.inner.gasFeeCap().Cmp(other)
}

// GasTipCapCmp比较两个交易的gasTipCap。
func (tx *Transaction) GasTipCapCmp(other *Transaction) int {
	return tx.inner.gasTipCap().Cmp(other.inner.gasTipCap())
}

// GasTipCapIntCmp比较交易的gasTipCap与给定的gasTipCap。
func (tx *Transaction) GasTipCapIntCmp(other *big.Int) int {
	return tx.inner.gasTipCap().Cmp(other)
}

// EffectiveGasTip返回给定基础费用的有效矿工gasTipCap。
// 注意：如果有效gasTipCap为负，此方法会同时返回错误、
// 实际的负值，以及ErrGasFeeCapTooLow
func (tx *Transaction) EffectiveGasTip(baseFee *big.Int) (*big.Int, error) {
	if baseFee == nil {
		return tx.GasTipCap(), nil
	}
	var err error
	gasFeeCap := tx.GasFeeCap()
	if gasFeeCap.Cmp(baseFee) < 0 {
		err = ErrGasFeeCapTooLow
	}
	gasFeeCap = gasFeeCap.Sub(gasFeeCap, baseFee)

	gasTipCap := tx.GasTipCap()
	if gasTipCap.Cmp(gasFeeCap) < 0 {
		return gasTipCap, err
	}
	return gasFeeCap, err
}

// EffectiveGasTipValue与EffectiveGasTip相同，但在有效gasTipCap为负的情况下
// 不返回错误
func (tx *Transaction) EffectiveGasTipValue(baseFee *big.Int) *big.Int {
	effectiveTip, _ := tx.EffectiveGasTip(baseFee)
	return effectiveTip
}

// EffectiveGasTipCmp在给定基础费用的假设下比较两个交易的有效gasTipCap。
func (tx *Transaction) EffectiveGasTipCmp(other *Transaction, baseFee *big.Int) int {
	if baseFee == nil {
		return tx.GasTipCapCmp(other)
	}
	return tx.EffectiveGasTipValue(baseFee).Cmp(other.EffectiveGasTipValue(baseFee))
}

// EffectiveGasTipIntCmp比较交易的有效gasTipCap与给定的gasTipCap。
func (tx *Transaction) EffectiveGasTipIntCmp(other *big.Int, baseFee *big.Int) int {
	if baseFee == nil {
		return tx.GasTipCapIntCmp(other)
	}
	return tx.EffectiveGasTipValue(baseFee).Cmp(other)
}

// BlobGas returns the blob gas limit of the transaction for blob transactions, 0 otherwise.
// BlobGas返回blob交易的blob gas限制，非blob交易返回0。
func (tx *Transaction) BlobGas() uint64 {
	if blobtx, ok := tx.inner.(*BlobTx); ok {
		return blobtx.blobGas()
	}
	return 0
}

// BlobGasFeeCap returns the blob gas fee cap per blob gas of the transaction for blob transactions, nil otherwise.
// BlobGasFeeCap返回blob交易的每blob gas的blob gas费用上限，非blob交易返回nil。
func (tx *Transaction) BlobGasFeeCap() *big.Int {
	if blobtx, ok := tx.inner.(*BlobTx); ok {
		return blobtx.BlobFeeCap.ToBig()
	}
	return nil
}

// BlobHashes returns the hashes of the blob commitments for blob transactions, nil otherwise.
// BlobHashes返回blob交易的blob承诺哈希，非blob交易返回nil。
func (tx *Transaction) BlobHashes() []common.Hash {
	if blobtx, ok := tx.inner.(*BlobTx); ok {
		return blobtx.BlobHashes
	}
	return nil
}

// BlobTxSidecar returns the sidecar of a blob transaction, nil otherwise.
// BlobTxSidecar返回blob交易的侧链车，非blob交易返回nil。
func (tx *Transaction) BlobTxSidecar() *BlobTxSidecar {
	if blobtx, ok := tx.inner.(*BlobTx); ok {
		return blobtx.Sidecar
	}
	return nil
}

// BlobGasFeeCapCmp比较两个交易的blob费用上限。
func (tx *Transaction) BlobGasFeeCapCmp(other *Transaction) int {
	return tx.BlobGasFeeCap().Cmp(other.BlobGasFeeCap())
}

// BlobGasFeeCapIntCmp比较交易的blob费用上限与给定的blob费用上限。
func (tx *Transaction) BlobGasFeeCapIntCmp(other *big.Int) int {
	return tx.BlobGasFeeCap().Cmp(other)
}

// WithoutBlobTxSidecar返回一个移除了blob侧链车的交易副本。
func (tx *Transaction) WithoutBlobTxSidecar() *Transaction {
	blobtx, ok := tx.inner.(*BlobTx)
	if !ok {
		return tx
	}
	cpy := &Transaction{
		inner: blobtx.withoutSidecar(),
		time:  tx.time,
	}
	// Note: tx.size cache not carried over because the sidecar is included in size!
	// 注意：不携带tx.size缓存，因为侧链车包含在大小中！
	if h := tx.hash.Load(); h != nil {
		cpy.hash.Store(h)
	}
	if f := tx.from.Load(); f != nil {
		cpy.from.Store(f)
	}
	return cpy
}

// WithBlobTxSidecar返回一个添加了blob侧链车的交易副本。
func (tx *Transaction) WithBlobTxSidecar(sideCar *BlobTxSidecar) *Transaction {
	blobtx, ok := tx.inner.(*BlobTx)
	if !ok {
		return tx
	}
	cpy := &Transaction{
		inner: blobtx.withSidecar(sideCar),
		time:  tx.time,
	}
	// Note: tx.size cache not carried over because the sidecar is included in size!
	// 注意：不携带tx.size缓存，因为侧链车包含在大小中！
	if h := tx.hash.Load(); h != nil {
		cpy.hash.Store(h)
	}
	if f := tx.from.Load(); f != nil {
		cpy.from.Store(f)
	}
	return cpy
}

// SetCodeAuthorizations返回交易的授权列表。
func (tx *Transaction) SetCodeAuthorizations() []SetCodeAuthorization {
	setcodetx, ok := tx.inner.(*SetCodeTx)
	if !ok {
		return nil
	}
	return setcodetx.AuthList
}

// SetCodeAuthorities从授权列表中返回唯一的授权者列表。
func (tx *Transaction) SetCodeAuthorities() []common.Address {
	setcodetx, ok := tx.inner.(*SetCodeTx)
	if !ok {
		return nil
	}
	var (
		marks = make(map[common.Address]bool)
		auths = make([]common.Address, 0, len(setcodetx.AuthList))
	)
	for _, auth := range setcodetx.AuthList {
		if addr, err := auth.Authority(); err == nil {
			if marks[addr] {
				continue
			}
			marks[addr] = true
			auths = append(auths, addr)
		}
	}
	return auths
}

// SetTime设置交易的解码时间。这用于测试设置任意时间，
// 以及持久化交易池从磁盘加载旧交易时。
func (tx *Transaction) SetTime(t time.Time) {
	tx.time = t
}

// Time返回交易首次在网络中看到的时间。这是一个启发式方法，
// 在其他条件相同的情况下优先挖掘较旧的交易而不是新交易。
func (tx *Transaction) Time() time.Time {
	return tx.time
}

// Hash返回交易哈希。
func (tx *Transaction) Hash() common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return *hash
	}

	var h common.Hash
	if tx.Type() == LegacyTxType {
		h = rlpHash(tx.inner)
	} else {
		h = prefixedRlpHash(tx.Type(), tx.inner)
	}
	tx.hash.Store(&h)
	return h
}

// Size返回交易的真实编码存储大小，通过编码并返回它，
// 或者返回先前缓存的值。
func (tx *Transaction) Size() uint64 {
	if size := tx.size.Load(); size > 0 {
		return size
	}

	// Cache miss, encode and cache.
	// 缓存未命中，编码并缓存。
	// Note we rely on the assumption that all tx.inner values are RLP-encoded!
	// 注意，我们依赖于所有tx.inner值都是RLP编码的假设！
	c := writeCounter(0)
	rlp.Encode(&c, &tx.inner)
	size := uint64(c)

	// For blob transactions, add the size of the blob content and the outer list of the
	// tx + sidecar encoding.
	// 对于blob交易，添加blob内容的大小和tx + sidecar编码的外部列表。
	if sc := tx.BlobTxSidecar(); sc != nil {
		size += rlp.ListSize(sc.encodedSize())
	}

	// For typed transactions, the encoding also includes the leading type byte.
	// 对于类型化交易，编码还包括前导类型字节。
	if tx.Type() != LegacyTxType {
		size += 1
	}

	tx.size.Store(size)
	return size
}

// WithSignature返回具有给定签名的新交易。
// 此签名需要采用[R || S || V]格式，其中V为0或1。
func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	if r == nil || s == nil || v == nil {
		return nil, fmt.Errorf("%w: r: %s, s: %s, v: %s", ErrInvalidSig, r, s, v)
	}
	cpy := tx.inner.copy()
	cpy.setSignatureValues(signer.ChainID(), v, r, s)
	return &Transaction{inner: cpy, time: tx.time}, nil
}

// Transactions implements DerivableList for transactions.
// Transactions为交易实现DerivableList接口。
type Transactions []*Transaction

// Len returns the length of s.
// Len返回s的长度。
func (s Transactions) Len() int { return len(s) }

// EncodeIndex encodes the i'th transaction to w. Note that this does not check for errors
// because we assume that *Transaction will only ever contain valid txs that were either
// constructed by decoding or via public API in this package.
// EncodeIndex将第i个交易编码到w。注意，这不检查错误，
// 因为我们假设*Transaction只会包含通过解码或通过此包中的公共API
// 构造的有效交易。
func (s Transactions) EncodeIndex(i int, w *bytes.Buffer) {
	tx := s[i]
	if tx.Type() == LegacyTxType {
		rlp.Encode(w, tx.inner)
	} else {
		tx.encodeTyped(w)
	}
}

// TxDifference returns a new set of transactions that are present in a but not in b.
// TxDifference返回存在于a但不存在于b中的新交易集合。
func TxDifference(a, b Transactions) Transactions {
	keep := make(Transactions, 0, len(a))

	remove := make(map[common.Hash]struct{}, b.Len())
	for _, tx := range b {
		remove[tx.Hash()] = struct{}{}
	}

	for _, tx := range a {
		if _, ok := remove[tx.Hash()]; !ok {
			keep = append(keep, tx)
		}
	}

	return keep
}

// HashDifference returns a new set of hashes that are present in a but not in b.
// HashDifference返回存在于a但不存在于b中的新哈希集合。
func HashDifference(a, b []common.Hash) []common.Hash {
	keep := make([]common.Hash, 0, len(a))

	remove := make(map[common.Hash]struct{})
	for _, hash := range b {
		remove[hash] = struct{}{}
	}

	for _, hash := range a {
		if _, ok := remove[hash]; !ok {
			keep = append(keep, hash)
		}
	}

	return keep
}

// TxByNonce implements the sort interface to allow sorting a list of transactions
// by their nonces. This is usually only useful for sorting transactions from a
// single account, otherwise a nonce comparison doesn't make much sense.
// TxByNonce实现了排序接口，允许按nonce排序交易列表。
// 这通常只对对单个账户的交易进行排序有用，否则nonce比较没有多大意义。
type TxByNonce Transactions

func (s TxByNonce) Len() int           { return len(s) }
func (s TxByNonce) Less(i, j int) bool { return s[i].Nonce() < s[j].Nonce() }
func (s TxByNonce) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// copyAddressPtr copies an address.
// copyAddressPtr复制一个地址。
func copyAddressPtr(a *common.Address) *common.Address {
	if a == nil {
		return nil
	}
	cpy := *a
	return &cpy
}

// getPooledBuffer gets a pooled buffer and copies the encoded tx into it.
// getPooledBuffer获取一个池化缓冲区并将编码的交易复制到其中。
func getPooledBuffer(size uint64) ([]byte, *bytes.Buffer, error) {
	buf := encodeBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.Grow(int(size))
	_, err := io.CopyN(buf, rand.Reader, int64(size))
	return buf.Bytes(), buf, err
}

// prefixedRlpHash computes the hash of the data by first adding the prefix.
// prefixedRlpHash通过首先添加前缀来计算数据的哈希。
func prefixedRlpHash(prefix byte, x interface{}) (h common.Hash) {
	sha := sha3.NewLegacyKeccak256()
	sha.Write([]byte{prefix})
	rlp.Encode(sha, x)
	sha.Sum(h[:0])
	return h
}

// writeCounter counts the bytes written to it.
// writeCounter计算写入的字节数。
type writeCounter int

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}
