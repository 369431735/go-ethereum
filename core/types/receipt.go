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

package types

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

//go:generate go run github.com/fjl/gencodec -type Receipt -field-override receiptMarshaling -out gen_receipt_json.go

var (
	receiptStatusFailedRLP     = []byte{}
	receiptStatusSuccessfulRLP = []byte{0x01}
)

var errShortTypedReceipt = errors.New("typed receipt too short")

const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	// ReceiptStatusFailed是交易执行失败时的状态码。
	ReceiptStatusFailed = uint64(0)

	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	// ReceiptStatusSuccessful是交易执行成功时的状态码。
	ReceiptStatusSuccessful = uint64(1)
)

// Receipt represents the results of a transaction.
// Receipt表示交易的结果。
type Receipt struct {
	// Consensus fields: These fields are defined by the Yellow Paper
	// 共识字段：这些字段由黄皮书定义
	Type              uint8  `json:"type,omitempty"`
	PostState         []byte `json:"root"`
	Status            uint64 `json:"status"`
	CumulativeGasUsed uint64 `json:"cumulativeGasUsed" gencodec:"required"`
	Bloom             Bloom  `json:"logsBloom"         gencodec:"required"`
	Logs              []*Log `json:"logs"              gencodec:"required"`

	// Implementation fields: These fields are added by geth when processing a transaction.
	// 实现字段：这些字段是geth在处理交易时添加的。
	TxHash            common.Hash    `json:"transactionHash" gencodec:"required"`
	ContractAddress   common.Address `json:"contractAddress"`
	GasUsed           uint64         `json:"gasUsed" gencodec:"required"`
	EffectiveGasPrice *big.Int       `json:"effectiveGasPrice"` // required, but tag omitted for backwards compatibility
	BlobGasUsed       uint64         `json:"blobGasUsed,omitempty"`
	BlobGasPrice      *big.Int       `json:"blobGasPrice,omitempty"`

	// Inclusion information: These fields provide information about the inclusion of the
	// transaction corresponding to this receipt.
	// 包含信息：这些字段提供关于与此收据对应的交易包含的信息。
	BlockHash        common.Hash `json:"blockHash,omitempty"`
	BlockNumber      *big.Int    `json:"blockNumber,omitempty"`
	TransactionIndex uint        `json:"transactionIndex"`
}

type receiptMarshaling struct {
	Type              hexutil.Uint64
	PostState         hexutil.Bytes
	Status            hexutil.Uint64
	CumulativeGasUsed hexutil.Uint64
	GasUsed           hexutil.Uint64
	EffectiveGasPrice *hexutil.Big
	BlobGasUsed       hexutil.Uint64
	BlobGasPrice      *hexutil.Big
	BlockNumber       *hexutil.Big
	TransactionIndex  hexutil.Uint
}

// receiptRLP is the consensus encoding of a receipt.
// receiptRLP是收据的共识编码。
type receiptRLP struct {
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Bloom             Bloom
	Logs              []*Log
}

// storedReceiptRLP is the storage encoding of a receipt.
// storedReceiptRLP是收据的存储编码。
type storedReceiptRLP struct {
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Logs              []*Log
}

// NewReceipt creates a barebone transaction receipt, copying the init fields.
// Deprecated: create receipts using a struct literal instead.
// NewReceipt创建一个基本的交易收据，复制初始字段。
// 已弃用：请使用结构体字面量创建收据。
func NewReceipt(root []byte, failed bool, cumulativeGasUsed uint64) *Receipt {
	r := &Receipt{
		Type:              LegacyTxType,
		PostState:         common.CopyBytes(root),
		CumulativeGasUsed: cumulativeGasUsed,
	}
	if failed {
		r.Status = ReceiptStatusFailed
	} else {
		r.Status = ReceiptStatusSuccessful
	}
	return r
}

// EncodeRLP implements rlp.Encoder, and flattens the consensus fields of a receipt
// into an RLP stream. If no post state is present, byzantium fork is assumed.
// EncodeRLP实现rlp.Encoder接口，并将收据的共识字段扁平化为RLP流。
// 如果没有后置状态，则假定为拜占庭分叉。
func (r *Receipt) EncodeRLP(w io.Writer) error {
	data := &receiptRLP{r.statusEncoding(), r.CumulativeGasUsed, r.Bloom, r.Logs}
	if r.Type == LegacyTxType {
		return rlp.Encode(w, data)
	}
	buf := encodeBufferPool.Get().(*bytes.Buffer)
	defer encodeBufferPool.Put(buf)
	buf.Reset()
	if err := r.encodeTyped(data, buf); err != nil {
		return err
	}
	return rlp.Encode(w, buf.Bytes())
}

// encodeTyped writes the canonical encoding of a typed receipt to w.
// encodeTyped将类型化收据的规范编码写入w。
func (r *Receipt) encodeTyped(data *receiptRLP, w *bytes.Buffer) error {
	w.WriteByte(r.Type)
	return rlp.Encode(w, data)
}

// MarshalBinary returns the consensus encoding of the receipt.
// MarshalBinary返回收据的共识编码。
func (r *Receipt) MarshalBinary() ([]byte, error) {
	if r.Type == LegacyTxType {
		return rlp.EncodeToBytes(r)
	}
	data := &receiptRLP{r.statusEncoding(), r.CumulativeGasUsed, r.Bloom, r.Logs}
	var buf bytes.Buffer
	err := r.encodeTyped(data, &buf)
	return buf.Bytes(), err
}

// DecodeRLP implements rlp.Decoder, and loads the consensus fields of a receipt
// from an RLP stream.
// DecodeRLP实现rlp.Decoder接口，并从RLP流中加载收据的共识字段。
func (r *Receipt) DecodeRLP(s *rlp.Stream) error {
	kind, size, err := s.Kind()
	switch {
	case err != nil:
		return err
	case kind == rlp.List:
		// It's a legacy receipt.
		var dec receiptRLP
		if err := s.Decode(&dec); err != nil {
			return err
		}
		r.Type = LegacyTxType
		return r.setFromRLP(dec)
	case kind == rlp.Byte:
		return errShortTypedReceipt
	default:
		// It's an EIP-2718 typed tx receipt.
		b, buf, err := getPooledBuffer(size)
		if err != nil {
			return err
		}
		defer encodeBufferPool.Put(buf)
		if err := s.ReadBytes(b); err != nil {
			return err
		}
		return r.decodeTyped(b)
	}
}

// UnmarshalBinary decodes the consensus encoding of receipts.
// It supports legacy RLP receipts and EIP-2718 typed receipts.
// UnmarshalBinary解码收据的共识编码。
// 它支持传统的RLP收据和EIP-2718类型化收据。
func (r *Receipt) UnmarshalBinary(b []byte) error {
	if len(b) > 0 && b[0] > 0x7f {
		// It's a legacy receipt decode the RLP
		var data receiptRLP
		err := rlp.DecodeBytes(b, &data)
		if err != nil {
			return err
		}
		r.Type = LegacyTxType
		return r.setFromRLP(data)
	}
	// It's an EIP2718 typed transaction envelope.
	return r.decodeTyped(b)
}

// decodeTyped decodes a typed receipt from its canonical encoding.
// decodeTyped从其规范编码中解码类型化收据。
func (r *Receipt) decodeTyped(b []byte) error {
	if len(b) <= 1 {
		return errShortTypedReceipt
	}
	switch b[0] {
	case DynamicFeeTxType, AccessListTxType, BlobTxType, SetCodeTxType:
		var data receiptRLP
		err := rlp.DecodeBytes(b[1:], &data)
		if err != nil {
			return err
		}
		r.Type = b[0]
		return r.setFromRLP(data)
	default:
		return ErrTxTypeNotSupported
	}
}

// setFromRLP sets the receipt from the given receiptRLP.
// setFromRLP从给定的receiptRLP设置收据。
func (r *Receipt) setFromRLP(data receiptRLP) error {
	r.CumulativeGasUsed, r.Bloom, r.Logs = data.CumulativeGasUsed, data.Bloom, data.Logs
	return r.setStatus(data.PostStateOrStatus)
}

// setStatus sets the status of the receipt from the given post state or status.
// setStatus从给定的后置状态或状态设置收据的状态。
func (r *Receipt) setStatus(postStateOrStatus []byte) error {
	switch {
	case bytes.Equal(postStateOrStatus, receiptStatusSuccessfulRLP):
		r.Status = ReceiptStatusSuccessful
	case bytes.Equal(postStateOrStatus, receiptStatusFailedRLP):
		r.Status = ReceiptStatusFailed
	case len(postStateOrStatus) == len(common.Hash{}):
		r.PostState = postStateOrStatus
	default:
		return fmt.Errorf("invalid receipt status %x", postStateOrStatus)
	}
	return nil
}

// statusEncoding returns the status encoding of the receipt.
// statusEncoding返回收据的状态编码。
func (r *Receipt) statusEncoding() []byte {
	if len(r.PostState) == 0 {
		if r.Status == ReceiptStatusFailed {
			return receiptStatusFailedRLP
		}
		return receiptStatusSuccessfulRLP
	}
	return r.PostState
}

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
// Size返回所有内部内容使用的近似内存。它用于
// 近似和限制各种缓存的内存消耗。
func (r *Receipt) Size() common.StorageSize {
	size := common.StorageSize(unsafe.Sizeof(*r)) + common.StorageSize(len(r.PostState))
	size += common.StorageSize(len(r.Logs)) * common.StorageSize(unsafe.Sizeof(Log{}))
	for _, log := range r.Logs {
		size += common.StorageSize(len(log.Topics)*common.HashLength + len(log.Data))
	}
	return size
}

// ReceiptForStorage is a wrapper around a Receipt with RLP serialization
// that omits the Bloom field and deserialization that re-computes it.
// ReceiptForStorage是Receipt的包装器，具有RLP序列化
// 它省略了Bloom字段，并在反序列化时重新计算它。
type ReceiptForStorage Receipt

// EncodeRLP implements rlp.Encoder, and flattens all content fields of a receipt
// into an RLP stream.
// EncodeRLP实现rlp.Encoder接口，并将收据的所有内容字段扁平化为RLP流。
func (r *ReceiptForStorage) EncodeRLP(_w io.Writer) error {
	w := rlp.NewEncoderBuffer(_w)
	outerList := w.List()
	w.WriteBytes((*Receipt)(r).statusEncoding())
	w.WriteUint64(r.CumulativeGasUsed)
	logList := w.List()
	for _, log := range r.Logs {
		if err := log.EncodeRLP(w); err != nil {
			return err
		}
	}
	w.ListEnd(logList)
	w.ListEnd(outerList)
	return w.Flush()
}

// DecodeRLP implements rlp.Decoder, and loads both consensus and implementation
// fields of a receipt from an RLP stream.
// DecodeRLP实现rlp.Decoder接口，并从RLP流中加载收据的共识和实现字段。
func (r *ReceiptForStorage) DecodeRLP(s *rlp.Stream) error {
	var stored storedReceiptRLP
	if err := s.Decode(&stored); err != nil {
		return err
	}
	if err := (*Receipt)(r).setStatus(stored.PostStateOrStatus); err != nil {
		return err
	}
	r.CumulativeGasUsed = stored.CumulativeGasUsed
	r.Logs = stored.Logs
	r.Bloom = CreateBloom((*Receipt)(r))

	return nil
}

// Receipts implements DerivableList for receipts.
// Receipts为收据实现DerivableList接口。
type Receipts []*Receipt

// Len returns the number of receipts in this list.
// Len返回此列表中收据的数量。
func (rs Receipts) Len() int { return len(rs) }

// EncodeIndex encodes the i'th receipt to w.
// EncodeIndex将第i个收据编码到w。
func (rs Receipts) EncodeIndex(i int, w *bytes.Buffer) {
	r := rs[i]
	data := &receiptRLP{r.statusEncoding(), r.CumulativeGasUsed, r.Bloom, r.Logs}
	if r.Type == LegacyTxType {
		rlp.Encode(w, data)
		return
	}
	w.WriteByte(r.Type)
	switch r.Type {
	case AccessListTxType, DynamicFeeTxType, BlobTxType, SetCodeTxType:
		rlp.Encode(w, data)
	default:
		// For unsupported types, write nothing. Since this is for
		// DeriveSha, the error will be caught matching the derived hash
		// to the block.
	}
}

// DeriveFields fills the receipts with their computed fields based on consensus
// data and contextual infos like containing block and transactions.
// DeriveFields根据共识数据和上下文信息（如包含区块和交易）
// 填充收据的计算字段。
func (rs Receipts) DeriveFields(config *params.ChainConfig, hash common.Hash, number uint64, time uint64, baseFee *big.Int, blobGasPrice *big.Int, txs []*Transaction) error {
	signer := MakeSigner(config, new(big.Int).SetUint64(number), time)

	logIndex := uint(0)
	if len(txs) != len(rs) {
		return errors.New("transaction and receipt count mismatch")
	}
	for i := 0; i < len(rs); i++ {
		// The transaction type and hash can be retrieved from the transaction itself
		rs[i].Type = txs[i].Type()
		rs[i].TxHash = txs[i].Hash()
		rs[i].EffectiveGasPrice = txs[i].inner.effectiveGasPrice(new(big.Int), baseFee)

		// EIP-4844 blob transaction fields
		if txs[i].Type() == BlobTxType {
			rs[i].BlobGasUsed = txs[i].BlobGas()
			rs[i].BlobGasPrice = blobGasPrice
		}

		// block location fields
		rs[i].BlockHash = hash
		rs[i].BlockNumber = new(big.Int).SetUint64(number)
		rs[i].TransactionIndex = uint(i)

		// The contract address can be derived from the transaction itself
		if txs[i].To() == nil {
			// Deriving the signer is expensive, only do if it's actually needed
			from, _ := Sender(signer, txs[i])
			rs[i].ContractAddress = crypto.CreateAddress(from, txs[i].Nonce())
		} else {
			rs[i].ContractAddress = common.Address{}
		}

		// The used gas can be calculated based on previous r
		if i == 0 {
			rs[i].GasUsed = rs[i].CumulativeGasUsed
		} else {
			rs[i].GasUsed = rs[i].CumulativeGasUsed - rs[i-1].CumulativeGasUsed
		}

		// The derived log fields can simply be set from the block and transaction
		for j := 0; j < len(rs[i].Logs); j++ {
			rs[i].Logs[j].BlockNumber = number
			rs[i].Logs[j].BlockHash = hash
			rs[i].Logs[j].TxHash = rs[i].TxHash
			rs[i].Logs[j].TxIndex = uint(i)
			rs[i].Logs[j].Index = logIndex
			logIndex++
		}
	}
	return nil
}
