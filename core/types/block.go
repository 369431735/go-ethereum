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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"slices"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-verkle"
)

// A BlockNonce is a 64-bit hash which proves (combined with the
// mix-hash) that a sufficient amount of computation has been carried
// out on a block.
// BlockNonce是一个64位哈希值，它（与mix-hash结合）证明了
// 在区块上已经进行了足够的计算量。
type BlockNonce [8]byte

// EncodeNonce converts the given integer to a block nonce.
// EncodeNonce将给定的整数转换为区块nonce。
func EncodeNonce(i uint64) BlockNonce {
	var n BlockNonce
	binary.BigEndian.PutUint64(n[:], i)
	return n
}

// Uint64 returns the integer value of a block nonce.
// Uint64返回区块nonce的整数值。
func (n BlockNonce) Uint64() uint64 {
	return binary.BigEndian.Uint64(n[:])
}

// MarshalText encodes n as a hex string with 0x prefix.
func (n BlockNonce) MarshalText() ([]byte, error) {
	return hexutil.Bytes(n[:]).MarshalText()
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (n *BlockNonce) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("BlockNonce", input, n[:])
}

// ExecutionWitness represents the witness + proof used in a verkle context,
// to provide the ability to execute a block statelessly.
// ExecutionWitness表示在verkle上下文中使用的见证+证明，
// 用于提供无状态执行区块的能力。
type ExecutionWitness struct {
	StateDiff   verkle.StateDiff    `json:"stateDiff"`
	VerkleProof *verkle.VerkleProof `json:"verkleProof"`
}

//go:generate go run github.com/fjl/gencodec -type Header -field-override headerMarshaling -out gen_header_json.go
//go:generate go run ../../rlp/rlpgen -type Header -out gen_header_rlp.go

// Header represents a block header in the Ethereum blockchain.
// Header表示以太坊区块链中的区块头。
type Header struct {
	ParentHash  common.Hash    `json:"parentHash"       gencodec:"required"`
	UncleHash   common.Hash    `json:"sha3Uncles"       gencodec:"required"`
	Coinbase    common.Address `json:"miner"`
	Root        common.Hash    `json:"stateRoot"        gencodec:"required"`
	TxHash      common.Hash    `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash common.Hash    `json:"receiptsRoot"     gencodec:"required"`
	Bloom       Bloom          `json:"logsBloom"        gencodec:"required"`
	Difficulty  *big.Int       `json:"difficulty"       gencodec:"required"`
	Number      *big.Int       `json:"number"           gencodec:"required"`
	GasLimit    uint64         `json:"gasLimit"         gencodec:"required"`
	GasUsed     uint64         `json:"gasUsed"          gencodec:"required"`
	Time        uint64         `json:"timestamp"        gencodec:"required"`
	Extra       []byte         `json:"extraData"        gencodec:"required"`
	MixDigest   common.Hash    `json:"mixHash"`
	Nonce       BlockNonce     `json:"nonce"`

	// BaseFee was added by EIP-1559 and is ignored in legacy headers.
	BaseFee *big.Int `json:"baseFeePerGas" rlp:"optional"`

	// WithdrawalsHash was added by EIP-4895 and is ignored in legacy headers.
	WithdrawalsHash *common.Hash `json:"withdrawalsRoot" rlp:"optional"`

	// BlobGasUsed was added by EIP-4844 and is ignored in legacy headers.
	BlobGasUsed *uint64 `json:"blobGasUsed" rlp:"optional"`

	// ExcessBlobGas was added by EIP-4844 and is ignored in legacy headers.
	ExcessBlobGas *uint64 `json:"excessBlobGas" rlp:"optional"`

	// ParentBeaconRoot was added by EIP-4788 and is ignored in legacy headers.
	ParentBeaconRoot *common.Hash `json:"parentBeaconBlockRoot" rlp:"optional"`

	// RequestsHash was added by EIP-7685 and is ignored in legacy headers.
	RequestsHash *common.Hash `json:"requestsHash" rlp:"optional"`
}

// field type overrides for gencodec
type headerMarshaling struct {
	Difficulty    *hexutil.Big
	Number        *hexutil.Big
	GasLimit      hexutil.Uint64
	GasUsed       hexutil.Uint64
	Time          hexutil.Uint64
	Extra         hexutil.Bytes
	BaseFee       *hexutil.Big
	Hash          common.Hash `json:"hash"` // adds call to Hash() in MarshalJSON
	BlobGasUsed   *hexutil.Uint64
	ExcessBlobGas *hexutil.Uint64
}

// Hash returns the block hash of the header, which is simply the keccak256 hash of its
// RLP encoding.
// Hash返回区块头的区块哈希，即其RLP编码的keccak256哈希。
func (h *Header) Hash() common.Hash {
	return rlpHash(h)
}

var headerSize = common.StorageSize(reflect.TypeOf(Header{}).Size())

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (h *Header) Size() common.StorageSize {
	var baseFeeBits int
	if h.BaseFee != nil {
		baseFeeBits = h.BaseFee.BitLen()
	}
	return headerSize + common.StorageSize(len(h.Extra)+(h.Difficulty.BitLen()+h.Number.BitLen()+baseFeeBits)/8)
}

// SanityCheck checks a few basic things -- these checks are way beyond what
// any 'sane' production values should hold, and can mainly be used to prevent
// that the unbounded fields are stuffed with junk data to add processing
// overhead
// SanityCheck检查一些基本事项 -- 这些检查远超任何"正常"生产值应该有的范围，
// 主要用于防止无界字段被填充垃圾数据以增加处理开销
func (h *Header) SanityCheck() error {
	if h.Number != nil && !h.Number.IsUint64() {
		return fmt.Errorf("too large block number: bitlen %d", h.Number.BitLen())
	}
	if h.Difficulty != nil {
		if diffLen := h.Difficulty.BitLen(); diffLen > 80 {
			return fmt.Errorf("too large block difficulty: bitlen %d", diffLen)
		}
	}
	if eLen := len(h.Extra); eLen > 100*1024 {
		return fmt.Errorf("too large block extradata: size %d", eLen)
	}
	if h.BaseFee != nil {
		if bfLen := h.BaseFee.BitLen(); bfLen > 256 {
			return fmt.Errorf("too large base fee: bitlen %d", bfLen)
		}
	}
	return nil
}

// EmptyBody returns true if there is no additional 'body' to complete the header
// that is: no transactions, no uncles and no withdrawals.
// EmptyBody在没有额外的"主体"来完成区块头时返回true，
// 即：没有交易、没有叔块和没有提款。
func (h *Header) EmptyBody() bool {
	var (
		emptyWithdrawals = h.WithdrawalsHash == nil || *h.WithdrawalsHash == EmptyWithdrawalsHash
	)
	return h.TxHash == EmptyTxsHash && h.UncleHash == EmptyUncleHash && emptyWithdrawals
}

// EmptyReceipts returns true if there are no receipts for this header/block.
// EmptyReceipts在此区块头/区块没有收据时返回true。
func (h *Header) EmptyReceipts() bool {
	return h.ReceiptHash == EmptyReceiptsHash
}

// Body is a simple (mutable, non-safe) data container for storing and moving
// a block's data contents (transactions and uncles) together.
// Body是一个简单的（可变的，非安全的）数据容器，用于存储和移动
// 区块的数据内容（交易和叔块）。
type Body struct {
	Transactions []*Transaction
	Uncles       []*Header
	Withdrawals  []*Withdrawal `rlp:"optional"`
}

// Block represents an Ethereum block.
// Block表示一个以太坊区块。
//
// Note the Block type tries to be 'immutable', and contains certain caches that rely
// on that. The rules around block immutability are as follows:
// 注意Block类型尝试保持"不可变"，并包含依赖于此的某些缓存。
// 关于区块不可变性的规则如下：
//
//   - We copy all data when the block is constructed. This makes references held inside
//     the block independent of whatever value was passed in.
//
//   - 在构造区块时，我们复制所有数据。这使得区块内部持有的引用独立于传入的值。
//
//   - We copy all header data on access. This is because any change to the header would mess
//     up the cached hash and size values in the block. Calling code is expected to take
//     advantage of this to avoid over-allocating!
//
//   - 在访问时我们复制所有区块头数据。这是因为对区块头的任何更改都会
//     破坏区块中缓存的哈希和大小值。调用代码应利用这一点以避免过度分配！
//
//   - When new body data is attached to the block, a shallow copy of the block is returned.
//     This ensures block modifications are race-free.
//
//   - 当新的主体数据附加到区块时，会返回区块的浅拷贝。
//     这确保区块修改是无竞争的。
//
//   - We do not copy body data on access because it does not affect the caches, and also
//     because it would be too expensive.
//
//   - 我们在访问时不复制主体数据，因为它不影响缓存，
//     而且复制成本也太高。
type Block struct {
	header       *Header
	uncles       []*Header
	transactions Transactions
	withdrawals  Withdrawals

	// witness is not an encoded part of the block body.
	// It is held in Block in order for easy relaying to the places
	// that process it.
	witness *ExecutionWitness

	// caches
	hash atomic.Pointer[common.Hash]
	size atomic.Uint64

	// These fields are used by package eth to track
	// inter-peer block relay.
	ReceivedAt   time.Time
	ReceivedFrom interface{}
}

// "external" block encoding. used for eth protocol, etc.
type extblock struct {
	Header      *Header
	Txs         []*Transaction
	Uncles      []*Header
	Withdrawals []*Withdrawal `rlp:"optional"`
}

// NewBlock creates a new block. The input data is copied, changes to header and to the
// field values will not affect the block.
// NewBlock创建一个新区块。输入数据被复制，对区块头和字段值的更改不会影响区块。
//
// The body elements and the receipts are used to recompute and overwrite the
// relevant portions of the header.
// 主体元素和收据用于重新计算和覆盖区块头的相关部分。
//
// The receipt's bloom must already calculated for the block's bloom to be
// correctly calculated.
// 收据的布隆过滤器必须已经计算好，以便正确计算区块的布隆过滤器。
func NewBlock(header *Header, body *Body, receipts []*Receipt, hasher TrieHasher) *Block {
	if body == nil {
		body = &Body{}
	}
	var (
		b           = NewBlockWithHeader(header)
		txs         = body.Transactions
		uncles      = body.Uncles
		withdrawals = body.Withdrawals
	)

	if len(txs) == 0 {
		b.header.TxHash = EmptyTxsHash
	} else {
		b.header.TxHash = DeriveSha(Transactions(txs), hasher)
		b.transactions = make(Transactions, len(txs))
		copy(b.transactions, txs)
	}

	if len(receipts) == 0 {
		b.header.ReceiptHash = EmptyReceiptsHash
	} else {
		b.header.ReceiptHash = DeriveSha(Receipts(receipts), hasher)
		// Receipts must go through MakeReceipt to calculate the receipt's bloom
		// already. Merge the receipt's bloom together instead of recalculating
		// everything.
		b.header.Bloom = MergeBloom(receipts)
	}

	if len(uncles) == 0 {
		b.header.UncleHash = EmptyUncleHash
	} else {
		b.header.UncleHash = CalcUncleHash(uncles)
		b.uncles = make([]*Header, len(uncles))
		for i := range uncles {
			b.uncles[i] = CopyHeader(uncles[i])
		}
	}

	if withdrawals == nil {
		b.header.WithdrawalsHash = nil
	} else if len(withdrawals) == 0 {
		b.header.WithdrawalsHash = &EmptyWithdrawalsHash
		b.withdrawals = Withdrawals{}
	} else {
		hash := DeriveSha(Withdrawals(withdrawals), hasher)
		b.header.WithdrawalsHash = &hash
		b.withdrawals = slices.Clone(withdrawals)
	}

	return b
}

// CopyHeader creates a deep copy of a block header.
// CopyHeader创建区块头的深拷贝。
func CopyHeader(h *Header) *Header {
	cpy := *h
	if cpy.Difficulty = new(big.Int); h.Difficulty != nil {
		cpy.Difficulty.Set(h.Difficulty)
	}
	if cpy.Number = new(big.Int); h.Number != nil {
		cpy.Number.Set(h.Number)
	}
	if h.BaseFee != nil {
		cpy.BaseFee = new(big.Int).Set(h.BaseFee)
	}
	if len(h.Extra) > 0 {
		cpy.Extra = make([]byte, len(h.Extra))
		copy(cpy.Extra, h.Extra)
	}
	if h.WithdrawalsHash != nil {
		cpy.WithdrawalsHash = new(common.Hash)
		*cpy.WithdrawalsHash = *h.WithdrawalsHash
	}
	if h.ExcessBlobGas != nil {
		cpy.ExcessBlobGas = new(uint64)
		*cpy.ExcessBlobGas = *h.ExcessBlobGas
	}
	if h.BlobGasUsed != nil {
		cpy.BlobGasUsed = new(uint64)
		*cpy.BlobGasUsed = *h.BlobGasUsed
	}
	if h.ParentBeaconRoot != nil {
		cpy.ParentBeaconRoot = new(common.Hash)
		*cpy.ParentBeaconRoot = *h.ParentBeaconRoot
	}
	if h.RequestsHash != nil {
		cpy.RequestsHash = new(common.Hash)
		*cpy.RequestsHash = *h.RequestsHash
	}
	return &cpy
}

// DecodeRLP decodes a block from RLP.
// DecodeRLP从RLP解码一个区块。
func (b *Block) DecodeRLP(s *rlp.Stream) error {
	var eb extblock
	_, size, _ := s.Kind()
	if err := s.Decode(&eb); err != nil {
		return err
	}
	b.header, b.uncles, b.transactions, b.withdrawals = eb.Header, eb.Uncles, eb.Txs, eb.Withdrawals
	b.size.Store(rlp.ListSize(size))
	return nil
}

// EncodeRLP serializes a block as RLP.
// EncodeRLP将区块序列化为RLP。
func (b *Block) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &extblock{
		Header:      b.header,
		Txs:         b.transactions,
		Uncles:      b.uncles,
		Withdrawals: b.withdrawals,
	})
}

// Body returns the non-header content of the block.
// Note the returned data is not an independent copy.
// Body返回区块的非区块头内容。
// 注意返回的数据不是独立副本。
func (b *Block) Body() *Body {
	return &Body{b.transactions, b.uncles, b.withdrawals}
}

// Accessors for body data. These do not return a copy because the content
// of the body slices does not affect the cached hash/size in block.
// 主体数据的访问器。这些不返回副本，因为主体切片的内容
// 不影响区块中缓存的哈希/大小。

// Uncles returns the uncle block headers.
// Uncles返回叔块区块头。
func (b *Block) Uncles() []*Header { return b.uncles }

// Transactions returns the block transactions.
// Transactions返回区块交易。
func (b *Block) Transactions() Transactions { return b.transactions }

// Withdrawals returns the block withdrawals.
// Withdrawals返回区块提款。
func (b *Block) Withdrawals() Withdrawals { return b.withdrawals }

// Transaction returns a specific transaction in the block.
// Transaction返回区块中的特定交易。
func (b *Block) Transaction(hash common.Hash) *Transaction {
	for _, transaction := range b.transactions {
		if transaction.Hash() == hash {
			return transaction
		}
	}
	return nil
}

// Header returns the block header (as a copy).
// Header返回区块头（作为副本）。
func (b *Block) Header() *Header {
	return CopyHeader(b.header)
}

// Header value accessors. These do copy!
// 区块头值访问器。这些会进行复制！

// Number returns the block number.
// Number返回区块号。
func (b *Block) Number() *big.Int { return new(big.Int).Set(b.header.Number) }

// GasLimit returns the gas limit of the block.
// GasLimit返回区块的gas限制。
func (b *Block) GasLimit() uint64 { return b.header.GasLimit }

// GasUsed returns the amount of gas used in the block.
// GasUsed返回区块中使用的gas数量。
func (b *Block) GasUsed() uint64 { return b.header.GasUsed }

// Difficulty returns the difficulty of the block.
// Difficulty返回区块的难度。
func (b *Block) Difficulty() *big.Int { return new(big.Int).Set(b.header.Difficulty) }

// Time returns the timestamp of the block.
// Time返回区块的时间戳。
func (b *Block) Time() uint64 { return b.header.Time }

// NumberU64 returns the block number in uint64.
// NumberU64以uint64形式返回区块号。
func (b *Block) NumberU64() uint64 { return b.header.Number.Uint64() }

// MixDigest returns the mix digest of the block.
// MixDigest返回区块的混合摘要。
func (b *Block) MixDigest() common.Hash { return b.header.MixDigest }

// Nonce returns the nonce of the block.
// Nonce返回区块的nonce值。
func (b *Block) Nonce() uint64 { return binary.BigEndian.Uint64(b.header.Nonce[:]) }

// Bloom returns the bloom filter of the block.
// Bloom返回区块的布隆过滤器。
func (b *Block) Bloom() Bloom { return b.header.Bloom }

// Coinbase returns the coinbase address of the block.
// Coinbase返回区块的coinbase地址。
func (b *Block) Coinbase() common.Address { return b.header.Coinbase }

// Root returns the state root hash of the block.
// Root返回区块的状态根哈希。
func (b *Block) Root() common.Hash { return b.header.Root }

// ParentHash returns the parent hash of the block.
// ParentHash返回区块的父哈希。
func (b *Block) ParentHash() common.Hash { return b.header.ParentHash }

// TxHash returns the transaction root hash of the block.
// TxHash返回区块的交易根哈希。
func (b *Block) TxHash() common.Hash { return b.header.TxHash }

// ReceiptHash returns the receipt root hash of the block.
// ReceiptHash返回区块的收据根哈希。
func (b *Block) ReceiptHash() common.Hash { return b.header.ReceiptHash }

// UncleHash returns the uncle root hash of the block.
// UncleHash返回区块的叔块根哈希。
func (b *Block) UncleHash() common.Hash { return b.header.UncleHash }

// Extra returns the extra data of the block.
// Extra返回区块的额外数据。
func (b *Block) Extra() []byte { return common.CopyBytes(b.header.Extra) }

// BaseFee returns the EIP-1559 base fee of the block.
// BaseFee返回区块的EIP-1559基础费用。
func (b *Block) BaseFee() *big.Int {
	if b.header.BaseFee == nil {
		return nil
	}
	return new(big.Int).Set(b.header.BaseFee)
}

// BeaconRoot returns the beacon root of the block.
// BeaconRoot返回区块的信标根。
func (b *Block) BeaconRoot() *common.Hash { return b.header.ParentBeaconRoot }

// RequestsHash returns the requests hash of the block.
// RequestsHash返回区块的请求哈希。
func (b *Block) RequestsHash() *common.Hash { return b.header.RequestsHash }

// ExcessBlobGas returns the excess blob gas of the block.
// ExcessBlobGas返回区块的超额blob gas。
func (b *Block) ExcessBlobGas() *uint64 {
	var excessBlobGas *uint64
	if b.header.ExcessBlobGas != nil {
		excessBlobGas = new(uint64)
		*excessBlobGas = *b.header.ExcessBlobGas
	}
	return excessBlobGas
}

// BlobGasUsed returns the blob gas used of the block.
// BlobGasUsed返回区块使用的blob gas。
func (b *Block) BlobGasUsed() *uint64 {
	var blobGasUsed *uint64
	if b.header.BlobGasUsed != nil {
		blobGasUsed = new(uint64)
		*blobGasUsed = *b.header.BlobGasUsed
	}
	return blobGasUsed
}

// ExecutionWitness returns the verkle execution witneess + proof for a block
// ExecutionWitness返回区块的verkle执行见证+证明
func (b *Block) ExecutionWitness() *ExecutionWitness { return b.witness }

// Size returns the true RLP encoded storage size of the block, either by encoding
// and returning it, or returning a previously cached value.
// Size返回区块的真实RLP编码存储大小，通过编码并返回它，
// 或者返回先前缓存的值。
func (b *Block) Size() uint64 {
	if size := b.size.Load(); size > 0 {
		return size
	}
	c := writeCounter(0)
	rlp.Encode(&c, b)
	b.size.Store(uint64(c))
	return uint64(c)
}

// SanityCheck can be used to prevent that unbounded fields are
// stuffed with junk data to add processing overhead
// SanityCheck可用于防止无界字段被填充垃圾数据以增加处理开销
func (b *Block) SanityCheck() error {
	return b.header.SanityCheck()
}

type writeCounter uint64

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}

// CalcUncleHash calculates the uncle hash of a list of uncles.
// CalcUncleHash计算叔块列表的叔块哈希。
func CalcUncleHash(uncles []*Header) common.Hash {
	if len(uncles) == 0 {
		return EmptyUncleHash
	}
	return rlpHash(uncles)
}

// CalcRequestsHash creates the block requestsHash value for a list of requests.
// CalcRequestsHash为请求列表创建区块requestsHash值。
func CalcRequestsHash(requests [][]byte) common.Hash {
	h1, h2 := sha256.New(), sha256.New()
	var buf common.Hash
	for _, item := range requests {
		if len(item) > 1 { // skip items with only requestType and no data.
			h1.Reset()
			h1.Write(item)
			h2.Write(h1.Sum(buf[:0]))
		}
	}
	h2.Sum(buf[:0])
	return buf
}

// NewBlockWithHeader creates a block with the given header data. The
// header data is copied, changes to header and to the field values
// will not affect the block.
// NewBlockWithHeader使用给定的区块头数据创建一个区块。
// 区块头数据被复制，对区块头和字段值的更改不会影响区块。
func NewBlockWithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

// WithSeal returns a new block with the data from b but the header replaced with
// the sealed one.
// WithSeal返回一个新区块，数据来自b但区块头替换为封存的区块头。
func (b *Block) WithSeal(header *Header) *Block {
	return &Block{
		header:       CopyHeader(header),
		transactions: b.transactions,
		uncles:       b.uncles,
		withdrawals:  b.withdrawals,
		witness:      b.witness,
	}
}

// WithBody returns a new block with the original header and a deep copy of the
// provided body.
// WithBody返回一个新区块，包含原始区块头和提供的主体的深拷贝。
func (b *Block) WithBody(body Body) *Block {
	block := &Block{
		header:       b.header,
		transactions: slices.Clone(body.Transactions),
		uncles:       make([]*Header, len(body.Uncles)),
		withdrawals:  slices.Clone(body.Withdrawals),
		witness:      b.witness,
	}
	for i := range body.Uncles {
		block.uncles[i] = CopyHeader(body.Uncles[i])
	}
	return block
}

// WithWitness returns a new block with the witness set.
// WithWitness返回一个设置了见证的新区块。
func (b *Block) WithWitness(witness *ExecutionWitness) *Block {
	return &Block{
		header:       b.header,
		transactions: b.transactions,
		uncles:       b.uncles,
		withdrawals:  b.withdrawals,
		witness:      witness,
	}
}

// Hash returns the keccak256 hash of b's header.
// The hash is computed on the first call and cached thereafter.
// Hash返回b的区块头的keccak256哈希。
// 哈希在第一次调用时计算，此后缓存。
func (b *Block) Hash() common.Hash {
	if hash := b.hash.Load(); hash != nil {
		return *hash
	}
	h := b.header.Hash()
	b.hash.Store(&h)
	return h
}

// Blocks is a slice of Block.
// Blocks是Block的切片。
type Blocks []*Block

// HeaderParentHashFromRLP returns the parentHash of an RLP-encoded
// header. If 'header' is invalid, the zero hash is returned.
// HeaderParentHashFromRLP返回RLP编码的区块头的parentHash。
// 如果'header'无效，则返回零哈希。
func HeaderParentHashFromRLP(header []byte) common.Hash {
	// parentHash is the first list element.
	listContent, _, err := rlp.SplitList(header)
	if err != nil {
		return common.Hash{}
	}
	parentHash, _, err := rlp.SplitString(listContent)
	if err != nil {
		return common.Hash{}
	}
	if len(parentHash) != 32 {
		return common.Hash{}
	}
	return common.BytesToHash(parentHash)
}
