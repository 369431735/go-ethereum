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
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// bytesBacked接口定义了能够返回底层字节表示的类型
type bytesBacked interface {
	Bytes() []byte
}

const (
	// BloomByteLength represents the number of bytes used in a header log bloom.
	// BloomByteLength表示在区块头日志布隆过滤器中使用的字节数。
	BloomByteLength = 256

	// BloomBitLength represents the number of bits used in a header log bloom.
	// BloomBitLength表示在区块头日志布隆过滤器中使用的位数。
	BloomBitLength = 8 * BloomByteLength
)

// Bloom represents a 2048 bit bloom filter.
// Bloom表示一个2048位的布隆过滤器。
type Bloom [BloomByteLength]byte

// BytesToBloom converts a byte slice to a bloom filter.
// It panics if b is not of suitable size.
// BytesToBloom将字节切片转换为布隆过滤器。
// 如果b不是合适的大小，则会引发panic。
func BytesToBloom(b []byte) Bloom {
	var bloom Bloom
	bloom.SetBytes(b)
	return bloom
}

// SetBytes sets the content of b to the given bytes.
// It panics if d is not of suitable size.
// SetBytes将b的内容设置为给定的字节。
// 如果d不是合适的大小，则会引发panic。
func (b *Bloom) SetBytes(d []byte) {
	if len(b) < len(d) {
		panic(fmt.Sprintf("bloom bytes too big %d %d", len(b), len(d)))
	}
	copy(b[BloomByteLength-len(d):], d)
}

// Add adds d to the filter. Future calls of Test(d) will return true.
// Add将d添加到过滤器中。未来调用Test(d)将返回true。
func (b *Bloom) Add(d []byte) {
	b.add(d, make([]byte, 6))
}

// add is internal version of Add, which takes a scratch buffer for reuse (needs to be at least 6 bytes)
// add是Add的内部版本，它接受一个可重用的临时缓冲区（至少需要6个字节）
func (b *Bloom) add(d []byte, buf []byte) {
	i1, v1, i2, v2, i3, v3 := bloomValues(d, buf)
	b[i1] |= v1
	b[i2] |= v2
	b[i3] |= v3
}

// Big converts b to a big integer.
// Note: Converting a bloom filter to a big.Int and then calling GetBytes
// does not return the same bytes, since big.Int will trim leading zeroes
// Big将b转换为大整数。
// 注意：将布隆过滤器转换为big.Int然后调用GetBytes
// 不会返回相同的字节，因为big.Int会修剪前导零
func (b Bloom) Big() *big.Int {
	return new(big.Int).SetBytes(b[:])
}

// Bytes returns the backing byte slice of the bloom
// Bytes返回布隆过滤器的底层字节切片
func (b Bloom) Bytes() []byte {
	return b[:]
}

// Test checks if the given topic is present in the bloom filter
// Test检查给定的主题是否存在于布隆过滤器中
func (b Bloom) Test(topic []byte) bool {
	i1, v1, i2, v2, i3, v3 := bloomValues(topic, make([]byte, 6))
	return v1 == v1&b[i1] &&
		v2 == v2&b[i2] &&
		v3 == v3&b[i3]
}

// MarshalText encodes b as a hex string with 0x prefix.
// MarshalText将b编码为带有0x前缀的十六进制字符串。
func (b Bloom) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText()
}

// UnmarshalText b as a hex string with 0x prefix.
// UnmarshalText将b解码为带有0x前缀的十六进制字符串。
func (b *Bloom) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Bloom", input, b[:])
}

// CreateBloom creates a bloom filter out of the give Receipt (+Logs)
// CreateBloom根据给定的收据（及其日志）创建布隆过滤器
func CreateBloom(receipt *Receipt) Bloom {
	var (
		bin Bloom
		buf = make([]byte, 6)
	)
	for _, log := range receipt.Logs {
		bin.add(log.Address.Bytes(), buf)
		for _, b := range log.Topics {
			bin.add(b[:], buf)
		}
	}
	return bin
}

// MergeBloom merges the precomputed bloom filters in the Receipts without
// recalculating them. It assumes that each receipt's Bloom field is already
// correctly populated.
// MergeBloom合并收据中预先计算的布隆过滤器，无需重新计算。
// 它假设每个收据的Bloom字段已经正确填充。
func MergeBloom(receipts Receipts) Bloom {
	var bin Bloom
	for _, receipt := range receipts {
		if len(receipt.Logs) != 0 {
			bl := receipt.Bloom.Bytes()
			for i := range bin {
				bin[i] |= bl[i]
			}
		}
	}
	return bin
}

// Bloom9 returns the bloom filter for the given data
// Bloom9返回给定数据的布隆过滤器
func Bloom9(data []byte) []byte {
	var b Bloom
	b.SetBytes(data)
	return b.Bytes()
}

// bloomValues returns the bytes (index-value pairs) to set for the given data
// bloomValues返回给定数据要设置的字节（索引-值对）
func bloomValues(data []byte, hashbuf []byte) (uint, byte, uint, byte, uint, byte) {
	sha := hasherPool.Get().(crypto.KeccakState)
	sha.Reset()
	sha.Write(data)
	sha.Read(hashbuf)
	hasherPool.Put(sha)
	// The actual bits to flip
	// 要翻转的实际位
	v1 := byte(1 << (hashbuf[1] & 0x7))
	v2 := byte(1 << (hashbuf[3] & 0x7))
	v3 := byte(1 << (hashbuf[5] & 0x7))
	// The indices for the bytes to OR in
	// 要进行OR操作的字节的索引
	i1 := BloomByteLength - uint((binary.BigEndian.Uint16(hashbuf)&0x7ff)>>3) - 1
	i2 := BloomByteLength - uint((binary.BigEndian.Uint16(hashbuf[2:])&0x7ff)>>3) - 1
	i3 := BloomByteLength - uint((binary.BigEndian.Uint16(hashbuf[4:])&0x7ff)>>3) - 1

	return i1, v1, i2, v2, i3, v3
}

// BloomLookup is a convenience-method to check presence in the bloom filter
// BloomLookup是一个便捷方法，用于检查主题是否存在于布隆过滤器中
func BloomLookup(bin Bloom, topic bytesBacked) bool {
	return bin.Test(topic.Bytes())
}
