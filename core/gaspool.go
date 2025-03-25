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
	"fmt"
	"math"
)

// GasPool tracks the amount of gas available during execution of the transactions
// in a block. The zero value is a pool with zero gas available.
// GasPool 跟踪区块中交易执行期间可用的gas量。
// 零值表示没有可用gas的池。
type GasPool uint64

// AddGas makes gas available for execution.
// AddGas 使gas可用于执行。
func (gp *GasPool) AddGas(amount uint64) *GasPool {
	if uint64(*gp) > math.MaxUint64-amount {
		panic("gas pool pushed above uint64")
	}
	*(*uint64)(gp) += amount
	return gp
}

// SubGas deducts the given amount from the pool if enough gas is
// available and returns an error otherwise.
// SubGas 如果有足够的gas可用，则从池中扣除给定数量，
// 否则返回错误。
func (gp *GasPool) SubGas(amount uint64) error {
	if uint64(*gp) < amount {
		return ErrGasLimitReached
	}
	*(*uint64)(gp) -= amount
	return nil
}

// Gas returns the amount of gas remaining in the pool.
// Gas 返回池中剩余的gas量。
func (gp *GasPool) Gas() uint64 {
	return uint64(*gp)
}

// SetGas sets the amount of gas with the provided number.
// SetGas 设置gas量为提供的数字。
func (gp *GasPool) SetGas(gas uint64) {
	*(*uint64)(gp) = gas
}

// String returns a string representation of the gas pool.
// String 返回gas池的字符串表示。
func (gp *GasPool) String() string {
	return fmt.Sprintf("%d", *gp)
}
