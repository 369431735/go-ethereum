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

package core

import (
	"github.com/ethereum/go-ethereum/core/types"
)

// NewTxsEvent is posted when a batch of transactions enter the transaction pool.
// NewTxsEvent 在一批交易进入交易池时发布。
type NewTxsEvent struct{ Txs []*types.Transaction }

// RemovedLogsEvent is posted when a reorg happens
// RemovedLogsEvent 在发生重组时发布。
type RemovedLogsEvent struct{ Logs []*types.Log }

// ChainEvent represents a chain event like a new header was added to the chain.
// ChainEvent 表示链事件，如新的区块头被添加到链中。
type ChainEvent struct {
	Header *types.Header
}

// ChainHeadEvent is posted when a new head block is added to the canonical chain.
// ChainHeadEvent 在新的头区块被添加到规范链时发布。
type ChainHeadEvent struct {
	Header *types.Header
}
