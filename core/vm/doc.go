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

/*
Package vm implements the Ethereum Virtual Machine.

The vm package implements one EVM, a byte code VM. The BC (Byte Code) VM loops
over a set of bytes and executes them according to the set of rules defined
in the Ethereum yellow paper.

包vm实现了以太坊虚拟机。

vm包实现了一个EVM，一个字节码虚拟机。BC（字节码）VM循环
遍历一组字节并根据以太坊黄皮书中定义的规则集
执行它们。
*/
package vm
