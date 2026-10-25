// SPDX-License-Identifier: MIT
package main

var left float64 = 1.5
var right float64 = 2.25

func main() {
	if left+right != 3.75 || right/left != 1.5 {
		panic("software floating point result mismatch")
	}
	println("A64_GO_SOFT_PROBE_PASS")
}
