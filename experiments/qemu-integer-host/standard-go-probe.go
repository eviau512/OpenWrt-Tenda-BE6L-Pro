// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if math.Sqrt(2) != 1.4142135623730951 || math.Float64bits(3.75) != 0x400e000000000000 {
		panic("FP mismatch")
	}
	sum := sha256.Sum256([]byte("abc"))
	if fmt.Sprintf("%x", sum) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		panic("SHA256 mismatch")
	}
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil { panic(err) }
	aead, err := cipher.NewGCM(block)
	if err != nil { panic(err) }
	nonce := make([]byte, aead.NonceSize())
	plain := []byte("standard A53 ABI emulation test")
	sealed := aead.Seal(nil, nonce, plain, nil)
	opened, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil || !bytes.Equal(opened, plain) { panic("AES-GCM mismatch") }
	var count atomic.Uint64
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 10000; j++ { count.Add(1) }
		}()
	}
	group.Wait()
	if count.Load() != 80000 { panic("atomic mismatch") }
	channel := make(chan os.Signal, 1)
	signal.Notify(channel, syscall.SIGUSR1)
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil { panic(err) }
	select {
	case <-channel:
	case <-time.After(5*time.Second): panic("signal timeout")
	}
	signal.Stop(channel)
	runtime.GC()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	fmt.Printf("STANDARD_A53_GO_PASS go=%s fp=ok sha256=ok aesgcm=ok goroutines=8 atomic64=80000 signal=ok heap_sys=%d\n", runtime.Version(), memory.HeapSys)
}
