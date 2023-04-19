package main

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"unsafe"

	"github.com/NanoRed/loin/pkg/logger"
)

const (
	StatusDeleted int32 = -1
	StatusEnd
	StatusNormal
)

type IDMap map[string]int

func NewIDMap() *IDMap {
	idmap := make(IDMap)
	return &idmap
}

func (i *IDMap) Encode() []byte {
	var buffer bytes.Buffer
	gob.NewEncoder(&buffer).Encode(i)
	return buffer.Bytes()
}

func (i *IDMap) Decode(b []byte) {
	gob.NewDecoder(bytes.NewBuffer(b)).Decode(i)
}

// func (i IDMap) Decode(b []byte) {
// 	gob.NewDecoder(bytes.NewBuffer(b)).Decode(&i)
// }

type KKKI struct {
	Id int
}

func test123() (*KKKI, error) {
	return &KKKI{123}, nil
}

func test321() (kkk *KKKI) {
	kkk, err := test123()
	if err != nil {

	}
	return
}

func test333() {
	fmt.Println("bbbbbbbbbbbbb")
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			debug.PrintStack()
			var x int
			fmt.Scanln(&x)
		}
	}()

	defer test333()
	panic("vvvv")

	popopo := []any{123, "ddd"}
	fmt.Println(popopo[1].(string))

	koko := make(chan int)
	koko2 := make(chan int)
	close(koko)
	close(koko2)
	select {
	case <-koko2:
	case koko <- 2:
	default:
	}

	var ttt [2]int
	fmt.Println(ttt[1])

	fmt.Println(test321(), 888)

	// var uuu int32 = 987
	// var lll *int32 = &uuu
	// for i := 0; i < 1000; i++ {
	// 	go func() {
	// 		// poi := atomic.LoadInt32(lll)
	// 		// fmt.Println(poi)
	// 		fmt.Println(*lll)
	// 	}()
	// 	go func(m int32) {
	// 		if m == 157 {
	// 			*lll = m
	// 			// atomic.StoreInt32(lll, m)
	// 		}
	// 	}(int32(i))
	// }

	logger.Info("dsfadfafda\nasdfasdfa\nasdgad")

	var ooo *IDMap
	var ppp IDMap = IDMap{"q": 1, "g": 4, "bb": 123, "qwe": 999}
	var ppp2 IDMap = IDMap{}
	var qqq *IDMap = &ppp2
	// var qqq map[string]int = map[string]int{"p": 2}
	// ooo = &qqq
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&ooo)), unsafe.Pointer(&ppp))
	fmt.Println(*ooo)

	b := ppp.Encode()
	fmt.Println(b)
	qqq.Decode(b)
	fmt.Println(*qqq)

	var yyy *KKKI
	fmt.Println(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&yyy))) == nil)
	xxx := &KKKI{888}
	atomic.CompareAndSwapPointer((*unsafe.Pointer)(unsafe.Pointer(&yyy)), unsafe.Pointer(nil), unsafe.Pointer(xxx))
	fmt.Println(yyy)
	fmt.Println(unsafe.Pointer(nil) == nil)

	fmt.Println()
	fmt.Println()
	fmt.Println()
	fmt.Println()
	fmt.Println()

	var packetType uint8 = 5
	var packetSize uint16 = 1354
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, packetSize)
	header[0] |= packetType << 5

	fmt.Println(header)

	packetType = header[0] >> 5
	packetSize = uint16(header[0]&0x07)<<8 | uint16(header[1])
	fmt.Println(packetType, packetSize)

	b = []byte{0, 0, 0, 0}
	fmt.Printf("%s %d\n", b, len(b))

	fmt.Println(StatusDeleted, StatusEnd, StatusNormal)

	var y int32
	var x *int32 = &y
	atomic.StoreInt32(x, 222)
	fmt.Println(*x, y)

	// var i int
	// for {
	// 	kk := i
	// 	fmt.Println(kk)

	// 	i++
	// 	if i > 20 {
	// 		break
	// 	}
	// }

	fmt.Println(test2())

	var test22 []byte
	test11 := make([]byte, 1)
	fmt.Println(append(test11, test22...), len(test22))

}

func test() (int, error) {
	return 1, errors.New("aaaaa")
}

func test2() (err error) {
	kk, err := test()
	if err != nil {
		fmt.Println(kk)
	}
	return
}
