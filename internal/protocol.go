package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

var (
	HeartbeatInterval time.Duration = time.Second * 5
)

type FrameType uint8

const (
	SrvEndToEnd FrameType = iota
	SrvBroadcast
	SrvHeartbeat
	SrvRegister
)

const (
	CliEndToEnd FrameType = iota
	CliBroadcast
	CliResponse
	CliJunction
)

type Frame struct {
	Type     FrameType
	Reserved int
	Payload  []byte
}

func (f *Frame) Encode() []byte {
	header := make([]byte, 2, 2048)
	binary.BigEndian.PutUint16(header, uint16(len(f.Payload)))
	header[0] |= byte(f.Type) << 6
	header[0] |= byte(f.Reserved) << 3
	b := &bytes.Buffer{}
	b.Write(header)
	b.Write(f.Payload)
	return b.Bytes()
}

func (f *Frame) DecodeHeader(header []byte) {
	f.Type = FrameType(header[0]) >> 6
	f.Reserved = int(header[0]&0x38) >> 3
	if size := uint16(header[0]&0x07)<<8 | uint16(header[1]); size > 0 {
		f.Payload = make([]byte, size)
	}
}

type FrameReader struct {
	Reader io.Reader
	Header []byte
}

func NewFrameReader(rd io.Reader) (frameReader *FrameReader) {
	frameReader = &FrameReader{
		Reader: rd,
		Header: make([]byte, 2),
	}
	return
}

func (f *FrameReader) NextFrame() (frame *Frame, err error) {
	_, err = io.ReadFull(f.Reader, f.Header)
	if err != nil {
		err = errors.Join(err, errors.New("read header error"))
		return
	}
	frame = &Frame{}
	frame.DecodeHeader(f.Header)
	if frame.Payload != nil {
		_, err = io.ReadFull(f.Reader, frame.Payload)
		if err != nil {
			err = errors.Join(err, errors.New("read payload error"))
			return
		}
	}
	return
}
