package internal

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"github.com/NanoRed/loin/pkg/logger"
)

type Server struct {
	Endpoint *Endpoint
	Junction *Junction
}

func NewServer(endpoint *Endpoint) *Server {
	return &Server{
		Endpoint: endpoint,
		Junction: NewJunction(),
	}
}

func (s *Server) ListenAndServe() {
	ln, err := net.Listen(
		s.Endpoint.Address.Port.Type.String(),
		s.Endpoint.GetIPPort(),
	)
	if err != nil {
		logger.Panic("failed to listen the address:%v", err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("failed to accept connection:%v", err)
			continue
		}
		go s.Handle(&Link{Conn: conn})
	}
}

func (s *Server) Handle(link *Link) {
	defer link.Close()
	reader := NewFrameReader(link.Conn)
	for {
		err := link.Conn.SetReadDeadline(time.Now().Add(LinkReadDuration))
		if err != nil {
			logger.Error("failed to set link's deadline:%v", err)
			return
		}
		frame, err := reader.NextFrame()
		if err != nil {
			logger.Error("failed to read next frame:%v", err)
			return
		}
		switch frame.Type {
		case SrvEndToEnd:
			if link := s.Junction.GetLink(frame.Reserved); link != nil {
				var b bytes.Buffer
				b.Write(reader.Header)
				b.Write(frame.Payload)
				if _, err := link.SafeWrite(b.Bytes()); err != nil {
					logger.Error("failed to write end to end frame:%v", err)
					return
				}
				logger.Info("frame(%d) to %d", len(frame.Payload), frame.Reserved)
			} else {
				logger.Warn("link unavailable:%d", frame.Reserved)
			}
		case SrvBroadcast:
			var b bytes.Buffer
			b.Write(reader.Header)
			b.Write(frame.Payload)
			frameBytes := b.Bytes()
			s.Junction.Range(func(key byte, id int, link *Link) {
				go func() {
					if id != frame.Reserved {
						if _, err := link.SafeWrite(frameBytes); err != nil {
							logger.Error("failed to write junction frame:%d %v", id, err)
							link.Close()
						}
					}
				}()
			})
			logger.Info("broadcast frame(%d) from %d", len(frame.Payload), frame.Reserved)
		case SrvHeartbeat:
			continue
		case SrvRegister:
			link.Agent = &Endpoint{}
			link.From = &Endpoint{}
			agentDataSize := binary.BigEndian.Uint16(frame.Payload)
			link.Agent.Decode(frame.Payload[3 : 3+agentDataSize])
			link.From.Decode(frame.Payload[3+agentDataSize:])
			if id, ok := s.Junction.Register(link); ok {
				defer s.Junction.Unregister(id)
				logger.Info("%s successfully registered", link.From.GetIP().String())
				payload := s.Junction.Encode()
				// broadcast the junction guide
				s.Junction.Range(func(key byte, id int, link *Link) {
					go func() {
						frame := &Frame{
							Type:     CliJunction,
							Reserved: id,
							Payload:  payload,
						}
						if _, err := link.SafeWrite(frame.Encode()); err != nil {
							logger.Error("failed to write junction frame:%d %v", id, err)
							link.Close()
						}
					}()
				})
			} else {
				logger.Warn("%s failed to register", link.From.GetIP().String())
				frame := &Frame{
					Type:     CliResponse,
					Reserved: 2,
					Payload:  []byte("failed to register to the junction in server"),
				}
				if _, err := link.SafeWrite(frame.Encode()); err != nil {
					logger.Error("failed to write response frame:%v", err)
					return
				}
			}
		default:
			logger.Error("unknown frame type")
			return
		}
	}
}
