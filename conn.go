package noiseconn

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/flynn/noise"
	"github.com/zeebo/errs"
)

const HeaderByte = 0x80

// TODO(jt): this code is not 0-RTT for initial payloads larger than
// 65535 bytes! to my knowledge i don't know if this is actually a noise
// requirement, but is at least a github.com/flynn/noise requirement.

type Conn struct {
	net.Conn
	initiator        bool
	hs               *noise.HandshakeState
	hsResponsibility bool
	readBuf          []byte
	send, recv       *noise.CipherState
}

// NewConn wraps an existing net.Conn with encryption provided by
// noise.Config.
func NewConn(conn net.Conn, config noise.Config) (*Conn, error) {
	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &Conn{
		Conn:             conn,
		hs:               hs,
		initiator:        config.Initiator,
		hsResponsibility: config.Initiator,
	}, nil
}

func (c *Conn) setCipherStates(cs1, cs2 *noise.CipherState) {
	if c.initiator {
		c.send, c.recv = cs1, cs2
	} else {
		c.send, c.recv = cs2, cs1
	}
}

func (c *Conn) hsRead() error {
	m, err := c.readMsg(nil) // TODO(jt): nil
	if err != nil {
		return err
	}
	var cs1, cs2 *noise.CipherState
	c.readBuf, cs1, cs2, err = c.hs.ReadMessage(c.readBuf, m)
	if err != nil {
		return errs.Wrap(err)
	}
	c.setCipherStates(cs1, cs2)
	c.hsResponsibility = true
	if c.send != nil {
		c.hs = nil
	}
	return nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	handleBuffered := func() bool {
		if len(c.readBuf) == 0 {
			return false
		}
		n = copy(b, c.readBuf)
		copy(c.readBuf, c.readBuf[n:])
		c.readBuf = c.readBuf[:len(c.readBuf)-n]
		return true
	}

	if handleBuffered() {
		return n, nil
	}

	for c.hs != nil {
		if c.hsResponsibility {
			err = c.hsWrite(nil)
			if err != nil {
				return 0, err
			}
			if c.hs == nil {
				break
			}
		}
		err = c.hsRead()
		if err != nil {
			return 0, err
		}
		if handleBuffered() {
			return n, nil
		}
	}

	for {
		m, err := c.readMsg(nil) // TODO(jt): nil
		if err != nil {
			return 0, err
		}
		// TODO(jt): use b directly if b is big enough!
		// One option is to use b if it's big enough to
		// hold noise.MaxMsgLen, but another option that
		// would be neat is to figure out the payload size
		// from within m. it is also likely that
		// the payload size is never larger than the
		// message size and we could use that.
		c.readBuf, err = c.recv.Decrypt(c.readBuf, nil, m)
		if err != nil {
			return 0, errs.Wrap(err)
		}
		if handleBuffered() {
			return n, nil
		}
	}
}

// readMsg appends a message to b.
func (c *Conn) readMsg(b []byte) ([]byte, error) {
	// TODO(jt): make sure these reads are through bufio somewhere in the stack
	// appropriate.
	var msgHeader [4]byte
	_, err := io.ReadFull(c.Conn, msgHeader[:])
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if msgHeader[0] != HeaderByte {
		// TODO(jt): close conn?
		return nil, errs.New("unknown message header")
	}
	msgHeader[0] = 0
	msgSize := int(binary.BigEndian.Uint32(msgHeader[:]))
	b = append(b[len(b):], make([]byte, msgSize)...)
	_, err = io.ReadFull(c.Conn, b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errs.Wrap(io.ErrUnexpectedEOF)
		}
		return nil, errs.Wrap(err)
	}
	return b, nil
}

func (c *Conn) writeMsg(b []byte) error {
	// TODO(jt): make sure these writes are through bufio somewhere in the stack
	// appropriate.
	var msgHeader [4]byte
	if len(b) >= 1<<(8*3) {
		return errs.New("message too large: %d", len(b))
	}
	binary.BigEndian.PutUint32(msgHeader[:], uint32(len(b)))
	msgHeader[0] = HeaderByte
	_, err := c.Conn.Write(msgHeader[:])
	if err != nil {
		// TODO(jt): close?
		return errs.Wrap(err)
	}
	_, err = c.Conn.Write(b)
	return errs.Wrap(err)
}

func (c *Conn) hsWrite(payload []byte) (err error) {
	var out []byte // TODO(jt)
	var cs1, cs2 *noise.CipherState
	out, cs1, cs2, err = c.hs.WriteMessage(out, payload)
	if err != nil {
		return errs.Wrap(err)
	}
	c.setCipherStates(cs1, cs2)
	c.hsResponsibility = false
	if c.send != nil {
		c.hs = nil
	}
	return c.writeMsg(out)
}

func (c *Conn) writePayload(b []byte) (err error) {
	if c.hs != nil && !c.hsResponsibility {
		err = c.hsRead()
		if err != nil {
			return err
		}
	}
	if c.hs != nil {
		return c.hsWrite(b)
	}

	var out []byte // TODO(jt)
	out, err = c.send.Encrypt(out, nil, b)
	if err != nil {
		return errs.Wrap(err)
	}
	return c.writeMsg(out)
}

// If a Noise handshake is still occurring (or has yet to occur), the
// data provided to Write will be included in handshake payloads.
func (c *Conn) Write(b []byte) (n int, err error) {
	// TODO(jt): breaking up a large buffer for writes simplifies the noise
	// code, but we really ought to minimize the number of writes to the
	// underlying Conn if we want to later implement GSO.
	for len(b) > 0 {
		l := min(noise.MaxMsgLen, len(b))
		err = c.writePayload(b[:l])
		if err != nil {
			return n, err
		}
		n += l
		b = b[l:]
	}
	return n, nil
}

// HandshakeComplete returns whether a handshake is complete.
func (c *Conn) HandshakeComplete() bool {
	return c.hs == nil
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

