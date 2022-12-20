package main

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/flynn/noise"
	"golang.org/x/exp/constraints"
	"golang.org/x/sync/errgroup"
)

type Conn struct {
	net.Conn
	hs         *noise.HandshakeState
	send, recv *noise.CipherState
}

func NewConn(conn net.Conn, config noise.Config) (*Conn, error) {
	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: conn, hs: hs}, nil
}

func (c *Conn) Read(b []byte) (n int, err error) {

	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {

	return c.Conn.Write(b)
}

func main() {
	p1, p2 := net.Pipe()

	clientKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}
	serverKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}

	client, err := NewConn(p1, noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: clientKey,
		PeerStatic:    serverKey.Public,
	})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	server, err := NewConn(p2, noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: serverKey,
	})
	if err != nil {
		panic(err)
	}
	defer server.Close()

	var eg errgroup.Group

	eg.Go(func() error {
		_, err := client.Write(make([]byte, 65536))
		return err
	})
	eg.Go(func() error {
		b := make([]byte, 655360)
		n, err := server.Read(b)
		fmt.Printf("%x\n", b[:n])
		return err
	})
	err = eg.Wait()
	if err != nil {
		panic(err)
	}
}

func min[T constraints.Ordered](a, b T) T {
	if a <= b {
		return a
	}
	return b
}
