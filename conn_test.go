package noiseconn

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"

	"github.com/flynn/noise"
	"golang.org/x/sync/errgroup"
)

func TestConn(t *testing.T) {
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

	data := make([]byte, 65536)
	for i := range data {
		data[i] = byte(i % 256)
	}
	eg.Go(func() error {
		_, err := client.Write(data)
		return err
	})
	eg.Go(func() error {
		b := make([]byte, 655360)
		n, err := server.Read(b)
		if err != nil {
			return err
		}
		m, err := server.Read(b[n:])
		if err != nil {
			return err
		}
		if !bytes.Equal(b[:n+m], data) {
			panic("failure")
		}
		return nil
	})
	err = eg.Wait()
	if err != nil {
		panic(err)
	}
}
