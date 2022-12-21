package noiseconn

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/dsnet/try"
	"github.com/flynn/noise"
	"golang.org/x/sync/errgroup"
)

func osNetPipe() (client net.Conn, server net.Conn, err error) {
	defer try.HandleF(&err, func() {
		if client != nil {
			client.Close()
		}
		if server != nil {
			server.Close()
		}
	})
	l := try.E1(net.Listen("tcp", "127.0.0.1:0"))
	defer l.Close()

	var eg errgroup.Group

	eg.Go(func() (err error) {
		defer try.Handle(&err)
		client = try.E1(net.Dial(l.Addr().Network(), l.Addr().String()))
		return nil
	})
	eg.Go(func() (err error) {
		defer try.Handle(&err)
		server = try.E1(l.Accept())
		return nil
	})
	try.E(eg.Wait())
	return client, server, nil
}

func BenchmarkThroughput(b *testing.B) {
	defer try.F(b.Fatal)
	p1, p2 := try.E2(osNetPipe())

	clientKey := try.E1(noise.DH25519.GenerateKeypair(rand.Reader))
	serverKey := try.E1(noise.DH25519.GenerateKeypair(rand.Reader))

	client := try.E1(NewConn(p1, noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: clientKey,
		PeerStatic:    serverKey.Public,
	}))
	defer client.Close()

	server := try.E1(NewConn(p2, noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: serverKey,
	}))
	defer server.Close()

	data := make([]byte, 1024*b.N)
	try.E1(rand.Read(data))
	b.SetBytes(1024)
	b.ResetTimer()

	errch := make(chan error, 2)
	go func() {
		errch <- (func() (err error) {
			defer try.Handle(&err)
			try.E1(client.Write([]byte("get data")))
			if !bytes.Equal(try.E1(io.ReadAll(io.LimitReader(client, int64(len(data))))), data) {
				return fmt.Errorf("data mismatch")
			}
			return nil
		})()
	}()
	go func() {
		errch <- (func() (err error) {
			defer try.Handle(&err)
			cmd := make([]byte, len("get data"))
			try.E1(io.ReadFull(server, cmd))
			if !bytes.Equal(cmd, []byte("get data")) {
				return fmt.Errorf("cmd mismatch")
			}
			try.E1(io.Copy(server, bytes.NewBuffer(data)))
			return nil
		})()
	}()
	try.E(<-errch)
	try.E(<-errch)
	try.E(client.Close())
	try.E(server.Close())
}
