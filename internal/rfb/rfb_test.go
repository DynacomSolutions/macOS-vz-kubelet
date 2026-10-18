package rfb

import (
	"io"
	"net"
	"testing"
)

func TestHandshakeAndKey(t *testing.T) {
	cs, sc := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		defer sc.Close()
		sc.Write([]byte("RFB 003.889\n")[:12])
		buf := make([]byte, 12)
		io.ReadFull(sc, buf)
		sc.Write([]byte{1, 1})
		one := make([]byte, 1)
		io.ReadFull(sc, one)
		sc.Write([]byte{0, 0, 0, 0})
		io.ReadFull(sc, one)
		init := make([]byte, 24+2)
		init[23] = 2
		sc.Write(init)
		k := make([]byte, 8)
		io.ReadFull(sc, k)
		got <- k
	}()
	cl, err := Handshake(cs, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.Key(0xff0d, true); err != nil {
		t.Fatal(err)
	}
	want := []byte{4, 1, 0, 0, 0, 0, 0xff, 0x0d}
	if k := <-got; string(k) != string(want) {
		t.Fatalf("got %v want %v", k, want)
	}
}

func TestHandshakeRejectsNonRFB(t *testing.T) {
	cs, sc := net.Pipe()
	go func() { sc.Write([]byte("HTTP/1.1 200 ")[:12]); sc.Close() }()
	if _, err := Handshake(cs, ""); err == nil {
		t.Fatal("accepted a non-RFB server")
	}
}

func TestVNCAuth(t *testing.T) {
	cs, sc := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		defer sc.Close()
		sc.Write([]byte("RFB 003.008\n"))
		buf := make([]byte, 12)
		io.ReadFull(sc, buf)
		sc.Write([]byte{1, 2})
		one := make([]byte, 1)
		io.ReadFull(sc, one)
		sc.Write(make([]byte, 16))
		resp := make([]byte, 16)
		io.ReadFull(sc, resp)
		got <- resp
		sc.Write([]byte{0, 0, 0, 0})
		io.ReadFull(sc, one)
		init := make([]byte, 24)
		sc.Write(init)
	}()
	if _, err := Handshake(cs, "secret"); err != nil {
		t.Fatal(err)
	}
	want, _ := vncAuth([16]byte{}, "secret")
	if string(<-got) != string(want) {
		t.Fatal("wrong challenge response")
	}
}
