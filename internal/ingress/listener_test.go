package ingress

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestListenerBoundsSocketsAndUnblocksDuringShutdown(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := LimitListener(raw, 1)
	defer listener.Close()
	firstClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	first, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	secondClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	type result struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() { c, err := listener.Accept(); accepted <- result{c, err} }()
	select {
	case result := <-accepted:
		if result.conn != nil {
			result.conn.Close()
		}
		t.Fatal("accepted sockets exceeded the limit")
	case <-time.After(50 * time.Millisecond):
	}
	first.Close()
	first.Close() // Closing twice must release only one capacity slot.
	var second net.Conn
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		second = result.conn
		defer second.Close()
	case <-time.After(time.Second):
		t.Fatal("closing a connection did not restore listener capacity")
	}
	go func() { c, err := listener.Accept(); accepted <- result{c, err} }()
	listener.Close()
	select {
	case result := <-accepted:
		if result.conn != nil {
			result.conn.Close()
		}
		if !errors.Is(result.err, net.ErrClosed) {
			t.Fatal("shutdown did not stop a capacity-blocked accept")
		}
	case <-time.After(time.Second):
		t.Fatal("listener shutdown left accept blocked")
	}
}
