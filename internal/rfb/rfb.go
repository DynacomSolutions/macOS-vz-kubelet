// Package rfb is the smallest RFB (VNC) client that can press keys: protocol 3.8, security type
// None or VNC authentication, KeyEvent messages only. create-base uses it to drive macOS Recovery through the
// loopback-only VNC server of Virtualization.framework; the framebuffer is never read.
package rfb

import (
	"bufio"
	"bytes"
	"crypto/des"
	"errors"
	"fmt"
	"image"
	"io"
	"math/bits"
	"net"
	"time"
)

// Client is a connected RFB session.
type Client struct {
	c  net.Conn
	r  *bufio.Reader
	fb *image.RGBA // framebuffer kept across screenshots

	// Server details from ServerInit.
	addr, password string

	// Timeout bounds one screenshot read (default 30 s).
	Timeout time.Duration

	Width, Height int
	Name          string
	Format        PixelFormat // the format in use (the server's until Screenshot sets ours)
}

// Handshake runs the RFB 3.8 handshake over c (shared session) and reads the ServerInit. With an
// empty password only security type None is accepted; otherwise VNC authentication (type 2) is
// used. It takes ownership of c.
func Handshake(c net.Conn, password string) (*Client, error) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	defer c.SetDeadline(time.Time{}) //nolint:errcheck
	r := bufio.NewReader(c)
	var ver [12]byte
	if _, err := io.ReadFull(r, ver[:]); err != nil {
		return nil, fmt.Errorf("rfb: reading server version: %w", err)
	}
	if string(ver[:4]) != "RFB " {
		return nil, fmt.Errorf("rfb: not an RFB server: %q", ver[:])
	}
	if _, err := c.Write([]byte("RFB 003.008\n")); err != nil {
		return nil, err
	}
	n, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("rfb: server refused the connection")
	}
	types := make([]byte, n)
	if _, err := io.ReadFull(r, types); err != nil {
		return nil, err
	}
	want := byte(1)
	if password != "" {
		want = 2
	}
	if !bytes.Contains(types, []byte{want}) {
		return nil, fmt.Errorf("rfb: server offers security types %v, want %d", types, want)
	}
	if _, err := c.Write([]byte{want}); err != nil {
		return nil, err
	}
	if want == 2 {
		var ch [16]byte
		if _, err := io.ReadFull(r, ch[:]); err != nil {
			return nil, err
		}
		resp, err := vncAuth(ch, password)
		if err != nil {
			return nil, err
		}
		if _, err := c.Write(resp); err != nil {
			return nil, err
		}
	}
	var res [4]byte
	if _, err := io.ReadFull(r, res[:]); err != nil {
		return nil, err
	}
	if res != [4]byte{} {
		return nil, errors.New("rfb: security handshake failed")
	}
	if _, err := c.Write([]byte{1}); err != nil { // ClientInit: shared
		return nil, err
	}
	var init [24]byte // width, height, pixel format, name length
	if _, err := io.ReadFull(r, init[:]); err != nil {
		return nil, err
	}
	nameLen := uint32(init[20])<<24 | uint32(init[21])<<16 | uint32(init[22])<<8 | uint32(init[23])
	if nameLen > 1<<16 {
		return nil, errors.New("rfb: implausible desktop name length")
	}
	name := make([]byte, nameLen)
	if _, err := io.ReadFull(r, name); err != nil {
		return nil, err
	}
	pf := parsePixelFormat(init[4:20])
	return &Client{c: c, r: r, Name: string(name), Format: pf,
		Width: int(init[0])<<8 | int(init[1]), Height: int(init[2])<<8 | int(init[3])}, nil
}

// vncAuth answers a VNC authentication challenge: DES with the password's first 8 bytes as key,
// each byte bit-reversed (the protocol's quirk).
func vncAuth(ch [16]byte, password string) ([]byte, error) {
	var key [8]byte
	copy(key[:], password)
	for i, b := range key {
		key[i] = bits.Reverse8(b)
	}
	blk, err := des.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	blk.Encrypt(out[:8], ch[:8])
	blk.Encrypt(out[8:], ch[8:])
	return out, nil
}

// Dial connects to addr and runs Handshake.
func Dial(addr, password string) (*Client, error) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	cl, err := Handshake(c, password)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	cl.addr, cl.password = addr, password
	return cl, nil
}

// reconnect drops the connection and dials the same server again (only for clients made by Dial).
// The framebuffer starts blank and the pixel format and encodings are sent again.
func (cl *Client) reconnect() error {
	if cl.addr == "" {
		return errors.New("rfb: client was not made by Dial, cannot reconnect")
	}
	_ = cl.c.Close()
	n, err := Dial(cl.addr, cl.password)
	if err != nil {
		return err
	}
	*cl = *n
	return nil
}

// pointerEvent encodes a PointerEvent message (type 5): button mask, x, y.
func pointerEvent(x, y int, buttons byte) []byte {
	return []byte{5, buttons, byte(x >> 8), byte(x), byte(y >> 8), byte(y)}
}

// Pointer moves the pointer to (x, y) with the given button mask held (bit 0 is the left button).
func (cl *Client) Pointer(x, y int, buttons byte) error {
	_, err := cl.c.Write(pointerEvent(x, y, buttons))
	return err
}

// Click moves to the point at fraction (fx, fy) of the desktop and clicks the left button.
func (cl *Client) Click(fx, fy float64) error {
	if fx < 0 || fx > 1 || fy < 0 || fy > 1 {
		return fmt.Errorf("rfb: click (%v, %v) is outside 0..1", fx, fy)
	}
	x, y := int(fx*float64(cl.Width-1)), int(fy*float64(cl.Height-1))
	for _, b := range []byte{0, 1, 0} {
		if err := cl.Pointer(x, y, b); err != nil {
			return err
		}
		time.Sleep(80 * time.Millisecond)
	}
	return nil
}

// Key sends one KeyEvent (X11 keysym).
func (cl *Client) Key(sym uint32, down bool) error {
	m := [8]byte{4, 0, 0, 0, byte(sym >> 24), byte(sym >> 16), byte(sym >> 8), byte(sym)}
	if down {
		m[1] = 1
	}
	_, err := cl.c.Write(m[:])
	return err
}

// Close closes the connection.
func (cl *Client) Close() error { return cl.c.Close() }
