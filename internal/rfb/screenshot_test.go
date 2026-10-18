package rfb

import (
	"encoding/binary"
	"image"
	"image/color"
	"io"
	"net"
	"os"
	"testing"
)

func TestDecodeRaw32(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 2, 1))
	// bytes B G R X per pixel: pixel 0 red, pixel 1 (10,20,30)
	data := []byte{0, 0, 255, 0, 30, 20, 10, 0}
	if err := decodeRaw(img, rgb888, 0, 0, 2, 1, data); err != nil {
		t.Fatal(err)
	}
	if got := img.RGBAAt(0, 0); got != (color.RGBA{255, 0, 0, 255}) {
		t.Fatalf("pixel 0 = %v", got)
	}
	if got := img.RGBAAt(1, 0); got != (color.RGBA{10, 20, 30, 255}) {
		t.Fatalf("pixel 1 = %v", got)
	}
}

func TestDecodeRaw16BigEndian565(t *testing.T) {
	pf := PixelFormat{BPP: 16, Depth: 16, BigEndian: true, TrueColour: true, RMax: 31, GMax: 63, BMax: 31, RShift: 11, GShift: 5, BShift: 0}
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	if err := decodeRaw(img, pf, 0, 0, 1, 1, []byte{0xf8, 0x00}); err != nil { // pure red
		t.Fatal(err)
	}
	if got := img.RGBAAt(0, 0); got != (color.RGBA{255, 0, 0, 255}) {
		t.Fatalf("got %v", got)
	}
}

func TestDecodeRawRejects(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	if decodeRaw(img, rgb888, 0, 0, 2, 2, make([]byte, 3)) == nil {
		t.Error("short data accepted")
	}
	if decodeRaw(img, rgb888, 1, 1, 2, 2, make([]byte, 16)) == nil {
		t.Error("rectangle outside the framebuffer accepted")
	}
	if decodeRaw(img, PixelFormat{BPP: 8}, 0, 0, 1, 1, []byte{0}) == nil {
		t.Error("palette format accepted")
	}
}

func TestScreenshot(t *testing.T) {
	cs, sc := net.Pipe()
	go func() {
		defer sc.Close()
		sc.Write([]byte("RFB 003.008\n"))
		io.ReadFull(sc, make([]byte, 12))
		sc.Write([]byte{1, 1})
		io.ReadFull(sc, make([]byte, 1))
		sc.Write([]byte{0, 0, 0, 0})
		io.ReadFull(sc, make([]byte, 1))
		init := make([]byte, 24)
		binary.BigEndian.PutUint16(init[0:], 2) // width
		binary.BigEndian.PutUint16(init[2:], 1) // height
		init[4], init[5], init[7] = 32, 24, 1   // bpp, depth, true colour
		init[23] = 2
		sc.Write(append(init, 'h', 'i'))
		io.ReadFull(sc, make([]byte, 20+8)) // SetPixelFormat + SetEncodings
		io.ReadFull(sc, make([]byte, 10))   // FramebufferUpdateRequest
		sc.Write([]byte{2})                 // a bell first
		upd := []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0}
		sc.Write(append(upd, 0, 0, 255, 0, 30, 20, 10, 0))
	}()
	cl, err := Handshake(cs, "")
	if err != nil {
		t.Fatal(err)
	}
	if cl.Width != 2 || cl.Height != 1 || cl.Name != "hi" || cl.Format.BPP != 32 {
		t.Fatalf("server init: %+v", cl)
	}
	img, err := cl.Screenshot()
	if err != nil {
		t.Fatal(err)
	}
	r, g, b, _ := img.At(1, 0).RGBA()
	if r>>8 != 10 || g>>8 != 20 || b>>8 != 30 {
		t.Fatalf("pixel (1,0) = %d %d %d", r>>8, g>>8, b>>8)
	}
}

func TestWritePNG(t *testing.T) {
	p := t.TempDir() + "/a.png"
	if err := WritePNG(p, image.NewRGBA(image.Rect(0, 0, 3, 2))); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() == 0 {
		t.Fatalf("stat: %v %v", fi, err)
	}
	if WritePNG(p, image.NewRGBA(image.Rect(0, 0, 1, 1))) == nil {
		t.Fatal("overwrote an existing screenshot")
	}
}
