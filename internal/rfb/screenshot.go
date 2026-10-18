package rfb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"time"
)

// PixelFormat is the RFB pixel format (RFC 6143, 7.4).
type PixelFormat struct {
	BPP, Depth             int
	BigEndian, TrueColour  bool
	RMax, GMax, BMax       int
	RShift, GShift, BShift int
}

func (p PixelFormat) String() string {
	return fmt.Sprintf("%dbpp depth %d bigEndian=%t trueColour=%t max=%d/%d/%d shift=%d/%d/%d",
		p.BPP, p.Depth, p.BigEndian, p.TrueColour, p.RMax, p.GMax, p.BMax, p.RShift, p.GShift, p.BShift)
}

func parsePixelFormat(b []byte) PixelFormat {
	return PixelFormat{
		BPP: int(b[0]), Depth: int(b[1]), BigEndian: b[2] != 0, TrueColour: b[3] != 0,
		RMax: int(binary.BigEndian.Uint16(b[4:])), GMax: int(binary.BigEndian.Uint16(b[6:])), BMax: int(binary.BigEndian.Uint16(b[8:])),
		RShift: int(b[10]), GShift: int(b[11]), BShift: int(b[12]),
	}
}

func (p PixelFormat) bytes() []byte {
	b := make([]byte, 16)
	b[0], b[1] = byte(p.BPP), byte(p.Depth)
	if p.BigEndian {
		b[2] = 1
	}
	if p.TrueColour {
		b[3] = 1
	}
	binary.BigEndian.PutUint16(b[4:], uint16(p.RMax))
	binary.BigEndian.PutUint16(b[6:], uint16(p.GMax))
	binary.BigEndian.PutUint16(b[8:], uint16(p.BMax))
	b[10], b[11], b[12] = byte(p.RShift), byte(p.GShift), byte(p.BShift)
	return b
}

// rgb888 is the format Screenshot asks for: 32 bits, bytes B G R X in memory.
var rgb888 = PixelFormat{BPP: 32, Depth: 24, TrueColour: true, RMax: 255, GMax: 255, BMax: 255, RShift: 16, GShift: 8, BShift: 0}

// decodeRaw paints a Raw rectangle (w*h pixels in format pf) onto img at (x, y).
func decodeRaw(img *image.RGBA, pf PixelFormat, x, y, w, h int, data []byte) error {
	if !pf.TrueColour || (pf.BPP != 8 && pf.BPP != 16 && pf.BPP != 32) || pf.RMax == 0 || pf.GMax == 0 || pf.BMax == 0 {
		return fmt.Errorf("rfb: unsupported pixel format %s", pf)
	}
	bytesPer := pf.BPP / 8
	if len(data) != w*h*bytesPer {
		return fmt.Errorf("rfb: raw rectangle has %d bytes, want %d", len(data), w*h*bytesPer)
	}
	if !image.Rect(x, y, x+w, y+h).In(img.Bounds()) {
		return errors.New("rfb: rectangle outside the framebuffer")
	}
	scale := func(v, max int) uint8 { return uint8(v * 255 / max) }
	for j := 0; j < h; j++ {
		for i := 0; i < w; i++ {
			p := data[(j*w+i)*bytesPer:]
			var v uint32
			switch {
			case bytesPer == 1:
				v = uint32(p[0])
			case bytesPer == 2 && pf.BigEndian:
				v = uint32(binary.BigEndian.Uint16(p))
			case bytesPer == 2:
				v = uint32(binary.LittleEndian.Uint16(p))
			case pf.BigEndian:
				v = binary.BigEndian.Uint32(p)
			default:
				v = binary.LittleEndian.Uint32(p)
			}
			img.SetRGBA(x+i, y+j, color.RGBA{
				R: scale(int(v>>uint(pf.RShift))&pf.RMax, pf.RMax),
				G: scale(int(v>>uint(pf.GShift))&pf.GMax, pf.GMax),
				B: scale(int(v>>uint(pf.BShift))&pf.BMax, pf.BMax), A: 255})
		}
	}
	return nil
}

// Screenshot asks for a full, non-incremental framebuffer update (Raw encoding only) and returns
// the whole framebuffer. Other server messages that arrive first are skipped.
func (cl *Client) Screenshot() (image.Image, error) {
	_ = cl.c.SetDeadline(time.Now().Add(30 * time.Second))
	defer cl.c.SetDeadline(time.Time{}) //nolint:errcheck
	if cl.fb == nil {
		cl.fb = image.NewRGBA(image.Rect(0, 0, cl.Width, cl.Height))
		setPF := append([]byte{0, 0, 0, 0}, rgb888.bytes()...)
		setEnc := []byte{2, 0, 0, 1, 0, 0, 0, 0} // one encoding: Raw (0)
		if _, err := cl.c.Write(append(setPF, setEnc...)); err != nil {
			return nil, err
		}
		cl.Format = rgb888
	}
	req := []byte{3, 0, 0, 0, 0, 0, byte(cl.Width >> 8), byte(cl.Width), byte(cl.Height >> 8), byte(cl.Height)}
	if _, err := cl.c.Write(req); err != nil {
		return nil, err
	}
	for {
		t, err := cl.r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch t {
		case 0: // FramebufferUpdate
			var h [3]byte
			if _, err := io.ReadFull(cl.r, h[:]); err != nil {
				return nil, err
			}
			for n := int(binary.BigEndian.Uint16(h[1:])); n > 0; n-- {
				var rh [12]byte
				if _, err := io.ReadFull(cl.r, rh[:]); err != nil {
					return nil, err
				}
				x, y := int(binary.BigEndian.Uint16(rh[0:])), int(binary.BigEndian.Uint16(rh[2:]))
				w, hh := int(binary.BigEndian.Uint16(rh[4:])), int(binary.BigEndian.Uint16(rh[6:]))
				if enc := int32(binary.BigEndian.Uint32(rh[8:])); enc != 0 {
					return nil, fmt.Errorf("rfb: server sent encoding %d, only Raw was requested", enc)
				}
				data := make([]byte, w*hh*cl.Format.BPP/8)
				if _, err := io.ReadFull(cl.r, data); err != nil {
					return nil, err
				}
				if err := decodeRaw(cl.fb, cl.Format, x, y, w, hh, data); err != nil {
					return nil, err
				}
			}
			out := image.NewRGBA(cl.fb.Bounds())
			copy(out.Pix, cl.fb.Pix)
			return out, nil
		case 1: // SetColourMapEntries
			var h [5]byte
			if _, err := io.ReadFull(cl.r, h[:]); err != nil {
				return nil, err
			}
			if _, err := io.CopyN(io.Discard, cl.r, int64(binary.BigEndian.Uint16(h[3:]))*6); err != nil {
				return nil, err
			}
		case 2: // Bell
		case 3: // ServerCutText
			var h [7]byte
			if _, err := io.ReadFull(cl.r, h[:]); err != nil {
				return nil, err
			}
			if _, err := io.CopyN(io.Discard, cl.r, int64(binary.BigEndian.Uint32(h[3:]))); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("rfb: unknown server message %d", t)
		}
	}
}

// WritePNG writes img to path (mode 0600, must not exist yet).
func WritePNG(path string, img image.Image) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
