package recoverykeys

import (
	"context"
	"image"
	"image/color"
	"image/draw"
	"testing"
	"time"
)

type rec struct {
	ev     []uint32
	clicks [][2]float64
	looks  []image.Image // returned in order, the last one repeats
	n      int
}

func (r *rec) Key(s uint32, down bool) error {
	if down {
		r.ev = append(r.ev, s)
	}
	return nil
}
func (r *rec) Click(fx, fy float64) error {
	r.clicks = append(r.clicks, [2]float64{fx, fy})
	return nil
}
func (r *rec) Look() (image.Image, error) {
	i := r.n
	if i >= len(r.looks) {
		i = len(r.looks) - 1
	}
	r.n++
	return r.looks[i], nil
}

func solid(c color.Color) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 160, 96))
	draw.Draw(img, img.Bounds(), image.NewUniform(c), image.Point{}, draw.Src)
	return img
}

// picker is black with a small bright icon; recovery is a mid-grey window screen.
func picker() *image.RGBA {
	img := solid(color.Black)
	draw.Draw(img, image.Rect(60, 40, 70, 50), image.NewUniform(color.White), image.Point{}, draw.Src)
	return img
}

var noSleep = func(context.Context, time.Duration) error { return nil }

func TestDefaultScriptParses(t *testing.T) {
	if _, err := Parse(DefaultScript); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	steps, err := Parse("note hello\nwait 1s\nkey ctrl+alt+cmd+t\ntype aZ!\nsecret pw\nkey return\nclick 0.5 0.25\n")
	if err != nil {
		t.Fatal(err)
	}
	var waited time.Duration
	var labels, notes []string
	r := &rec{}
	err = Run(context.Background(), r, steps, Options{
		Secrets: map[string]string{"pw": "x"},
		Sleep:   func(_ context.Context, d time.Duration) error { waited += d; return nil },
		Snap:    func(l string) { labels = append(labels, l) },
		Logf:    func(f string, a ...any) { notes = append(notes, f) },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{0xffe3, 0xffe9, 0xffeb, 't', 'a', 0xffe1, 'Z', 0xffe1, '!', 'x', 0xff0d}
	if len(r.ev) != len(want) {
		t.Fatalf("got %v want %v", r.ev, want)
	}
	for i := range want {
		if r.ev[i] != want[i] {
			t.Fatalf("got %v want %v", r.ev, want)
		}
	}
	if len(r.clicks) != 1 || r.clicks[0] != [2]float64{0.5, 0.25} {
		t.Fatalf("clicks %v", r.clicks)
	}
	if want := "02-wait-1s 03-key 04-type 06-key 07-click"; join(labels) != want {
		t.Fatalf("labels %v want %v (none after note or secret)", labels, want)
	}
	if len(notes) != 1 || waited != time.Second {
		t.Fatalf("notes %v waited %v", notes, waited)
	}
}

func join(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += " "
		}
		out += x
	}
	return out
}

func TestWaitLeavePicker(t *testing.T) {
	steps, _ := Parse("wait-leave-picker 1m\n")
	r := &rec{looks: []image.Image{solid(color.Black), picker(), picker(), solid(color.Gray{Y: 120})}}
	if err := Run(context.Background(), r, steps, Options{Sleep: noSleep}); err != nil {
		t.Fatal(err)
	}
	if r.n != 4 {
		t.Fatalf("looked %d times, want 4", r.n)
	}
}

func TestWaitFatalOnTimeout(t *testing.T) {
	steps, _ := Parse("wait-leave-picker 1s\n")
	r := &rec{looks: []image.Image{picker()}}
	tick := time.Now()
	sleep := func(context.Context, time.Duration) error { time.Sleep(600 * time.Millisecond); _ = tick; return nil }
	if err := Run(context.Background(), r, steps, Options{Sleep: sleep}); err == nil {
		t.Fatal("a screen stuck on the picker must fail the step")
	}
}

func TestWaitStableAndChangeAreNotFatal(t *testing.T) {
	steps, _ := Parse("wait-change 1s\nwait-stable 1s\n")
	a, b := solid(color.Gray{Y: 100}), solid(color.Gray{Y: 200})
	r := &rec{looks: []image.Image{a, a, b, b, b}}
	sleep := func(context.Context, time.Duration) error { time.Sleep(400 * time.Millisecond); return nil }
	if err := Run(context.Background(), r, steps, Options{Sleep: sleep}); err != nil {
		t.Fatal(err)
	}
}

func TestScreenClassifiers(t *testing.T) {
	if !IsBlack(solid(color.Black)) || IsBlack(picker()) || !IsPicker(picker()) || IsPicker(solid(color.Gray{Y: 120})) {
		t.Fatal("classifiers")
	}
	if Diff(solid(color.Gray{Y: 10}), solid(color.Gray{Y: 11})) != 0 || Diff(solid(color.Gray{Y: 10}), solid(color.Gray{Y: 200})) != 1 {
		t.Fatal("diff")
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{"", "# only", "jump", "wait x", "wait 11m", "key bogus", "key t+ctrl", "secret", "click 2 0", "click 0.5", "wait-stable 0s", "wait-leave-picker x"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUnknownSecretTypesNothing(t *testing.T) {
	steps, _ := Parse("type a\nsecret nope\n")
	r := &rec{}
	if err := Run(context.Background(), r, steps, Options{}); err == nil || len(r.ev) != 0 {
		t.Fatalf("err=%v ev=%v", err, r.ev)
	}
}
