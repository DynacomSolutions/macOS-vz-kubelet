// Package recoverykeys parses and runs the script that drives macOS Recovery for
// create-base --recovery-sip-off through a VNC client: keys, pointer clicks and waits that
// look at the screen. One step per line:
//
//	# comment
//	note text...                 logged when reached: what the screen should show now
//	wait 30s                     fixed pause (use only where nothing on screen changes)
//	wait-visible 3m              until the screen is not black (the boot picker or later); fatal on timeout
//	wait-leave-picker 3m         until the screen is not the boot picker; fatal on timeout
//	wait-change 60s              until the screen differs from the last look; a timeout is logged, not fatal
//	wait-stable 30s              until two looks 3 s apart are equal; a timeout is logged, not fatal
//	click 0.56 0.46              left click at that fraction of width and height
//	key ctrl+alt+cmd+t           modifiers ctrl alt(opt) cmd shift, then one key: a character,
//	                             return tab esc space up down left right, f1..f12
//	type csrutil disable         types the rest of the line (no trailing return)
//	secret guest_password        types the named secret (never logged)
package recoverykeys

import (
	"context"
	"fmt"
	"image"
	"strconv"
	"strings"
	"time"
)

// DefaultScript is a best guess for macOS 26, based on the first screenshots of a hardware run: the
// guest stops at the boot picker (a "Macintosh HD" icon and an "Options" gear on black), not in
// recoveryOS. Replace it with --recovery-script once the screenshots show the real screens.
const DefaultScript = `note boot picker: black screen, Macintosh HD and Options icons
wait-visible 3m
wait 5s
click 0.558 0.4625
wait 2s
note Options selected: a Continue button should appear under it
key return
wait-leave-picker 3m
wait-stable 90s
note recoveryOS: a language screen or "Select a user you know the password for"
key return
wait-stable 30s
note user list: pick admin, then Next
click 0.5 0.45
wait 1s
key return
wait-stable 20s
note password prompt for admin
secret guest_password
key return
wait-stable 60s
note recovery utilities window: open Utilities > Terminal from the menu bar
click 0.3 0.008
wait 1s
click 0.3 0.04
wait-stable 20s
note Terminal should be open
type csrutil disable
key return
wait-stable 10s
type y
key return
wait-stable 10s
type admin
key return
wait 3s
secret guest_password
key return
wait-stable 30s
type csrutil authenticated-root disable
key return
wait-stable 10s
type y
key return
wait-stable 10s
type admin
key return
wait 3s
secret guest_password
key return
wait-stable 30s
type csrutil status; csrutil authenticated-root status
key return
wait 5s
`

// Keyer presses and releases a key by X11 keysym.
type Keyer interface {
	Key(sym uint32, down bool) error
}

// Env is what Run needs from the VNC client: keys, clicks at fractions of the desktop, and a
// fresh full screenshot.
type Env interface {
	Keyer
	Click(fx, fy float64) error
	Look() (image.Image, error)
}

// Options are the optional parts of Run. Zero values are fine for tests that do not look at the screen.
type Options struct {
	Secrets map[string]string                          // values for `secret` steps
	Sleep   func(context.Context, time.Duration) error // default Sleep
	Snap    func(label string)                         // called after wait, key, type, click and the wait-* steps
	Logf    func(format string, args ...any)           // `note` lines and what the wait-* steps saw
	Poll    time.Duration                              // gap between looks in wait-* steps, default 3 s
}

// Step is one parsed script line.
type Step struct {
	Wait   time.Duration
	Keys   []uint32 // modifiers first, then the key
	Text   string
	Secret string

	Note    string
	Click   *[2]float64
	Until   string        // "visible", "leave-picker", "change" or "stable"
	Timeout time.Duration // for Until
}

var named = map[string]uint32{
	"return": 0xff0d, "tab": 0xff09, "esc": 0xff1b, "space": 0x20,
	"up": 0xff52, "down": 0xff54, "left": 0xff51, "right": 0xff53,
}

var mods = map[string]uint32{"ctrl": 0xffe3, "alt": 0xffe9, "opt": 0xffe9, "cmd": 0xffeb, "shift": 0xffe1}

func keysym(name string) (uint32, error) {
	if s, ok := named[name]; ok {
		return s, nil
	}
	if len(name) >= 2 && name[0] == 'f' {
		if n, err := strconv.Atoi(name[1:]); err == nil && n >= 1 && n <= 12 {
			return 0xffbe + uint32(n-1), nil
		}
	}
	if r := []rune(name); len(r) == 1 && r[0] >= 0x20 && r[0] < 0x7f {
		return uint32(r[0]), nil
	}
	return 0, fmt.Errorf("unknown key %q", name)
}

// Parse reads a script. Unknown verbs, keys or durations are errors.
func Parse(script string) ([]Step, error) {
	var steps []Step
	for i, line := range strings.Split(script, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		verb, rest, _ := strings.Cut(line, " ")
		fail := func(err error) ([]Step, error) { return nil, fmt.Errorf("recovery script line %d: %w", i+1, err) }
		switch verb {
		case "wait":
			d, err := time.ParseDuration(strings.TrimSpace(rest))
			if err != nil || d < 0 || d > 10*time.Minute {
				return fail(fmt.Errorf("bad wait %q", rest))
			}
			steps = append(steps, Step{Wait: d})
		case "key":
			parts := strings.Split(strings.TrimSpace(rest), "+")
			var keys []uint32
			for j, p := range parts {
				if m, ok := mods[p]; ok && j < len(parts)-1 {
					keys = append(keys, m)
					continue
				}
				if j != len(parts)-1 {
					return fail(fmt.Errorf("%q is not a modifier", p))
				}
				s, err := keysym(p)
				if err != nil {
					return fail(err)
				}
				keys = append(keys, s)
			}
			steps = append(steps, Step{Keys: keys})
		case "type":
			steps = append(steps, Step{Text: rest})
		case "note":
			steps = append(steps, Step{Note: rest})
		case "click":
			var fx, fy float64
			if _, err := fmt.Sscanf(strings.TrimSpace(rest), "%g %g", &fx, &fy); err != nil || fx < 0 || fx > 1 || fy < 0 || fy > 1 {
				return fail(fmt.Errorf("click needs two fractions between 0 and 1, got %q", rest))
			}
			steps = append(steps, Step{Click: &[2]float64{fx, fy}})
		case "wait-visible", "wait-leave-picker", "wait-change", "wait-stable":
			d, err := time.ParseDuration(strings.TrimSpace(rest))
			if err != nil || d <= 0 || d > 10*time.Minute {
				return fail(fmt.Errorf("bad timeout %q", rest))
			}
			steps = append(steps, Step{Until: strings.TrimPrefix(verb, "wait-"), Timeout: d})
		case "secret":
			if strings.TrimSpace(rest) == "" {
				return fail(fmt.Errorf("secret needs a name"))
			}
			steps = append(steps, Step{Secret: strings.TrimSpace(rest)})
		default:
			return fail(fmt.Errorf("unknown verb %q", verb))
		}
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("recovery script has no steps")
	}
	return steps, nil
}

// Run plays steps through env. A missing secret is an error before anything is typed. Snap, when set,
// is called with a label such as "03-wait-30s" after every step except note and secret.
func Run(ctx context.Context, env Env, steps []Step, o Options) error {
	for _, s := range steps {
		if s.Secret != "" {
			if _, ok := o.Secrets[s.Secret]; !ok {
				return fmt.Errorf("recovery script uses unknown secret %q", s.Secret)
			}
		}
	}
	if o.Sleep == nil {
		o.Sleep = Sleep
	}
	if o.Poll <= 0 {
		o.Poll = 3 * time.Second
	}
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var last image.Image // the most recent look, for wait-change
	for i, s := range steps {
		var err error
		label := ""
		switch {
		case s.Note != "":
			logf("step %d expects: %s", i+1, s.Note)
		case s.Wait > 0:
			err = o.Sleep(ctx, s.Wait)
			label = "wait-" + s.Wait.String()
		case len(s.Keys) > 0:
			err = chord(env, s.Keys)
			label = "key"
		case s.Text != "":
			err = typeText(env, s.Text)
			label = "type"
		case s.Secret != "":
			err = typeText(env, o.Secrets[s.Secret])
		case s.Click != nil:
			err = env.Click(s.Click[0], s.Click[1])
			label = "click"
		case s.Until != "":
			last, err = waitScreen(ctx, env, s, last, o, logf)
			label = "wait-" + s.Until
		}
		if err != nil {
			return fmt.Errorf("step %d: %w", i+1, err)
		}
		if o.Snap != nil && label != "" {
			o.Snap(fmt.Sprintf("%02d-%s", i+1, label))
		}
	}
	return nil
}

// waitScreen polls the screen until the step's condition holds. visible and leave-picker fail on
// timeout; change and stable only log it. A look that fails counts as "no information yet".
func waitScreen(ctx context.Context, env Env, s Step, last image.Image, o Options, logf func(string, ...any)) (image.Image, error) {
	deadline := time.Now().Add(s.Timeout)
	var prev image.Image
	for n := 0; ; n++ {
		img, err := env.Look()
		if err != nil {
			logf("wait-%s: look failed: %v", s.Until, err)
		} else {
			ok := false
			switch s.Until {
			case "visible":
				ok = !IsBlack(img)
			case "leave-picker":
				ok = !IsBlack(img) && !IsPicker(img)
			case "change":
				ok = last != nil && Diff(last, img) > 0.01
			case "stable":
				ok = prev != nil && Diff(prev, img) < 0.001
			}
			if ok {
				logf("wait-%s satisfied after %d look(s)", s.Until, n+1)
				return img, nil
			}
			prev = img
			if s.Until == "change" && last == nil {
				last = img // nothing to compare with yet: the first look is the baseline
			}
		}
		if time.Now().After(deadline) {
			if s.Until == "visible" || s.Until == "leave-picker" {
				return prev, fmt.Errorf("wait-%s: screen did not get there within %s", s.Until, s.Timeout)
			}
			logf("wait-%s: timed out after %s, going on", s.Until, s.Timeout)
			return prev, nil
		}
		if err := o.Sleep(ctx, o.Poll); err != nil {
			return prev, err
		}
	}
}

// lumaRatio samples the image on a grid and returns the fraction of samples darker than 24/255.
func lumaRatio(img image.Image) float64 {
	b := img.Bounds()
	dark, total := 0, 0
	for y := b.Min.Y; y < b.Max.Y; y += 8 {
		for x := b.Min.X; x < b.Max.X; x += 8 {
			r, g, bl, _ := img.At(x, y).RGBA()
			if (r+g+bl)/3>>8 < 24 {
				dark++
			}
			total++
		}
	}
	if total == 0 {
		return 1
	}
	return float64(dark) / float64(total)
}

// IsBlack reports a screen that is (almost) entirely black: no display output yet.
func IsBlack(img image.Image) bool { return lumaRatio(img) > 0.999 }

// IsPicker reports the boot picker: a mostly black screen with a few icons. recoveryOS and the
// installed macOS draw a wallpaper or window, which is far from black.
func IsPicker(img image.Image) bool { return lumaRatio(img) > 0.9 }

// Diff is the fraction of sampled pixels that differ by more than 16 in some channel; the images
// must have the same bounds or Diff returns 1.
func Diff(a, b image.Image) float64 {
	if a.Bounds() != b.Bounds() {
		return 1
	}
	r := a.Bounds()
	diff, total := 0, 0
	for y := r.Min.Y; y < r.Max.Y; y += 8 {
		for x := r.Min.X; x < r.Max.X; x += 8 {
			ar, ag, ab, _ := a.At(x, y).RGBA()
			br, bg, bb, _ := b.At(x, y).RGBA()
			if absDiff(ar, br) > 16<<8 || absDiff(ag, bg) > 16<<8 || absDiff(ab, bb) > 16<<8 {
				diff++
			}
			total++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(diff) / float64(total)
}

func absDiff(a, b uint32) uint32 {
	if a > b {
		return a - b
	}
	return b - a
}

func chord(k Keyer, keys []uint32) error {
	for _, s := range keys {
		if err := k.Key(s, true); err != nil {
			return err
		}
	}
	time.Sleep(50 * time.Millisecond)
	for i := len(keys) - 1; i >= 0; i-- {
		if err := k.Key(keys[i], false); err != nil {
			return err
		}
	}
	time.Sleep(50 * time.Millisecond)
	return nil
}

func typeText(k Keyer, text string) error {
	for _, r := range text {
		if r < 0x20 || r >= 0x7f {
			return fmt.Errorf("cannot type non-ASCII or control character %U", r)
		}
		keys := []uint32{uint32(r)}
		if (r >= 'A' && r <= 'Z') || strings.ContainsRune(`~!@#$%^&*()_+{}|:"<>?`, r) {
			keys = []uint32{0xffe1, uint32(r)} // Shift_L, then the character
		}
		if err := chord(k, keys); err != nil {
			return err
		}
	}
	return nil
}

// Sleep waits d or until ctx ends.
func Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
