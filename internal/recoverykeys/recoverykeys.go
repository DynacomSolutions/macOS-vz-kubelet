// Package recoverykeys parses and runs the keystroke script that drives macOS Recovery for
// create-base --recovery-sip-off. The script is blind (no screen reading), so every step is a
// plain line and timings are explicit:
//
//	# comment
//	wait 30s
//	key ctrl+alt+cmd+t      modifiers ctrl alt(opt) cmd shift, then one key: a character,
//	                        return tab esc space up down left right, f1..f12
//	type csrutil disable    types the rest of the line (no trailing return)
//	secret guest_password   types the named secret (never logged)
package recoverykeys

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DefaultScript disables SIP and authenticated-root from the Recovery Terminal and shuts the
// session down. It is a best guess for macOS 26 and can be replaced with --recovery-script.
const DefaultScript = `# language/Options screen
wait 90s
key return
wait 20s
# open Terminal from Recovery
key ctrl+alt+cmd+t
wait 15s
type csrutil disable
key return
wait 10s
type y
key return
wait 5s
type admin
key return
wait 3s
secret guest_password
key return
wait 20s
type csrutil authenticated-root disable
key return
wait 10s
type y
key return
wait 5s
type admin
key return
wait 3s
secret guest_password
key return
wait 20s
`

// Keyer presses and releases a key by X11 keysym.
type Keyer interface {
	Key(sym uint32, down bool) error
}

// Step is one parsed script line.
type Step struct {
	Wait   time.Duration
	Keys   []uint32 // modifiers first, then the key
	Text   string
	Secret string
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

// Run plays steps through k. secrets maps secret names to values; a missing name is an error
// before anything is typed. sleep is time.Sleep-like and honours ctx. snap, when not nil, is called
// with a label such as "03-wait-30s" after every wait, key and type step (never after a secret).
func Run(ctx context.Context, k Keyer, steps []Step, secrets map[string]string, sleep func(context.Context, time.Duration) error, snap func(label string)) error {
	for _, s := range steps {
		if s.Secret != "" {
			if _, ok := secrets[s.Secret]; !ok {
				return fmt.Errorf("recovery script uses unknown secret %q", s.Secret)
			}
		}
	}
	for i, s := range steps {
		var err error
		label := ""
		switch {
		case s.Wait > 0:
			err = sleep(ctx, s.Wait)
			label = "wait-" + s.Wait.String()
		case len(s.Keys) > 0:
			err = chord(k, s.Keys)
			label = "key"
		case s.Text != "":
			err = typeText(k, s.Text)
			label = "type"
		case s.Secret != "":
			err = typeText(k, secrets[s.Secret])
		}
		if err != nil {
			return err
		}
		if snap != nil && label != "" {
			snap(fmt.Sprintf("%02d-%s", i+1, label))
		}
	}
	return nil
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
