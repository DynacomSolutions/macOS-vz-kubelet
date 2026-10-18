package recoverykeys

import (
	"context"
	"testing"
	"time"
)

type rec struct{ ev []uint32 }

func (r *rec) Key(s uint32, down bool) error {
	if down {
		r.ev = append(r.ev, s)
	}
	return nil
}

func TestDefaultScriptParses(t *testing.T) {
	if _, err := Parse(DefaultScript); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	steps, err := Parse("wait 1s\nkey ctrl+alt+cmd+t\ntype aZ\nsecret pw\nkey return\n")
	if err != nil {
		t.Fatal(err)
	}
	var waited time.Duration
	r := &rec{}
	sleep := func(_ context.Context, d time.Duration) error { waited += d; return nil }
	if err := Run(context.Background(), r, steps, map[string]string{"pw": "x"}, sleep); err != nil {
		t.Fatal(err)
	}
	want := []uint32{0xffe3, 0xffe9, 0xffeb, 't', 'a', 'Z', 'x', 0xff0d}
	if len(r.ev) != len(want) {
		t.Fatalf("got %v want %v", r.ev, want)
	}
	for i := range want {
		if r.ev[i] != want[i] {
			t.Fatalf("got %v want %v", r.ev, want)
		}
	}
	if waited != time.Second {
		t.Fatalf("waited %v", waited)
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{"", "# only", "jump", "wait x", "wait 11m", "key bogus", "key t+ctrl", "secret"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUnknownSecretTypesNothing(t *testing.T) {
	steps, _ := Parse("type a\nsecret nope\n")
	r := &rec{}
	if err := Run(context.Background(), r, steps, nil, Sleep); err == nil || len(r.ev) != 0 {
		t.Fatalf("err=%v ev=%v", err, r.ev)
	}
}
