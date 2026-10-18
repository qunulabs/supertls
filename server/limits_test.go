package server

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultLimitsMatchSentinel(t *testing.T) {
	t.Parallel()

	want := Limits{
		MaxConcurrent:          1024,
		MaxPerAddress:          256,
		OpenBurst:              512,
		OpenRefillPerSecond:    17.0,
		BucketSweep:            5 * time.Minute,
		AcceptTimeout:          5 * time.Second,
		InnerHandshakeTimeout:  20 * time.Second,
		InnerMaxConnectionIdle: 5 * time.Minute,
		MaxLifetime:            4 * time.Hour,
	}
	if got := DefaultLimits(); got != want {
		t.Fatalf("DefaultLimits() = %+v, want %+v", got, want)
	}
	if KeepaliveMinTime != 5*time.Second {
		t.Fatalf("KeepaliveMinTime = %s, want 5s", KeepaliveMinTime)
	}
	if err := want.Validate(); err != nil {
		t.Fatalf("the defaults are not valid: %v", err)
	}
}

func TestLimitsValidateRejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		mut  func(*Limits)
	}{
		{"MaxConcurrent zero", func(l *Limits) { l.MaxConcurrent = 0 }},
		{"MaxConcurrent negative", func(l *Limits) { l.MaxConcurrent = -1 }},
		{"MaxPerAddress zero", func(l *Limits) { l.MaxPerAddress = 0 }},
		{"OpenBurst zero", func(l *Limits) { l.OpenBurst = 0 }},
		{"OpenBurst negative", func(l *Limits) { l.OpenBurst = -5 }},
		{"OpenRefillPerSecond zero", func(l *Limits) { l.OpenRefillPerSecond = 0 }},
		{"OpenRefillPerSecond negative", func(l *Limits) { l.OpenRefillPerSecond = -1 }},
		{"BucketSweep zero", func(l *Limits) { l.BucketSweep = 0 }},
		{"AcceptTimeout zero", func(l *Limits) { l.AcceptTimeout = 0 }},
		{"InnerHandshakeTimeout negative", func(l *Limits) { l.InnerHandshakeTimeout = -time.Second }},
		{"InnerMaxConnectionIdle zero", func(l *Limits) { l.InnerMaxConnectionIdle = 0 }},
		{"MaxLifetime zero", func(l *Limits) { l.MaxLifetime = 0 }},
		{"MaxPerAddress above MaxConcurrent", func(l *Limits) { l.MaxConcurrent, l.MaxPerAddress = 10, 11 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := DefaultLimits()
			tc.mut(&l)
			if err := l.Validate(); !errors.Is(err, ErrInvalidOption) {
				t.Fatalf("Validate() = %v, want ErrInvalidOption", err)
			}
		})
	}
}

func TestServerWindowsValidate(t *testing.T) {
	t.Parallel()

	const k = 1 << 10
	cases := []struct {
		name string
		w    Windows
		want error // nil means valid
	}{
		{"zero value", Windows{}, nil},
		{"all set", Windows{OuterStream: 1024 * k, OuterConn: 2048 * k, InnerStream: 512 * k, InnerConn: 1024 * k}, nil},
		{"outer pair equal", Windows{OuterStream: 512 * k, InnerConn: 512 * k}, nil},
		{"only conn windows", Windows{OuterConn: 128 * k, InnerStream: 128 * k}, nil},
		{"outer stream below floor", Windows{OuterStream: 64*k - 1, InnerConn: 64 * k}, ErrInvalidOption},
		{"outer conn below floor", Windows{OuterConn: 1}, ErrInvalidOption},
		{"inner stream below floor", Windows{InnerStream: 100}, ErrInvalidOption},
		{"inner conn below floor", Windows{OuterStream: 1024 * k, InnerConn: 64*k - 1}, ErrInvalidOption},
		{"negative window", Windows{OuterConn: -1}, ErrInvalidOption},
		{"only outer stream set", Windows{OuterStream: 1024 * k}, ErrWindowInvariant},
		{"only inner conn set", Windows{InnerConn: 1024 * k}, ErrWindowInvariant},
		{"outer stream below inner conn", Windows{OuterStream: 512 * k, InnerConn: 1024 * k}, ErrWindowInvariant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.w.Validate()
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate() = %v, want %v", err, tc.want)
			}
		})
	}
}
