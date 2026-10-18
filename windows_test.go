package supertls

import (
	"errors"
	"testing"
)

func TestDefaultWindowsMatchSentinel(t *testing.T) {
	t.Parallel()
	w := DefaultWindows()
	if w.OuterStream != 1048576 || w.OuterConn != 2097152 || w.InnerStream != 524288 ||
		w.InnerConn != 1048576 || w.Buffer != 65536 {
		t.Fatalf("defaults drifted from the proven values: %+v", w)
	}
	if err := w.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

func TestWindowsRefuseOuterStreamBelowInnerConn(t *testing.T) {
	t.Parallel()
	w := DefaultWindows()
	w.OuterStream, w.InnerConn = 512<<10, 1<<20
	if err := w.Validate(); !errors.Is(err, ErrWindowInvariant) {
		t.Fatalf("err = %v, want ErrWindowInvariant", err)
	}
	w.OuterStream = w.InnerConn
	if err := w.Validate(); err != nil {
		t.Fatalf("equal windows must pass: %v", err)
	}
}

func TestWindowsRefuseTooSmall(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*Windows){
		"OuterStream": func(w *Windows) { w.OuterStream = MinWindow - 1 },
		"OuterConn":   func(w *Windows) { w.OuterConn = MinWindow - 1 },
		"InnerStream": func(w *Windows) { w.InnerStream = MinWindow - 1 },
		"InnerConn":   func(w *Windows) { w.InnerConn = MinWindow - 1 },
		"zero":        func(w *Windows) { w.InnerStream = 0 },
		"negative":    func(w *Windows) { w.OuterConn = -1 },
		"Buffer0":     func(w *Windows) { w.Buffer = 0 },
		"BufferNeg":   func(w *Windows) { w.Buffer = -1 },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := DefaultWindows()
			mut(&w)
			if err := w.Validate(); !errors.Is(err, ErrInvalidOption) {
				t.Fatalf("err = %v, want ErrInvalidOption", err)
			}
		})
	}
}

func TestWindowsMinimumIsAccepted(t *testing.T) {
	t.Parallel()
	w := Windows{OuterStream: MinWindow, OuterConn: MinWindow, InnerStream: MinWindow, InnerConn: MinWindow, Buffer: 1}
	if err := w.Validate(); err != nil {
		t.Fatalf("MinWindow must be accepted: %v", err)
	}
}
