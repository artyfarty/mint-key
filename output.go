package main

import (
	"bytes"
	"io"
	"os"
	"sync"
)

// outW and errW are where the action code (mint, grant, clean-keys) writes its
// progress and the children it runs write theirs. The CLI leaves them on the
// terminal; `mintk web` points both at a buffer for the length of one action so
// the browser gets the same transcript the terminal would have shown.
//
// They are process globals on purpose: the web server runs one card action at a
// time (it holds actionMu around withOutput), and the CLI is single-threaded, so
// there is never a second writer to race with.
var (
	outW io.Writer = os.Stdout
	errW io.Writer = os.Stderr
)

// withOutput runs f with both streams redirected to w, restoring them after.
func withOutput(w io.Writer, f func() error) error {
	prevOut, prevErr := outW, errW
	outW, errW = w, w
	defer func() { outW, errW = prevOut, prevErr }()
	return f()
}

// syncBuffer is a bytes.Buffer safe for the concurrent writes exec makes when a
// child's stdout and stderr are both copied into it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
