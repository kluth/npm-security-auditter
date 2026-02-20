package reporter

import (
	"bytes"
	"fmt"
	"testing"
)

func TestDebugKlingon(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTerminal, LangTLH)
	report := Report{
		Package: "klingon-pkg",
		Version: "1.0.0",
	}
	err := r.Render(report)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("DEBUG KLINGON OUTPUT:\n%s\n", buf.String())
}
