package ihex

import (
	"fmt"
	"strings"
	"testing"
)

func ExampleParser() {
	lines := `
:1000000000E10EBFEFE531E001E011E0010F40E05B
:1000100052E00E94710432E000E111EF010F41E073
:00000001FF
`
	parser := NewParser(strings.NewReader(lines))
	for parser.Parse() {
		data := parser.Data()
		fmt.Printf("%04x %d\n", data.Address, len(data.Bytes))
	}
	if err := parser.Err(); err != nil {
		fmt.Println("error:", err)
	}
	// Output:
	// 0000 16
	// 0010 16
}

func TestData(t *testing.T) {
	record := ":0B0010006164647265737320676170A7"
	bytes := []byte{
		0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x20, 0x67, 0x61, 0x70,
	}
	p := NewParser(strings.NewReader(record))
	p.Parse()
	if p.Err() != nil {
		t.Fatal("unexpected error")
	}
	data := p.Data()
	if data.Address != 0x0010 {
		t.Fatal("wrong address")
	}
	if len(data.Bytes) != 11 {
		t.Fatal("wrong data length")
	}
	for i, b := range data.Bytes {
		if b != bytes[i] {
			t.Fatal("incorrect data byte", b, bytes[i])
		}
	}
}

func TestEnd(t *testing.T) {
	record := ""
	p := NewParser(strings.NewReader(record))
	for p.Parse() {
	}
	if p.Err().Error() != "line 0: missing end record" {
		t.Error("missed missing end record")
	}

	record = ":0B0010006164647265737320676170A7"
	p = NewParser(strings.NewReader(record))
	for p.Parse() {
	}
	if p.Err().Error() != "line 1: missing end record" {
		t.Error("missed missing end record")
	}

	record = ":00000001FF\n:020000021200EA"
	p = NewParser(strings.NewReader(record))
	for p.Parse() {
	}
	if p.Err().Error() != "line 1: record after end" {
		t.Error("missed record after end")
	}
}

func TestBad(t *testing.T) {
	var cases = [][]string{
		{":0C0010006164647265737320676170A7", "data too short"},
		{":00000001", "missing bytes"},
		{":00000001F", "uneven hex"},
		{":00000001FF00", "trailing bytes"},
		{"00000001FF", "missing record mark"},
		{":01000001FF", "invalid record length"},
		{":00000001FE", "invalid checksum"},
	}
	for _, data := range cases {
		p := NewParser(strings.NewReader(data[0]))
		p.Parse()
		if p.Err() == nil {
			t.Error("missed", data[1])
		}
	}
}

func TestLBASBA(t *testing.T) {
	records := `
:0B0010006164647265737320676170A7
:020000021200EA
:0B0010006164647265737320676170A7
:02000004FFFFFC
:0B0010006164647265737320676170A7
:020000020000FC
:0B0010006164647265737320676170A7
:00000001FF
`
	addrs := []uint32{0x10, 0x12010, 0xffff0010, 0x10}
	p := NewParser(strings.NewReader(records))
	n := 0
	for p.Parse() {
		data := p.Data()
		if data.Address != addrs[n] {
			t.Error("Expected", addrs[n], "but got", data.Address)
		}
		n++
	}
	if p.Err() != nil {
		t.Error("unexpected error")
	}
}

func TestSegWrap(t *testing.T) {
	records := `
:020000021200EA
:02FFFF00000000
`
	p := NewParser(strings.NewReader(records))
	p.Parse()
	if p.Err() != nil {
		t.Fatal("unexpected error")
	}
	data := p.Data()
	if len(data.Bytes) != 1 || data.Address != 0x21fff {
		t.Error("incorrect pre-wrap data")
	}
	p.Parse()
	if p.Err() != nil {
		t.Fatal("unexpected error")
	}
	data = p.Data()
	if len(data.Bytes) != 1 || data.Address != 0x12000 {
		t.Error("incorrect post-wrap data")
	}
}
