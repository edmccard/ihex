// Package ihex implements a parser for Intel HEX files.
package ihex

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
)

// A Record holds the address and data bytes from a data (type 0)
// record. The Address field is calculated from the load offset of the
// record plus any segment that is in effect.
type Record struct {
	Address uint32
	Bytes   []byte
}

// A ParseError represents an error encountered during parsing.
type ParseError struct {
	Line int
	Msg  string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
}

// A Parser reads records from an io.Reader, with an interface similar
// to bufio.Scanner.
type Parser struct {
	scanner *bufio.Scanner
	field   [256]byte
	err     error
	lba     uint32
	useLBA  bool
	sba     uint32
	useSBA  bool
	cs      uint16
	ip      uint16
	hasCSIP bool
	eip     uint32
	hasEIP  bool
	data    Record
	wrap    *Record
	b       []byte
	line    int
	sum     byte
	ended   bool
}

// NewParser returns a new Parser to read from r.
func NewParser(r io.Reader) *Parser {
	return &Parser{scanner: bufio.NewScanner(r)}
}

// Parse reads the next data record, which can then be accessed by the
// Data method. It returns false when there are no more data records,
// or if an error occurred during parsing. After parsing is finished,
// information from record types 3 or 5 can be accessed by the CSIP or
// EIP methods; an error, if any, can be accessed by the Err method.
func (p *Parser) Parse() bool {
NextRec:
	if p.err != nil {
		return false
	}
	if p.wrap != nil {
		p.data = *p.wrap
		p.wrap = nil
		return true
	}
	if !p.scanLine() {
		return false
	}
	b := p.scanner.Bytes()
	if len(b) == 0 {
		goto NextRec
	}
	if b[0] != ':' {
		p.err = p.makeError("missing record mark")
		return false
	}
	p.b = b[1:]
	p.sum = 0
	reclen := p.readByteField()
	offset := p.readWordField()
	rectyp := p.readByteField()
	p.checkRecLen(rectyp, reclen)
	if !p.parseInfo(rectyp, reclen, offset) {
		goto NextRec
	}
	return p.err == nil
}

func (p *Parser) scanLine() bool {
	if ok := p.scanner.Scan(); !ok {
		p.err = p.scanner.Err()
		if p.err == nil {
			if !p.ended {
				p.err = p.makeError("missing end record")
			}
		}
		return false
	}
	if p.ended {
		p.err = p.makeError("record after end")
		return false
	}
	p.line++
	return true
}

func (p *Parser) checkRecLen(rectyp, reclen byte) {
	if p.err != nil {
		return
	}
	if rectyp > 0 && reclen != reclens[rectyp] {
		p.err = p.makeError("invalid record length")
		return
	}
}

var reclens = [...]byte{0, 0, 2, 4, 2, 4}

// Data returns the last record read by the Parse method. The
// underlying data may be overwritten by subsequent calls to Parse.
func (p *Parser) Data() Record {
	return p.data
}

// Err returns the first error that was encountered by the Parser.
func (p *Parser) Err() error {
	return p.err
}

// CSIP returns cs and ip with ok true if the parser read a record of
// type 3; otherwise it returns with ok false.
func (p *Parser) CSIP() (cs uint16, ip uint16, ok bool) {
	return p.cs, p.ip, p.hasCSIP
}

// EIP returns eip with ok true if the parser read a record of type 5;
// otherwise it returns with ok false.
func (p *Parser) EIP() (eip uint32, ok bool) {
	return p.eip, p.hasEIP
}

func (p *Parser) parseInfo(rectyp, reclen byte, offset uint16) bool {
	if p.err != nil {
		return true
	}
	gotData := false
	switch rectyp {
	case 0:
		p.data.Bytes = p.readField(reclen)
		if p.useSBA {
			p.data.Address = p.sba + uint32(offset)
		} else if p.useLBA {
			p.data.Address = p.lba | uint32(offset)
		} else {
			p.data.Address = uint32(offset)
		}
		if !p.useLBA {
			next := int(offset) + len(p.data.Bytes)
			extra := (next - 1) - 0xffff
			if extra > 0 {
				p.wrap = &Record{}
				// p.sba == 0 if useSBA is false
				p.wrap.Address = p.sba + (uint32(next-1) & 0xffff)
				p.wrap.Bytes = p.data.Bytes[extra:]
				p.data.Bytes = p.data.Bytes[:extra]
			}
		}
		gotData = true
	case 1:
		p.ended = true
	case 2:
		p.sba = uint32(p.readWordField()) << 4
		p.useSBA = true
		p.lba = 0
		p.useLBA = false
	case 3:
		p.cs = p.readWordField()
		p.ip = p.readWordField()
		p.hasCSIP = true
	case 4:
		p.sba = 0
		p.useSBA = false
		p.lba = uint32(p.readWordField()) << 16
		p.useLBA = true
	case 5:
		p.eip = uint32(p.readWordField())
		p.eip <<= 16
		p.eip |= uint32(p.readWordField())
		p.hasEIP = true
	}
	p.endRecord()
	return gotData
}

func (p *Parser) endRecord() {
	// read checksum without overwriting the previous field
	p.readFieldInto(1, p.field[255:])
	if p.err != nil {
		return
	}
	if p.sum != 0 {
		p.err = p.makeError("invalid checksum")
		return
	}
	if len(p.b) > 0 {
		p.err = p.makeError("trailing data")
	}
}

func (p *Parser) readByteField() byte {
	bytes := p.readField(1)
	if p.err != nil {
		return 0
	}
	return bytes[0]
}

func (p *Parser) readWordField() uint16 {
	bytes := p.readField(2)
	if p.err != nil {
		return 0
	}
	return (uint16(bytes[0]) << 8) | uint16(bytes[1])
}

func (p *Parser) readField(n byte) []byte {
	return p.readFieldInto(n, p.field[:])
}

func (p *Parser) readFieldInto(n byte, field []byte) []byte {
	if p.err != nil {
		return nil
	}
	var nd int
	nd, p.err = hex.Decode(field[:], p.b[:n*2])
	p.b = p.b[nd*2:]
	if byte(nd) < n {
		p.err = p.makeError("record too short")
		return nil
	}
	if p.err != nil {
		return nil
	}
	for i := 0; i < nd; i++ {
		p.sum += field[i]
	}
	return field[:nd]
}

func (p *Parser) makeError(msg string) error {
	return ParseError{Line: p.line, Msg: msg}
}
