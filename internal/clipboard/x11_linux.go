package clipboard

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	x11SelectionClear   = 29
	x11SelectionRequest = 30
	x11AtomString       = 31
	x11AtomAtom         = 4
)

func probeX11Clipboard() error {
	conn, err := x11Dial()
	if err != nil {
		return err
	}
	return conn.Close()
}

func startX11Clipboard(text string, lost func()) (clipboardHolder, error) {
	xc, err := x11Dial()
	if err != nil {
		return nil, err
	}
	clip, err := xc.internAtom("CLIPBOARD")
	if err != nil {
		_ = xc.Close()
		return nil, err
	}
	utf8, err := xc.internAtom("UTF8_STRING")
	if err != nil {
		_ = xc.Close()
		return nil, err
	}
	targets, err := xc.internAtom("TARGETS")
	if err != nil {
		_ = xc.Close()
		return nil, err
	}
	win, err := xc.createWindow()
	if err != nil {
		_ = xc.Close()
		return nil, err
	}
	if err := xc.setSelectionOwner(clip, win); err != nil {
		_ = xc.Close()
		return nil, err
	}

	h := &x11Holder{
		xc:      xc,
		win:     win,
		clip:    clip,
		utf8:    utf8,
		targets: targets,
		text:    text,
		lost:    lost,
		done:    make(chan struct{}),
	}
	go h.serve()
	return h, nil
}

type x11Holder struct {
	xc      *x11Conn
	win     uint32
	clip    uint32
	utf8    uint32
	targets uint32
	text    string
	lost    func()
	done    chan struct{}
	once    sync.Once
}

func (h *x11Holder) Close() error {
	var err error
	h.once.Do(func() {
		close(h.done)
		err = h.xc.Close()
	})
	return err
}

func (h *x11Holder) serve() {
	defer func() {
		if h.lost != nil {
			h.lost()
		}
	}()
	for {
		kind, _, body, err := h.xc.read()
		if err != nil {
			return
		}
		select {
		case <-h.done:
			return
		default:
		}
		ev := kind & 0x7f
		switch ev {
		case x11SelectionClear:
			if len(body) >= 16 && binary.LittleEndian.Uint32(body[12:16]) == h.clip {
				return
			}
		case x11SelectionRequest:
			h.handleRequest(body)
		}
	}
}

func (h *x11Holder) handleRequest(body []byte) {
	if len(body) < 32 {
		return
	}
	timeStamp := binary.LittleEndian.Uint32(body[4:8])
	requestor := binary.LittleEndian.Uint32(body[12:16])
	selection := binary.LittleEndian.Uint32(body[16:20])
	target := binary.LittleEndian.Uint32(body[20:24])
	property := binary.LittleEndian.Uint32(body[24:28])
	if selection != h.clip {
		return
	}
	if property == 0 {
		property = target
	}

	ok := false
	switch target {
	case h.targets:
		atoms := []uint32{h.targets, h.utf8, x11AtomString}
		ok = h.xc.changeProperty(requestor, property, x11AtomAtom, 32, uint32sToBytes(atoms)) == nil
	case h.utf8, x11AtomString:
		ok = h.xc.changeProperty(requestor, property, target, 8, []byte(h.text)) == nil
	default:
		property = 0
		ok = true
	}
	if !ok {
		property = 0
	}
	_ = h.xc.sendSelectionNotify(requestor, timeStamp, selection, target, property)
}

type x11Conn struct {
	c      net.Conn
	seq    uint16
	base   uint32
	mask   uint32
	nextID uint32
	root   uint32
}

func x11Dial() (*x11Conn, error) {
	display := os.Getenv("DISPLAY")
	socket, number, err := x11SocketAndNumber(display)
	if err != nil {
		return nil, err
	}
	c, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("x11 connect %s: %w", socket, err)
	}
	proto, cookie := x11Auth(number)
	if err := x11WriteSetup(c, proto, cookie); err != nil {
		_ = c.Close()
		return nil, err
	}
	xc := &x11Conn{c: c}
	if err := xc.readSetup(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return xc, nil
}

func (xc *x11Conn) Close() error {
	return xc.c.Close()
}

func (xc *x11Conn) internAtom(name string) (uint32, error) {
	padded := pad4(len(name))
	req := make([]byte, 8+padded)
	req[0] = 16
	binary.LittleEndian.PutUint16(req[2:4], uint16(2+padded/4))
	binary.LittleEndian.PutUint16(req[4:6], uint16(len(name)))
	copy(req[8:], name)
	seq, err := xc.write(req)
	if err != nil {
		return 0, err
	}
	body, err := xc.readReply(seq)
	if err != nil {
		return 0, err
	}
	if len(body) < 12 {
		return 0, fmt.Errorf("x11 intern atom %s: short reply", name)
	}
	return binary.LittleEndian.Uint32(body[8:12]), nil
}

func (xc *x11Conn) createWindow() (uint32, error) {
	wid := xc.allocID()
	req := make([]byte, 32)
	req[0] = 1
	binary.LittleEndian.PutUint16(req[2:4], 8)
	binary.LittleEndian.PutUint32(req[4:8], wid)
	binary.LittleEndian.PutUint32(req[8:12], xc.root)
	binary.LittleEndian.PutUint16(req[16:18], 1)
	binary.LittleEndian.PutUint16(req[18:20], 1)
	binary.LittleEndian.PutUint16(req[22:24], 1)
	_, err := xc.write(req)
	return wid, err
}

func (xc *x11Conn) setSelectionOwner(selection, owner uint32) error {
	req := make([]byte, 16)
	req[0] = 22
	binary.LittleEndian.PutUint16(req[2:4], 4)
	binary.LittleEndian.PutUint32(req[4:8], owner)
	binary.LittleEndian.PutUint32(req[8:12], selection)
	_, err := xc.write(req)
	return err
}

func (xc *x11Conn) changeProperty(window, property, typ uint32, format byte, data []byte) error {
	padded := pad4(len(data))
	req := make([]byte, 24+padded)
	req[0] = 18
	req[1] = 0
	binary.LittleEndian.PutUint16(req[2:4], uint16(6+padded/4))
	binary.LittleEndian.PutUint32(req[4:8], window)
	binary.LittleEndian.PutUint32(req[8:12], property)
	binary.LittleEndian.PutUint32(req[12:16], typ)
	req[16] = format
	units := len(data)
	if format == 16 {
		units = len(data) / 2
	}
	if format == 32 {
		units = len(data) / 4
	}
	binary.LittleEndian.PutUint32(req[20:24], uint32(units))
	copy(req[24:], data)
	_, err := xc.write(req)
	return err
}

func (xc *x11Conn) sendSelectionNotify(requestor, timeStamp, selection, target, property uint32) error {
	req := make([]byte, 44)
	req[0] = 25
	binary.LittleEndian.PutUint16(req[2:4], 11)
	binary.LittleEndian.PutUint32(req[4:8], requestor)
	req[12] = x11SelectionRequest + 1 // SelectionNotify = 31
	binary.LittleEndian.PutUint32(req[16:20], timeStamp)
	binary.LittleEndian.PutUint32(req[20:24], requestor)
	binary.LittleEndian.PutUint32(req[24:28], selection)
	binary.LittleEndian.PutUint32(req[28:32], target)
	binary.LittleEndian.PutUint32(req[32:36], property)
	_, err := xc.write(req)
	return err
}

func (xc *x11Conn) allocID() uint32 {
	id := xc.base | xc.nextID
	xc.nextID++
	return id
}

func (xc *x11Conn) write(req []byte) (uint16, error) {
	xc.seq++
	if _, err := xc.c.Write(req); err != nil {
		return xc.seq, err
	}
	return xc.seq, nil
}

func (xc *x11Conn) read() (kind byte, seq uint16, body []byte, err error) {
	var hdr [32]byte
	if _, err := io.ReadFull(xc.c, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	kind = hdr[0]
	seq = binary.LittleEndian.Uint16(hdr[2:4])
	if kind == 1 {
		extra := binary.LittleEndian.Uint32(hdr[4:8])
		body = make([]byte, 32+4*extra)
		copy(body, hdr[:])
		if extra > 0 {
			if _, err := io.ReadFull(xc.c, body[32:]); err != nil {
				return 1, seq, nil, err
			}
		}
		return 1, seq, body, nil
	}
	out := make([]byte, 32)
	copy(out, hdr[:])
	return kind, seq, out, nil
}

func (xc *x11Conn) readReply(want uint16) ([]byte, error) {
	for {
		kind, seq, body, err := xc.read()
		if err != nil {
			return nil, err
		}
		if kind == 0 {
			return nil, fmt.Errorf("x11 error code=%d", body[1])
		}
		if kind == 1 && seq == want {
			return body, nil
		}
	}
}

func (xc *x11Conn) readSetup() error {
	var hdr [8]byte
	if _, err := io.ReadFull(xc.c, hdr[:]); err != nil {
		return err
	}
	if hdr[0] == 0 {
		reasonLen := int(hdr[1])
		rest := int(binary.LittleEndian.Uint16(hdr[6:8])) * 4
		buf := make([]byte, rest)
		_, _ = io.ReadFull(xc.c, buf)
		if reasonLen > len(buf) {
			reasonLen = len(buf)
		}
		return fmt.Errorf("x11 setup failed: %s", strings.TrimSpace(string(buf[:reasonLen])))
	}
	if hdr[0] != 1 {
		return fmt.Errorf("x11 setup: unexpected status %d", hdr[0])
	}
	rest := int(binary.LittleEndian.Uint16(hdr[6:8])) * 4
	buf := make([]byte, rest)
	if _, err := io.ReadFull(xc.c, buf); err != nil {
		return err
	}
	if len(buf) < 32 {
		return fmt.Errorf("x11 setup: short additional data")
	}
	xc.base = binary.LittleEndian.Uint32(buf[4:8])
	xc.mask = binary.LittleEndian.Uint32(buf[8:12])
	vendorLen := int(binary.LittleEndian.Uint16(buf[16:18]))
	nFormats := int(buf[21])
	off := 32 + pad4(vendorLen) + 8*nFormats
	if off+4 > len(buf) {
		return fmt.Errorf("x11 setup: missing root window")
	}
	xc.root = binary.LittleEndian.Uint32(buf[off : off+4])
	return nil
}

func x11WriteSetup(c net.Conn, proto, cookie []byte) error {
	protoPad := pad4(len(proto))
	cookiePad := pad4(len(cookie))
	req := make([]byte, 12+protoPad+cookiePad)
	req[0] = 'l'
	binary.LittleEndian.PutUint16(req[2:4], 11)
	binary.LittleEndian.PutUint16(req[6:8], uint16(len(proto)))
	binary.LittleEndian.PutUint16(req[8:10], uint16(len(cookie)))
	copy(req[12:], proto)
	copy(req[12+protoPad:], cookie)
	_, err := c.Write(req)
	return err
}

func x11SocketAndNumber(display string) (socketPath, number string, err error) {
	if display == "" {
		return "", "", fmt.Errorf("DISPLAY is empty")
	}
	hostDisp := display
	if i := strings.LastIndex(display, "."); i > strings.LastIndex(display, ":") {
		hostDisp = display[:i]
	}
	colon := strings.LastIndex(hostDisp, ":")
	if colon < 0 {
		return "", "", fmt.Errorf("invalid DISPLAY %q", display)
	}
	host := hostDisp[:colon]
	number = hostDisp[colon+1:]
	if number == "" {
		return "", "", fmt.Errorf("invalid DISPLAY %q", display)
	}
	if host != "" && host != "unix" && host != "localhost" && host != "127.0.0.1" {
		return "", "", fmt.Errorf("x11 clipboard uses a local unix socket, not host %q", host)
	}
	name := "X" + number
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		candidate := filepath.Join(runtimeDir, ".X11-unix", name)
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate, number, nil
		}
	}
	return filepath.Join("/tmp/.X11-unix", name), number, nil
}

func x11Auth(displayNumber string) (proto, cookie []byte) {
	path := os.Getenv("XAUTHORITY")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil
		}
		path = filepath.Join(home, ".Xauthority")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	hostname, _ := os.Hostname()
	off := 0
	for off+10 <= len(data) {
		family := binary.BigEndian.Uint16(data[off : off+2])
		off += 2
		addr, n, ok := xauthString(data, off)
		if !ok {
			return nil, nil
		}
		off = n
		number, n, ok := xauthString(data, off)
		if !ok {
			return nil, nil
		}
		off = n
		name, n, ok := xauthString(data, off)
		if !ok {
			return nil, nil
		}
		off = n
		value, n, ok := xauthBytes(data, off)
		if !ok {
			return nil, nil
		}
		off = n
		if string(number) != displayNumber && string(number) != "" {
			continue
		}
		switch family {
		case 65535, 252:
			return name, value
		case 256:
			if string(addr) == hostname {
				return name, value
			}
		}
	}
	return nil, nil
}

func xauthString(data []byte, off int) ([]byte, int, bool) {
	b, n, ok := xauthBytes(data, off)
	if !ok {
		return nil, off, false
	}
	return b, n, true
}

func xauthBytes(data []byte, off int) ([]byte, int, bool) {
	if off+2 > len(data) {
		return nil, off, false
	}
	n := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if off+n > len(data) {
		return nil, off, false
	}
	return data[off : off+n], off + n, true
}

func pad4(n int) int {
	return (n + 3) &^ 3
}

func uint32sToBytes(v []uint32) []byte {
	out := make([]byte, 4*len(v))
	for i, a := range v {
		binary.LittleEndian.PutUint32(out[i*4:], a)
	}
	return out
}
