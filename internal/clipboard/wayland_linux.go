package clipboard

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const (
	wlrDataControlManager = "zwlr_data_control_manager_v1"
	wlSeatInterface       = "wl_seat"
)

func probeWaylandClipboard() error {
	w, err := waylandHandshake()
	if err != nil {
		return err
	}
	return w.Close()
}

func startWaylandClipboard(text string, lost func()) (clipboardHolder, error) {
	w, err := waylandHandshake()
	if err != nil {
		return nil, err
	}

	source := w.alloc()
	device := w.alloc()
	if err := w.send(w.manager, 0, wlNewID(source)); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.send(w.manager, 1, append(wlNewID(device), wlNewID(w.seat)...)); err != nil {
		_ = w.Close()
		return nil, err
	}
	for _, mime := range []string{"text/plain;charset=utf-8", "text/plain"} {
		if err := w.send(source, 0, wlString(mime)); err != nil {
			_ = w.Close()
			return nil, err
		}
	}
	if err := w.send(device, 0, wlNewID(source)); err != nil {
		_ = w.Close()
		return nil, err
	}

	h := &waylandHolder{
		w:      w,
		source: source,
		device: device,
		text:   text,
		lost:   lost,
		done:   make(chan struct{}),
	}
	w.handlers[source] = h.onSource
	go h.serve()
	return h, nil
}

type waylandHolder struct {
	w      *wlConn
	source uint32
	device uint32
	text   string
	lost   func()
	done   chan struct{}
	once   sync.Once
}

func (h *waylandHolder) Close() error {
	var err error
	h.once.Do(func() {
		close(h.done)
		_ = h.w.send(h.device, 0, wlNewID(0))
		_ = h.w.send(h.source, 1, nil)
		err = h.w.Close()
	})
	return err
}

func (h *waylandHolder) serve() {
	defer func() {
		if h.lost != nil {
			h.lost()
		}
	}()
	for {
		select {
		case <-h.done:
			return
		default:
		}
		if err := h.w.dispatchOne(); err != nil {
			return
		}
	}
}

func (h *waylandHolder) onSource(opcode uint16, payload []byte, fds []int) {
	switch opcode {
	case 0: // send
		fd, ok := h.w.takeFD()
		if !ok {
			return
		}
		f := os.NewFile(uintptr(fd), "wayland-clipboard")
		_, _ = f.Write([]byte(h.text))
		_ = f.Close()
	case 1: // cancelled
		_ = h.Close()
	}
}

type wlConn struct {
	c        *net.UnixConn
	nextID   uint32
	handlers map[uint32]func(opcode uint16, payload []byte, fds []int)
	buf      []byte
	fds      []int
	registry uint32
	seat     uint32
	manager  uint32
}

func waylandHandshake() (*wlConn, error) {
	path, err := waylandSocket()
	if err != nil {
		return nil, err
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("wayland connect %s: %w", path, err)
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("wayland socket is not unix")
	}

	w := &wlConn{
		c:        uc,
		nextID:   1,
		handlers: map[uint32]func(opcode uint16, payload []byte, fds []int){},
	}

	var seatName, mgrName, mgrVersion uint32
	var haveSeat, haveMgr bool
	w.registry = w.alloc()
	w.handlers[w.registry] = func(opcode uint16, payload []byte, fds []int) {
		if opcode != 0 || len(payload) < 8 {
			return
		}
		name := binary.LittleEndian.Uint32(payload[0:4])
		iface, rest := wlReadString(payload[4:])
		if len(rest) < 4 {
			return
		}
		version := binary.LittleEndian.Uint32(rest[:4])
		switch iface {
		case wlSeatInterface:
			haveSeat = true
			seatName = name
		case wlrDataControlManager:
			haveMgr = true
			mgrName = name
			mgrVersion = version
		}
	}

	if err := w.send(1, 1, wlNewID(w.registry)); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.sync(); err != nil {
		_ = w.Close()
		return nil, err
	}
	if !haveSeat || !haveMgr {
		_ = w.Close()
		return nil, fmt.Errorf("wayland compositor does not advertise %s", wlrDataControlManager)
	}

	if mgrVersion > 2 {
		mgrVersion = 2
	}
	w.manager = w.bind(w.registry, mgrName, wlrDataControlManager, mgrVersion)
	w.seat = w.bind(w.registry, seatName, wlSeatInterface, 1)
	return w, nil
}

func (w *wlConn) bind(registry, name uint32, iface string, version uint32) uint32 {
	id := w.alloc()
	payload := append(wlNewID(name), wlString(iface)...)
	payload = append(payload, wlNewID(version)...)
	payload = append(payload, wlNewID(id)...)
	_ = w.send(registry, 0, payload)
	return id
}

func (w *wlConn) sync() error {
	cb := w.alloc()
	done := false
	w.handlers[cb] = func(opcode uint16, payload []byte, fds []int) {
		done = true
		delete(w.handlers, cb)
	}
	if err := w.send(1, 0, wlNewID(cb)); err != nil {
		return err
	}
	for !done {
		if err := w.dispatchOne(); err != nil {
			return err
		}
	}
	return nil
}

func (w *wlConn) alloc() uint32 {
	w.nextID++
	return w.nextID
}

func (w *wlConn) send(obj uint32, opcode uint16, payload []byte) error {
	size := 8 + len(payload)
	msg := make([]byte, size)
	binary.LittleEndian.PutUint32(msg[0:4], obj)
	binary.LittleEndian.PutUint16(msg[4:6], opcode)
	binary.LittleEndian.PutUint16(msg[6:8], uint16(size))
	copy(msg[8:], payload)
	_, err := w.c.Write(msg)
	return err
}

func (w *wlConn) dispatchOne() error {
	for len(w.buf) < 8 {
		if err := w.fill(); err != nil {
			return err
		}
	}
	size := int(binary.LittleEndian.Uint16(w.buf[6:8]))
	if size < 8 {
		return fmt.Errorf("wayland: invalid message size %d", size)
	}
	for len(w.buf) < size {
		if err := w.fill(); err != nil {
			return err
		}
	}
	obj := binary.LittleEndian.Uint32(w.buf[0:4])
	opcode := binary.LittleEndian.Uint16(w.buf[4:6])
	payload := append([]byte(nil), w.buf[8:size]...)
	w.buf = w.buf[size:]
	if h := w.handlers[obj]; h != nil {
		h(opcode, payload, nil)
	}
	return nil
}

func (w *wlConn) takeFD() (int, bool) {
	if len(w.fds) == 0 {
		return 0, false
	}
	fd := w.fds[0]
	w.fds = w.fds[1:]
	return fd, true
}

func (w *wlConn) fill() error {
	buf := make([]byte, 4096)
	oob := make([]byte, 256)
	n, oobn, _, _, err := w.c.ReadMsgUnix(buf, oob)
	if err != nil {
		return err
	}
	w.buf = append(w.buf, buf[:n]...)
	if oobn > 0 {
		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return err
		}
		for i := range msgs {
			got, err := syscall.ParseUnixRights(&msgs[i])
			if err != nil {
				return err
			}
			w.fds = append(w.fds, got...)
		}
	}
	return nil
}

func (w *wlConn) Close() error {
	for _, fd := range w.fds {
		_ = syscall.Close(fd)
	}
	w.fds = nil
	return w.c.Close()
}

func waylandSocket() (string, error) {
	display := os.Getenv("WAYLAND_DISPLAY")
	if display == "" {
		return "", fmt.Errorf("WAYLAND_DISPLAY is empty")
	}
	if filepath.IsAbs(display) {
		return display, nil
	}
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return "", fmt.Errorf("XDG_RUNTIME_DIR is empty")
	}
	return filepath.Join(dir, display), nil
}

func wlNewID(id uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], id)
	return b[:]
}

func wlString(s string) []byte {
	n := len(s) + 1
	padded := pad4(n)
	out := make([]byte, 4+padded)
	binary.LittleEndian.PutUint32(out[0:4], uint32(n))
	copy(out[4:], s)
	return out
}

func wlReadString(p []byte) (string, []byte) {
	if len(p) < 4 {
		return "", nil
	}
	n := int(binary.LittleEndian.Uint32(p[0:4]))
	if n <= 0 {
		return "", p[4:]
	}
	padded := pad4(n)
	if len(p) < 4+padded {
		return "", nil
	}
	s := p[4 : 4+n]
	if n > 0 && s[n-1] == 0 {
		s = s[:n-1]
	}
	return string(s), p[4+padded:]
}
