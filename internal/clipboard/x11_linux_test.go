package clipboard

import "testing"

func TestX11SocketAndNumber(t *testing.T) {
	path, number, err := x11SocketAndNumber(":0")
	if err != nil {
		t.Fatalf(":0: %v", err)
	}
	if number != "0" {
		t.Fatalf("number=%q", number)
	}
	if path == "" {
		t.Fatal("empty socket path")
	}

	_, number, err = x11SocketAndNumber("unix:1.0")
	if err != nil {
		t.Fatalf("unix:1.0: %v", err)
	}
	if number != "1" {
		t.Fatalf("unix number=%q", number)
	}

	if _, _, err := x11SocketAndNumber("remotehost:0"); err == nil {
		t.Fatal("expected remote DISPLAY to be rejected")
	}
	if _, _, err := x11SocketAndNumber(""); err == nil {
		t.Fatal("expected empty DISPLAY to be rejected")
	}
}

func TestPad4(t *testing.T) {
	if pad4(0) != 0 || pad4(1) != 4 || pad4(4) != 4 || pad4(5) != 8 {
		t.Fatalf("pad4 produced unexpected values")
	}
}
