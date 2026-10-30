package clipboard

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCloseWaitsForClearCallbackAndPreventsNewWorkers(t *testing.T) {
	m, err := NewManager(BackendMemory, "", 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer func() { releaseOnce.Do(func() { close(release) }); _ = m.Close() }()
	m.NotifyCleared(func() { close(started); <-release })
	if err := m.Copy("secret"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("clear callback did not start")
	}
	done := make(chan error, 1)
	go func() { done <- m.Close() }()
	select {
	case <-done:
		t.Fatal("Close returned before callback stopped")
	case <-time.After(30 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish")
	}
	if err := m.Copy("late secret"); !errors.Is(err, ErrClosed) {
		t.Fatalf("copy after Close: %v", err)
	}
	m.ScheduleClear("late secret")
	if err := m.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
}

func TestCopyAndCloseRace(t *testing.T) {
	for range 25 {
		m, err := NewManager(BackendMemory, "", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 10 {
					if err := m.Copy("secret"); err != nil && !errors.Is(err, ErrClosed) {
						t.Error(err)
					}
					m.ScheduleClear("secret")
				}
			}()
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
	}
}
