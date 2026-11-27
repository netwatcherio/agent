package probes

import "testing"

func TestInterfaceWatcherUnregister(t *testing.T) {
	w := NewInterfaceWatcher(0)
	un1 := w.OnChange(func(InterfaceChangeEvent) {})
	un2 := w.OnChange(func(InterfaceChangeEvent) {})
	if got := w.HandlerCount(); got != 2 {
		t.Fatalf("HandlerCount = %d, want 2", got)
	}
	un1()
	un1() // idempotent
	if got := w.HandlerCount(); got != 1 {
		t.Fatalf("HandlerCount after unregister = %d, want 1", got)
	}
	un2()
	if got := w.HandlerCount(); got != 0 {
		t.Fatalf("HandlerCount after all unregistered = %d, want 0", got)
	}
}

func TestMtrRejectsMissingTarget(t *testing.T) {
	if _, err := Mtr(&Probe{ID: 1}, true); err == nil {
		t.Fatal("Mtr with no targets should return an error, not panic")
	}
	if _, err := Mtr(nil, true); err == nil {
		t.Fatal("Mtr(nil) should return an error, not panic")
	}
}
