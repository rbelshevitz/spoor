package main

import "testing"

func TestProcessSortKeepsPinnedProcessFirst(t *testing.T) {
	u := &ui{sortBy: 1, pinnedPID: 42, snap: Snapshot{Processes: []Process{
		{PID: 7, RSSBytes: 900},
		{PID: 42, RSSBytes: 10},
		{PID: 3, RSSBytes: 900},
	}}}
	u.sort()
	if got := u.snap.Processes[0].PID; got != 42 {
		t.Fatalf("pinned PID moved to %d", got)
	}
	if got := u.snap.Processes[1].PID; got != 3 {
		t.Fatalf("equal-memory processes are not deterministic, got PID %d", got)
	}
}

func TestProcessSortByCPUUsesPIDAsTieBreaker(t *testing.T) {
	u := &ui{sortBy: 2, snap: Snapshot{Processes: []Process{
		{PID: 20, CPUPercent: 4},
		{PID: 10, CPUPercent: 4},
	}}}
	u.sort()
	if got := u.snap.Processes[0].PID; got != 10 {
		t.Fatalf("CPU tie-breaker returned PID %d", got)
	}
}

func TestCPUTextHasStableVisibleWidth(t *testing.T) {
	for _, value := range []float64{0, 1.2, 99.9, 100} {
		if got := len(cpuText(value)); got != 15 {
			t.Fatalf("CPU text width for %.1f is %d, want 15", value, got)
		}
	}
}

func TestDecodeAddr(t *testing.T) {
	if got := decodeAddr("0100007F:1F90"); got != "127.0.0.1:8080" {
		t.Fatalf("decodeAddr() = %q", got)
	}
	if got := decodeAddr("00000000000000000000000001000000:1F90"); got != "[::1]:8080" {
		t.Fatalf("decodeAddr() IPv6 = %q", got)
	}
	if got := decodeAddr("GG00007F:1F90"); got != "GG00007F:1F90" {
		t.Fatalf("decodeAddr() invalid IPv4 = %q", got)
	}
}

func TestTrimKeepsUTF8Valid(t *testing.T) {
	got := trim("сервер-приложение", 8)
	if got != "сервер-…" {
		t.Fatalf("trim() = %q", got)
	}
}

func TestEscapeKeyRecognizesFunctionKeyVariants(t *testing.T) {
	tests := map[string]string{
		"[11~":   "f1",
		"[15~":   "f5",
		"[15;2~": "f5",
		"[24~":   "f12",
		"OP":     "f1",
		"[A":     "up",
	}
	for sequence, want := range tests {
		if got := escapeKey(sequence); got != want {
			t.Errorf("escapeKey(%q) = %q, want %q", sequence, got, want)
		}
	}
}
