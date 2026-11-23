// spoor answers “why is this running?” with a small, dependency-free TUI.
// It intentionally reads Linux procfs directly, so it remains useful on a
// rescue host where installing a large monitoring stack is not an option.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const reset = "\x1b[0m"

type Process struct {
	PID        int     `json:"pid"`
	PPID       int     `json:"ppid"`
	User       string  `json:"user"`
	State      string  `json:"state"`
	Name       string  `json:"name"`
	Cmd        string  `json:"command"`
	RSS        string  `json:"rss"`
	Started    string  `json:"started,omitempty"`
	Cgroup     string  `json:"cgroup,omitempty"`
	RSSBytes   int64   `json:"-"`
	RSSDelta   int64   `json:"memory_delta_bytes,omitempty"`
	RSSRate    float64 `json:"memory_rate_bytes_sec,omitempty"`
	CPUTime    uint64  `json:"-"`
	StartTime  uint64  `json:"-"`
	CPUPercent float64 `json:"cpu_percent,omitempty"`
	Children   int     `json:"children"`
}
type Port struct {
	Proto   string `json:"protocol"`
	Local   string `json:"local"`
	State   string `json:"state"`
	PID     string `json:"pid"`
	Process string `json:"process"`
}
type Container struct {
	Runtime string `json:"runtime"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	Status  string `json:"status"`
}
type Pressure struct {
	CPU    float64 `json:"cpu,omitempty"`
	Memory float64 `json:"memory,omitempty"`
	IO     float64 `json:"io,omitempty"`
}
type SystemStats struct {
	MemTotal     int64   `json:"mem_total_bytes,omitempty"`
	MemAvailable int64   `json:"mem_available_bytes,omitempty"`
	SwapTotal    int64   `json:"swap_total_bytes,omitempty"`
	SwapFree     int64   `json:"swap_free_bytes,omitempty"`
	Load1        float64 `json:"load1,omitempty"`
	Load5        float64 `json:"load5,omitempty"`
	Load15       float64 `json:"load15,omitempty"`
	Uptime       float64 `json:"uptime_seconds,omitempty"`
}
type TimelinePoint struct {
	At        time.Time `json:"at"`
	Processes int       `json:"processes"`
	Ports     int       `json:"ports"`
	CPU       float64   `json:"cpu,omitempty"`
	Memory    float64   `json:"memory,omitempty"`
	IO        float64   `json:"io,omitempty"`
	New       int       `json:"new"`
	Gone      int       `json:"gone"`
	Restarts  int       `json:"restarts,omitempty"`
}
type Snapshot struct {
	At         time.Time   `json:"at"`
	Access     string      `json:"access"`
	Pressure   Pressure    `json:"pressure"`
	System     SystemStats `json:"system"`
	Processes  []Process   `json:"processes"`
	Ports      []Port      `json:"ports"`
	Containers []Container `json:"containers"`
}

func main() {
	pid := flag.Int("pid", 0, "focus a PID")
	port := flag.Int("port", 0, "focus a port")
	jsonOut := flag.Bool("json", false, "print a machine-readable snapshot")
	htmlOut := flag.String("html", "", "write a human-readable HTML report")
	interval := flag.Duration("interval", 2*time.Second, "refresh interval")
	flag.Parse()
	if *jsonOut {
		s := collect()
		printJSON(s, *pid, *port)
		return
	}
	if *htmlOut != "" {
		if err := writeHTMLReport(*htmlOut, collect()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("wrote", *htmlOut)
		return
	}
	if *pid > 0 || *port > 0 {
		runFocused(*pid, *port)
	}
	startTUI(*interval)
}

func collect() Snapshot {
	p := processes()
	return Snapshot{At: time.Now(), Access: accessMode(), Pressure: pressure(), System: systemStats(), Processes: p, Ports: ports(p), Containers: containers()}
}

func systemStats() SystemStats {
	stats := SystemStats{}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			value, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				continue
			}
			value *= 1024
			switch fields[0] {
			case "MemTotal:":
				stats.MemTotal = value
			case "MemAvailable:":
				stats.MemAvailable = value
			case "SwapTotal:":
				stats.SwapTotal = value
			case "SwapFree:":
				stats.SwapFree = value
			}
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) >= 3 {
			stats.Load1, _ = strconv.ParseFloat(fields[0], 64)
			stats.Load5, _ = strconv.ParseFloat(fields[1], 64)
			stats.Load15, _ = strconv.ParseFloat(fields[2], 64)
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) > 0 {
			stats.Uptime, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
	return stats
}

func pressure() Pressure {
	return Pressure{CPU: readPressure("/proc/pressure/cpu"), Memory: readPressure("/proc/pressure/memory"), IO: readPressure("/proc/pressure/io")}
}

func readPressure(path string) float64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	line := strings.Split(string(b), "\n")[0]
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, "avg10=") {
			value, _ := strconv.ParseFloat(strings.TrimPrefix(field, "avg10="), 64)
			return value
		}
	}
	return 0
}

func accessMode() string {
	if os.Geteuid() == 0 {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			return "ROOT via sudo (from " + sudoUser + ")"
		}
		return "ROOT"
	}
	return fmt.Sprintf("USER (uid %d)", os.Geteuid())
}

func accessColor(access string) string {
	if strings.HasPrefix(access, "ROOT") {
		return green
	}
	return yellow
}

func processes() []Process {
	ents, _ := os.ReadDir("/proc")
	out := make([]Process, 0, len(ents))
	counts := map[int]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, err := readProcess(pid)
		if err == nil {
			out = append(out, p)
			counts[p.PPID]++
		}
	}
	for i := range out {
		out[i].Children = counts[out[i].PID]
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := processStateRank(out[i].State), processStateRank(out[j].State)
		if ri != rj {
			return ri < rj
		}
		return out[i].PID < out[j].PID
	})
	return out
}

func readProcess(pid int) (Process, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return Process{}, err
	}
	line := string(b)
	a, z := strings.IndexByte(line, '('), strings.LastIndexByte(line, ')')
	if a < 0 || z < a {
		return Process{}, errors.New("bad stat")
	}
	name := line[a+1 : z]
	f := strings.Fields(line[z+2:])
	if len(f) < 22 {
		return Process{}, errors.New("short stat")
	}
	ppid, _ := strconv.Atoi(f[1])
	state := f[0]
	// /proc/[pid]/stat reports RSS in memory pages, not kilobytes.
	rssPages, _ := strconv.ParseInt(f[21], 10, 64)
	userTicks, _ := strconv.ParseUint(f[11], 10, 64)
	systemTicks, _ := strconv.ParseUint(f[12], 10, 64)
	startTime, _ := strconv.ParseUint(f[19], 10, 64)
	rss := fmt.Sprintf("%dM", rssPages*int64(os.Getpagesize())/1024/1024)
	cmd := name
	if cb, e := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); e == nil && len(cb) > 0 {
		cmd = strings.TrimSpace(strings.ReplaceAll(string(cb), "\x00", " "))
	}
	user := "?"
	if st, e := os.Stat(fmt.Sprintf("/proc/%d", pid)); e == nil {
		if u, e := statUID(st); e == nil {
			user = u
		}
	}
	return Process{PID: pid, PPID: ppid, User: user, State: state, Name: name, Cmd: cmd, RSS: rss, Cgroup: readCgroup(pid), RSSBytes: rssPages * int64(os.Getpagesize()), CPUTime: userTicks + systemTicks, StartTime: startTime}, nil
}

func readCgroup(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	var fallback string
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[2] == "" {
			continue
		}
		if fields[0] == "0" {
			return fields[2]
		}
		fallback = fields[2]
	}
	return fallback
}

func statUID(st fs.FileInfo) (string, error) {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "?", errors.New("no uid")
	}
	return strconv.FormatUint(uint64(s.Uid), 10), nil
}

func ports(ps []Process) []Port {
	byInode := map[string]Process{}
	for _, p := range ps {
		fdDir := fmt.Sprintf("/proc/%d/fd", p.PID)
		entries, _ := os.ReadDir(fdDir)
		for _, entry := range entries {
			target, e := os.Readlink(filepath.Join(fdDir, entry.Name()))
			if e != nil {
				continue
			}
			if strings.HasPrefix(target, "socket:[") {
				byInode[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = p
			}
		}
	}
	var out []Port
	for _, proto := range []string{"tcp", "tcp6"} {
		out = append(out, readNet(fmt.Sprintf("/proc/net/%s", proto), proto, byInode)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Local < out[j].Local })
	return out
}

func readNet(path, proto string, owners map[string]Process) []Port {
	f, e := os.Open(path)
	if e != nil {
		return nil
	}
	defer f.Close()
	var out []Port
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		local := decodeAddr(f[1])
		state := map[string]string{"0A": "LISTEN", "01": "ESTABLISHED", "06": "TIME_WAIT"}[f[3]]
		if state == "" {
			state = f[3]
		}
		p := owners[f[9]]
		out = append(out, Port{Proto: strings.TrimSuffix(proto, "6"), Local: local, State: state, PID: fmt.Sprint(p.PID), Process: p.Name})
	}
	return out
}

func decodeAddr(v string) string {
	x := strings.Split(v, ":")
	if len(x) != 2 {
		return v
	}
	n, e := strconv.ParseUint(x[1], 16, 16)
	if e != nil {
		return v
	}
	ip := x[0]
	if len(ip) == 8 {
		b, err := hex.DecodeString(ip)
		if err != nil || len(b) != 4 {
			return v
		}
		for i, j := 0, 3; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d", b[0], b[1], b[2], b[3], n)
	}
	if len(ip) == 32 {
		b, err := hex.DecodeString(ip)
		if err != nil {
			return v
		}
		// Linux stores each 32-bit IPv6 word little-endian in /proc/net/tcp6.
		for start := 0; start < len(b); start += 4 {
			for i, j := start, start+3; i < j; i, j = i+1, j-1 {
				b[i], b[j] = b[j], b[i]
			}
		}
		return net.JoinHostPort(net.IP(b).String(), strconv.Itoa(int(n)))
	}
	return v
}

var (
	containerCacheAt time.Time
	containerCache   []Container
)

func containers() []Container {
	if time.Since(containerCacheAt) < 5*time.Second {
		return append([]Container(nil), containerCache...)
	}
	var out []Container
	for _, runtime := range []string{"docker", "podman"} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		b, e := exec.CommandContext(ctx, runtime, "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}").Output()
		cancel()
		if e != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			f := strings.Split(line, "|")
			if len(f) == 4 {
				out = append(out, Container{Runtime: runtime, ID: f[0], Name: f[1], Image: f[2], Status: f[3]})
			}
		}
	}
	containerCacheAt = time.Now()
	containerCache = append(containerCache[:0], out...)
	return append([]Container(nil), out...)
}

func printJSON(s Snapshot, pid, port int) {
	type report struct {
		Snapshot
		Focus    *Process  `json:"focus,omitempty"`
		Port     *Port     `json:"port,omitempty"`
		Ancestry []Process `json:"ancestry,omitempty"`
	}
	r := report{Snapshot: s}
	if pid > 0 {
		for _, p := range s.Processes {
			if p.PID == pid {
				r.Focus = &p
				r.Ancestry = ancestry(s.Processes, pid)
				break
			}
		}
	}
	if port > 0 {
		for _, p := range s.Ports {
			if strings.HasSuffix(p.Local, ":"+strconv.Itoa(port)) {
				r.Port = &p
				break
			}
		}
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(b))
}
func ancestry(ps []Process, pid int) []Process {
	by := map[int]Process{}
	for _, p := range ps {
		by[p.PID] = p
	}
	var out []Process
	for pid > 0 {
		p, ok := by[pid]
		if !ok {
			break
		}
		out = append(out, p)
		if p.PPID == pid {
			break
		}
		pid = p.PPID
	}
	return out
}
func runFocused(pid, port int) {
	s := collect()
	if pid > 0 {
		for _, p := range s.Processes {
			if p.PID == pid {
				fmt.Printf("%s %s (pid %d)\n\n", accent("FOCUS", cyan), p.Name, p.PID)
				for _, a := range ancestry(s.Processes, pid) {
					fmt.Printf("  %s %s\n", arrow, a.Cmd)
				}
			}
		}
	}
	if port > 0 {
		for _, p := range s.Ports {
			if strings.HasSuffix(p.Local, ":"+strconv.Itoa(port)) {
				fmt.Printf("%s %s → %s (%s)\n", accent("PORT", yellow), p.Local, p.Process, p.PID)
			}
		}
	}
	os.Exit(0)
}

var terminalInput *os.File
var savedTermios *syscall.Termios

type terminalWinsize struct {
	Row, Col, Xpixel, Ypixel uint16
}

type ui struct {
	snap             Snapshot
	base             Snapshot
	tab, cursor      int
	offset           int
	pinnedPID        int
	filter           string
	sortBy           int
	detail           *Process
	confirm          bool
	diff             bool
	searching        bool
	showIdle         bool
	refreshRequested bool
	timelineMode     bool
	timeline         []TimelinePoint
	status           string
	width            int
	height           int
	last             time.Time
	treeMode         bool
	tagged           map[int]bool
	cpuReady         bool
}

func startTUI(interval time.Duration) {
	u := &ui{tab: 0, tagged: make(map[int]bool)}
	restoreTerminal := setupTerminal()
	defer restoreTerminal()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; fmt.Print("\x1b[?25h\x1b[0m\n"); os.Exit(0) }()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	snapshots := make(chan Snapshot, 1)
	refreshing := false
	requestSnapshot := func() {
		if refreshing {
			return
		}
		refreshing = true
		go func() { snapshots <- collect() }()
	}
	requestSnapshot()
	for {
		if k := readKey(); k != "" {
			if u.handle(k) {
				break
			}
			if u.refreshRequested {
				u.refreshRequested = false
				requestSnapshot()
			}
		}
		select {
		case snapshot := <-snapshots:
			refreshing = false
			u.applySnapshot(snapshot)
		case <-ticker.C:
			requestSnapshot()
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	fmt.Print("\x1b[?25h\x1b[0m\n")
}
func (u *ui) refresh() {
	u.applySnapshot(collect())
}

func (u *ui) applySnapshot(snapshot Snapshot) {
	if !u.snap.At.IsZero() {
		annotateCPU(&snapshot, u.snap)
		u.cpuReady = true
	}
	if !u.snap.At.IsZero() {
		newCount, goneCount, restartCount := diffCounts(u.snap.Processes, snapshot.Processes)
		u.timeline = append(u.timeline, TimelinePoint{At: snapshot.At, Processes: len(snapshot.Processes), Ports: len(snapshot.Ports), CPU: snapshot.Pressure.CPU, Memory: snapshot.Pressure.Memory, IO: snapshot.Pressure.IO, New: newCount, Gone: goneCount, Restarts: restartCount})
		if restartCount > 0 {
			u.status = fmt.Sprintf("PID identity radar: %d PID reuse event(s)", restartCount)
		}
		if len(u.timeline) > 60 {
			u.timeline = u.timeline[len(u.timeline)-60:]
		}
	}
	u.snap = snapshot
	if u.tab >= u.tabCount() {
		u.tab = 0
		u.cursor, u.offset = 0, 0
	}
	// A background refresh must preserve the user's selected ordering.
	// Otherwise memory mode appears to disappear every interval.
	u.sort()
	if u.base.At.IsZero() {
		u.base = u.snap
	}
	u.last = time.Now()
	u.normalize()
	u.draw()
}

func annotateCPU(snapshot *Snapshot, previous Snapshot) {
	elapsed := snapshot.At.Sub(previous.At).Seconds()
	if elapsed <= 0 {
		return
	}
	old := make(map[int]uint64, len(previous.Processes))
	oldRSS := make(map[int]int64, len(previous.Processes))
	for _, p := range previous.Processes {
		old[p.PID] = p.CPUTime
		oldRSS[p.PID] = p.RSSBytes
	}
	for i := range snapshot.Processes {
		p := &snapshot.Processes[i]
		if before, ok := old[p.PID]; ok && p.CPUTime >= before {
			// Linux procfs reports utime/stime in USER_HZ ticks; USER_HZ is
			// conventionally 100 on Linux. This is a per-core percentage.
			p.CPUPercent = float64(p.CPUTime-before) / elapsed
		}
		if beforeRSS, ok := oldRSS[p.PID]; ok {
			p.RSSDelta = p.RSSBytes - beforeRSS
			p.RSSRate = float64(p.RSSDelta) / elapsed
		}
	}
}
func (u *ui) count() int {
	switch u.tab {
	case 0:
		return len(u.processRows())
	case 1:
		return len(u.portRows())
	case 2:
		return len(u.containerRows())
	}
	return 0
}

func (u *ui) tabCount() int {
	if len(u.snap.Containers) > 0 {
		return 3
	}
	return 2
}

func (u *ui) handle(k string) bool {
	if u.confirm {
		if k == "y" && u.detail != nil {
			_ = syscall.Kill(u.detail.PID, syscall.SIGTERM)
			u.confirm = false
			u.detail = nil
			u.refresh()
			return false
		}
		if k == "n" || k == "esc" {
			u.confirm = false
			u.draw()
		}
		return false
	}
	if u.detail != nil && (k == "esc" || k == "enter") {
		u.detail = nil
		u.draw()
		return false
	}
	switch k {
	case "q":
		return true
	case "esc":
		if u.filter != "" {
			u.filter = ""
			u.cursor, u.offset = 0, 0
			break
		}
		return true
	case "tab":
		u.tab = (u.tab + 1) % u.tabCount()
		u.cursor = 0
		u.offset = 0
	case "1", "2", "3":
		u.tab, _ = strconv.Atoi(k)
		u.tab--
		if u.tab >= u.tabCount() {
			u.tab = u.tabCount() - 1
		}
		u.cursor, u.offset = 0, 0
	case "up", "k":
		u.cursor--
	case "down", "j":
		u.cursor++
	case "pageup":
		u.cursor -= u.listHeight()
	case "pagedown":
		u.cursor += u.listHeight()
	case " ":
		if u.tab == 0 && u.count() > 0 {
			if u.tagged == nil {
				u.tagged = make(map[int]bool)
			}
			if p, ok := u.selectedProcess(); ok {
				u.tagged[p.PID] = !u.tagged[p.PID]
				u.status = fmt.Sprintf("%s PID %d", map[bool]string{true: "tagged", false: "untagged"}[u.tagged[p.PID]], p.PID)
			}
		}
	case "g":
		u.cursor = 0
	case "G":
		u.cursor = u.count() - 1
	case "r":
		u.refreshRequested = true
		u.status = "refresh requested"
		return false
	case "d":
		u.diff = !u.diff
		u.cursor = 0
	case "i":
		u.showIdle = !u.showIdle
		u.cursor, u.offset = 0, 0
	case "t", "f5":
		u.treeMode = !u.treeMode
		u.timelineMode = false
		u.cursor, u.offset = 0, 0
	case "L":
		u.timelineMode = !u.timelineMode
		u.cursor, u.offset = 0, 0
	case "?":
		u.help()
		return false
	case "/", "f3", "f4":
		u.searchInteractive()
	case "f1":
		u.help()
		return false
	case "f6":
		u.sortBy = (u.sortBy + 1) % 5
		u.sort()
	case "f9":
		if u.tab == 0 && u.count() > 0 {
			if p, ok := u.selectedProcess(); ok {
				u.detail = &p
				u.confirm = true
			}
		}
	case "enter":
		if u.tab == 0 && u.count() > 0 {
			if p, ok := u.selectedProcess(); ok {
				u.detail = &p
			}
		}
	case "x":
		if u.detail != nil {
			u.confirm = true
		}
	case "s":
		u.sortBy = (u.sortBy + 1) % 5
		u.sort()
	case "m":
		u.sortBy = 1
		u.sort()
	case "c":
		u.sortBy = 2
		u.sort()
	case "p":
		if u.tab == 0 && u.count() > 0 {
			p, ok := u.selectedProcess()
			if !ok {
				break
			}
			if u.pinnedPID == p.PID {
				u.pinnedPID = 0
				u.status = "unpinned PID " + strconv.Itoa(p.PID)
			} else {
				u.pinnedPID = p.PID
				u.status = "pinned PID " + strconv.Itoa(p.PID) + " at top"
			}
			u.sort()
			u.cursor, u.offset = 0, 0
		}
	case "e":
		b, _ := json.MarshalIndent(u.snap, "", "  ")
		if err := os.WriteFile("spoor-snapshot.json", b, 0644); err != nil {
			u.status = "export failed: " + err.Error()
		} else {
			u.status = "exported spoor-snapshot.json"
		}
	case "h":
		if err := writeHTMLReport("spoor-report.html", u.snap); err != nil {
			u.status = "HTML export failed: " + err.Error()
		} else {
			u.status = "exported spoor-report.html"
		}
	}
	u.normalize()
	u.draw()
	return false
}

func (u *ui) listHeight() int {
	h := u.height - 21
	if h < 6 {
		return 6
	}
	if h > 24 {
		return 24
	}
	return h
}

func (u *ui) screenWidth() int {
	if u.width < 72 {
		return 72
	}
	if u.width > 120 {
		return 120
	}
	return u.width
}

func (u *ui) commandWidth() int {
	w := u.screenWidth() - 88
	if w < 18 {
		return 18
	}
	return w
}

func (u *ui) normalize() {
	if u.cursor < 0 {
		u.cursor = 0
	}
	if u.cursor >= u.count() {
		u.cursor = u.count() - 1
	}
	if u.cursor < 0 {
		u.cursor = 0
	}
	if u.offset > u.cursor {
		u.offset = u.cursor
	}
	if u.cursor >= u.offset+u.listHeight() {
		u.offset = u.cursor - u.listHeight() + 1
	}
	if u.offset < 0 {
		u.offset = 0
	}
}

func (u *ui) processRows() []Process {
	rows := make([]Process, 0, len(u.snap.Processes))
	for _, p := range u.snap.Processes {
		if p.State == "I" && !u.showIdle {
			continue
		}
		if !match(fmt.Sprintf("%d %s %s %s %s %.1f", p.PID, p.User, p.Name, p.Cmd, p.State, p.CPUPercent), u.filter) {
			continue
		}
		if u.diff && !processChanged(u.base.Processes, p) {
			continue
		}
		rows = append(rows, p)
	}
	return rows
}

type processDisplayRow struct {
	Process
	Depth int
}

func (u *ui) displayProcessRows() []processDisplayRow {
	rows := u.processRows()
	if !u.treeMode {
		out := make([]processDisplayRow, len(rows))
		for i, p := range rows {
			out[i] = processDisplayRow{Process: p}
		}
		return out
	}
	byPID := make(map[int]Process, len(rows))
	children := make(map[int][]Process)
	for _, p := range rows {
		byPID[p.PID] = p
	}
	for _, p := range rows {
		if _, ok := byPID[p.PPID]; ok {
			children[p.PPID] = append(children[p.PPID], p)
		}
	}
	var roots []Process
	for _, p := range rows {
		if _, ok := byPID[p.PPID]; !ok {
			roots = append(roots, p)
		}
	}
	out := make([]processDisplayRow, 0, len(rows))
	visited := make(map[int]bool, len(rows))
	var visit func(Process, int)
	visit = func(p Process, depth int) {
		if visited[p.PID] {
			return
		}
		visited[p.PID] = true
		out = append(out, processDisplayRow{Process: p, Depth: depth})
		for _, child := range children[p.PID] {
			visit(child, depth+1)
		}
	}
	for _, root := range roots {
		visit(root, 0)
	}
	// A changing process table can contain a broken/cyclic parent link.
	// Keep such rows visible instead of silently dropping them.
	for _, p := range rows {
		if !visited[p.PID] {
			visit(p, 0)
		}
	}
	return out
}

func (u *ui) selectedProcess() (Process, bool) {
	rows := u.displayProcessRows()
	if u.cursor < 0 || u.cursor >= len(rows) {
		return Process{}, false
	}
	return rows[u.cursor].Process, true
}

func (u *ui) portRows() []Port {
	rows := make([]Port, 0, len(u.snap.Ports))
	for _, p := range u.snap.Ports {
		if match(fmt.Sprintf("%s %s %s %s %s", p.Proto, p.Local, p.State, p.PID, p.Process), u.filter) {
			rows = append(rows, p)
		}
	}
	return rows
}

func (u *ui) containerRows() []Container {
	rows := make([]Container, 0, len(u.snap.Containers))
	for _, c := range u.snap.Containers {
		if match(fmt.Sprintf("%s %s %s %s %s", c.Runtime, c.ID, c.Name, c.Image, c.Status), u.filter) {
			rows = append(rows, c)
		}
	}
	return rows
}

func (u *ui) rangeText(total int) string {
	if total == 0 {
		return "0 results"
	}
	start := u.offset + 1
	end := u.offset + u.listHeight()
	if end > total {
		end = total
	}
	return fmt.Sprintf("%d–%d of %d", start, end, total)
}

func (u *ui) searchFields() string {
	switch u.tab {
	case 0:
		return "PID/user/name/command/state"
	case 1:
		return "protocol/address/state/PID/process"
	case 2:
		return "runtime/ID/name/image/status"
	}
	return "visible fields"
}

func (u *ui) searchInteractive() {
	u.searching = true
	query := u.filter
	for {
		u.filter = query
		u.cursor, u.offset = 0, 0
		u.draw()
		k := ""
		for k == "" {
			k = readKey()
			if k == "" {
				time.Sleep(5 * time.Millisecond)
			}
		}
		switch k {
		case "enter":
			u.searching = false
			return
		case "esc":
			u.filter = ""
			u.searching = false
			return
		case "backspace":
			runes := []rune(query)
			if len(runes) > 0 {
				query = string(runes[:len(runes)-1])
			}
		case "/":
			// A repeated slash can arrive while the terminal is entering
			// search mode. Do not turn the shortcut itself into the query.
			if query != "" {
				query += "/"
			}
		case "pageup":
			query = ""
		default:
			// readKey returns printable characters as one-character strings;
			// navigation words are ignored while search is active.
			if len(k) == 1 && k[0] >= 32 && k[0] != 127 {
				query += k
			}
		}
	}
}
func (u *ui) sort() {
	sort.Slice(u.snap.Processes, func(i, j int) bool {
		a, b := u.snap.Processes[i], u.snap.Processes[j]
		if u.pinnedPID != 0 {
			iPinned := a.PID == u.pinnedPID
			jPinned := b.PID == u.pinnedPID
			if iPinned != jPinned {
				return iPinned
			}
		}
		if u.sortBy == 0 {
			ri, rj := processStateRank(a.State), processStateRank(b.State)
			if ri != rj {
				return ri < rj
			}
			return a.PID < b.PID
		}
		if u.sortBy == 1 {
			if a.RSSBytes != b.RSSBytes {
				return a.RSSBytes > b.RSSBytes
			}
			return a.PID < b.PID
		}
		if u.sortBy == 2 {
			if a.CPUPercent != b.CPUPercent {
				return a.CPUPercent > b.CPUPercent
			}
			return a.PID < b.PID
		}
		if u.sortBy == 3 {
			return a.PID < b.PID
		}
		ai, aj := strings.ToLower(a.Name), strings.ToLower(b.Name)
		if ai != aj {
			return ai < aj
		}
		return a.PID < b.PID
	})
}

func (u *ui) sortLabel() string {
	switch u.sortBy {
	case 0:
		return "state: active first"
	case 1:
		return "memory: largest first"
	case 2:
		return "CPU: highest first"
	case 3:
		return "PID"
	default:
		return "name"
	}
}

func processStateRank(state string) int {
	switch state {
	case "R":
		return 0 // running on CPU now
	case "S":
		return 1 // interruptible sleep, still alive
	case "I":
		return 2 // idle kernel thread
	case "D":
		return 3 // uninterruptible wait: worth noticing
	case "T", "t":
		return 4 // stopped/traced
	case "Z":
		return 5 // zombie
	default:
		return 6
	}
}
func (u *ui) draw() {
	u.width, u.height = terminalSize()
	fmt.Print("\x1b[2J\x1b[H\x1b[?25l")
	mode := "live / procfs"
	if u.diff {
		mode = "incident diff · d to exit"
	} else if u.timelineMode {
		mode = "timeline / history · L to exit"
	} else if u.treeMode {
		mode = "tree / process hierarchy · t to exit"
	}
	fmt.Printf("%s  %s  %s\n", accent("SPOOR", cyan), dim("causal process explorer"), dim(mode))
	line := fmt.Sprintf("  %s  %s", badge("PROC", fmt.Sprint(len(u.snap.Processes), " visible"), cyan), badge("PORT", fmt.Sprint(len(u.snap.Ports), " sockets"), yellow))
	if len(u.snap.Containers) > 0 {
		line += "  " + badge("CTR", fmt.Sprint(len(u.snap.Containers), " active"), magenta)
	}
	line += "  " + badge("ACCESS", u.snap.Access, accessColor(u.snap.Access))
	if u.pinnedPID != 0 {
		line += "  " + badge("PINNED", "PID "+strconv.Itoa(u.pinnedPID)+" · p unpin", yellow)
	}
	fmt.Printf("%s  %s\n", line, dim("updated "+u.last.Format("15:04:05")))
	fmt.Printf("  %s\n", dim(fmt.Sprintf("PSI  cpu %4.1f%%   memory %4.1f%%   io %4.1f%%   · system contention, avg10", u.snap.Pressure.CPU, u.snap.Pressure.Memory, u.snap.Pressure.IO)))
	u.drawMeters()
	if !strings.HasPrefix(u.snap.Access, "ROOT") {
		fmt.Printf("  %s\n", dim("limited visibility: processes and file descriptors owned by other users may be hidden"))
	}
	fmt.Printf("%s\n", rule(u.screenWidth()))
	tabs := []string{"PROCESSES", "PORTS"}
	if len(u.snap.Containers) > 0 {
		tabs = append(tabs, "CONTAINERS")
	}
	for i, t := range tabs {
		if i == u.tab {
			fmt.Printf(" %s ", accent(fmt.Sprintf("[%d] %s", i+1, t), cyan))
		} else {
			fmt.Printf("   %s   ", dim(fmt.Sprintf("[%d] %s", i+1, t)))
		}
	}
	fmt.Printf("   %s\n%s\n", dim("1/2/3 or Tab"), rule(u.screenWidth()))
	if u.filter != "" {
		fmt.Printf("  %s %s  %s\n", accent("SEARCH", yellow), accent("/"+u.filter, yellow), dim("substring · case-insensitive · "+u.searchFields()))
	} else if u.searching {
		fmt.Printf("  %s  %s\n", accent("SEARCH", yellow), dim("type to filter "+u.searchFields()+" · Enter keep · Esc clear"))
	} else {
		fmt.Printf("  %s\n", dim("Search: press / · substring, case-insensitive · "+u.searchFields()))
	}
	if u.tab == 0 {
		view := "flat"
		if u.treeMode {
			view = "tree"
		}
		fmt.Printf("  %s\n", dim("process view: "+view+" · order: "+u.sortLabel()+" · F6/s change"))
	}
	if u.detail != nil {
		u.drawDetail()
		return
	}
	if u.timelineMode {
		u.drawTimeline()
		return
	}
	switch u.tab {
	case 0:
		u.drawProcesses()
	case 1:
		u.drawPorts()
	case 2:
		u.drawContainers()
	}
	fmt.Printf("\n%s\n", rule(u.screenWidth()))
	u.drawKeyBar()
	if u.status != "" {
		fmt.Printf("  %s %s\n", accent("STATUS", green), u.status)
	}
}

func (u *ui) drawKeyBar() {
	keys := []struct{ key, label string }{
		{"F1", "help"}, {"F3", "search"}, {"F4", "filter"}, {"F5", "tree"}, {"F6", "sort"}, {"F9", "kill"}, {"p", "pin"}, {"L", "timeline"}, {"q", "quit"},
	}
	fmt.Print("  ")
	for i, item := range keys {
		if i > 0 {
			fmt.Print("  ")
		}
		fmt.Printf("%s %s", accent("["+item.key+"]", cyan), dim(item.label))
	}
	fmt.Println()
}

func (u *ui) drawMeters() {
	if u.snap.System.MemTotal > 0 {
		used := u.snap.System.MemTotal - u.snap.System.MemAvailable
		fmt.Printf("  %-5s %s %s   %-5s %s %s\n", "MEM", meter(float64(used)/float64(u.snap.System.MemTotal), cyan), fmt.Sprintf("%s / %s", formatBytes(used), formatBytes(u.snap.System.MemTotal)), "SWAP", meter(swapRatio(u.snap.System), yellow), fmt.Sprintf("%s / %s", formatBytes(u.snap.System.SwapTotal-u.snap.System.SwapFree), formatBytes(u.snap.System.SwapTotal)))
	}
	if u.cpuReady {
		var total float64
		for _, p := range u.snap.Processes {
			total += p.CPUPercent
		}
		cpu := total / float64(runtime.NumCPU()) / 100
		fmt.Printf("  %-5s %s %5.1f%%   %-5s load %.2f %.2f %.2f   up %s\n", "CPU", meter(cpu, green), cpu*100, "LOAD", u.snap.System.Load1, u.snap.System.Load5, u.snap.System.Load15, formatUptime(u.snap.System.Uptime))
	} else {
		fmt.Printf("  %-5s %s   %s\n", "CPU", dim("sampling…"), dim("load "+formatUptime(u.snap.System.Uptime)))
	}
}

func swapRatio(s SystemStats) float64 {
	if s.SwapTotal <= 0 {
		return 0
	}
	return float64(s.SwapTotal-s.SwapFree) / float64(s.SwapTotal)
}

func meter(ratio float64, color string) string {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	width := 20
	filled := int(ratio * float64(width))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return accent("["+bar+"]", color)
}

func formatBytes(value int64) string {
	if value < 0 {
		value = 0
	}
	units := []string{"B", "K", "M", "G", "T"}
	n := float64(value)
	unit := 0
	for n >= 1024 && unit < len(units)-1 {
		n /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d%s", value, units[unit])
	}
	return fmt.Sprintf("%.1f%s", n, units[unit])
}

func formatUptime(seconds float64) string {
	if seconds < 0 {
		seconds = 0
	}
	d := int(seconds) / 86400
	h := int(seconds) / 3600 % 24
	m := int(seconds) / 60 % 60
	if d > 0 {
		return fmt.Sprintf("%dd %02dh", d, h)
	}
	return fmt.Sprintf("%02dh %02dm", h, m)
}

func (u *ui) drawTimeline() {
	fmt.Printf("  %s  %s\n", accent("TIMELINE", yellow), dim("history of the live snapshots"))
	fmt.Printf("  %s\n", dim("Each row is one refresh. Use it to see whether process/socket counts or system pressure changed before an incident."))
	fmt.Printf("  %s\n", dim("RADAR  ↻ PID reuse = the same numeric PID now belongs to a different process identity."))
	fmt.Printf("  %s\n\n", dim("+new / -exited = process identities changed · PSI = time stalled, not CPU utilization · L returns to live"))
	if len(u.timeline) == 0 {
		fmt.Printf("  %s\n", dim("Collecting baseline… the next refresh will create the first history point."))
		return
	}
	fmt.Printf("  %s %s %s %s %s %s %s\n", headerCell("TIME", 9), headerCell("PROCS", 9), headerCell("PORTS", 9), headerCell("CPU PSI", 12), headerCell("MEM PSI", 12), headerCell("IO PSI", 12), headerCell("EVENT", 0))
	fmt.Printf("  %s\n", dim(rule(u.screenWidth()-2)))
	start := 0
	if len(u.timeline) > u.listHeight() {
		start = len(u.timeline) - u.listHeight()
	}
	for _, point := range u.timeline[start:] {
		event := dim("quiet")
		if point.New > 0 || point.Gone > 0 || point.Restarts > 0 {
			event = accent(fmt.Sprintf("+%d / -%d / ↻%d", point.New, point.Gone, point.Restarts), yellow)
		}
		fmt.Printf("  %-9s %-9d %-9d %s %s %s %s\n", point.At.Format("15:04:05"), point.Processes, point.Ports, psiValue(point.CPU), psiValue(point.Memory), psiValue(point.IO), event)
	}
	fmt.Printf("\n  %s\n", dim("Read a spike as contention: CPU PSI means runnable work waited, memory PSI means reclaim pressure, IO PSI means storage waited. ↻ is a confirmed PID identity change, not a guess about why it restarted."))
}

func psiValue(value float64) string {
	text := fmt.Sprintf("%-12s", fmt.Sprintf("%5.1f%%", value))
	if value >= 10 {
		return accent(text, red)
	}
	if value >= 2 {
		return accent(text, yellow)
	}
	return text
}
func (u *ui) drawProcesses() {
	displayRows := u.displayProcessRows()
	fmt.Printf("  %s %s %s %s %s %s %s %s %s\n", headerCell("PIN", 3), headerCell("TAG", 3), headerCell("PID", 7), headerCell("USER", 10), headerCell("PROCESS", 22), headerCell("CPU", 15), headerCell("RSS", 8), headerCell("STATE", 10), headerCell("COMMAND", 0))
	fmt.Printf("  %s\n", dim(rule(u.screenWidth()-2)))
	end := u.offset + u.listHeight()
	if end > len(displayRows) {
		end = len(displayRows)
	}
	for n := u.offset; n < end; n++ {
		row := displayRows[n]
		p := row.Process
		sel := n == u.cursor
		name := trim(treeName(row), 22)
		pin := ""
		if u.pinnedPID == p.PID {
			pin = "PIN"
		}
		tag := ""
		if u.tagged[p.PID] {
			tag = "TAG"
		}
		if sel {
			// The whole selected row is highlighted; a colored arrow alone
			// is too easy to miss on dim terminals.
			cpu := cpuText(p.CPUPercent)
			memory := fmt.Sprintf("%-8s", p.RSS)
			fmt.Printf("\x1b[1;7m▸ %-3s %-3s %-7d %-10s %-22s %s %s %s %s\x1b[0m\n",
				pin, tag, p.PID, p.User, name, cpu, memory, stateLabel(p.State), trim(p.Cmd, u.commandWidth()))
			continue
		}
		state := stateColor(p.State)
		memory := memoryColor(p.RSS, p.RSSBytes, u.sortBy == 1)
		cpu := cpuColor(p.CPUPercent)
		fmt.Printf("  %-3s %-3s %-7d %-10s %-22s %s %s %s %s\n", pin, tag, p.PID, p.User, name, cpu, memory, state, dim(trim(p.Cmd, u.commandWidth())))
	}
	if u.diff {
		newCount, goneCount, restartCount := diffCounts(u.base.Processes, u.snap.Processes)
		fmt.Printf("\n  %s\n", dim(fmt.Sprintf("+%d new · -%d exited · ↻%d restarted · changed rows are visible", newCount, goneCount, restartCount)))
	} else {
		idleNote := "idle kernel threads hidden · i show"
		if u.showIdle {
			idleNote = "idle kernel threads shown · i hide"
		}
		fmt.Printf("\n  %s\n", dim(fmt.Sprintf("%s · %d with children · %s", u.rangeText(len(displayRows)), countChildren(u.snap.Processes), idleNote)))
	}
	if len(displayRows) > 0 && u.cursor < len(displayRows) {
		p := displayRows[u.cursor].Process
		trend := "memory stable"
		if p.RSSDelta > 0 {
			trend = "memory ↑ " + rateLabel(p.RSSRate)
		} else if p.RSSDelta < 0 {
			trend = "memory ↓ " + rateLabel(-p.RSSRate)
		}
		fmt.Printf("\n  %s  %s\n", accent("SELECTED", cyan), dim(fmt.Sprintf("PID %d · %s · parent %d · %s · %s", p.PID, p.Name, p.PPID, trend, u.rangeText(len(displayRows)))))
		fmt.Printf("  %s\n", trim(p.Cmd, u.screenWidth()-2))
	}
	fmt.Printf("\n  %s\n", dim("STATE  "+stateLegend()+"   ·   CPU bar: each block ≈ 12.5% of one core"))
}

func treeName(row processDisplayRow) string {
	if row.Depth == 0 {
		return row.Name
	}
	return strings.Repeat("  ", row.Depth-1) + "└─ " + row.Name
}

func stateLabel(state string) string {
	label := "? " + state
	switch state {
	case "R":
		label = "● RUN"
	case "S":
		label = "○ SLEEP"
	case "I":
		label = "· IDLE-K"
	case "D":
		label = "● BLOCK"
	case "T", "t":
		label = "Ⅱ STOP"
	case "Z":
		label = "× ZOMB"
	}
	return fmt.Sprintf("%-10s", label)
}

func (u *ui) drawPorts() {
	rows := u.portRows()
	fmt.Printf("  %s %s %s %s %s\n", headerCell("PROTO", 8), headerCell("LOCAL", 24), headerCell("STATE", 14), headerCell("PID", 8), headerCell("PROCESS", 0))
	end := u.offset + u.listHeight()
	if end > len(rows) {
		end = len(rows)
	}
	for i := u.offset; i < end; i++ {
		p := rows[i]
		prefix := "  "
		if i == u.cursor {
			prefix = accent("▸ ", cyan)
		}
		fmt.Printf("%s%-8s %-24s %s %-8s %s\n", prefix, p.Proto, p.Local, portStateColor(p.State), p.PID, p.Process)
	}
	fmt.Printf("\n  %s\n", dim(u.rangeText(len(rows))))
}
func (u *ui) drawContainers() {
	rows := u.containerRows()
	fmt.Printf("  %s %s %s %s %s\n", headerCell("RUNTIME", 10), headerCell("NAME", 18), headerCell("IMAGE", 26), headerCell("STATUS", 24), headerCell("ID", 0))
	end := u.offset + u.listHeight()
	if end > len(rows) {
		end = len(rows)
	}
	for i := u.offset; i < end; i++ {
		c := rows[i]
		prefix := "  "
		if i == u.cursor {
			prefix = accent("▸ ", cyan)
		}
		fmt.Printf("%s%-10s %-18s %-26s %s %s\n", prefix, c.Runtime, c.Name, trim(c.Image, 26), containerStatusColor(c.Status), c.ID)
	}
	fmt.Printf("\n  %s\n", dim(u.rangeText(len(rows))))
}
func (u *ui) drawDetail() {
	p := *u.detail
	fmt.Printf("  %s %s (pid %d)\n\n", accent("PROCESS", cyan), p.Name, p.PID)
	trend := "stable"
	if p.RSSDelta > 0 {
		trend = "↑ " + rateLabel(p.RSSRate)
	} else if p.RSSDelta < 0 {
		trend = "↓ " + rateLabel(-p.RSSRate)
	}
	cgroup := p.Cgroup
	if cgroup == "" {
		cgroup = "not visible"
	}
	fmt.Printf("  %-12s %s\n  %-12s %s\n  %-12s %s (%s)\n  %-12s %s\n  %-12s %s\n\n", dim("user"), p.User, dim("state"), p.State, dim("memory"), p.RSS, trend, dim("cgroup"), cgroup, dim("command"), p.Cmd)
	fmt.Printf("  %s\n", dim("causal chain"))
	for i, a := range ancestry(u.snap.Processes, p.PID) {
		glyph := "└─"
		if i < len(ancestry(u.snap.Processes, p.PID))-1 {
			glyph = "├─"
		}
		fmt.Printf("  %s %s %s\n", dim(glyph), accent(fmt.Sprint(a.PID), yellow), a.Cmd)
	}
	related := make([]Port, 0, 4)
	for _, port := range u.snap.Ports {
		if port.PID == strconv.Itoa(p.PID) {
			related = append(related, port)
		}
	}
	if len(related) > 0 {
		fmt.Printf("\n  %s\n", dim("related sockets"))
		for _, port := range related {
			fmt.Printf("  %s %s %s\n", accent(port.Proto, cyan), port.Local, portStateColor(port.State))
		}
	} else {
		fmt.Printf("\n  %s\n", dim("related sockets: none visible"))
	}
	if u.confirm {
		fmt.Printf("\n  %s terminate PID %d (%s)? %s\n", accent("!", yellow), p.PID, p.Name, dim("y confirm / n cancel"))
	}
	fmt.Printf("\n  %s\n", dim("esc/enter back   x terminate (confirmation)"))
}

func badge(label, value, color string) string {
	return accent(" "+label+" ", color) + " " + value
}

func headerCell(label string, width int) string {
	if width > 0 {
		label = fmt.Sprintf("%-*s", width, label)
	}
	return dim(label)
}

func stateColor(state string) string {
	label := strings.TrimSpace(stateLabel(state))
	switch state {
	case "R":
		return accent(stateLabel(state), green)
	case "S":
		return dim(stateLabel(state))
	case "I":
		return dim(stateLabel(state))
	case "D":
		return accent(stateLabel(state), yellow)
	case "T", "t":
		return accent(stateLabel(state), yellow)
	case "Z":
		return accent(stateLabel(state), red)
	default:
		return accent(fmt.Sprintf("%-10s", label), magenta)
	}
}

func cpuColor(value float64) string {
	plain := fmt.Sprintf("%5.1f%%", value)
	blocks := int(value / 12.5)
	if blocks > 8 {
		blocks = 8
	}
	bar := strings.Repeat("█", blocks) + strings.Repeat("░", 8-blocks)
	text := fmt.Sprintf("%-15s", plain+" "+bar)
	if value >= 100 {
		return accent(text, red)
	}
	if value >= 25 {
		return accent(text, yellow)
	}
	if value >= 1 {
		return accent(text, green)
	}
	return dim(text)
}

func cpuText(value float64) string {
	return fmt.Sprintf("%-15s", fmt.Sprintf("%5.1f%%", value))
}

func stateLegend() string {
	return accent("● RUN", green) + "  " + dim("○ SLEEP") + "  " + accent("● BLOCK", yellow) + "  " + accent("× ZOMB", red) + "  " + dim("· IDLE-K")
}

func memoryColor(value string, bytes int64, sortedByMemory bool) string {
	value = fmt.Sprintf("%-8s", value)
	if !sortedByMemory {
		return value
	}
	if bytes >= 512*1024*1024 {
		return accent(value, red)
	}
	if bytes >= 128*1024*1024 {
		return accent(value, yellow)
	}
	return value
}

func portStateColor(state string) string {
	raw := state
	state = fmt.Sprintf("%-14s", raw)
	switch raw {
	case "LISTEN":
		return accent(state, green)
	case "ESTABLISHED":
		return accent(state, cyan)
	case "TIME_WAIT":
		return dim(state)
	default:
		return state
	}
}

func containerStatusColor(status string) string {
	status = fmt.Sprintf("%-24s", trim(status, 24))
	lower := strings.ToLower(status)
	if strings.Contains(lower, "up") || strings.Contains(lower, "running") {
		return accent(status, green)
	}
	if strings.Contains(lower, "exit") || strings.Contains(lower, "dead") {
		return accent(status, red)
	}
	return status
}
func (u *ui) help() {
	fmt.Print("\x1b[2J\x1b[H")
	fmt.Printf("%s  %s\n\n", accent("SPOOR", cyan), dim("help / current session"))
	fmt.Printf("  %s  %s\n", accent("WHAT YOU SEE", cyan), dim("A causal, live view of the machine"))
	fmt.Printf("  %s\n", dim("Processes = who is alive · Ports = what is exposed · Containers = what is packaged"))
	fmt.Printf("  %s\n", dim("ACCESS: "+u.snap.Access+" · PSI: CPU/memory/IO pressure over the last 10 seconds"))
	fmt.Printf("%s\n\n", rule(u.screenWidth()))

	fmt.Printf("  %s\n", accent("NAVIGATION", yellow))
	printHelpRow("Tab", "switch Processes / Ports / Containers")
	printHelpRow("↑ ↓   j k", "move one row")
	printHelpRow("PgUp/PgDn", "move one page")
	printHelpRow("Ctrl-U/D", "move one page (terminal-friendly)")
	printHelpRow("g / G", "jump to first / last result")
	printHelpRow("F5 / t", "toggle process tree view")
	printHelpRow("Space", "tag/untag the selected process")
	printHelpRow("p", "pin/unpin the selected process at the top of the list")
	printHelpRow("Enter", "inspect the selected process and its ancestry")
	printHelpRow("Esc", "clear search; from a detail view, go back")
	fmt.Println()

	fmt.Printf("  %s\n", accent("SEARCH", yellow))
	printHelpRow("F3 / /", "start live search; results update after every character")
	printHelpRow("F4", "start the same search as a process filter")
	printHelpRow("Backspace", "remove the last character")
	printHelpRow("Enter", "keep the query")
	printHelpRow("Esc", "clear the query")
	fmt.Printf("  %s\n", dim("Search is case-insensitive substring matching on the current tab."))
	fmt.Printf("  %s\n", dim("Examples: /nginx   /8080   /listen   /docker"))
	fmt.Println()

	fmt.Printf("  %s\n", accent("INVESTIGATION", yellow))
	printHelpRow("s", "cycle sort: state → memory ↓ → CPU ↓ → PID → name")
	printHelpRow("m", "jump straight to largest memory consumers")
	printHelpRow("c", "jump straight to highest CPU consumers")
	printHelpRow("F6", "cycle sort order")
	printHelpRow("i", "show/hide idle kernel threads")
	printHelpRow("d", "diff against the baseline captured at startup")
	printHelpRow("L", "open timeline: process/port counts, PID identity changes and PSI")
	printHelpRow("r", "request a fresh snapshot without blocking the UI")
	printHelpRow("e", "export the current snapshot to spoor-snapshot.json")
	printHelpRow("h", "export a human-readable report to spoor-report.html")
	fmt.Printf("  %s\n", dim("JSON is for jq, scripts, CI and agents; it contains the same snapshot without ANSI UI noise."))
	fmt.Printf("  %s\n", dim("Example: ./spoor --pid 1234 --json | jq '.ancestry'"))
	fmt.Println()

	fmt.Printf("  %s\n", accent("ACTIONS", yellow))
	printHelpRow("F9", "prepare TERM for the selected process; y confirms, n cancels")
	printHelpRow("x", "same action from process detail")
	printHelpRow("q", "quit and restore the terminal")
	fmt.Printf("\n%s\n", rule(u.screenWidth()))
	fmt.Printf("  %s\n", dim("States: R running · S sleeping/alive · D blocked IO · T stopped · Z zombie · I idle kernel thread"))
	fmt.Printf("  %s\n", dim("Detail view also shows cgroup boundary, memory trend and sockets owned by the selected PID."))
	fmt.Printf("  %s\n", accent("Press any key to return", cyan))
	for readKey() == "" {
		time.Sleep(5 * time.Millisecond)
	}
}

func printHelpRow(key, description string) {
	fmt.Printf("  %s %-12s %s\n", accent("▸", cyan), key, description)
}

type htmlReport struct {
	Generated string
	Snapshot  Snapshot
	Top       []Process
}

var htmlReportTemplate = template.Must(template.New("spoor-report").Funcs(template.FuncMap{"hasPrefix": strings.HasPrefix}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Spoor report</title><style>
:root{color-scheme:dark;--bg:#101419;--panel:#171d24;--line:#2b3541;--text:#edf2f7;--muted:#8b98a8;--cyan:#57d7ff;--green:#62e6a7;--yellow:#ffd166;--red:#ff6b7a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}main{max-width:1400px;margin:0 auto;padding:32px}h1{margin:0 0 6px;color:var(--cyan);font-size:25px}h2{font-size:15px;color:var(--cyan);margin:28px 0 10px}.sub,small{color:var(--muted)}.cards{display:flex;flex-wrap:wrap;gap:10px;margin:22px 0}.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 15px;min-width:150px}.label{color:var(--muted);font-size:11px;text-transform:uppercase}.value{margin-top:5px;font-size:16px}.ok{color:var(--green)}.warn{color:var(--yellow)}table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase}tr:last-child td{border-bottom:0}code{color:var(--yellow);white-space:pre-wrap;word-break:break-word}.empty{padding:18px;color:var(--muted)}footer{margin-top:30px;color:var(--muted);font-size:12px}
</style></head><body><main><h1>SPOOR / incident report</h1><div class="sub">Generated {{.Generated}} · access: <span class="{{if hasPrefix .Snapshot.Access "ROOT"}}ok{{else}}warn{{end}}">{{.Snapshot.Access}}</span></div>
<section class="cards"><div class="card"><div class="label">Processes</div><div class="value">{{len .Snapshot.Processes}}</div></div><div class="card"><div class="label">TCP sockets</div><div class="value">{{len .Snapshot.Ports}}</div></div><div class="card"><div class="label">Containers</div><div class="value">{{len .Snapshot.Containers}}</div></div><div class="card"><div class="label">PSI / cpu · mem · io</div><div class="value">{{printf "%.1f%% · %.1f%% · %.1f%%" .Snapshot.Pressure.CPU .Snapshot.Pressure.Memory .Snapshot.Pressure.IO}}</div></div></section>
<h2>Largest processes by RSS</h2>{{if .Top}}<table><tr><th>PID</th><th>Process</th><th>User</th><th>State</th><th>RSS</th><th>Command</th></tr>{{range .Top}}<tr><td>{{.PID}}</td><td>{{.Name}}</td><td>{{.User}}</td><td>{{.State}}</td><td>{{.RSS}}</td><td><code>{{.Cmd}}</code></td></tr>{{end}}</table>{{else}}<div class="empty">No processes visible.</div>{{end}}
<h2>Ports</h2>{{if .Snapshot.Ports}}<table><tr><th>Protocol</th><th>Local</th><th>State</th><th>PID</th><th>Process</th></tr>{{range .Snapshot.Ports}}<tr><td>{{.Proto}}</td><td>{{.Local}}</td><td>{{.State}}</td><td>{{.PID}}</td><td>{{.Process}}</td></tr>{{end}}</table>{{else}}<div class="empty">No TCP sockets visible.</div>{{end}}
<h2>Containers</h2>{{if .Snapshot.Containers}}<table><tr><th>Runtime</th><th>Name</th><th>Image</th><th>Status</th><th>ID</th></tr>{{range .Snapshot.Containers}}<tr><td>{{.Runtime}}</td><td>{{.Name}}</td><td>{{.Image}}</td><td>{{.Status}}</td><td>{{.ID}}</td></tr>{{end}}</table>{{else}}<div class="empty">No Docker or Podman containers detected.</div>{{end}}
<footer>spoor · JSON is the machine-readable source; this HTML file is the human-readable shareable report.</footer></main></body></html>`))

var htmlReportClassicTemplate = template.Must(template.New("spoor-classic-report").Funcs(template.FuncMap{"hasPrefix": strings.HasPrefix, "trim": trim}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Spoor system report</title><style>
:root{--navy:#17365d;--blue:#2d6fa3;--pale:#edf4fa;--line:#c8d4df;--ink:#24313d;--muted:#667786;--good:#287a4b;--warn:#9a6700;--bad:#a33a3a}
*{box-sizing:border-box}body{margin:0;background:#f3f5f7;color:var(--ink);font:13px/1.45 Arial,Helvetica,sans-serif}header{background:var(--navy);color:#fff;border-bottom:5px solid #8eb6d3}.head{max-width:1180px;margin:auto;padding:24px 28px 20px;display:flex;justify-content:space-between;gap:24px;align-items:end}.brand{font-size:25px;font-weight:700;letter-spacing:.08em}.title{font-size:14px;color:#cfe2f1;margin-top:4px}.meta{text-align:right;color:#dceaf5;font-size:12px;line-height:1.7}nav{background:#fff;border-bottom:1px solid var(--line);box-shadow:0 1px 2px #0000000a}nav .navin{max-width:1180px;margin:auto;padding:9px 28px}nav a{color:var(--blue);text-decoration:none;margin-right:24px;font-size:12px;font-weight:700}main{max-width:1180px;margin:auto;padding:22px 28px 40px}h2{font-size:17px;color:var(--navy);border-bottom:2px solid var(--blue);padding-bottom:6px;margin:28px 0 9px}.intro{color:var(--muted);margin:0 0 18px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.metric{background:#fff;border:1px solid var(--line);border-top:4px solid var(--blue);padding:12px 14px;min-height:73px}.metric .label{font-size:11px;color:var(--muted);text-transform:uppercase}.metric strong{display:block;color:var(--navy);font-size:21px;margin-top:5px}.notice{background:var(--pale);border-left:4px solid var(--blue);padding:11px 14px;margin-top:14px}.notice.warn{border-left-color:#d59b22}.tablewrap{background:#fff;border:1px solid var(--line);overflow:auto}table{width:100%;border-collapse:collapse;min-width:700px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e2e8ed;vertical-align:top}th{background:#e8f0f6;color:var(--navy);font-size:11px;text-transform:uppercase;white-space:nowrap}tr:nth-child(even){background:#f8fafb}tr:last-child td{border-bottom:0}td.num{text-align:right;font-variant-numeric:tabular-nums}code{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;color:#334e68;white-space:pre-wrap;word-break:break-word}.state{font-weight:700}.ok{color:var(--good)}.warntext{color:var(--warn)}.bad{color:var(--bad)}.empty{background:#fff;border:1px solid var(--line);padding:14px;color:var(--muted)}.foot{border-top:1px solid var(--line);margin-top:28px;padding-top:12px;color:var(--muted);font-size:11px}@media(max-width:720px){.head{display:block}.meta{text-align:left;margin-top:12px}.metrics{grid-template-columns:repeat(2,1fr)}main{padding:16px}.navin{overflow:auto;white-space:nowrap}}
</style></head><body><header><div class="head"><div><div class="brand">SPOOR</div><div class="title">System process and network report</div></div><div class="meta">Generated {{.Generated}}<br>Access: <strong>{{.Snapshot.Access}}</strong></div></div></header>
<nav><div class="navin"><a href="#summary">SUMMARY</a><a href="#processes">PROCESSES</a><a href="#network">NETWORK</a>{{if .Snapshot.Containers}}<a href="#containers">CONTAINERS</a>{{end}}</div></nav><main>
<section id="summary"><h2>Summary</h2><p class="intro">A static snapshot of what is running, what is exposed, and where the machine may be under pressure.</p><div class="metrics"><div class="metric"><div class="label">Visible processes</div><strong>{{len .Snapshot.Processes}}</strong></div><div class="metric"><div class="label">TCP sockets</div><strong>{{len .Snapshot.Ports}}</strong></div>{{if .Snapshot.Containers}}<div class="metric"><div class="label">Containers</div><strong>{{len .Snapshot.Containers}}</strong></div>{{end}}<div class="metric"><div class="label">PSI · CPU / MEM / IO</div><strong>{{printf "%.1f / %.1f / %.1f%%" .Snapshot.Pressure.CPU .Snapshot.Pressure.Memory .Snapshot.Pressure.IO}}</strong></div></div><div class="notice {{if hasPrefix .Snapshot.Access "ROOT"}}ok{{else}}warn{{end}}"><strong>Access:</strong> {{.Snapshot.Access}}. {{if hasPrefix .Snapshot.Access "ROOT"}}Full process visibility is available where the kernel permits it.{{else}}Some processes and file descriptors owned by other users may be hidden.{{end}}</div></section>
<section id="processes"><h2>Processes · largest by memory</h2><p class="intro">Top 30 processes sorted by resident memory (RSS). Command lines are included as evidence.</p>{{if .Top}}<div class="tablewrap"><table><tr><th>PID</th><th>Process</th><th>User</th><th>State</th><th>RSS</th><th>Command</th></tr>{{range .Top}}<tr><td class="num">{{.PID}}</td><td><strong>{{.Name}}</strong></td><td>{{.User}}</td><td class="state">{{.State}}</td><td class="num">{{.RSS}}</td><td><code>{{trim .Cmd 240}}</code></td></tr>{{end}}</table></div>{{else}}<div class="empty">No processes visible.</div>{{end}}</section>
<section id="network"><h2>Network · listening and active sockets</h2><p class="intro">TCP sockets resolved to their owning process when permissions allow.</p>{{if .Snapshot.Ports}}<div class="tablewrap"><table><tr><th>Protocol</th><th>Local address</th><th>State</th><th>PID</th><th>Process</th></tr>{{range .Snapshot.Ports}}<tr><td>{{.Proto}}</td><td><strong>{{.Local}}</strong></td><td>{{.State}}</td><td class="num">{{.PID}}</td><td>{{.Process}}</td></tr>{{end}}</table></div>{{else}}<div class="empty">No TCP sockets visible in this snapshot.</div>{{end}}</section>
{{if .Snapshot.Containers}}<section id="containers"><h2>Containers</h2><p class="intro">Best-effort Docker and Podman inventory.</p><div class="tablewrap"><table><tr><th>Runtime</th><th>Name</th><th>Image</th><th>Status</th><th>ID</th></tr>{{range .Snapshot.Containers}}<tr><td>{{.Runtime}}</td><td><strong>{{.Name}}</strong></td><td>{{.Image}}</td><td>{{.Status}}</td><td><code>{{.ID}}</code></td></tr>{{end}}</table></div></section>{{end}}
<div class="foot">Generated by spoor. JSON is the machine-readable source; this HTML document is the human-readable incident snapshot.</div></main></body></html>`))

const htmlReportEnhancements = `<style>
:root{--shadow:0 3px 14px rgba(23,54,93,.08);--focus:#d9ebf7}
html{scroll-behavior:smooth}body{background:linear-gradient(#f3f5f7 0,#eef3f7 330px,#f3f5f7 700px)}
header{box-shadow:0 2px 8px rgba(23,54,93,.16)}
nav{position:sticky;top:0;z-index:10}nav a{display:inline-block;padding:3px 0}nav a:hover{text-decoration:underline}
section{scroll-margin-top:58px}.metric,.tablewrap,.empty{box-shadow:var(--shadow)}
.metric{transition:transform .15s ease,box-shadow .15s ease}.metric:hover{transform:translateY(-2px);box-shadow:0 6px 18px rgba(23,54,93,.13)}
.tablewrap{border-radius:4px}tbody tr:hover{background:var(--focus)}td code{display:block;max-width:54ch}
th{position:sticky;top:42px;z-index:2}.notice{box-shadow:0 1px 4px rgba(23,54,93,.05)}
@media print{body{background:#fff;font-size:11px}nav{display:none}header{box-shadow:none}.metric,.tablewrap,.empty{box-shadow:none}th{position:static}section{break-inside:avoid}.tablewrap{overflow:visible}table{min-width:0}code{white-space:pre-wrap}}
</style>`

func writeHTMLReport(path string, snapshot Snapshot) error {
	top := append([]Process(nil), snapshot.Processes...)
	sort.Slice(top, func(i, j int) bool { return top[i].RSSBytes > top[j].RSSBytes })
	if len(top) > 30 {
		top = top[:30]
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data := htmlReport{Generated: time.Now().Format(time.RFC3339), Snapshot: snapshot, Top: top}
	var rendered bytes.Buffer
	if err := htmlReportClassicTemplate.Execute(&rendered, data); err != nil {
		return err
	}
	html := strings.Replace(rendered.String(), "</head>", htmlReportEnhancements+"</head>", 1)
	_, err = f.WriteString(html)
	return err
}
func readKey() string {
	if terminalInput != nil && !ttyReady() {
		return ""
	}
	b := make([]byte, 1)
	input := os.Stdin
	if terminalInput != nil {
		input = terminalInput
	}
	if n, _ := input.Read(b); n == 0 {
		return ""
	}
	if b[0] == 27 {
		seq := make([]byte, 0, 16)
		for len(seq) < cap(seq) {
			c, ok := readEscapeByte(input)
			if !ok {
				break
			}
			seq = append(seq, c)
			if c == '~' || (len(seq) > 1 && ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
				break
			}
		}
		if key := escapeKey(string(seq)); key != "" {
			return key
		}
		// A function key or Alt-key may use an escape sequence that this
		// small TUI does not know yet. Never turn it into Quit-on-Esc.
		if len(seq) > 0 {
			return "noop"
		}
		return "esc"
	}
	switch b[0] {
	case 'q':
		return "q"
	case 'y':
		return "y"
	case 'n':
		return "n"
	case 'j':
		return "j"
	case 'k':
		return "k"
	case 'r':
		return "r"
	case 'd':
		return "d"
	case 's':
		return "s"
	case 'e':
		return "e"
	case 'g':
		return "g"
	case 'G':
		return "G"
	case ' ':
		return " "
	case 4:
		return "pagedown"
	case 21:
		return "pageup"
	case '/':
		return "/"
	case '?':
		return "?"
	case 9:
		return "tab"
	case 13:
		return "enter"
	case 27:
		return "esc"
	case 8, 127:
		return "backspace"
	}
	return string(b[0])
}

func escapeKey(seq string) string {
	switch seq {
	case "[A", "OA":
		return "up"
	case "[B", "OB":
		return "down"
	case "[C", "OC":
		return "right"
	case "[D", "OD":
		return "left"
	case "OP":
		return "f1"
	case "OQ":
		return "f2"
	case "OR":
		return "f3"
	case "OS":
		return "f4"
	}
	if !strings.HasPrefix(seq, "[") || !strings.HasSuffix(seq, "~") {
		return ""
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(seq, "["), "~"), ";")
	if len(parts) == 0 {
		return ""
	}
	code, err := strconv.Atoi(parts[0])
	if err != nil {
		return ""
	}
	switch code {
	case 5:
		return "pageup"
	case 6:
		return "pagedown"
	case 11:
		return "f1"
	case 12:
		return "f2"
	case 13:
		return "f3"
	case 14:
		return "f4"
	case 15:
		return "f5"
	case 17:
		return "f6"
	case 18:
		return "f7"
	case 19:
		return "f8"
	case 20:
		return "f9"
	case 21:
		return "f10"
	case 23:
		return "f11"
	case 24:
		return "f12"
	}
	return ""
}

func readEscapeByte(input *os.File) (byte, bool) {
	if terminalInput != nil {
		fd := int(input.Fd())
		var set syscall.FdSet
		if fd/64 >= len(set.Bits) {
			return 0, false
		}
		set.Bits[fd/64] |= 1 << uint(fd%64)
		tv := syscall.Timeval{Sec: 0, Usec: 20000}
		ready, err := syscall.Select(fd+1, &set, nil, nil, &tv)
		if err != nil || ready == 0 {
			return 0, false
		}
	}
	var b [1]byte
	n, err := input.Read(b[:])
	return b[0], err == nil && n == 1
}

func ttyReady() bool {
	if terminalInput == nil {
		return true
	}
	fd := int(terminalInput.Fd())
	var set syscall.FdSet
	if fd/64 >= len(set.Bits) {
		return true
	}
	set.Bits[fd/64] |= 1 << uint(fd%64)
	tv := syscall.Timeval{}
	_, err := syscall.Select(fd+1, &set, nil, nil, &tv)
	return err == nil && set.Bits[fd/64]&(1<<uint(fd%64)) != 0
}

func setupTerminal() func() {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return func() {}
	}
	var state syscall.Termios
	if err := ioctl(int(tty.Fd()), syscall.TCGETS, unsafe.Pointer(&state)); err != nil {
		_ = tty.Close()
		return func() {}
	}
	raw := state
	raw.Lflag &^= syscall.ICANON | syscall.ECHO | syscall.ISIG | syscall.IEXTEN
	raw.Iflag &^= syscall.IXON | syscall.ICRNL | syscall.BRKINT | syscall.INPCK | syscall.ISTRIP
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 0
	raw.Cc[syscall.VTIME] = 0
	if err := ioctl(int(tty.Fd()), syscall.TCSETS, unsafe.Pointer(&raw)); err != nil {
		_ = tty.Close()
		return func() {}
	}
	terminalInput, savedTermios = tty, &state
	return func() {
		_ = ioctl(int(tty.Fd()), syscall.TCSETS, unsafe.Pointer(savedTermios))
		_ = tty.Close()
		terminalInput = nil
	}
}

func disableRawTTY() {
	if terminalInput != nil && savedTermios != nil {
		_ = ioctl(int(terminalInput.Fd()), syscall.TCSETS, unsafe.Pointer(savedTermios))
	}
}

func readLine(prompt string) string {
	disableRawTTY()
	defer func() {
		if terminalInput != nil {
			raw := *savedTermios
			raw.Lflag &^= syscall.ICANON | syscall.ECHO | syscall.ISIG | syscall.IEXTEN
			raw.Iflag &^= syscall.IXON | syscall.ICRNL | syscall.BRKINT | syscall.INPCK | syscall.ISTRIP
			raw.Cflag |= syscall.CS8
			raw.Cc[syscall.VMIN] = 0
			raw.Cc[syscall.VTIME] = 0
			_ = ioctl(int(terminalInput.Fd()), syscall.TCSETS, unsafe.Pointer(&raw))
		}
	}()
	fmt.Print("\x1b[?25h\n", prompt)
	input := os.Stdin
	if terminalInput != nil {
		input = terminalInput
	}
	r := bufio.NewReader(input)
	s, _ := r.ReadString('\n')
	return strings.TrimSpace(s)
}

func ioctl(fd int, request uintptr, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(arg), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func terminalSize() (int, int) {
	if terminalInput == nil {
		return 96, 32
	}
	var size terminalWinsize
	if err := ioctl(int(terminalInput.Fd()), syscall.TIOCGWINSZ, unsafe.Pointer(&size)); err != nil || size.Col == 0 || size.Row == 0 {
		return 96, 32
	}
	return int(size.Col), int(size.Row)
}
func match(s, q string) bool {
	return q == "" || strings.Contains(strings.ToLower(s), strings.ToLower(q))
}
func trim(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

func rateLabel(bytesPerSec float64) string {
	if bytesPerSec < 0 {
		bytesPerSec = -bytesPerSec
	}
	units := []string{"B/s", "KB/s", "MB/s", "GB/s"}
	unit := 0
	for bytesPerSec >= 1024 && unit < len(units)-1 {
		bytesPerSec /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f %s", bytesPerSec, units[unit])
}

func countChildren(ps []Process) int {
	n := 0
	for _, p := range ps {
		if p.Children > 0 {
			n++
		}
	}
	return n
}

func processChanged(base []Process, p Process) bool {
	for _, old := range base {
		if old.PID == p.PID {
			return old.PPID != p.PPID || old.State != p.State || old.Name != p.Name || old.Cmd != p.Cmd
		}
	}
	return true
}

func diffCounts(base, now []Process) (int, int, int) {
	old := map[int]uint64{}
	for _, p := range base {
		old[p.PID] = p.StartTime
	}
	cur := map[int]uint64{}
	newCount := 0
	restartCount := 0
	for _, p := range now {
		cur[p.PID] = p.StartTime
		previous, existed := old[p.PID]
		if !existed {
			newCount++
		} else if previous != 0 && p.StartTime != 0 && previous != p.StartTime {
			restartCount++
		}
	}
	goneCount := 0
	for pid := range old {
		if _, exists := cur[pid]; !exists {
			goneCount++
		}
	}
	return newCount, goneCount, restartCount
}
func rule(n int) string { return strings.Repeat("─", n) }

const (
	cyan    = "36"
	yellow  = "33"
	green   = "32"
	red     = "31"
	magenta = "35"
	arrow   = "└─"
)

func accent(s, c string) string { return "\x1b[1;" + c + "m" + s + reset }
func dim(s string) string       { return "\x1b[2m" + s + reset }
