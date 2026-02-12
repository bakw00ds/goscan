package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const defaultWebPortsSpec = "80,443,8000,8008,8080,8081,8443,8888,9000,9090,9443,10443"

type Job struct {
	Target string // hostname or IP string
	Port   int
}

type Result struct {
	Target  string `json:"target"`
	Proto   string `json:"proto"` // tcp, udp
	Port    int    `json:"port"`
	State   string `json:"state"` // open, closed, filtered, unknown
	Reason  string `json:"reason,omitempty"`
	Service string `json:"service,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
}

func main() {
	var (
		portSpec     string
		targetSpec   string
		targetFile   string
		timeoutMS    int
		concurrency  int
		outPath      string
		format       string
		onlyOpen     bool
		summary      bool
		importKind   string
		importPath   string
		maxTargets   int
		maxPorts     int
		summaryJSON  bool
		groupBy      string
		emit         string
		web          bool
		webPortsSpec string
	)

	flag.StringVar(&portSpec, "p", "80,443", "ports (e.g. 80,443,5900-5905)")
	flag.StringVar(&targetSpec, "t", "", "targets (comma-separated: host, ip, cidr, range; e.g. \"example.com,192.168.1.1,192.168.2.1-100,10.10.10.0/24\")")
	flag.StringVar(&targetFile, "tf", "", "targets file (one per line; blank lines and # comments allowed)")
	flag.IntVar(&timeoutMS, "timeout", 300, "TCP connect timeout in ms")
	flag.IntVar(&concurrency, "c", 512, "number of concurrent workers")
	flag.StringVar(&outPath, "out", "", "output file path (optional; default stdout)")
	flag.StringVar(&format, "format", "text", "output format: text|csv|json")
	flag.BoolVar(&onlyOpen, "only-open", false, "only output open ports")
	flag.BoolVar(&summary, "summary", true, "print summary (text only)")
	flag.BoolVar(&summaryJSON, "summary-json", false, "for --format json: include a JSON summary object alongside results")
	flag.StringVar(&groupBy, "group-by", "", "for --format csv: aggregate output by: target|port (default none)")
	flag.StringVar(&importKind, "import", "", "import results instead of scanning: nmap-xml")
	flag.StringVar(&importPath, "in", "", "input file path for --import")
	flag.IntVar(&maxTargets, "max-targets", 0, "safety limit for expanded targets (0 = unlimited)")
	flag.IntVar(&maxPorts, "max-ports", 0, "safety limit for parsed ports (0 = unlimited)")
	flag.StringVar(&emit, "emit", "none", "emit derived output instead of full results: none|urls|hostport")
	flag.BoolVar(&web, "web", false, "web-mode: use/filter common web ports")
	flag.StringVar(&webPortsSpec, "web-ports", defaultWebPortsSpec, "web-mode ports override (same format as -p)")
	flag.Parse()

	format = strings.ToLower(strings.TrimSpace(format))
	if format != "text" && format != "csv" && format != "json" {
		fatalf("invalid --format %q (expected text|csv|json)", format)
	}

	emit = strings.ToLower(strings.TrimSpace(emit))
	if emit == "" {
		emit = "none"
	}
	if emit != "none" && emit != "urls" && emit != "hostport" {
		fatalf("invalid --emit %q (expected none|urls|hostport)", emit)
	}

	// IMPORT MODE
	if strings.TrimSpace(importKind) != "" {
		if strings.TrimSpace(importPath) == "" {
			fatalf("--in is required when using --import")
		}
		results, err := importResults(importKind, importPath)
		if err != nil {
			fatalf("import failed: %v", err)
		}
		writeResults(results, outputOpts{Format: format, OutPath: outPath, OnlyOpen: onlyOpen, Summary: summary, SummaryJSON: summaryJSON, GroupBy: groupBy, Emit: emit, Web: web, WebPortsSpec: webPortsSpec})
		return
	}

	// SCAN MODE
	if strings.TrimSpace(targetSpec) == "" && strings.TrimSpace(targetFile) == "" {
		fatalf("specify -t and/or -tf")
	}

	if web {
		portSpec = webPortsSpec
	}
	ports, err := parsePorts(portSpec)
	if err != nil {
		fatalf("error parsing ports: %v", err)
	}
	if maxPorts > 0 && len(ports) > maxPorts {
		fatalf("refusing to scan %d ports (exceeds --max-ports=%d)", len(ports), maxPorts)
	}

	targets, err := parseTargets(targetSpec)
	if err != nil {
		fatalf("error parsing targets: %v", err)
	}
	if strings.TrimSpace(targetFile) != "" {
		fileTargets, err := parseTargetsFile(targetFile)
		if err != nil {
			fatalf("error parsing targets file: %v", err)
		}
		targets = append(targets, fileTargets...)
	}
	// Dedup/sort targets for nicer output
	targets = dedupStrings(targets)
	if maxTargets > 0 && len(targets) > maxTargets {
		fatalf("refusing to scan %d targets (exceeds --max-targets=%d)", len(targets), maxTargets)
	}

	timeout := time.Duration(timeoutMS) * time.Millisecond

	jobs := make(chan Job, 4096)
	resultsCh := make(chan Result, 4096)

	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: timeout}
			for job := range jobs {
				addr := net.JoinHostPort(job.Target, strconv.Itoa(job.Port))
				conn, err := dialer.Dial("tcp", addr)
				if err != nil {
					st, reason := classifyDialErr(err)
					resultsCh <- Result{Target: job.Target, Proto: "tcp", Port: job.Port, State: st, Reason: reason}
					continue
				}
				_ = conn.Close()
				resultsCh <- Result{Target: job.Target, Proto: "tcp", Port: job.Port, State: "open"}
			}
		}()
	}

	go func() {
		for _, t := range targets {
			for _, p := range ports {
				jobs <- Job{Target: t, Port: p}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var results []Result
	for r := range resultsCh {
		results = append(results, r)
	}

	sortResults(results)
	writeResults(results, outputOpts{Format: format, OutPath: outPath, OnlyOpen: onlyOpen, Summary: summary, SummaryJSON: summaryJSON, GroupBy: groupBy, Emit: emit, Web: web, WebPortsSpec: webPortsSpec})
}

type outputOpts struct {
	Format       string
	OutPath      string
	OnlyOpen     bool
	Summary      bool
	SummaryJSON  bool
	GroupBy      string
	Emit         string
	Web          bool
	WebPortsSpec string
}

func writeResults(results []Result, opts outputOpts) {
	var out io.Writer = os.Stdout
	var f *os.File
	if strings.TrimSpace(opts.OutPath) != "" {
		var err error
		f, err = os.Create(opts.OutPath)
		if err != nil {
			fatalf("error creating output file: %v", err)
		}
		defer f.Close()
		out = f
	}

	// Optional web-mode filtering (TCP only).
	if opts.Web {
		webPorts, err := parsePorts(opts.WebPortsSpec)
		if err != nil {
			fatalf("error parsing --web-ports: %v", err)
		}
		set := make(map[int]struct{}, len(webPorts))
		for _, p := range webPorts {
			set[p] = struct{}{}
		}
		filtered := results[:0]
		for _, r := range results {
			if r.Proto != "tcp" {
				continue
			}
			if _, ok := set[r.Port]; !ok {
				continue
			}
			filtered = append(filtered, r)
		}
		results = append([]Result(nil), filtered...)
	}

	if opts.Emit != "none" {
		switch opts.Emit {
		case "urls":
			writeEmitURLs(out, results, opts)
			return
		case "hostport":
			writeEmitHostPort(out, results, opts)
			return
		default:
			fatalf("unknown emit mode: %s", opts.Emit)
		}
	}

	switch opts.Format {
	case "json":
		if opts.SummaryJSON {
			sum := buildSummary(results)
			writeJSONWithSummary(out, filterResults(results, opts.OnlyOpen), sum)
		} else {
			writeJSON(out, filterResults(results, opts.OnlyOpen))
		}
	case "csv":
		writeCSV(out, filterResults(results, opts.OnlyOpen), opts.GroupBy)
	case "text":
		writeText(out, results, opts)
	default:
		fatalf("unknown format: %s", opts.Format)
	}
}

func filterResults(in []Result, onlyOpen bool) []Result {
	if !onlyOpen {
		return in
	}
	out := make([]Result, 0, len(in))
	for _, r := range in {
		if r.State == "open" {
			out = append(out, r)
		}
	}
	return out
}

func writeText(w io.Writer, results []Result, opts outputOpts) {
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush()

	for _, r := range results {
		if opts.OnlyOpen && r.State != "open" {
			continue
		}
		line := fmt.Sprintf("%s/%s:%d %s", r.Target, r.Proto, r.Port, r.State)
		if r.Service != "" {
			line += " " + r.Service
		}
		if r.Product != "" {
			line += " (" + r.Product
			if r.Version != "" {
				line += " " + r.Version
			}
			line += ")"
		}
		if r.Reason != "" && r.State != "open" {
			line += " [" + r.Reason + "]"
		}
		_, _ = bw.WriteString(line + "\n")
	}

	if !opts.Summary {
		return
	}

	openResults := make([]Result, 0)
	for _, r := range results {
		if r.State == "open" {
			openResults = append(openResults, r)
		}
	}
	sortResults(openResults)

	_, _ = bw.WriteString("\n--- SUMMARY (open ports, sorted by attacker interest) ---\n")
	if len(openResults) == 0 {
		_, _ = bw.WriteString("No open ports found.\n")
		return
	}

	byTarget := make(map[string][]int)
	for _, r := range openResults {
		byTarget[r.Target] = append(byTarget[r.Target], r.Port)
	}
	targets := make([]string, 0, len(byTarget))
	for t := range byTarget {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	for _, t := range targets {
		ps := dedupInts(byTarget[t])
		sort.Slice(ps, func(i, j int) bool {
			ri := interestRank(ps[i])
			rj := interestRank(ps[j])
			if ri != rj {
				return ri < rj
			}
			return ps[i] < ps[j]
		})
		_, _ = bw.WriteString(fmt.Sprintf("%s: %s\n", t, joinInts(ps)))
	}

	counts := make(map[int]int)
	for _, r := range openResults {
		counts[r.Port]++
	}
	ports := make([]int, 0, len(counts))
	for p := range counts {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool {
		ri := interestRank(ports[i])
		rj := interestRank(ports[j])
		if ri != rj {
			return ri < rj
		}
		if counts[ports[i]] != counts[ports[j]] {
			return counts[ports[i]] > counts[ports[j]]
		}
		return ports[i] < ports[j]
	})

	_, _ = bw.WriteString("\nOpen port prevalence:\n")
	for _, p := range ports {
		_, _ = bw.WriteString(fmt.Sprintf("%d (%d hosts)\n", p, counts[p]))
	}
}

func writeCSV(w io.Writer, results []Result, groupBy string) {
	groupBy = strings.ToLower(strings.TrimSpace(groupBy))
	cw := csv.NewWriter(w)

	switch groupBy {
	case "":
		_ = cw.Write([]string{"target", "proto", "port", "state", "reason", "service", "product", "version"})
		for _, r := range results {
			_ = cw.Write([]string{r.Target, r.Proto, strconv.Itoa(r.Port), r.State, r.Reason, r.Service, r.Product, r.Version})
		}
	case "target":
		// Aggregate OPEN ports per target.
		_ = cw.Write([]string{"target", "open_ports", "open_count"})
		byTarget := make(map[string][]int)
		for _, r := range results {
			if r.State != "open" {
				continue
			}
			byTarget[r.Target] = append(byTarget[r.Target], r.Port)
		}
		targets := make([]string, 0, len(byTarget))
		for t := range byTarget {
			targets = append(targets, t)
		}
		sort.Strings(targets)
		for _, t := range targets {
			ps := dedupInts(byTarget[t])
			sort.Slice(ps, func(i, j int) bool {
				ri := interestRank(ps[i])
				rj := interestRank(ps[j])
				if ri != rj {
					return ri < rj
				}
				return ps[i] < ps[j]
			})
			_ = cw.Write([]string{t, joinInts(ps), strconv.Itoa(len(ps))})
		}
	case "port":
		// Aggregate OPEN ports across targets.
		_ = cw.Write([]string{"proto", "port", "service", "hosts_open"})
		type key struct {
			proto string
			port  int
			serv  string
		}
		seen := make(map[key]map[string]struct{})
		for _, r := range results {
			if r.State != "open" {
				continue
			}
			k := key{proto: r.Proto, port: r.Port, serv: r.Service}
			m, ok := seen[k]
			if !ok {
				m = make(map[string]struct{})
				seen[k] = m
			}
			m[r.Target] = struct{}{}
		}
		keys := make([]key, 0, len(seen))
		for k := range seen {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			ri := interestRank(keys[i].port)
			rj := interestRank(keys[j].port)
			if ri != rj {
				return ri < rj
			}
			if len(seen[keys[i]]) != len(seen[keys[j]]) {
				return len(seen[keys[i]]) > len(seen[keys[j]])
			}
			if keys[i].proto != keys[j].proto {
				return keys[i].proto < keys[j].proto
			}
			return keys[i].port < keys[j].port
		})
		for _, k := range keys {
			_ = cw.Write([]string{k.proto, strconv.Itoa(k.port), k.serv, strconv.Itoa(len(seen[k]))})
		}
	default:
		fatalf("invalid --group-by %q (expected: target|port)", groupBy)
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		fatalf("csv write error: %v", err)
	}
}

func writeJSON(w io.Writer, results []Result) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		fatalf("json write error: %v", err)
	}
}

func writeJSONWithSummary(w io.Writer, results []Result, summary Summary) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	payload := struct {
		Results []Result `json:"results"`
		Summary Summary  `json:"summary"`
	}{Results: results, Summary: summary}
	if err := enc.Encode(payload); err != nil {
		fatalf("json write error: %v", err)
	}
}

func writeEmitURLs(w io.Writer, results []Result, opts outputOpts) {
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush()
	set := make(map[string]struct{})
	for _, r := range results {
		if r.Proto != "tcp" {
			continue
		}
		if r.State != "open" {
			continue
		}
		if opts.OnlyOpen == false {
			// emit modes are inherently open-only; nothing to do
		}
		url := urlForHostPort(r.Target, r.Port)
		set[url] = struct{}{}
	}
	urls := make([]string, 0, len(set))
	for u := range set {
		urls = append(urls, u)
	}
	sort.Slice(urls, func(i, j int) bool {
		// Sort https before http, then by interest, then lexicographically.
		si := schemeRank(urls[i])
		sj := schemeRank(urls[j])
		if si != sj {
			return si < sj
		}
		pi := portFromURL(urls[i])
		pj := portFromURL(urls[j])
		ri := interestRank(pi)
		rj := interestRank(pj)
		if ri != rj {
			return ri < rj
		}
		return urls[i] < urls[j]
	})
	for _, u := range urls {
		_, _ = bw.WriteString(u + "\n")
	}
}

func writeEmitHostPort(w io.Writer, results []Result, opts outputOpts) {
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush()
	type hp struct {
		host string
		port int
	}
	set := make(map[hp]struct{})
	for _, r := range results {
		if r.Proto != "tcp" {
			continue
		}
		if r.State != "open" {
			continue
		}
		set[hp{host: r.Target, port: r.Port}] = struct{}{}
	}
	list := make([]hp, 0, len(set))
	for k := range set {
		list = append(list, k)
	}
	sort.Slice(list, func(i, j int) bool {
		ri := interestRank(list[i].port)
		rj := interestRank(list[j].port)
		if ri != rj {
			return ri < rj
		}
		if list[i].host != list[j].host {
			return list[i].host < list[j].host
		}
		return list[i].port < list[j].port
	})
	for _, x := range list {
		_, _ = bw.WriteString(fmt.Sprintf("%s:%d\n", x.host, x.port))
	}
}

func urlForHostPort(host string, port int) string {
	scheme := "http"
	if isLikelyHTTPSPort(port) {
		scheme = "https"
	}
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

func isLikelyHTTPSPort(port int) bool {
	switch port {
	case 443, 4443, 5443, 8443, 9443, 10443:
		return true
	default:
		return false
	}
}

func schemeRank(u string) int {
	if strings.HasPrefix(u, "https://") {
		return 0
	}
	return 1
}

func portFromURL(u string) int {
	// best-effort parse. Not strict.
	// https://host:8443 -> 8443
	// https://host -> 443
	// http://host -> 80
	// http://host:8080 -> 8080
	if strings.HasPrefix(u, "https://") {
		u = strings.TrimPrefix(u, "https://")
		if strings.Contains(u, ":") {
			p := u[strings.LastIndex(u, ":")+1:]
			pi, _ := strconv.Atoi(p)
			return pi
		}
		return 443
	}
	if strings.HasPrefix(u, "http://") {
		u = strings.TrimPrefix(u, "http://")
		if strings.Contains(u, ":") {
			p := u[strings.LastIndex(u, ":")+1:]
			pi, _ := strconv.Atoi(p)
			return pi
		}
		return 80
	}
	return 0
}

func parsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port spec")
	}

	set := make(map[int]struct{})
	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			bits := strings.SplitN(part, "-", 2)
			if len(bits) != 2 {
				return nil, fmt.Errorf("bad port range: %q", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(bits[0]))
			if err != nil {
				return nil, fmt.Errorf("bad port: %q", bits[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(bits[1]))
			if err != nil {
				return nil, fmt.Errorf("bad port: %q", bits[1])
			}
			if start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				set[p] = struct{}{}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("bad port: %q", part)
			}
			if p <= 0 || p > 65535 {
				return nil, fmt.Errorf("invalid port: %d", p)
			}
			set[p] = struct{}{}
		}
	}

	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

func parseTargets(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var out []string
	parts := strings.Split(spec, ",")
	for _, raw := range parts {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}

		// CIDR
		if strings.Contains(token, "/") {
			ips, err := expandCIDR(token)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				out = append(out, ip.String())
			}
			continue
		}

		// Range (either A.B.C.D-E.F.G.H or A.B.C.D-XYZ)
		if strings.Contains(token, "-") {
			ips, err := expandRange(token)
			if err != nil {
				return nil, err
			}
			out = append(out, ips...)
			continue
		}

		// Single IP or hostname (keep as-is)
		out = append(out, token)
	}

	return out, nil
}

func parseTargetsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// allow comma-separated entries per line too
		targets, err := parseTargets(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", line, err)
		}
		out = append(out, targets...)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets in file")
	}
	return out, nil
}

func expandCIDR(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("bad CIDR %q: %w", cidr, err)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 CIDR supported (got %q)", cidr)
	}

	var ips []net.IP
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); cur = nextIPv4(cur) {
		// copy
		tmp := make(net.IP, len(cur))
		copy(tmp, cur)
		ips = append(ips, tmp)
	}
	return ips, nil
}

func expandRange(token string) ([]string, error) {
	token = strings.TrimSpace(token)
	bits := strings.SplitN(token, "-", 2)
	if len(bits) != 2 {
		return nil, fmt.Errorf("bad range: %q", token)
	}
	left := strings.TrimSpace(bits[0])
	right := strings.TrimSpace(bits[1])

	startIP := net.ParseIP(left).To4()
	if startIP == nil {
		return nil, fmt.Errorf("bad range start IP: %q", left)
	}

	// Case 1: full IP-IP
	if strings.Count(right, ".") == 3 {
		endIP := net.ParseIP(right).To4()
		if endIP == nil {
			return nil, fmt.Errorf("bad range end IP: %q", right)
		}
		if ipv4ToUint32(startIP) > ipv4ToUint32(endIP) {
			return nil, fmt.Errorf("range start > end: %q", token)
		}
		var out []string
		for cur := startIP; ; cur = nextIPv4(cur) {
			out = append(out, cur.String())
			if cur.Equal(endIP) {
				break
			}
		}
		return out, nil
	}

	// Case 2: shorthand last-octet (A.B.C.D-XYZ)
	endOct, err := strconv.Atoi(right)
	if err != nil {
		return nil, fmt.Errorf("bad shorthand range end (expected int or full IP): %q", right)
	}
	if endOct < 0 || endOct > 255 {
		return nil, fmt.Errorf("bad shorthand end octet: %d", endOct)
	}

	startOct := int(startIP[3])
	if endOct < startOct {
		return nil, fmt.Errorf("shorthand range end < start: %q", token)
	}

	base := []byte{startIP[0], startIP[1], startIP[2], 0}
	var out []string
	for o := startOct; o <= endOct; o++ {
		ip := net.IPv4(base[0], base[1], base[2], byte(o)).To4()
		out = append(out, ip.String())
	}
	return out, nil
}

func nextIPv4(ip net.IP) net.IP {
	v := ipv4ToUint32(ip)
	v++
	return uint32ToIPv4(v)
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIPv4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
}

func dedupStrings(in []string) []string {
	set := make(map[string]struct{}, len(in))
	for _, s := range in {
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func dedupInts(in []int) []int {
	set := make(map[int]struct{}, len(in))
	for _, v := range in {
		set[v] = struct{}{}
	}
	out := make([]int, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	return out
}

func joinInts(in []int) string {
	if len(in) == 0 {
		return ""
	}
	b := strings.Builder{}
	for i, v := range in {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(strconv.Itoa(v))
	}
	return b.String()
}

func sortResults(rs []Result) {
	sort.Slice(rs, func(i, j int) bool {
		// Open first
		if (rs[i].State == "open") != (rs[j].State == "open") {
			return rs[i].State == "open"
		}
		ri := interestRank(rs[i].Port)
		rj := interestRank(rs[j].Port)
		if ri != rj {
			return ri < rj
		}
		if rs[i].Target != rs[j].Target {
			return rs[i].Target < rs[j].Target
		}
		if rs[i].Proto != rs[j].Proto {
			return rs[i].Proto < rs[j].Proto
		}
		return rs[i].Port < rs[j].Port
	})
}

type Summary struct {
	OpenByTarget []TargetOpenSummary `json:"openByTarget"`
	OpenByPort   []PortOpenSummary   `json:"openByPort"`
	Totals       TotalsSummary       `json:"totals"`
}

type TargetOpenSummary struct {
	Target    string `json:"target"`
	OpenPorts []int  `json:"openPorts"`
}

type PortOpenSummary struct {
	Proto     string `json:"proto"`
	Port      int    `json:"port"`
	Service   string `json:"service,omitempty"`
	HostsOpen int    `json:"hostsOpen"`
}

type TotalsSummary struct {
	TargetsWithOpenPorts int `json:"targetsWithOpenPorts"`
	UniqueOpenPorts      int `json:"uniqueOpenPorts"`
	TotalOpenFindings    int `json:"totalOpenFindings"`
}

func buildSummary(results []Result) Summary {
	// target -> ports
	byTarget := make(map[string][]int)
	// (proto,port,service) -> set(target)
	type key struct {
		proto string
		port  int
		serv  string
	}
	byPort := make(map[key]map[string]struct{})

	totalOpenFindings := 0
	for _, r := range results {
		if r.State != "open" {
			continue
		}
		totalOpenFindings++
		byTarget[r.Target] = append(byTarget[r.Target], r.Port)
		k := key{proto: r.Proto, port: r.Port, serv: r.Service}
		m, ok := byPort[k]
		if !ok {
			m = make(map[string]struct{})
			byPort[k] = m
		}
		m[r.Target] = struct{}{}
	}

	// open by target
	targets := make([]string, 0, len(byTarget))
	for t := range byTarget {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	openByTarget := make([]TargetOpenSummary, 0, len(targets))
	uniquePorts := make(map[int]struct{})
	for _, t := range targets {
		ps := dedupInts(byTarget[t])
		for _, p := range ps {
			uniquePorts[p] = struct{}{}
		}
		sort.Slice(ps, func(i, j int) bool {
			ri := interestRank(ps[i])
			rj := interestRank(ps[j])
			if ri != rj {
				return ri < rj
			}
			return ps[i] < ps[j]
		})
		openByTarget = append(openByTarget, TargetOpenSummary{Target: t, OpenPorts: ps})
	}

	// open by port
	keys := make([]key, 0, len(byPort))
	for k := range byPort {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ri := interestRank(keys[i].port)
		rj := interestRank(keys[j].port)
		if ri != rj {
			return ri < rj
		}
		if len(byPort[keys[i]]) != len(byPort[keys[j]]) {
			return len(byPort[keys[i]]) > len(byPort[keys[j]])
		}
		if keys[i].proto != keys[j].proto {
			return keys[i].proto < keys[j].proto
		}
		return keys[i].port < keys[j].port
	})
	openByPort := make([]PortOpenSummary, 0, len(keys))
	for _, k := range keys {
		openByPort = append(openByPort, PortOpenSummary{Proto: k.proto, Port: k.port, Service: k.serv, HostsOpen: len(byPort[k])})
	}

	return Summary{
		OpenByTarget: openByTarget,
		OpenByPort:   openByPort,
		Totals: TotalsSummary{
			TargetsWithOpenPorts: len(byTarget),
			UniqueOpenPorts:      len(uniquePorts),
			TotalOpenFindings:    totalOpenFindings,
		},
	}
}

// interestRank returns a lower number for ports that are typically more
// interesting/valuable to attackers (remote access, lateral movement, admin).
func interestRank(port int) int {
	switch port {
	case 22: // SSH
		return 1
	case 3389: // RDP
		return 2
	case 445: // SMB
		return 3
	case 139: // NetBIOS/SMB
		return 4
	case 5900: // VNC
		return 5
	case 5985, 5986: // WinRM
		return 6
	case 135: // RPC
		return 7
	case 389, 636: // LDAP/LDAPS
		return 8
	case 80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 9000, 9090: // HTTP(S) + common admin web ports
		return 10
	case 6443, 10250: // Kubernetes API / kubelet
		return 10
	case 2375, 2376: // Docker API
		return 11
	case 2379, 2380: // etcd
		return 11
	case 3306: // MySQL
		return 12
	case 5432: // Postgres
		return 13
	case 1433, 1434: // MSSQL
		return 14
	case 1521: // Oracle
		return 15
	case 6379: // Redis
		return 16
	case 27017: // MongoDB
		return 17
	case 9200, 9300: // Elasticsearch
		return 18
	case 11211: // Memcached
		return 19
	case 2049, 111: // NFS / rpcbind
		return 20
	case 25, 465, 587: // SMTP
		return 25
	case 53: // DNS
		return 30
	case 161: // SNMP
		return 35
	case 21: // FTP
		return 40
	case 23: // Telnet
		return 41
	case 110, 143, 993, 995: // POP/IMAP
		return 45
	default:
		return 1000 + port
	}
}

func classifyDialErr(err error) (state, reason string) {
	// net.Error timeout
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "filtered", "timeout"
	}
	// unwrap to syscall errno
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// DNS errors bubble up as OpError sometimes
		var dnsErr *net.DNSError
		if errors.As(opErr.Err, &dnsErr) {
			return "unknown", "dns"
		}
		// Connection refused => closed
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return "closed", "refused"
		}
		if errors.Is(opErr.Err, syscall.EHOSTUNREACH) {
			return "filtered", "host-unreach"
		}
		if errors.Is(opErr.Err, syscall.ENETUNREACH) {
			return "filtered", "net-unreach"
		}
		if errors.Is(opErr.Err, syscall.ETIMEDOUT) {
			return "filtered", "timeout"
		}
		// Some platforms wrap in os.SyscallError
		var se *os.SyscallError
		if errors.As(opErr.Err, &se) {
			if errors.Is(se.Err, syscall.ECONNREFUSED) {
				return "closed", "refused"
			}
		}
	}
	return "unknown", "error"
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(2)
}

// --- Importers ---

func importResults(kind, path string) ([]Result, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch kind {
	case "nmap-xml":
		return importNmapXML(path)
	default:
		return nil, fmt.Errorf("unknown import kind %q", kind)
	}
}

// Minimal Nmap XML model.
// Reference: https://nmap.org/book/output-formats-output-to-xml.html

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Address   []nmapAddr    `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
	Hostnames nmapHostnames `xml:"hostnames"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddr struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Names []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Proto   string        `xml:"protocol,attr"`
	PortID  int           `xml:"portid,attr"`
	State   nmapPortState `xml:"state"`
	Service nmapService   `xml:"service"`
}

type nmapPortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func importNmapXML(path string) ([]Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var run nmapRun
	if err := xml.Unmarshal(b, &run); err != nil {
		return nil, err
	}

	var results []Result
	for _, h := range run.Hosts {
		if strings.ToLower(h.Status.State) != "up" {
			continue
		}
		// Prefer IPv4 address; fall back to hostname if present.
		target := ""
		for _, a := range h.Address {
			if a.Type == "ipv4" && a.Addr != "" {
				target = a.Addr
				break
			}
		}
		if target == "" {
			for _, a := range h.Address {
				if a.Addr != "" {
					target = a.Addr
					break
				}
			}
		}
		if target == "" && len(h.Hostnames.Names) > 0 {
			target = h.Hostnames.Names[0].Name
		}
		if target == "" {
			continue
		}

		for _, p := range h.Ports.Ports {
			st := strings.ToLower(strings.TrimSpace(p.State.State))
			if st == "" {
				st = "unknown"
			}
			results = append(results, Result{
				Target:  target,
				Proto:   strings.ToLower(p.Proto),
				Port:    p.PortID,
				State:   st,
				Reason:  p.State.Reason,
				Service: p.Service.Name,
				Product: p.Service.Product,
				Version: p.Service.Version,
			})
		}
	}

	if len(results) == 0 {
		return nil, errors.New("no results parsed (did you use -oX?)")
	}

	sortResults(results)
	return results, nil
}
