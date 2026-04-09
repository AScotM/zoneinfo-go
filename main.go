package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed probe.sh
var remoteScriptContent string

type CommandResult struct {
	Command    string  `json:"command"`
	ReturnCode int     `json:"return_code"`
	Stdout     string  `json:"stdout"`
	Stderr     string  `json:"stderr"`
	DurationS  float64 `json:"duration_s"`
}

type HostProbe struct {
	Host               string            `json:"host"`
	Target             string            `json:"target"`
	IsLocal            bool              `json:"is_local"`
	Reachable          bool              `json:"reachable"`
	Error              string            `json:"error"`
	Hostname           string            `json:"hostname"`
	FQDN               string            `json:"fqdn"`
	OSPrettyName       string            `json:"os_pretty_name"`
	Kernel             string            `json:"kernel"`
	GoVersion          string            `json:"go_version"`
	Timezone           string            `json:"timezone"`
	NTPServiceActive   *bool             `json:"ntp_service_active"`
	NTPSynchronized    *bool             `json:"ntp_synchronized"`
	LocalRTC           *bool             `json:"local_rtc"`
	LocaltimePath      string            `json:"localtime_path"`
	LocaltimeSHA256    string            `json:"localtime_sha256"`
	ZoneinfoPath       string            `json:"zoneinfo_path"`
	ZoneinfoSHA256     string            `json:"zoneinfo_sha256"`
	NowISO             string            `json:"now_iso"`
	NowEpoch           *int64            `json:"now_epoch"`
	UTCOffset          string            `json:"utc_offset"`
	TZAbbrev           string            `json:"tz_abbrev"`
	TimedatectlAvail   bool              `json:"timedatectl_available"`
	Source             string            `json:"source"`
	Warnings           []string          `json:"warnings"`
	RawFields          map[string]string `json:"raw_fields"`
	CommandLog         []CommandResult   `json:"command_log"`
	ProbeVersion       int               `json:"probe_version"`
	IncompatibleProbe  bool              `json:"incompatible_probe"`
}

type ComparisonIssue struct {
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Message  string   `json:"message"`
	Hosts    []string `json:"hosts"`
}

type ComparisonSummary struct {
	ReferenceHost             string            `json:"reference_host"`
	TimezoneConsistent        bool              `json:"timezone_consistent"`
	LocaltimeTargetConsistent bool              `json:"localtime_target_consistent"`
	LocaltimeHashConsistent   bool              `json:"localtime_hash_consistent"`
	ZoneinfoHashConsistent    bool              `json:"zoneinfo_hash_consistent"`
	NTPConsistent             bool              `json:"ntp_consistent"`
	SynchronizedConsistent    bool              `json:"synchronized_consistent"`
	UTCOffsetConsistent       bool              `json:"utc_offset_consistent"`
	ClockSkewWithinThreshold  bool              `json:"clock_skew_within_threshold"`
	MaxClockSkewSeconds       *int64            `json:"max_clock_skew_seconds"`
	Issues                    []ComparisonIssue `json:"issues"`
}

type JSONReport struct {
	GeneratedAt string            `json:"generated_at"`
	Summary     ComparisonSummary `json:"summary"`
	Hosts       []HostProbe       `json:"hosts"`
}

type RemoteExecutor struct {
	SSHUser        string
	SSHPort        int
	SSHOptions     []string
	ConnectTimeout int
}

func (r *RemoteExecutor) Run(ctx context.Context, target string, command string, isLocal bool) CommandResult {
	start := time.Now()
	var cmd *exec.Cmd

	if isLocal {
		cmd = exec.CommandContext(ctx, "bash", "-c", command)
	} else {
		sshTarget := target
		if r.SSHUser != "" && !strings.Contains(target, "@") {
			sshTarget = r.SSHUser + "@" + target
		}
		args := []string{
			"-p", strconv.Itoa(r.SSHPort),
			"-o", fmt.Sprintf("ConnectTimeout=%d", r.ConnectTimeout),
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=accept-new",
		}
		args = append(args, r.SSHOptions...)
		args = append(args, sshTarget, command)
		cmd = exec.CommandContext(ctx, "ssh", args...)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	rc := 0
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			rc = 124
			if stderr.Len() == 0 {
				stderr.WriteString("command timed out")
			}
		} else {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				rc = exitErr.ExitCode()
			} else {
				rc = 255
				if stderr.Len() == 0 {
					stderr.WriteString(err.Error())
				}
			}
		}
	}

	return CommandResult{
		Command:    command,
		ReturnCode: rc,
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		DurationS:  time.Since(start).Seconds(),
	}
}

type HostInspector struct {
	Executor *RemoteExecutor
}

func (h *HostInspector) Inspect(ctx context.Context, target string, localAliases []string) HostProbe {
	isLocal := isLocalTarget(target, localAliases)
	probe := HostProbe{
		Host:       target,
		Target:     target,
		IsLocal:    isLocal,
		Reachable:  false,
		RawFields:  map[string]string{},
		Warnings:   []string{},
		CommandLog: []CommandResult{},
	}

	result := h.Executor.Run(ctx, target, remoteScriptContent, isLocal)
	probe.CommandLog = append(probe.CommandLog, result)

	if result.ReturnCode != 0 {
		probe.Error = cleanText(result.Stderr)
		if probe.Error == "" {
			probe.Error = fmt.Sprintf("probe failed with rc=%d", result.ReturnCode)
		}
		return probe
	}

	raw := parseKeyValueOutput(result.Stdout)
	probe.RawFields = raw

	versionStr := raw["host_probe_version"]
	if versionStr != "" {
		if v, err := strconv.Atoi(versionStr); err == nil {
			probe.ProbeVersion = v
			if v != 1 {
				probe.IncompatibleProbe = true
				probe.Warnings = append(probe.Warnings, fmt.Sprintf("incompatible_probe_version_%d", v))
			}
		}
	}

	probe.Reachable = true
	probe.Hostname = raw["hostname"]
	probe.FQDN = raw["fqdn"]
	probe.OSPrettyName = raw["os_pretty_name"]
	probe.Kernel = raw["kernel"]
	probe.GoVersion = runtime.Version()
	probe.Timezone = raw["timezone"]
	probe.NTPServiceActive = parseTriBool(raw["ntp_service_active"])
	probe.NTPSynchronized = parseTriBool(raw["ntp_synchronized"])
	probe.LocalRTC = parseTriBool(raw["local_rtc"])
	probe.LocaltimePath = raw["localtime_path"]
	probe.LocaltimeSHA256 = raw["localtime_sha256"]
	probe.ZoneinfoPath = raw["zoneinfo_path"]
	probe.ZoneinfoSHA256 = raw["zoneinfo_sha256"]
	probe.NowISO = raw["now_iso"]
	probe.UTCOffset = raw["utc_offset"]
	probe.TZAbbrev = raw["tz_abbrev"]
	probe.TimedatectlAvail = strings.EqualFold(raw["timedatectl_available"], "true")

	if epochRaw := raw["now_epoch"]; epochRaw != "" {
		if parsed, err := strconv.ParseInt(epochRaw, 10, 64); err == nil {
			probe.NowEpoch = &parsed
		}
	}

	if probe.Timezone == "" {
		probe.Warnings = append(probe.Warnings, "timezone_unresolved")
	}
	if probe.LocaltimePath == "" {
		probe.Warnings = append(probe.Warnings, "localtime_path_unresolved")
	}
	if probe.LocaltimeSHA256 == "" {
		probe.Warnings = append(probe.Warnings, "localtime_hash_unresolved")
	}
	if probe.TimedatectlAvail && probe.NTPServiceActive == nil {
		probe.Warnings = append(probe.Warnings, "ntp_state_unresolved")
	}
	if probe.TimedatectlAvail && probe.NTPSynchronized == nil {
		probe.Warnings = append(probe.Warnings, "sync_state_unresolved")
	}
	if probe.ZoneinfoPath != "" && probe.ZoneinfoSHA256 == "" {
		probe.Warnings = append(probe.Warnings, "zoneinfo_hash_unresolved")
	}

	if isLocal {
		probe.Source = "local"
	} else {
		probe.Source = "ssh"
	}

	return probe
}

type Comparator struct {
	SkewThresholdSeconds int64
}

func (c *Comparator) Compare(probes []HostProbe) ComparisonSummary {
	summary := ComparisonSummary{
		TimezoneConsistent:        true,
		LocaltimeTargetConsistent: true,
		LocaltimeHashConsistent:   true,
		ZoneinfoHashConsistent:    true,
		NTPConsistent:             true,
		SynchronizedConsistent:    true,
		UTCOffsetConsistent:       true,
		ClockSkewWithinThreshold:  true,
		Issues:                    []ComparisonIssue{},
	}

	reachable := make([]HostProbe, 0)
	for _, p := range probes {
		if p.Reachable && !p.IncompatibleProbe {
			reachable = append(reachable, p)
		}
	}

	if len(reachable) == 0 {
		summary.Issues = append(summary.Issues, ComparisonIssue{
			Category: "reachability",
			Severity: "critical",
			Message:  "No reachable hosts with compatible probe version to compare",
		})
		return summary
	}

	ref := reachable[0]
	if ref.Hostname != "" {
		summary.ReferenceHost = ref.Hostname
	} else {
		summary.ReferenceHost = ref.Host
	}

	c.checkUniformString(&summary, reachable, "timezone")
	c.checkUniformString(&summary, reachable, "localtime_target")
	c.checkUniformString(&summary, reachable, "localtime_hash")
	c.checkUniformString(&summary, reachable, "zoneinfo_hash")
	c.checkUniformBool(&summary, reachable, "ntp")
	c.checkUniformBool(&summary, reachable, "synchronized")
	c.checkUniformString(&summary, reachable, "utc_offset")

	var epochs []int64
	var epochHosts []string
	for _, p := range reachable {
		if p.NowEpoch != nil {
			epochs = append(epochs, *p.NowEpoch)
			epochHosts = append(epochHosts, displayName(p))
		}
	}

	if len(epochs) >= 2 {
		minEpoch := epochs[0]
		maxEpoch := epochs[0]
		for _, v := range epochs[1:] {
			if v < minEpoch {
				minEpoch = v
			}
			if v > maxEpoch {
				maxEpoch = v
			}
		}
		skew := maxEpoch - minEpoch
		summary.MaxClockSkewSeconds = &skew
		if skew > c.SkewThresholdSeconds {
			summary.ClockSkewWithinThreshold = false
			summary.Issues = append(summary.Issues, ComparisonIssue{
				Category: "clock_skew",
				Severity: "warning",
				Message:  fmt.Sprintf("Clock skew exceeds threshold: %ds > %ds", skew, c.SkewThresholdSeconds),
				Hosts:    epochHosts,
			})
		}
	}

	var unreachable []string
	for _, p := range probes {
		if !p.Reachable {
			unreachable = append(unreachable, p.Host)
		}
	}
	if len(unreachable) > 0 {
		summary.Issues = append(summary.Issues, ComparisonIssue{
			Category: "reachability",
			Severity: "warning",
			Message:  fmt.Sprintf("%d host(s) unreachable", len(unreachable)),
			Hosts:    unreachable,
		})
	}

	var incompatible []string
	for _, p := range probes {
		if p.Reachable && p.IncompatibleProbe {
			incompatible = append(incompatible, displayName(p))
		}
	}
	if len(incompatible) > 0 {
		summary.Issues = append(summary.Issues, ComparisonIssue{
			Category: "compatibility",
			Severity: "warning",
			Message:  "Hosts with incompatible probe version",
			Hosts:    incompatible,
		})
	}

	var partial []string
	for _, p := range reachable {
		if len(p.Warnings) > 0 {
			partial = append(partial, displayName(p))
		}
	}
	if len(partial) > 0 {
		summary.Issues = append(summary.Issues, ComparisonIssue{
			Category: "partial_data",
			Severity: "info",
			Message:  "Some hosts returned incomplete timezone or synchronization data",
			Hosts:    partial,
		})
	}

	return summary
}

func (c *Comparator) checkUniformString(summary *ComparisonSummary, probes []HostProbe, category string) {
	values := map[string][]string{}
	for _, p := range probes {
		var v string
		switch category {
		case "timezone":
			v = p.Timezone
		case "localtime_target":
			v = p.LocaltimePath
		case "localtime_hash":
			v = p.LocaltimeSHA256
		case "zoneinfo_hash":
			v = p.ZoneinfoSHA256
		case "utc_offset":
			v = p.UTCOffset
		}
		values[v] = append(values[v], displayName(p))
	}

	var nonEmpty []string
	for k := range values {
		if k != "" {
			nonEmpty = append(nonEmpty, k)
		}
	}
	sort.Strings(nonEmpty)
	consistent := len(uniqueStrings(nonEmpty)) <= 1

	switch category {
	case "timezone":
		summary.TimezoneConsistent = consistent
	case "localtime_target":
		summary.LocaltimeTargetConsistent = consistent
	case "localtime_hash":
		summary.LocaltimeHashConsistent = consistent
	case "zoneinfo_hash":
		summary.ZoneinfoHashConsistent = consistent
	case "utc_offset":
		summary.UTCOffsetConsistent = consistent
	}

	if !consistent {
		var detail []string
		keys := make([]string, 0, len(values))
		for k := range values {
			if k != "" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			detail = append(detail, fmt.Sprintf("%q -> %s", k, strings.Join(values[k], ", ")))
		}
		summary.Issues = append(summary.Issues, ComparisonIssue{
			Category: category,
			Severity: "warning",
			Message:  fmt.Sprintf("Inconsistent %s: %s", category, strings.Join(detail, "; ")),
			Hosts:    hostNames(probes),
		})
	}
}

func (c *Comparator) checkUniformBool(summary *ComparisonSummary, probes []HostProbe, category string) {
	values := map[string][]string{}
	for _, p := range probes {
		key := "unknown"
		switch category {
		case "ntp":
			key = triBoolString(p.NTPServiceActive)
		case "synchronized":
			key = triBoolString(p.NTPSynchronized)
		}
		values[key] = append(values[key], displayName(p))
	}

	var meaningful []string
	for k := range values {
		if k != "unknown" {
			meaningful = append(meaningful, k)
		}
	}
	sort.Strings(meaningful)
	consistent := len(uniqueStrings(meaningful)) <= 1

	switch category {
	case "ntp":
		summary.NTPConsistent = consistent
	case "synchronized":
		summary.SynchronizedConsistent = consistent
	}

	if !consistent {
		var detail []string
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			detail = append(detail, fmt.Sprintf("%s -> %s", k, strings.Join(values[k], ", ")))
		}
		summary.Issues = append(summary.Issues, ComparisonIssue{
			Category: category,
			Severity: "warning",
			Message:  fmt.Sprintf("Inconsistent %s state: %s", category, strings.Join(detail, "; ")),
			Hosts:    hostNames(probes),
		})
	}
}

type Formatter struct {
	UseColor bool
	Width    int
}

func (f *Formatter) RenderTable(probes []HostProbe, summary ComparisonSummary) string {
	headers := []string{"host", "reachable", "timezone", "utc_offset", "tz", "ntp", "synced", "localtime_target", "local_sha256", "epoch"}
	rows := [][]string{headers}

	for _, p := range probes {
		row := []string{
			displayName(p),
			yesNo(p.Reachable),
			emptyDash(p.Timezone),
			emptyDash(p.UTCOffset),
			emptyDash(p.TZAbbrev),
			triBoolString(p.NTPServiceActive),
			triBoolString(p.NTPSynchronized),
			baseOrFull(p.LocaltimePath),
			truncateHash(p.LocaltimeSHA256),
			epochString(p.NowEpoch),
		}
		rows = append(rows, row)
	}

	widths := make([]int, len(headers))
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				if len(cell) > 40 {
					widths[i] = 40
				} else {
					widths[i] = len(cell)
				}
			}
		}
	}

	var b strings.Builder
	b.WriteString("Timezone Consistency Report\n")
	b.WriteString(strings.Repeat("-", min(f.Width, 120)))
	b.WriteString("\n")

	for idx, row := range rows {
		for i, cell := range row {
			if i > 0 {
				b.WriteString("  ")
			}
			b.WriteString(padRight(cell, widths[i]))
		}
		b.WriteString("\n")
		if idx == 0 {
			for i := range row {
				if i > 0 {
					b.WriteString("  ")
				}
				b.WriteString(strings.Repeat("-", widths[i]))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\nSummary\n")
	b.WriteString(strings.Repeat("-", min(f.Width, 120)))
	b.WriteString("\n")

	checks := []struct {
		Name  string
		Value bool
	}{
		{"timezone_consistent", summary.TimezoneConsistent},
		{"localtime_target_consistent", summary.LocaltimeTargetConsistent},
		{"localtime_hash_consistent", summary.LocaltimeHashConsistent},
		{"zoneinfo_hash_consistent", summary.ZoneinfoHashConsistent},
		{"ntp_consistent", summary.NTPConsistent},
		{"synchronized_consistent", summary.SynchronizedConsistent},
		{"utc_offset_consistent", summary.UTCOffsetConsistent},
		{"clock_skew_within_threshold", summary.ClockSkewWithinThreshold},
	}

	for _, c := range checks {
		state := "OK"
		if !c.Value {
			state = "MISMATCH"
		}
		b.WriteString(fmt.Sprintf("%s: %s\n", c.Name, state))
	}

	if summary.MaxClockSkewSeconds != nil {
		b.WriteString(fmt.Sprintf("max_clock_skew_seconds: %d\n", *summary.MaxClockSkewSeconds))
	}
	if summary.ReferenceHost != "" {
		b.WriteString(fmt.Sprintf("reference_host: %s\n", summary.ReferenceHost))
	}

	if len(summary.Issues) > 0 {
		b.WriteString("\nIssues\n")
		for _, issue := range summary.Issues {
			b.WriteString(fmt.Sprintf("- %s %s: %s", strings.ToUpper(issue.Severity), issue.Category, issue.Message))
			if len(issue.Hosts) > 0 {
				b.WriteString(fmt.Sprintf(" [%s]", strings.Join(issue.Hosts, ", ")))
			}
			b.WriteString("\n")
		}
	} else {
		b.WriteString("\nNo comparison issues detected\n")
	}

	b.WriteString("\nHost Details\n")
	b.WriteString(strings.Repeat("-", min(f.Width, 120)))
	b.WriteString("\n")

	for idx, p := range probes {
		b.WriteString(fmt.Sprintf("%s: %s\n", displayName(p), map[bool]string{true: "reachable", false: "unreachable"}[p.Reachable]))
		if !p.Reachable {
			b.WriteString(fmt.Sprintf("  error: %s\n", emptyDash(p.Error)))
		} else {
			b.WriteString(fmt.Sprintf("  target: %s\n", p.Target))
			b.WriteString(fmt.Sprintf("  source: %s\n", p.Source))
			b.WriteString(fmt.Sprintf("  fqdn: %s\n", emptyDash(p.FQDN)))
			b.WriteString(fmt.Sprintf("  os: %s\n", emptyDash(p.OSPrettyName)))
			b.WriteString(fmt.Sprintf("  kernel: %s\n", emptyDash(p.Kernel)))
			b.WriteString(fmt.Sprintf("  go: %s\n", emptyDash(p.GoVersion)))
			b.WriteString(fmt.Sprintf("  timezone: %s\n", emptyDash(p.Timezone)))
			b.WriteString(fmt.Sprintf("  utc_offset: %s\n", emptyDash(p.UTCOffset)))
			b.WriteString(fmt.Sprintf("  tz_abbrev: %s\n", emptyDash(p.TZAbbrev)))
			b.WriteString(fmt.Sprintf("  ntp_service_active: %s\n", triBoolString(p.NTPServiceActive)))
			b.WriteString(fmt.Sprintf("  ntp_synchronized: %s\n", triBoolString(p.NTPSynchronized)))
			b.WriteString(fmt.Sprintf("  local_rtc: %s\n", triBoolString(p.LocalRTC)))
			b.WriteString(fmt.Sprintf("  localtime_path: %s\n", emptyDash(p.LocaltimePath)))
			b.WriteString(fmt.Sprintf("  localtime_sha256: %s\n", emptyDash(p.LocaltimeSHA256)))
			b.WriteString(fmt.Sprintf("  zoneinfo_path: %s\n", emptyDash(p.ZoneinfoPath)))
			b.WriteString(fmt.Sprintf("  zoneinfo_sha256: %s\n", emptyDash(p.ZoneinfoSHA256)))
			b.WriteString(fmt.Sprintf("  now_iso: %s\n", emptyDash(p.NowISO)))
			b.WriteString(fmt.Sprintf("  now_epoch: %s\n", epochString(p.NowEpoch)))
			if p.IncompatibleProbe {
				b.WriteString(fmt.Sprintf("  warning: incompatible probe version %d\n", p.ProbeVersion))
			}
			if len(p.Warnings) > 0 {
				b.WriteString(fmt.Sprintf("  warnings: %s\n", strings.Join(p.Warnings, ", ")))
			}
		}
		if idx != len(probes)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func (f *Formatter) RenderJSON(probes []HostProbe, summary ComparisonSummary) string {
	payload := JSONReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary:     summary,
		Hosts:       probes,
	}
	encoded, _ := json.MarshalIndent(payload, "", "  ")
	return string(encoded)
}

type stringListFlag []string

func (s *stringListFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringListFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type Config struct {
	Hosts         []string
	HostsFile     string
	SSHUser       string
	SSHPort       int
	SSHOptions    []string
	Timeout       int
	Workers       int
	JSON          bool
	NoColor       bool
	SkewThreshold int64
	ShowCommands  bool
	LocalAliases  []string
	Strict        bool
	GlobalTimeout int
	Retries       int
}

func parseArgs() Config {
	var sshOptions stringListFlag
	var localAliases stringListFlag
	var hostsFile string
	var sshUser string
	var sshPort int
	var timeout int
	var workers int
	var jsonOutput bool
	var noColor bool
	var skewThreshold int64
	var showCommands bool
	var strict bool
	var globalTimeout int
	var retries int

	flag.StringVar(&hostsFile, "hosts-file", "", "")
	flag.StringVar(&sshUser, "ssh-user", "", "")
	flag.IntVar(&sshPort, "ssh-port", 22, "")
	flag.Var(&sshOptions, "ssh-option", "")
	flag.IntVar(&timeout, "timeout", 5, "")
	flag.IntVar(&workers, "workers", 8, "")
	flag.BoolVar(&jsonOutput, "json", false, "")
	flag.BoolVar(&noColor, "no-color", false, "")
	flag.Int64Var(&skewThreshold, "skew-threshold", 3, "")
	flag.BoolVar(&showCommands, "show-commands", false, "")
	flag.Var(&localAliases, "local-alias", "")
	flag.BoolVar(&strict, "strict", false, "")
	flag.IntVar(&globalTimeout, "global-timeout", 300, "")
	flag.IntVar(&retries, "retries", 0, "")
	flag.Parse()

	return Config{
		Hosts:         flag.Args(),
		HostsFile:     hostsFile,
		SSHUser:       sshUser,
		SSHPort:       sshPort,
		SSHOptions:    sshOptions,
		Timeout:       timeout,
		Workers:       workers,
		JSON:          jsonOutput,
		NoColor:       noColor,
		SkewThreshold: skewThreshold,
		ShowCommands:  showCommands,
		LocalAliases:  localAliases,
		Strict:        strict,
		GlobalTimeout: globalTimeout,
		Retries:       retries,
	}
}

func main() {
	cfg := parseArgs()

	targets, err := collectTargets(cfg.Hosts, cfg.HostsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if cfg.Workers <= 0 {
		fmt.Fprintln(os.Stderr, "workers must be positive")
		os.Exit(1)
	}

	executor := &RemoteExecutor{
		SSHUser:        cfg.SSHUser,
		SSHPort:        cfg.SSHPort,
		SSHOptions:     cfg.SSHOptions,
		ConnectTimeout: cfg.Timeout,
	}

	inspector := &HostInspector{Executor: executor}
	comparator := &Comparator{SkewThresholdSeconds: cfg.SkewThreshold}
	formatter := &Formatter{UseColor: !cfg.NoColor && !cfg.JSON, Width: 120}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.GlobalTimeout)*time.Second)
	defer cancel()

	probes := inspectTargets(ctx, targets, cfg.Workers, cfg.Retries, inspector, cfg.LocalAliases)

	sort.SliceStable(probes, func(i, j int) bool {
		return indexOf(targets, probes[i].Target) < indexOf(targets, probes[j].Target)
	})

	summary := comparator.Compare(probes)

	if cfg.ShowCommands && !cfg.JSON {
		printCommandLogs(probes)
	}

	if cfg.JSON {
		fmt.Println(formatter.RenderJSON(probes, summary))
	} else {
		fmt.Print(formatter.RenderTable(probes, summary))
	}

	os.Exit(computeExitCode(summary, probes, cfg.Strict))
}

func inspectTargets(ctx context.Context, targets []string, workers int, retries int, inspector *HostInspector, localAliases []string) []HostProbe {
	type item struct {
		Index int
		Host  string
	}

	jobs := make(chan item)
	results := make(chan HostProbe, len(targets))
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				var probe HostProbe
				for attempt := 0; attempt <= retries; attempt++ {
					probe = inspector.Inspect(ctx, job.Host, localAliases)
					if probe.Reachable {
						break
					}
					if attempt < retries {
						time.Sleep(time.Duration(attempt+1) * time.Second)
					}
				}
				results <- probe
			}
		}()
	}

	go func() {
		for idx, host := range targets {
			select {
			case jobs <- item{Index: idx, Host: host}:
			case <-ctx.Done():
				break
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var probes []HostProbe
	for probe := range results {
		probes = append(probes, probe)
	}
	return probes
}

func collectTargets(hosts []string, hostsFile string) ([]string, error) {
	targets := append([]string{}, hosts...)
	if hostsFile != "" {
		fromFile, err := readHostsFromFile(hostsFile)
		if err != nil {
			return nil, err
		}
		targets = append(targets, fromFile...)
	}
	targets = uniqueStrings(targets)
	if len(targets) == 0 {
		targets = []string{"localhost"}
	}
	return targets, nil
}

func readHostsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hosts []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, line)
	}
	return hosts, scanner.Err()
}

func printCommandLogs(probes []HostProbe) {
	fmt.Println("Command Execution")
	fmt.Println(strings.Repeat("-", 120))
	for _, probe := range probes {
		name := displayName(probe)
		for _, entry := range probe.CommandLog {
			cmdDisplay := entry.Command
			if len(cmdDisplay) > 200 {
				cmdDisplay = cmdDisplay[:200]
			}
			fmt.Printf("host=%s rc=%d duration=%.3fs command=%q\n", name, entry.ReturnCode, entry.DurationS, cmdDisplay)
			if strings.TrimSpace(entry.Stderr) != "" {
				fmt.Printf("stderr=%s\n", strings.TrimSpace(entry.Stderr))
			}
		}
	}
	fmt.Println()
}

func computeExitCode(summary ComparisonSummary, probes []HostProbe, strict bool) int {
	if strict {
		for _, p := range probes {
			if !p.Reachable {
				return 2
			}
		}
		if !(summary.TimezoneConsistent &&
			summary.LocaltimeTargetConsistent &&
			summary.LocaltimeHashConsistent &&
			summary.ZoneinfoHashConsistent &&
			summary.NTPConsistent &&
			summary.SynchronizedConsistent &&
			summary.UTCOffsetConsistent &&
			summary.ClockSkewWithinThreshold) {
			return 3
		}
	}
	return 0
}

func parseKeyValueOutput(output string) map[string]string {
	data := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		data[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return data
}

func parseTriBool(value string) *bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		v := true
		return &v
	case "false":
		v := false
		return &v
	default:
		return nil
	}
}

func triBoolString(v *bool) string {
	if v == nil {
		return "unknown"
	}
	if *v {
		return "true"
	}
	return "false"
}

func cleanText(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(value, "\r", ""))
}

func isLocalTarget(target string, localAliases []string) bool {
	lowered := strings.ToLower(strings.TrimSpace(target))
	if lowered == "localhost" || lowered == "127.0.0.1" || lowered == "::1" {
		return true
	}
	if host, err := os.Hostname(); err == nil && strings.EqualFold(lowered, host) {
		return true
	}
	if fqdn, err := currentFQDN(); err == nil && strings.EqualFold(lowered, fqdn) {
		return true
	}
	for _, alias := range localAliases {
		if strings.EqualFold(lowered, alias) {
			return true
		}
	}
	return false
}

func currentFQDN() (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", err
	}
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return host, nil
	}
	names, err := net.LookupAddr(addrs[0].String())
	if err != nil || len(names) == 0 {
		return host, nil
	}
	return strings.TrimSuffix(names[0], "."), nil
}

func displayName(p HostProbe) string {
	if p.Hostname != "" {
		return p.Hostname
	}
	return p.Host
}

func hostNames(probes []HostProbe) []string {
	names := make([]string, 0, len(probes))
	for _, p := range probes {
		names = append(names, displayName(p))
	}
	return names
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	var result []string
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func baseOrFull(value string) string {
	if value == "" {
		return "-"
	}
	base := filepath.Base(value)
	if base != "" && base != "localtime" {
		return base
	}
	return value
}

func truncateHash(value string) string {
	if value == "" {
		return "-"
	}
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

func epochString(v *int64) string {
	if v == nil {
		return "-"
	}
	return strconv.FormatInt(*v, 10)
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func indexOf(values []string, target string) int {
	for i, v := range values {
		if v == target {
			return i
		}
	}
	return len(values)
}
