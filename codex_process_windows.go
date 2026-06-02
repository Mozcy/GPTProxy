//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v4/process"
)

const codexProcessAncestorScanDepth = 12

type codexProcessSnapshot struct {
	pid         int32
	ppid        int32
	name        string
	commandLine string
}

type codexProcessEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriorityClass   int32
	Flags           uint32
	ExeFile         [260]uint16
}

func scanCodexProcessesByName(processName string) ([]CodexProcessInfo, error) {
	start := time.Now()
	snapshots, err := scanCodexProcessSnapshots()
	if err != nil {
		return nil, err
	}
	snapshotElapsed := time.Since(start)

	procMap := make(map[int32]*process.Process)
	commandStart := time.Now()
	enrichCodexAppServerSnapshotCommandLines(snapshots, procMap, processName)
	commandElapsed := time.Since(commandStart)

	matchStart := time.Now()
	primaryPIDs := preferredCodexAppServerProcessIDs(snapshots, processName)
	matchElapsed := time.Since(matchStart)
	fileInfoCache := make(map[string]CodexProcessInfo, len(primaryPIDs))

	detailStart := time.Now()
	rows := make([]CodexProcessInfo, 0, len(primaryPIDs))
	for _, pid := range primaryPIDs {
		p, err := ensureCodexProcess(procMap, pid)
		if err != nil || p == nil {
			continue
		}
		info := collectCodexProcessListInfo(p, snapshots[pid].name, procMap, snapshots, fileInfoCache)
		rows = append(rows, info)
	}
	detailElapsed := time.Since(detailStart)

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].ProcessID < rows[j].ProcessID
	})
	appLogger.Info(
		"Codex 进程扫描阶段耗时",
		"snapshot", snapshotElapsed.String(),
		"command", commandElapsed.String(),
		"match", matchElapsed.String(),
		"detail", detailElapsed.String(),
		"count", len(rows),
	)
	return rows, nil
}

func scanCodexProcessIDsByName(processName string) ([]int32, error) {
	snapshots, err := scanCodexProcessSnapshots()
	if err != nil {
		return nil, err
	}

	enrichCodexAppServerSnapshotCommandLines(snapshots, make(map[int32]*process.Process), processName)
	pids := preferredCodexAppServerProcessIDs(snapshots, processName)
	return normalizeProcessIDs(pids), nil
}

func scanCodexProcessSnapshots() (map[int32]codexProcessSnapshot, error) {
	snapshotHandle, _, callErr := codexProcessCreateToolhelp32Snapshot.Call(codexProcessTH32CSSnapProcess, 0)
	if syscall.Handle(snapshotHandle) == ^syscall.Handle(0) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) 失败: %w", codexProcessSyscallError(callErr))
	}
	defer codexProcessCloseHandle.Call(snapshotHandle)

	var entry codexProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ok, _, callErr := codexProcessProcess32FirstW.Call(snapshotHandle, uintptr(unsafe.Pointer(&entry)))
	if ok == 0 {
		return nil, fmt.Errorf("Process32FirstW 失败: %w", codexProcessSyscallError(callErr))
	}

	snapshots := make(map[int32]codexProcessSnapshot)
	for {
		pid := int32(entry.ProcessID)
		if pid > 0 {
			snapshots[pid] = codexProcessSnapshot{
				pid:  pid,
				ppid: int32(entry.ParentProcessID),
				name: syscall.UTF16ToString(entry.ExeFile[:]),
			}
		}

		ok, _, callErr = codexProcessProcess32NextW.Call(snapshotHandle, uintptr(unsafe.Pointer(&entry)))
		if ok == 0 {
			break
		}
	}
	return snapshots, nil
}

func collectCodexProcessSnapshots(procs []*process.Process, processName string) map[int32]codexProcessSnapshot {
	snapshots := make(map[int32]codexProcessSnapshot, len(procs))
	for _, p := range procs {
		if p == nil || p.Pid <= 0 {
			continue
		}
		name := getProcessString(p.Name)
		snapshots[p.Pid] = codexProcessSnapshot{
			pid:  p.Pid,
			ppid: getProcessInt32(p.Ppid),
			name: name,
		}
	}
	return snapshots
}

func procMapFromProcesses(procs []*process.Process) map[int32]*process.Process {
	procMap := make(map[int32]*process.Process, len(procs))
	for _, p := range procs {
		if p != nil && p.Pid > 0 {
			procMap[p.Pid] = p
		}
	}
	return procMap
}

func ensureCodexProcess(procMap map[int32]*process.Process, pid int32) (*process.Process, error) {
	if procMap == nil {
		procMap = make(map[int32]*process.Process)
	}
	if proc := procMap[pid]; proc != nil {
		return proc, nil
	}
	proc, err := process.NewProcess(pid)
	if err != nil {
		return nil, err
	}
	procMap[pid] = proc
	return proc, nil
}

func enrichCodexAppServerSnapshotCommandLines(snapshots map[int32]codexProcessSnapshot, procMap map[int32]*process.Process, processName string) {
	preferredCandidates := collectCodexLauncherDescendantPIDs(snapshots)
	for pid := range preferredCandidates {
		enrichCodexSnapshotCommandLine(snapshots, procMap, pid, processName)
	}
	if len(launcherSubtreeCodexAppServerProcessIDs(snapshots, processName)) > 0 {
		return
	}
	for pid, snapshot := range snapshots {
		if strings.EqualFold(snapshot.name, processName) {
			enrichCodexSnapshotCommandLine(snapshots, procMap, pid, processName)
		}
	}
}

func enrichCodexSnapshotCommandLine(snapshots map[int32]codexProcessSnapshot, procMap map[int32]*process.Process, pid int32, processName string) {
	snapshot, ok := snapshots[pid]
	if !ok || !strings.EqualFold(snapshot.name, processName) || snapshot.commandLine != "" {
		return
	}
	proc := procMap[pid]
	if proc == nil {
		var err error
		proc, err = ensureCodexProcess(procMap, pid)
		if err != nil || proc == nil {
			return
		}
	}
	snapshot.commandLine = getProcessString(proc.Cmdline)
	snapshots[pid] = snapshot
}

func isCodexAppServerProcess(p *process.Process) bool {
	if p == nil {
		return false
	}
	return isCodexAppServerCommandLine(getProcessString(p.Cmdline))
}

func primaryCodexAppServerProcessIDs(snapshots map[int32]codexProcessSnapshot, processName string) []int32 {
	pids := make([]int32, 0)
	for _, snapshot := range snapshots {
		if !isCodexAppServerSnapshot(snapshot, processName) {
			continue
		}
		if hasCodexAppServerAncestor(snapshot, snapshots, processName) {
			continue
		}
		pids = append(pids, snapshot.pid)
	}
	return normalizeProcessIDs(pids)
}

func preferredCodexAppServerProcessIDs(snapshots map[int32]codexProcessSnapshot, processName string) []int32 {
	if pids := launcherSubtreeCodexAppServerProcessIDs(snapshots, processName); len(pids) > 0 {
		return pids
	}
	return primaryCodexAppServerProcessIDs(snapshots, processName)
}

func launcherSubtreeCodexAppServerProcessIDs(snapshots map[int32]codexProcessSnapshot, processName string) []int32 {
	descendantPIDs := collectCodexLauncherDescendantPIDs(snapshots)
	if len(descendantPIDs) == 0 {
		return nil
	}

	pids := make([]int32, 0)
	for pid := range descendantPIDs {
		snapshot, ok := snapshots[pid]
		if !ok || !isCodexAppServerSnapshot(snapshot, processName) {
			continue
		}
		if hasCodexAppServerAncestor(snapshot, snapshots, processName) {
			continue
		}
		pids = append(pids, pid)
	}
	return normalizeProcessIDs(pids)
}

func collectCodexLauncherDescendantPIDs(snapshots map[int32]codexProcessSnapshot) map[int32]struct{} {
	children := make(map[int32][]int32, len(snapshots))
	roots := make([]int32, 0)
	for _, snapshot := range snapshots {
		if snapshot.ppid > 0 {
			children[snapshot.ppid] = append(children[snapshot.ppid], snapshot.pid)
		}
		if isCodexProcessLauncherSnapshot(snapshot) {
			roots = append(roots, snapshot.pid)
		}
	}
	if len(roots) == 0 {
		return nil
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i] < roots[j]
	})
	for _, pids := range children {
		sort.Slice(pids, func(i, j int) bool {
			return pids[i] < pids[j]
		})
	}

	descendants := make(map[int32]struct{})
	seen := make(map[int32]struct{}, len(roots))
	queue := append([]int32(nil), roots...)
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		for _, childPID := range children[pid] {
			descendants[childPID] = struct{}{}
			queue = append(queue, childPID)
		}
	}
	return descendants
}

func isCodexProcessLauncherSnapshot(snapshot codexProcessSnapshot) bool {
	_, ok := matchCodexProcessLauncher(snapshot.name, "")
	return ok
}

func isCodexAppServerSnapshot(snapshot codexProcessSnapshot, processName string) bool {
	return strings.EqualFold(snapshot.name, processName) && isCodexAppServerCommandLine(snapshot.commandLine)
}

func hasCodexAppServerAncestor(snapshot codexProcessSnapshot, snapshots map[int32]codexProcessSnapshot, processName string) bool {
	current := snapshot
	seen := map[int32]struct{}{
		current.pid: {},
	}
	for depth := 0; depth < codexProcessAncestorScanDepth; depth++ {
		if current.ppid <= 0 {
			return false
		}
		if _, ok := seen[current.ppid]; ok {
			return false
		}
		parent, ok := snapshots[current.ppid]
		if !ok {
			return false
		}
		if isCodexAppServerSnapshot(parent, processName) {
			return true
		}
		seen[parent.pid] = struct{}{}
		current = parent
	}
	return false
}

func isCodexAppServerCommandLine(commandLine string) bool {
	for _, field := range strings.FieldsFunc(commandLine, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '"' || r == '\''
	}) {
		normalized := strings.ToLower(strings.TrimSpace(field))
		normalized = strings.TrimLeft(normalized, "-/")
		if normalized == "app-server" || strings.HasPrefix(normalized, "app-server=") {
			return true
		}
	}
	return false
}

func collectCodexProcessListInfo(p *process.Process, name string, procMap map[int32]*process.Process, snapshots map[int32]codexProcessSnapshot, fileInfoCache map[string]CodexProcessInfo) CodexProcessInfo {
	info := CodexProcessInfo{
		ProcessID: p.Pid,
		Name:      name,
	}

	info.CommandLine = getProcessString(p.Cmdline)
	info.ExecutablePath = getProcessString(p.Exe)
	info.ParentProcessID = getProcessInt32(p.Ppid)

	if parent := procMap[info.ParentProcessID]; parent != nil {
		info.ParentName = getProcessString(parent.Name)
		info.ParentCommandLine = getProcessString(parent.Cmdline)
	}
	enrichCodexProcessLauncher(&info, p, procMap)

	if info.ExecutablePath != "" {
		enrichCodexProcessListFileInfoCached(&info, fileInfoCache)
	}

	return info
}

func collectCodexProcessInfo(p *process.Process, name string, procMap map[int32]*process.Process, snapshots map[int32]codexProcessSnapshot, fileInfoCache map[string]CodexProcessInfo) CodexProcessInfo {
	info := collectCodexProcessListInfo(p, name, procMap, snapshots, fileInfoCache)

	info.Owner = getProcessString(p.Username)
	info.Status = strings.Join(getProcessStringSlice(p.Status), ", ")
	info.ThreadCount = getProcessInt32(p.NumThreads)
	info.HandleCount = uint32(getProcessInt32(p.NumFDs))
	info.IsRunning = getProcessBoolPtr(p.IsRunning)
	info.Foreground = getProcessBoolPtr(p.Foreground)

	if ms, err := p.CreateTime(); err == nil && ms > 0 {
		info.CreationDate = time.Unix(0, ms*int64(time.Millisecond)).Local().Format("2006-01-02 15:04:05")
	}

	if mem, err := p.MemoryInfo(); err == nil && mem != nil {
		info.WorkingSetMB = processMBPtr(mem.RSS)
		info.VirtualSizeMB = processMBPtr(mem.VMS)
		info.PeakWorkingSetMB = processMBPtr(mem.HWM)
		info.DataMemoryMB = processMBPtr(mem.Data)
	}

	if ioStat, err := p.IOCounters(); err == nil && ioStat != nil {
		info.ReadCount = ioStat.ReadCount
		info.WriteCount = ioStat.WriteCount
		info.ReadBytesMB = processMBPtr(ioStat.ReadBytes)
		info.WriteBytesMB = processMBPtr(ioStat.WriteBytes)
	}

	if cpuPercent, err := p.CPUPercent(); err == nil {
		info.CPUPercent = processRoundPtr(cpuPercent)
	}

	if times, err := p.Times(); err == nil && times != nil {
		info.TotalCPUSeconds = processRoundPtr(times.User + times.System)
		info.UserModeTimeSec = processRoundPtr(times.User)
		info.KernelModeTimeSec = processRoundPtr(times.System)
	}

	if info.ExecutablePath != "" {
		enrichCodexProcessFileInfoCached(&info, fileInfoCache)
	}

	return info
}

type codexProcessAncestor struct {
	pid            int32
	name           string
	executablePath string
	commandLine    string
}

type codexProcessLauncherMatch struct {
	displayName string
	confidence  string
}

var codexProcessLauncherNames = map[string]codexProcessLauncherMatch{
	"idea.exe":            {displayName: "IntelliJ IDEA", confidence: "high"},
	"idea64.exe":          {displayName: "IntelliJ IDEA", confidence: "high"},
	"goland.exe":          {displayName: "GoLand", confidence: "high"},
	"goland64.exe":        {displayName: "GoLand", confidence: "high"},
	"code.exe":            {displayName: "VS Code", confidence: "high"},
	"code - insiders.exe": {displayName: "VS Code Insiders", confidence: "high"},
	"codium.exe":          {displayName: "VSCodium", confidence: "high"},
	"vscodium.exe":        {displayName: "VSCodium", confidence: "high"},
	"cursor.exe":          {displayName: "Cursor", confidence: "high"},
	"windsurf.exe":        {displayName: "Windsurf", confidence: "high"},
	"trae.exe":            {displayName: "Trae", confidence: "high"},
	"pycharm.exe":         {displayName: "PyCharm", confidence: "high"},
	"pycharm64.exe":       {displayName: "PyCharm", confidence: "high"},
	"webstorm.exe":        {displayName: "WebStorm", confidence: "high"},
	"webstorm64.exe":      {displayName: "WebStorm", confidence: "high"},
	"rider.exe":           {displayName: "Rider", confidence: "high"},
	"rider64.exe":         {displayName: "Rider", confidence: "high"},
	"clion.exe":           {displayName: "CLion", confidence: "high"},
	"clion64.exe":         {displayName: "CLion", confidence: "high"},
	"phpstorm.exe":        {displayName: "PhpStorm", confidence: "high"},
	"phpstorm64.exe":      {displayName: "PhpStorm", confidence: "high"},
	"rubymine.exe":        {displayName: "RubyMine", confidence: "high"},
	"rubymine64.exe":      {displayName: "RubyMine", confidence: "high"},
}

var codexProcessFallbackLauncherNames = map[string]codexProcessLauncherMatch{
	"windowsterminal.exe":      {displayName: "Windows Terminal", confidence: "medium"},
	"openterminal.exe":         {displayName: "Windows Terminal", confidence: "medium"},
	"openconsole.exe":          {displayName: "Console Host", confidence: "medium"},
	"conhost.exe":              {displayName: "Console Host", confidence: "medium"},
	"powershell.exe":           {displayName: "PowerShell", confidence: "medium"},
	"pwsh.exe":                 {displayName: "PowerShell", confidence: "medium"},
	"cmd.exe":                  {displayName: "Command Prompt", confidence: "medium"},
	"explorer.exe":             {displayName: "Windows Shell", confidence: "medium"},
	"applicationframehost.exe": {displayName: "Windows App Host", confidence: "medium"},
}

func enrichCodexProcessLauncher(info *CodexProcessInfo, p *process.Process, procMap map[int32]*process.Process) {
	ancestors := collectCodexProcessAncestors(p, procMap, codexProcessAncestorScanDepth)
	info.ProcessTree = formatCodexProcessTree(info.ProcessID, info.Name, ancestors)

	for _, ancestor := range ancestors {
		match, ok := matchCodexProcessLauncher(ancestor.name, ancestor.executablePath)
		if !ok {
			continue
		}
		info.LauncherName = match.displayName
		info.LauncherPID = ancestor.pid
		info.LauncherPath = ancestor.executablePath
		info.LauncherCommandLine = ancestor.commandLine
		info.LauncherConfidence = match.confidence
		return
	}
	if match, launcher, evidence, ok := matchCodexProcessLauncherFromEnv(p); ok {
		info.LauncherName = match.displayName
		info.LauncherPID = launcher.pid
		info.LauncherPath = launcher.executablePath
		info.LauncherCommandLine = firstNonEmpty(launcher.commandLine, evidence)
		info.LauncherConfidence = match.confidence
		return
	}
	if match, launcher, ok := matchCodexProcessFallbackLauncher(info, ancestors); ok {
		info.LauncherName = match.displayName
		info.LauncherPID = launcher.pid
		info.LauncherPath = launcher.executablePath
		info.LauncherCommandLine = launcher.commandLine
		info.LauncherConfidence = match.confidence
		return
	}
	info.LauncherConfidence = "low"
}

func collectCodexProcessAncestors(p *process.Process, procMap map[int32]*process.Process, maxDepth int) []codexProcessAncestor {
	ancestors := make([]codexProcessAncestor, 0, maxDepth)
	seen := map[int32]struct{}{
		p.Pid: {},
	}
	current := p
	for depth := 0; depth < maxDepth; depth++ {
		ppid := getProcessInt32(current.Ppid)
		if ppid <= 0 {
			break
		}
		if _, ok := seen[ppid]; ok {
			break
		}
		seen[ppid] = struct{}{}

		parent := procMap[ppid]
		if parent == nil {
			var err error
			parent, err = process.NewProcess(ppid)
			if err != nil || parent == nil {
				break
			}
		}

		ancestors = append(ancestors, codexProcessAncestor{
			pid:            parent.Pid,
			name:           getProcessString(parent.Name),
			executablePath: getProcessString(parent.Exe),
			commandLine:    getProcessString(parent.Cmdline),
		})
		current = parent
	}
	return ancestors
}

func matchCodexProcessLauncher(name string, path string) (codexProcessLauncherMatch, bool) {
	candidates := []string{name}
	if path != "" {
		parts := strings.FieldsFunc(path, func(r rune) bool {
			return r == '\\' || r == '/'
		})
		if len(parts) > 0 {
			candidates = append(candidates, parts[len(parts)-1])
		}
	}
	for _, candidate := range candidates {
		if match, ok := codexProcessLauncherNames[strings.ToLower(strings.TrimSpace(candidate))]; ok {
			return match, true
		}
	}
	return codexProcessLauncherMatch{}, false
}

func matchCodexProcessFallbackLauncher(info *CodexProcessInfo, ancestors []codexProcessAncestor) (codexProcessLauncherMatch, codexProcessAncestor, bool) {
	if isCodexProcessMicrosoftStorePath(info.ExecutablePath) || isCodexProcessMicrosoftStorePath(info.CommandLine) {
		return codexProcessLauncherMatch{displayName: "Microsoft Store Codex", confidence: "medium"}, codexProcessAncestor{
			pid:            info.ProcessID,
			name:           info.Name,
			executablePath: info.ExecutablePath,
			commandLine:    firstNonEmpty(info.CommandLine, info.ExecutablePath),
		}, true
	}
	for _, ancestor := range ancestors {
		normalized := strings.ToLower(strings.TrimSpace(ancestor.name))
		if match, ok := codexProcessFallbackLauncherNames[normalized]; ok {
			return match, ancestor, true
		}
		if isCodexProcessMicrosoftStorePath(ancestor.executablePath) || isCodexProcessMicrosoftStorePath(ancestor.commandLine) {
			return codexProcessLauncherMatch{displayName: "Microsoft Store / WindowsApps", confidence: "medium"}, ancestor, true
		}
	}
	return codexProcessLauncherMatch{}, codexProcessAncestor{}, false
}

func isCodexProcessMicrosoftStorePath(value string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(value, "/", "\\"))
	return strings.Contains(normalized, "\\windowsapps\\") ||
		strings.Contains(normalized, "\\microsoft\\windowsapps\\") ||
		strings.Contains(normalized, "microsoft.windowsapps")
}

func matchCodexProcessLauncherFromEnv(p *process.Process) (codexProcessLauncherMatch, codexProcessAncestor, string, bool) {
	env, err := p.Environ()
	if err != nil || len(env) == 0 {
		return codexProcessLauncherMatch{}, codexProcessAncestor{}, "", false
	}

	envMap := make(map[string]string, len(env))
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		envMap[strings.ToUpper(strings.TrimSpace(key))] = value
	}

	if key, ok := findEnvKeyWithPrefix(envMap, "CURSOR_"); ok {
		return codexProcessLauncherMatch{displayName: "Cursor", confidence: "medium"}, codexProcessAncestor{}, "环境变量: " + key, true
	}
	if strings.EqualFold(envMap["TERM_PROGRAM"], "vscode") {
		return codexProcessLauncherMatch{displayName: "VS Code", confidence: "medium"}, codexProcessAncestor{}, "环境变量: TERM_PROGRAM=vscode", true
	}
	if key, ok := findEnvKeyWithPrefix(envMap, "VSCODE_"); ok {
		return codexProcessLauncherMatch{displayName: "VS Code", confidence: "medium"}, codexProcessAncestor{}, "环境变量: " + key, true
	}
	if strings.Contains(strings.ToLower(envMap["TERMINAL_EMULATOR"]), "jetbrains") {
		return codexProcessLauncherMatch{displayName: "JetBrains Terminal", confidence: "medium"}, codexProcessAncestor{}, "环境变量: TERMINAL_EMULATOR=" + envMap["TERMINAL_EMULATOR"], true
	}
	if key, ok := findEnvKeyWithPrefix(envMap, "__INTELLIJ_"); ok {
		return codexProcessLauncherMatch{displayName: "JetBrains Terminal", confidence: "medium"}, codexProcessAncestor{}, "环境变量: " + key, true
	}
	if _, ok := envMap["WT_SESSION"]; ok {
		return codexProcessLauncherMatch{displayName: "Windows Terminal", confidence: "medium"}, codexProcessAncestor{}, "环境变量: WT_SESSION", true
	}
	return codexProcessLauncherMatch{}, codexProcessAncestor{}, "", false
}

func findEnvKeyWithPrefix(envMap map[string]string, prefix string) (string, bool) {
	keys := make([]string, 0, len(envMap))
	for key := range envMap {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return "", false
	}
	sort.Strings(keys)
	return keys[0], true
}

func formatCodexProcessTree(pid int32, name string, ancestors []codexProcessAncestor) string {
	parts := []string{formatCodexProcessNode(name, pid)}
	for _, ancestor := range ancestors {
		parts = append(parts, formatCodexProcessNode(ancestor.name, ancestor.pid))
	}
	return strings.Join(parts, " <- ")
}

func formatCodexProcessNode(name string, pid int32) string {
	if name == "" {
		name = "unknown"
	}
	return fmt.Sprintf("%s(%d)", name, pid)
}

func codexProcessFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(hash.Sum(nil))), nil
}

func enrichCodexProcessFileInfo(info *CodexProcessInfo) {
	if hash, err := codexProcessFileSHA256(info.ExecutablePath); err == nil {
		info.SHA256 = hash
	}

	if stat, err := os.Stat(info.ExecutablePath); err == nil {
		info.FileSizeMB = processMBPtr(uint64(stat.Size()))
		info.FileModified = stat.ModTime().Format("2006-01-02 15:04:05")
	}

	if created, ok := codexProcessFileCreationTime(info.ExecutablePath); ok {
		info.FileCreated = created.Format("2006-01-02 15:04:05")
	}

	version := readCodexProcessFileVersionInfo(info.ExecutablePath)
	info.FileProductName = version.ProductName
	info.FileProductVersion = version.ProductVersion
	info.FileVersion = version.FileVersion
	info.FileCompany = version.CompanyName
	info.FileDescription = version.FileDescription
}

func enrichCodexProcessFileInfoCached(info *CodexProcessInfo, cache map[string]CodexProcessInfo) {
	if cache == nil || info.ExecutablePath == "" {
		enrichCodexProcessFileInfo(info)
		return
	}
	if cached, ok := cache[info.ExecutablePath]; ok {
		copyCodexProcessFileInfo(info, cached)
		return
	}
	enrichCodexProcessFileInfo(info)
	cache[info.ExecutablePath] = *info
}

func copyCodexProcessFileInfo(info *CodexProcessInfo, source CodexProcessInfo) {
	info.FileSizeMB = source.FileSizeMB
	info.FileCreated = source.FileCreated
	info.FileModified = source.FileModified
	info.FileProductName = source.FileProductName
	info.FileProductVersion = source.FileProductVersion
	info.FileVersion = source.FileVersion
	info.FileCompany = source.FileCompany
	info.FileDescription = source.FileDescription
	info.SHA256 = source.SHA256
}

func enrichCodexProcessListFileInfoCached(info *CodexProcessInfo, cache map[string]CodexProcessInfo) {
	if cache == nil || info.ExecutablePath == "" {
		enrichCodexProcessListFileInfo(info)
		return
	}
	if cached, ok := cache[info.ExecutablePath]; ok {
		copyCodexProcessListFileInfo(info, cached)
		return
	}
	enrichCodexProcessListFileInfo(info)
	cache[info.ExecutablePath] = *info
}

func enrichCodexProcessListFileInfo(info *CodexProcessInfo) {
	version := readCodexProcessFileVersionInfo(info.ExecutablePath)
	info.FileVersion = version.FileVersion
}

func copyCodexProcessListFileInfo(info *CodexProcessInfo, source CodexProcessInfo) {
	info.FileVersion = source.FileVersion
}

func getProcessString(fn func() (string, error)) string {
	v, err := fn()
	if err != nil {
		return ""
	}
	return v
}

func getProcessStringSlice(fn func() ([]string, error)) []string {
	v, err := fn()
	if err != nil {
		return nil
	}
	return v
}

func getProcessInt32(fn func() (int32, error)) int32 {
	v, err := fn()
	if err != nil {
		return 0
	}
	return v
}

func getProcessBoolPtr(fn func() (bool, error)) *bool {
	v, err := fn()
	if err != nil {
		return nil
	}
	return &v
}

func processMBPtr(bytes uint64) *float64 {
	return processRoundPtr(float64(bytes) / 1024 / 1024)
}

func processRoundPtr(v float64) *float64 {
	rounded := float64(int64(v*1000+0.5)) / 1000
	return &rounded
}

var (
	codexProcessKernel32                 = syscall.NewLazyDLL("kernel32.dll")
	codexProcessVersionDLL               = syscall.NewLazyDLL("version.dll")
	codexProcessCloseHandle              = codexProcessKernel32.NewProc("CloseHandle")
	codexProcessCreateToolhelp32Snapshot = codexProcessKernel32.NewProc("CreateToolhelp32Snapshot")
	codexProcessCreateFileW              = codexProcessKernel32.NewProc("CreateFileW")
	codexProcessGetFileTime              = codexProcessKernel32.NewProc("GetFileTime")
	codexProcessProcess32FirstW          = codexProcessKernel32.NewProc("Process32FirstW")
	codexProcessProcess32NextW           = codexProcessKernel32.NewProc("Process32NextW")
	codexProcessGetFileVersionSizeW      = codexProcessVersionDLL.NewProc("GetFileVersionInfoSizeW")
	codexProcessGetFileVersionInfoW      = codexProcessVersionDLL.NewProc("GetFileVersionInfoW")
	codexProcessVerQueryValueW           = codexProcessVersionDLL.NewProc("VerQueryValueW")
)

const codexProcessTH32CSSnapProcess = 0x00000002

func codexProcessSyscallError(err error) error {
	if err == nil || errors.Is(err, syscall.Errno(0)) {
		return syscall.EINVAL
	}
	return err
}

func codexProcessFileCreationTime(path string) (time.Time, bool) {
	const (
		genericRead       = 0x80000000
		fileShareRead     = 0x00000001
		fileShareWrite    = 0x00000002
		fileShareDelete   = 0x00000004
		openExisting      = 3
		fileAttributeNorm = 0x00000080
	)

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return time.Time{}, false
	}

	handle, _, _ := codexProcessCreateFileW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		genericRead,
		fileShareRead|fileShareWrite|fileShareDelete,
		0,
		openExisting,
		fileAttributeNorm,
		0,
	)
	if handle == 0 || handle == ^uintptr(0) {
		return time.Time{}, false
	}
	defer codexProcessCloseHandle.Call(handle)

	var created syscall.Filetime
	ok, _, _ := codexProcessGetFileTime.Call(handle, uintptr(unsafe.Pointer(&created)), 0, 0)
	if ok == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, created.Nanoseconds()).Local(), true
}

type codexProcessVersionInfo struct {
	ProductName     string
	ProductVersion  string
	FileVersion     string
	CompanyName     string
	FileDescription string
}

type codexProcessFixedFileInfo struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

type codexProcessTranslation struct {
	Language uint16
	CodePage uint16
}

func readCodexProcessFileVersionInfo(path string) codexProcessVersionInfo {
	var info codexProcessVersionInfo

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return info
	}

	size, _, _ := codexProcessGetFileVersionSizeW.Call(uintptr(unsafe.Pointer(pathPtr)), 0)
	if size == 0 {
		return info
	}

	data := make([]byte, int(size))
	ok, _, _ := codexProcessGetFileVersionInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		size,
		uintptr(unsafe.Pointer(&data[0])),
	)
	if ok == 0 {
		return info
	}

	if fixed, ok := queryCodexProcessFixedFileInfo(data); ok {
		info.FileVersion = codexProcessVersionFromParts(fixed.FileVersionMS, fixed.FileVersionLS)
		info.ProductVersion = codexProcessVersionFromParts(fixed.ProductVersionMS, fixed.ProductVersionLS)
	}

	lang, codePage := queryCodexProcessTranslation(data)
	for _, key := range []struct {
		name string
		dest *string
	}{
		{"ProductName", &info.ProductName},
		{"ProductVersion", &info.ProductVersion},
		{"FileVersion", &info.FileVersion},
		{"CompanyName", &info.CompanyName},
		{"FileDescription", &info.FileDescription},
	} {
		if v := queryCodexProcessVersionString(data, lang, codePage, key.name); v != "" {
			*key.dest = v
		}
	}
	return info
}

func queryCodexProcessFixedFileInfo(data []byte) (*codexProcessFixedFileInfo, bool) {
	var ptr uintptr
	var size uint32
	subBlock, _ := syscall.UTF16PtrFromString(`\`)
	ok, _, _ := codexProcessVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(subBlock)),
		uintptr(unsafe.Pointer(&ptr)),
		uintptr(unsafe.Pointer(&size)),
	)
	if ok == 0 || ptr == 0 || size < uint32(unsafe.Sizeof(codexProcessFixedFileInfo{})) {
		return nil, false
	}
	return (*codexProcessFixedFileInfo)(unsafe.Pointer(ptr)), true
}

func queryCodexProcessTranslation(data []byte) (uint16, uint16) {
	var ptr uintptr
	var size uint32
	subBlock, _ := syscall.UTF16PtrFromString(`\VarFileInfo\Translation`)
	ok, _, _ := codexProcessVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(subBlock)),
		uintptr(unsafe.Pointer(&ptr)),
		uintptr(unsafe.Pointer(&size)),
	)
	if ok == 0 || ptr == 0 || size < uint32(unsafe.Sizeof(codexProcessTranslation{})) {
		return 0x0409, 0x04b0
	}
	t := (*codexProcessTranslation)(unsafe.Pointer(ptr))
	return t.Language, t.CodePage
}

func queryCodexProcessVersionString(data []byte, lang uint16, codePage uint16, name string) string {
	subBlock := fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, lang, codePage, name)
	subBlockPtr, err := syscall.UTF16PtrFromString(subBlock)
	if err != nil {
		return ""
	}

	var ptr uintptr
	var length uint32
	ok, _, _ := codexProcessVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(subBlockPtr)),
		uintptr(unsafe.Pointer(&ptr)),
		uintptr(unsafe.Pointer(&length)),
	)
	if ok == 0 || ptr == 0 || length == 0 {
		return ""
	}

	chars := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), length)
	return syscall.UTF16ToString(chars)
}

func codexProcessVersionFromParts(ms uint32, ls uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ms>>16, ms&0xffff, ls>>16, ls&0xffff)
}
