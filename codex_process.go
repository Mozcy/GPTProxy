package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// CodexProcessInfo 表示 Codex 进程扫描结果。
type CodexProcessInfo struct {
	ProcessID           int32    `json:"pid"`
	Name                string   `json:"name"`
	CommandLine         string   `json:"commandLine"`
	ExecutablePath      string   `json:"executablePath"`
	Owner               string   `json:"owner"`
	CreationDate        string   `json:"creationDate"`
	ParentProcessID     int32    `json:"parentPid"`
	ParentName          string   `json:"parentName"`
	ParentCommandLine   string   `json:"parentCommandLine"`
	LauncherName        string   `json:"launcherName"`
	LauncherPID         int32    `json:"launcherPid"`
	LauncherPath        string   `json:"launcherPath"`
	LauncherCommandLine string   `json:"launcherCommandLine"`
	LauncherConfidence  string   `json:"launcherConfidence"`
	AccountID           string   `json:"accountId"`
	Email               string   `json:"email"`
	ProcessTree         string   `json:"processTree"`
	ChildProcesses      string   `json:"childProcesses"`
	HelperProcesses     string   `json:"helperProcesses"`
	Status              string   `json:"status"`
	ThreadCount         int32    `json:"threadCount"`
	HandleCount         uint32   `json:"handleCount"`
	WorkingSetMB        *float64 `json:"workingSetMB"`
	VirtualSizeMB       *float64 `json:"virtualSizeMB"`
	PeakWorkingSetMB    *float64 `json:"peakWorkingSetMB"`
	SharedMemoryMB      *float64 `json:"sharedMemoryMB"`
	DataMemoryMB        *float64 `json:"dataMemoryMB"`
	ReadCount           uint64   `json:"readCount"`
	WriteCount          uint64   `json:"writeCount"`
	ReadBytesMB         *float64 `json:"readBytesMB"`
	WriteBytesMB        *float64 `json:"writeBytesMB"`
	CPUPercent          *float64 `json:"cpuPercent"`
	TotalCPUSeconds     *float64 `json:"totalCPUSeconds"`
	UserModeTimeSec     *float64 `json:"userModeTimeSec"`
	KernelModeTimeSec   *float64 `json:"kernelModeTimeSec"`
	IsRunning           *bool    `json:"isRunning"`
	Foreground          *bool    `json:"foreground"`
	FileSizeMB          *float64 `json:"fileSizeMB"`
	FileCreated         string   `json:"fileCreated"`
	FileModified        string   `json:"fileModified"`
	FileProductName     string   `json:"fileProductName"`
	FileProductVersion  string   `json:"fileProductVersion"`
	FileVersion         string   `json:"fileVersion"`
	FileCompany         string   `json:"fileCompany"`
	FileDescription     string   `json:"fileDescription"`
	SHA256              string   `json:"sha256"`
	TCPConnections      string   `json:"tcpConnections"`
}

// ScanCodexProcesses 扫描正在运行的 Codex app-server 进程。
func (a *App) ScanCodexProcesses() ([]CodexProcessInfo, error) {
	a.clearSelectedCodexProcessPIDs()

	start := time.Now()
	rows, err := scanCodexProcessesByName("codex.exe")
	if err != nil {
		appLogger.Error("扫描 Codex 进程失败", "error", err)
		return nil, err
	}
	scanElapsed := time.Since(start)
	a.enrichCodexProcessAccounts(rows)
	appLogger.Info("扫描 Codex 进程完成", "count", len(rows), "scan_elapsed", scanElapsed.String(), "total_elapsed", time.Since(start).String())
	return rows, nil
}

func (a *App) enrichCodexProcessAccounts(rows []CodexProcessInfo) {
	if a == nil || a.proxyStore == nil {
		return
	}

	var wg sync.WaitGroup
	for i := range rows {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			accountID, err := readCodexProcessMemoryAccountIDForInfo(rows[idx])
			if err != nil {
				appLogger.Warn("读取 Codex 进程 account_id 失败", "pid", rows[idx].ProcessID, "error", err)
				return
			}
			rows[idx].AccountID = accountID

			claims, err := readCodexProcessMemoryAccessTokenClaimsForInfo(rows[idx])
			if err != nil {
				appLogger.Warn("读取 Codex 进程 access_token 失败", "pid", rows[idx].ProcessID, "account_id", accountID, "error", err)
			} else {
				rows[idx].Email = tokenClaimsEmail(claims)
			}

			if accountID != "" && rows[idx].Email == "" {
				account, err := a.proxyStore.GetAccountByAccountID(accountID)
				if err != nil {
					appLogger.Warn("未匹配到 Codex 进程账号", "pid", rows[idx].ProcessID, "account_id", accountID, "error", err)
					return
				}
				rows[idx].Email = account.Email
			}
		}(i)
	}
	wg.Wait()
}

// SetSelectedCodexProcessPIDs 保存当前 Codex Process 表格勾选的 PID 集合。
func (a *App) SetSelectedCodexProcessPIDs(pids []int32) {
	a.processMu.Lock()
	defer a.processMu.Unlock()

	a.selectedPIDs = make(map[int32]struct{}, len(pids))
	for _, pid := range pids {
		if pid > 0 {
			a.selectedPIDs[pid] = struct{}{}
		}
	}
	appLogger.Info("Codex 进程选择状态已更新", "count", len(a.selectedPIDs))
}

// GetSelectedCodexProcessPIDs 返回当前内存中保存的 Codex Process 勾选 PID。
func (a *App) GetSelectedCodexProcessPIDs() []int32 {
	a.processMu.RLock()
	defer a.processMu.RUnlock()

	pids := make([]int32, 0, len(a.selectedPIDs))
	for pid := range a.selectedPIDs {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool {
		return pids[i] < pids[j]
	})
	return pids
}

// SetSelectedCodexProcessLauncherKeys 保存激活账号时自动注入的 Codex 启动来源。
func (a *App) SetSelectedCodexProcessLauncherKeys(keys []string) {
	a.processMu.Lock()
	defer a.processMu.Unlock()

	a.selectedLauncherKeys = make(map[string]struct{}, len(keys))
	for _, key := range keys {
		normalized := normalizeCodexProcessLauncherKey(key)
		if normalized != "" && isSupportedCodexProcessLauncherKey(normalized) {
			a.selectedLauncherKeys[normalized] = struct{}{}
		}
	}
	appLogger.Info("Codex 自动注入来源选择已更新", "count", len(a.selectedLauncherKeys), "keys", strings.Join(a.getSelectedCodexProcessLauncherKeysLocked(), ","))
}

// GetSelectedCodexProcessLauncherKeys 返回当前内存中保存的自动注入来源。
func (a *App) GetSelectedCodexProcessLauncherKeys() []string {
	a.processMu.RLock()
	defer a.processMu.RUnlock()

	return a.getSelectedCodexProcessLauncherKeysLocked()
}

func (a *App) getSelectedCodexProcessLauncherKeysLocked() []string {
	keys := make([]string, 0, len(a.selectedLauncherKeys))
	for key := range a.selectedLauncherKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// InjectActiveAccountToCodexProcess 将当前激活账号写入指定 Codex 进程内存。
func (a *App) InjectActiveAccountToCodexProcess(pid int32) error {
	if err := a.ensureProxyService(); err != nil {
		appLogger.Error("注入 Codex 进程失败: 服务未初始化", "error", err, "pid", pid)
		return err
	}
	if pid <= 0 {
		return errors.New("Codex 进程 PID 无效")
	}

	record, ok, err := a.proxyStore.GetActiveAccountRecord()
	if err != nil {
		appLogger.Error("注入 Codex 进程失败: 查询激活账号失败", "error", err, "pid", pid)
		return err
	}
	if !ok {
		return errors.New("未找到当前激活账号")
	}

	if err := patchCodexProcessMemory(pid, record); err != nil {
		appLogger.Error("注入 Codex 进程失败", "error", err, "pid", pid, "account_id", record.AccountID, "email", record.Email)
		return err
	}
	appLogger.Info("注入 Codex 进程成功", "pid", pid, "account_id", record.AccountID, "email", record.Email)
	return nil
}

func (a *App) patchSelectedCodexProcesses(record accountRecord) error {
	keys := a.GetSelectedCodexProcessLauncherKeys()
	if len(keys) == 0 {
		return nil
	}

	rows, err := scanCodexProcessesByName("codex.exe")
	if err != nil {
		return fmt.Errorf("扫描自动注入 Codex 进程失败: %w", err)
	}

	selected := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		selected[key] = struct{}{}
	}
	pids := make([]int32, 0, len(rows))
	for _, row := range rows {
		key := codexProcessLauncherKey(row.LauncherName)
		if key == "" {
			continue
		}
		if _, ok := selected[key]; ok {
			pids = append(pids, row.ProcessID)
		}
	}
	if len(pids) == 0 {
		appLogger.Info("Codex 自动注入未匹配到进程", "keys", strings.Join(keys, ","))
		return nil
	}
	return patchCodexProcesses(pids, record)
}

func patchCodexProcesses(pids []int32, record accountRecord) error {
	var errs []error
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		if err := patchCodexProcessMemory(pid, record); err != nil {
			errs = append(errs, fmt.Errorf("PID %d: %w", pid, err))
			continue
		}
		appLogger.Info("Codex 进程内存替换成功", "pid", pid, "account_id", record.AccountID, "email", record.Email)
	}
	if len(errs) > 0 {
		return fmt.Errorf("Codex 进程内存替换失败: %w", errors.Join(errs...))
	}
	return nil
}

func (a *App) clearSelectedCodexProcessPIDs() {
	a.processMu.Lock()
	defer a.processMu.Unlock()

	a.selectedPIDs = make(map[int32]struct{})
}

func normalizeCodexProcessLauncherKey(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}

func isSupportedCodexProcessLauncherKey(key string) bool {
	switch key {
	case "vscode", "desktop",
		"jetbrains:intellij_idea",
		"jetbrains:pycharm",
		"jetbrains:goland",
		"jetbrains:webstorm",
		"jetbrains:rider",
		"jetbrains:clion",
		"jetbrains:phpstorm",
		"jetbrains:rubymine",
		"jetbrains:terminal":
		return true
	default:
		return false
	}
}

func codexProcessLauncherKey(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "vs code", "vs code insiders", "vscodium":
		return "vscode"
	case "microsoft store codex", "microsoft store / windowsapps", "codex desktop":
		return "desktop"
	case "intellij idea":
		return "jetbrains:intellij_idea"
	case "pycharm":
		return "jetbrains:pycharm"
	case "goland":
		return "jetbrains:goland"
	case "webstorm":
		return "jetbrains:webstorm"
	case "rider":
		return "jetbrains:rider"
	case "clion":
		return "jetbrains:clion"
	case "phpstorm":
		return "jetbrains:phpstorm"
	case "rubymine":
		return "jetbrains:rubymine"
	case "jetbrains terminal":
		return "jetbrains:terminal"
	default:
		return ""
	}
}
