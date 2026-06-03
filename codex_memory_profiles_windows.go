//go:build windows

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/shirou/gopsutil/v4/process"
)

type codexMemoryLauncherKind string

const (
	codexMemoryLauncherVSCode    codexMemoryLauncherKind = "vscode"
	codexMemoryLauncherJetBrains codexMemoryLauncherKind = "jetbrains"
	codexMemoryLauncherDesktop   codexMemoryLauncherKind = "desktop"
)

type codexMemoryPatchField struct {
	name       string
	baseOffset uintptr
	offsets    []uintptr
	length     int
}

type codexMemoryPatchProfile struct {
	launcher codexMemoryLauncherKind
	version  string
	sha256   string
	fields   []codexMemoryPatchField
}

type codexMemoryPatchContext struct {
	launcherName       string
	launcherConfidence string
	launcherKind       codexMemoryLauncherKind
	version            string
	versionCandidates  []string
	modulePath         string
	sha256             string
}

var codexMemoryPatchProfiles = []codexMemoryPatchProfile{
	{
		launcher: codexMemoryLauncherVSCode,
		version:  "0.133.0-alpha.1",
		sha256:   "3FE3FDA152A5AD1CF23D8684689094BC38708E58EEE181631267B106840AC672",
		fields: []codexMemoryPatchField{
			{
				name:       "account_id",
				baseOffset: 0x0E4F4000,
				offsets:    []uintptr{0x18, 0x68, 0x10, 0x238, 0xB0, 0x1B8, 0x0},
				length:     36,
			},
			{
				name:       "access_token",
				baseOffset: 0x0E4F4000,
				offsets:    []uintptr{0xE0, 0x670, 0x278, 0xA20, 0x118, 0xB8, 0x0},
				length:     2,
			},
		},
	},
	{
		launcher: codexMemoryLauncherVSCode,
		version:  "",
		sha256:   "DB991D1D96EE2F3F1EA715B8F8FA1067FDB934C11FF1056C54E732ABEFB86392",
		fields: []codexMemoryPatchField{
			{
				name:       "account_id",
				baseOffset: 0x0EA5BA10,
				offsets:    []uintptr{0x18, 0xB0, 0x340, 0xDA0, 0x0, 0x140, 0x0},
				length:     36,
			},
			{
				name:       "access_token",
				baseOffset: 0x0EA5BA10,
				offsets:    []uintptr{0x18, 0x78, 0x78, 0x5E8, 0x120, 0xB8, 0x0},
				length:     2,
			},
		},
	},
	{
		launcher: codexMemoryLauncherJetBrains,
		version:  "0.128.0",
		sha256:   "85A75FAF207720A9A3032F6FA77664B537E67884EB6A7E0C954D22E7F864A5AE",
		fields: []codexMemoryPatchField{
			{
				name:       "account_id",
				baseOffset: 0x0E299648,
				offsets:    []uintptr{0xD8, 0x950, 0x258, 0x10, 0x68, 0x2A0, 0x0},
				length:     36,
			},
			{
				name:       "access_token",
				baseOffset: 0x0E299648,
				offsets:    []uintptr{0x240, 0x1F0, 0x108, 0x58, 0x118, 0xB8, 0x0},
				length:     2,
			},
		},
	},
	{
		launcher: codexMemoryLauncherDesktop,
		version:  "",
		sha256:   "76651FA56A58BEECF5FE0B60DDA8E13E596519B6E16BD698FDAA0E7473D97E3E",
		fields: []codexMemoryPatchField{
			{
				name:       "account_id",
				baseOffset: 0x0EE848F0,
				offsets:    []uintptr{0x18, 0x38, 0x120, 0xE8, 0x0},
				length:     36,
			},
			{
				name:       "access_token",
				baseOffset: 0x0EE84A80,
				offsets:    []uintptr{0x1A8, 0xB0, 0x2A8, 0xD8, 0x120, 0xB8, 0x0},
				length:     2,
			},
		},
	},
}

func resolveCodexMemoryPatchProfile(pid int32, modulePath string) (codexMemoryPatchProfile, codexMemoryPatchContext, error) {
	ctx, err := buildCodexMemoryPatchContext(pid, modulePath)
	if err != nil {
		return codexMemoryPatchProfile{}, ctx, err
	}
	return matchCodexMemoryPatchProfile(ctx)
}

func resolveCodexMemoryPatchProfileForProcessInfo(info CodexProcessInfo, modulePath string) (codexMemoryPatchProfile, codexMemoryPatchContext, error) {
	ctx := buildCodexMemoryPatchContextFromProcessInfo(info, modulePath)
	return matchCodexMemoryPatchProfile(ctx)
}

func matchCodexMemoryPatchProfile(ctx codexMemoryPatchContext) (codexMemoryPatchProfile, codexMemoryPatchContext, error) {
	if ctx.launcherKind == "" {
		return codexMemoryPatchProfile{}, ctx, fmt.Errorf("不支持的 Codex 启动来源: %s", firstNonEmpty(ctx.launcherName, "未知"))
	}

	for _, profile := range codexMemoryPatchProfiles {
		if profile.launcher != ctx.launcherKind {
			continue
		}
		if strings.TrimSpace(profile.version) == "" {
			continue
		}
		for _, candidate := range ctx.versionCandidates {
			if strings.EqualFold(profile.version, candidate) {
				ctx.version = candidate
				return profile, ctx, nil
			}
		}
	}

	if hash, ok := codexMemoryPatchContextSHA256(&ctx); ok {
		for _, profile := range codexMemoryPatchProfiles {
			if profile.launcher != ctx.launcherKind || strings.TrimSpace(profile.sha256) == "" {
				continue
			}
			if strings.EqualFold(profile.sha256, hash) {
				return profile, ctx, nil
			}
		}
	}
	return codexMemoryPatchProfile{}, ctx, fmt.Errorf(
		"未找到 %s 的 Codex 偏移配置，版本: %s，SHA256: %s，已支持: %s",
		ctx.launcherKind,
		firstNonEmpty(ctx.version, strings.Join(ctx.versionCandidates, "/"), "未知版本"),
		firstNonEmpty(ctx.sha256, "未知"),
		formatCodexMemorySupportedProfiles(ctx.launcherKind),
	)
}

func codexMemoryPatchContextSHA256(ctx *codexMemoryPatchContext) (string, bool) {
	if ctx == nil {
		return "", false
	}
	if strings.TrimSpace(ctx.sha256) != "" {
		return ctx.sha256, true
	}
	if strings.TrimSpace(ctx.modulePath) == "" {
		return "", false
	}
	hash, err := codexProcessFileSHA256(ctx.modulePath)
	if err != nil {
		return "", false
	}
	ctx.sha256 = hash
	return hash, true
}

func buildCodexMemoryPatchContext(pid int32, modulePath string) (codexMemoryPatchContext, error) {
	ctx := codexMemoryPatchContext{}

	procMap, proc, err := codexMemoryProcessMap(pid)
	if err != nil {
		return ctx, err
	}

	info := CodexProcessInfo{
		ProcessID:      pid,
		Name:           getProcessString(proc.Name),
		ExecutablePath: modulePath,
	}
	info.CommandLine = getProcessString(proc.Cmdline)
	enrichCodexProcessLauncher(&info, proc, procMap)

	ctx.launcherName = info.LauncherName
	ctx.launcherConfidence = info.LauncherConfidence
	ctx.launcherKind = codexMemoryLauncherKindFromName(info.LauncherName)
	ctx.modulePath = modulePath
	ctx.versionCandidates = codexMemoryVersionCandidates(modulePath)
	if len(ctx.versionCandidates) > 0 {
		ctx.version = ctx.versionCandidates[0]
	}
	return ctx, nil
}

func buildCodexMemoryPatchContextFromProcessInfo(info CodexProcessInfo, modulePath string) codexMemoryPatchContext {
	ctx := codexMemoryPatchContext{}
	ctx.launcherName = info.LauncherName
	ctx.launcherConfidence = info.LauncherConfidence
	ctx.launcherKind = codexMemoryLauncherKindFromName(info.LauncherName)
	ctx.modulePath = modulePath
	ctx.versionCandidates = codexMemoryVersionCandidatesFromProcessInfo(info, modulePath)
	if len(ctx.versionCandidates) > 0 {
		ctx.version = ctx.versionCandidates[0]
	}
	return ctx
}

func codexMemoryProcessMap(pid int32) (map[int32]*process.Process, *process.Process, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, nil, err
	}

	procMap := make(map[int32]*process.Process, len(procs))
	for _, p := range procs {
		if p != nil && p.Pid > 0 {
			procMap[p.Pid] = p
		}
	}

	proc := procMap[pid]
	if proc == nil {
		proc, err = process.NewProcess(pid)
		if err != nil {
			return nil, nil, fmt.Errorf("未找到 Codex 进程 %d: %w", pid, err)
		}
		procMap[pid] = proc
	}
	return procMap, proc, nil
}

func codexMemoryLauncherKindFromName(name string) codexMemoryLauncherKind {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "vs code", "vs code insiders", "vscodium":
		return codexMemoryLauncherVSCode
	case "intellij idea", "goland", "pycharm", "webstorm", "rider", "clion", "phpstorm", "rubymine", "jetbrains terminal":
		return codexMemoryLauncherJetBrains
	case "microsoft store codex", "microsoft store / windowsapps", "codex desktop":
		return codexMemoryLauncherDesktop
	default:
		return ""
	}
}

func codexMemoryVersionCandidates(path string) []string {
	version := readCodexProcessFileVersionInfo(path)
	values := []string{
		version.ProductVersion,
		version.FileVersion,
	}

	seen := make(map[string]struct{}, len(values))
	candidates := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(strings.TrimPrefix(value, "v"))
		if normalized == "" {
			continue
		}
		key := strings.ToLower(normalized)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, normalized)
	}
	return candidates
}

func codexMemoryVersionCandidatesFromProcessInfo(info CodexProcessInfo, path string) []string {
	values := []string{
		info.FileProductVersion,
		info.FileVersion,
	}

	seen := make(map[string]struct{}, len(values))
	candidates := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(strings.TrimPrefix(value, "v"))
		if normalized == "" {
			continue
		}
		key := strings.ToLower(normalized)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, normalized)
	}
	if len(candidates) > 0 {
		return candidates
	}
	return codexMemoryVersionCandidates(path)
}

func formatCodexMemorySupportedProfiles(launcher codexMemoryLauncherKind) string {
	versions := make([]string, 0)
	for _, profile := range codexMemoryPatchProfiles {
		if launcher != "" && profile.launcher != launcher {
			continue
		}
		versions = append(versions, formatCodexMemoryPatchProfileID(profile))
	}
	sort.Strings(versions)
	if len(versions) == 0 {
		return "无"
	}
	return strings.Join(versions, ", ")
}

func formatCodexMemoryPatchProfileID(profile codexMemoryPatchProfile) string {
	if strings.TrimSpace(profile.version) != "" {
		return fmt.Sprintf("%s/%s", profile.launcher, profile.version)
	}
	if strings.TrimSpace(profile.sha256) != "" {
		return fmt.Sprintf("%s/sha256:%s", profile.launcher, strings.ToUpper(profile.sha256))
	}
	return string(profile.launcher)
}
