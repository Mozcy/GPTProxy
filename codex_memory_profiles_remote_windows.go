//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	codexMemoryRemoteConfigSource     = "github"
	codexMemoryRemoteConfigURL        = "https://raw.githubusercontent.com/Mozcy/GPTManager/main/config/config.json"
	codexMemoryRemoteConfigEnv        = "GPTMANAGER_CODEX_MEMORY_CONFIG_URL"
	codexMemoryRemoteConfigHTTPMax    = 2 << 20
	codexMemoryRemoteConfigHTTPSecond = 8
)

type codexMemoryRemoteConfig struct {
	SchemaVersion int                        `json:"schema_version"`
	DataVersion   int                        `json:"data_version"`
	Profiles      []codexMemoryRemoteProfile `json:"profiles"`
}

type codexMemoryRemoteProfile struct {
	ID              string                   `json:"id"`
	Launcher        string                   `json:"launcher"`
	CodexVersion    string                   `json:"codex_version"`
	SHA256          string                   `json:"sha256"`
	ProfileRevision int                      `json:"profile_revision"`
	Enabled         *bool                    `json:"enabled"`
	Module          string                   `json:"module"`
	BaseAddress     string                   `json:"base_address"`
	Fields          []codexMemoryRemoteField `json:"fields"`
}

type codexMemoryRemoteField struct {
	Name        string   `json:"name"`
	BaseAddress string   `json:"base_address"`
	Offsets     []string `json:"offsets"`
	Length      int      `json:"length"`
}

type codexMemoryParsedRemoteConfig struct {
	schemaVersion int
	dataVersion   int
	profiles      []codexMemoryPatchProfile
}

var (
	codexMemoryBuiltInProfilesOnce sync.Once
	codexMemoryBuiltInProfiles     []codexMemoryPatchProfile
)

func (a *App) startCodexMemoryProfileLoader() {
	if a == nil || a.proxyStore == nil {
		return
	}

	a.loadCachedCodexMemoryProfiles()
	go a.refreshCodexMemoryProfilesFromRemote(context.Background())
}

func (a *App) loadCachedCodexMemoryProfiles() {
	record, ok, err := a.proxyStore.GetCodexMemoryProfileConfig()
	if err != nil {
		appLogger.Warn("读取 Codex 注入配置缓存失败", "error", err)
		return
	}
	if !ok || strings.TrimSpace(record.RawJSON) == "" {
		appLogger.Info("未找到 Codex 注入配置缓存，使用内置配置")
		return
	}

	parsed, err := parseCodexMemoryRemoteConfig([]byte(record.RawJSON))
	if err != nil {
		appLogger.Warn("Codex 注入配置缓存无效，继续使用内置配置", "error", err)
		return
	}
	applyCodexMemoryRemoteProfiles(parsed.profiles)
	appLogger.Info("Codex 注入配置缓存已加载", "schema_version", parsed.schemaVersion, "data_version", parsed.dataVersion, "count", len(parsed.profiles))
}

func (a *App) refreshCodexMemoryProfilesFromRemote(ctx context.Context) {
	if err := a.updateCodexMemoryProfilesFromRemote(ctx); err != nil {
		appLogger.Warn("拉取远程 Codex 配置文件失败", "error", err)
	}
}

func (a *App) updateCodexMemoryProfilesFromRemote(ctx context.Context) error {
	url := codexMemoryRemoteConfigURLValue()
	if strings.TrimSpace(url) == "" {
		return errors.New("远程 Codex 配置文件 URL 为空")
	}

	data, err := fetchCodexMemoryRemoteConfig(ctx, url)
	if err != nil {
		return fmt.Errorf("拉取远程 Codex 配置文件失败: %w", err)
	}

	parsed, err := parseCodexMemoryRemoteConfig(data)
	if err != nil {
		return fmt.Errorf("远程 Codex 配置文件无效: %w", err)
	}

	cached, ok, err := a.proxyStore.GetCodexMemoryProfileConfig()
	if err != nil {
		appLogger.Warn("读取 Codex 注入配置缓存版本失败", "error", err)
	} else if ok && cached.DataVersion > parsed.dataVersion {
		appLogger.Info("远程 Codex 配置文件版本低于本地缓存，已忽略", "remote_data_version", parsed.dataVersion, "cached_data_version", cached.DataVersion)
		return nil
	}

	if err := a.proxyStore.SaveCodexMemoryProfileConfig(codexMemoryProfileConfigRecord{
		Source:        codexMemoryRemoteConfigSource,
		SchemaVersion: parsed.schemaVersion,
		DataVersion:   parsed.dataVersion,
		RawJSON:       string(data),
	}); err != nil {
		return err
	}

	applyCodexMemoryRemoteProfiles(parsed.profiles)
	appLogger.Info("远程 Codex 配置文件已加载", "url", url, "schema_version", parsed.schemaVersion, "data_version", parsed.dataVersion, "count", len(parsed.profiles))
	return nil
}

func codexMemoryRemoteConfigURLValue() string {
	if value := strings.TrimSpace(os.Getenv(codexMemoryRemoteConfigEnv)); value != "" {
		return value
	}
	return codexMemoryRemoteConfigURL
}

func fetchCodexMemoryRemoteConfig(ctx context.Context, url string) ([]byte, error) {
	parsedURL, err := neturl.Parse(url)
	if err != nil {
		return nil, err
	}
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("远程配置仅支持 HTTPS: %s", url)
	}

	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(codexMemoryRemoteConfigHTTPSecond)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, codexMemoryRemoteConfigHTTPMax))
}

func parseCodexMemoryRemoteConfig(data []byte) (codexMemoryParsedRemoteConfig, error) {
	var config codexMemoryRemoteConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return codexMemoryParsedRemoteConfig{}, err
	}
	if config.SchemaVersion != 1 {
		return codexMemoryParsedRemoteConfig{}, fmt.Errorf("不支持的 schema_version: %d", config.SchemaVersion)
	}
	if config.DataVersion <= 0 {
		return codexMemoryParsedRemoteConfig{}, errors.New("data_version 必须大于 0")
	}
	if len(config.Profiles) == 0 {
		return codexMemoryParsedRemoteConfig{}, errors.New("profiles 不能为空")
	}

	profiles := make([]codexMemoryPatchProfile, 0, len(config.Profiles))
	revisions := make(map[string]int, len(config.Profiles))
	indexes := make(map[string]int, len(config.Profiles))
	for i, item := range config.Profiles {
		if item.Enabled != nil && !*item.Enabled {
			continue
		}
		profile, revision, enabled, err := parseCodexMemoryRemoteProfile(item, i)
		if err != nil {
			return codexMemoryParsedRemoteConfig{}, err
		}
		if !enabled {
			continue
		}
		key := codexMemoryPatchProfileKey(profile)
		if existing, ok := indexes[key]; ok {
			if revision <= revisions[key] {
				continue
			}
			profiles[existing] = profile
			revisions[key] = revision
			continue
		}
		indexes[key] = len(profiles)
		revisions[key] = revision
		profiles = append(profiles, profile)
	}
	if len(profiles) == 0 {
		return codexMemoryParsedRemoteConfig{}, errors.New("profiles 没有启用项")
	}

	return codexMemoryParsedRemoteConfig{
		schemaVersion: config.SchemaVersion,
		dataVersion:   config.DataVersion,
		profiles:      profiles,
	}, nil
}

func parseCodexMemoryRemoteProfile(item codexMemoryRemoteProfile, index int) (codexMemoryPatchProfile, int, bool, error) {
	enabled := true
	if item.Enabled != nil {
		enabled = *item.Enabled
	}

	launcher, err := parseCodexMemoryRemoteLauncher(item.Launcher)
	if err != nil {
		return codexMemoryPatchProfile{}, 0, enabled, fmt.Errorf("profiles[%d]: %w", index, err)
	}
	version := strings.TrimSpace(strings.TrimPrefix(item.CodexVersion, "v"))
	sha256 := strings.ToUpper(strings.TrimSpace(item.SHA256))
	if version == "" && sha256 == "" {
		return codexMemoryPatchProfile{}, 0, enabled, fmt.Errorf("profiles[%d]: codex_version 和 sha256 不能同时为空", index)
	}
	if sha256 != "" && !isCodexMemoryRemoteSHA256(sha256) {
		return codexMemoryPatchProfile{}, 0, enabled, fmt.Errorf("profiles[%d]: sha256 格式无效", index)
	}
	module := strings.ToLower(strings.TrimSpace(item.Module))
	if module != "" && module != "codex.exe" {
		return codexMemoryPatchProfile{}, 0, enabled, fmt.Errorf("profiles[%d]: module 仅支持 codex.exe", index)
	}
	defaultBase, hasDefaultBase, err := parseCodexMemoryRemoteHexOptional(item.BaseAddress)
	if err != nil {
		return codexMemoryPatchProfile{}, 0, enabled, fmt.Errorf("profiles[%d]: base_address 无效: %w", index, err)
	}
	if len(item.Fields) == 0 {
		return codexMemoryPatchProfile{}, 0, enabled, fmt.Errorf("profiles[%d]: fields 不能为空", index)
	}

	fields := make([]codexMemoryPatchField, 0, len(item.Fields))
	seenFields := make(map[string]struct{}, len(item.Fields))
	for fieldIndex, field := range item.Fields {
		parsedField, err := parseCodexMemoryRemoteField(field, defaultBase, hasDefaultBase)
		if err != nil {
			return codexMemoryPatchProfile{}, 0, enabled, fmt.Errorf("profiles[%d].fields[%d]: %w", index, fieldIndex, err)
		}
		if _, ok := seenFields[parsedField.name]; ok {
			return codexMemoryPatchProfile{}, 0, enabled, fmt.Errorf("profiles[%d].fields[%d]: 字段重复: %s", index, fieldIndex, parsedField.name)
		}
		seenFields[parsedField.name] = struct{}{}
		fields = append(fields, parsedField)
	}
	for _, required := range []string{"account_id", "access_token"} {
		if _, ok := seenFields[required]; !ok {
			return codexMemoryPatchProfile{}, 0, enabled, fmt.Errorf("profiles[%d]: 缺少字段 %s", index, required)
		}
	}

	return codexMemoryPatchProfile{
		launcher: launcher,
		version:  version,
		sha256:   sha256,
		fields:   fields,
	}, item.ProfileRevision, enabled, nil
}

func parseCodexMemoryRemoteLauncher(value string) (codexMemoryLauncherKind, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(codexMemoryLauncherVSCode):
		return codexMemoryLauncherVSCode, nil
	case string(codexMemoryLauncherJetBrains):
		return codexMemoryLauncherJetBrains, nil
	case string(codexMemoryLauncherDesktop):
		return codexMemoryLauncherDesktop, nil
	default:
		return "", fmt.Errorf("launcher 不支持: %s", value)
	}
}

func parseCodexMemoryRemoteField(field codexMemoryRemoteField, defaultBase uintptr, hasDefaultBase bool) (codexMemoryPatchField, error) {
	name := strings.ToLower(strings.TrimSpace(field.Name))
	if name != "account_id" && name != "access_token" {
		return codexMemoryPatchField{}, fmt.Errorf("字段名不支持: %s", field.Name)
	}
	if name == "account_id" && field.Length != 36 {
		return codexMemoryPatchField{}, fmt.Errorf("account_id length 必须是 36")
	}
	if name == "access_token" && field.Length != 2 {
		return codexMemoryPatchField{}, fmt.Errorf("access_token length 必须是 2")
	}

	base, hasFieldBase, err := parseCodexMemoryRemoteHexOptional(field.BaseAddress)
	if err != nil {
		return codexMemoryPatchField{}, fmt.Errorf("base_address 无效: %w", err)
	}
	if !hasFieldBase {
		if !hasDefaultBase {
			return codexMemoryPatchField{}, errors.New("缺少 base_address")
		}
		base = defaultBase
	}
	if len(field.Offsets) == 0 || len(field.Offsets) > 16 {
		return codexMemoryPatchField{}, fmt.Errorf("offsets 数量无效: %d", len(field.Offsets))
	}

	offsets := make([]uintptr, 0, len(field.Offsets))
	for _, value := range field.Offsets {
		offset, err := parseCodexMemoryRemoteHex(value)
		if err != nil {
			return codexMemoryPatchField{}, fmt.Errorf("offsets 包含无效值 %q: %w", value, err)
		}
		offsets = append(offsets, offset)
	}
	return codexMemoryPatchField{
		name:       name,
		baseOffset: base,
		offsets:    offsets,
		length:     field.Length,
	}, nil
}

func parseCodexMemoryRemoteHexOptional(value string) (uintptr, bool, error) {
	if strings.TrimSpace(value) == "" {
		return 0, false, nil
	}
	parsed, err := parseCodexMemoryRemoteHex(value)
	return parsed, true, err
}

func parseCodexMemoryRemoteHex(value string) (uintptr, error) {
	normalized := strings.TrimSpace(value)
	normalized = strings.TrimPrefix(strings.ToLower(normalized), "0x")
	parsed, err := strconv.ParseUint(normalized, 16, 64)
	if err != nil {
		return 0, err
	}
	return uintptr(parsed), nil
}

func isCodexMemoryRemoteSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func applyCodexMemoryRemoteProfiles(remoteProfiles []codexMemoryPatchProfile) {
	merged := codexMemoryBuiltInPatchProfiles()
	indexes := make(map[string]int, len(merged)+len(remoteProfiles))
	for i, profile := range merged {
		indexes[codexMemoryPatchProfileKey(profile)] = i
	}
	for _, profile := range remoteProfiles {
		key := codexMemoryPatchProfileKey(profile)
		if index, ok := indexes[key]; ok {
			merged[index] = profile
			continue
		}
		indexes[key] = len(merged)
		merged = append(merged, profile)
	}
	setCodexMemoryPatchProfiles(merged)
}

func codexMemoryBuiltInPatchProfiles() []codexMemoryPatchProfile {
	codexMemoryBuiltInProfilesOnce.Do(func() {
		codexMemoryBuiltInProfiles = codexMemoryPatchProfilesSnapshot()
	})
	return cloneCodexMemoryPatchProfiles(codexMemoryBuiltInProfiles)
}

func codexMemoryPatchProfileKey(profile codexMemoryPatchProfile) string {
	return strings.ToLower(fmt.Sprintf("%s|%s|%s", profile.launcher, strings.TrimSpace(profile.version), strings.TrimSpace(profile.sha256)))
}
