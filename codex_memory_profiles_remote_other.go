//go:build !windows

package main

import (
	"context"
	"errors"
)

func (a *App) startCodexMemoryProfileLoader() {}

func (a *App) updateCodexMemoryProfilesFromRemote(ctx context.Context) error {
	return errors.New("Codex 注入偏移配置更新仅支持 Windows")
}
