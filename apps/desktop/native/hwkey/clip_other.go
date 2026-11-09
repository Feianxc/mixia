//go:build !windows

package main

import "errors"

func writeClipboard(string) (uint32, error) { return 0, errors.New("unsupported") }

func clearClipboard(uint32) (bool, error) { return false, errors.New("unsupported") }
