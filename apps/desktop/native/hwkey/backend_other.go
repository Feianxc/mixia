//go:build !windows

package main

func newBackend() backend { return unavailableBackend{} }
