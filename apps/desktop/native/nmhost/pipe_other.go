//go:build !windows

package main

import (
	"errors"
	"io"
)

var errUnsupported = errors.New("browser fill needs a platform transport")

func serveDesktop(io.Reader, io.Writer) error { return errUnsupported }

func dialDesktop() (io.ReadWriteCloser, error) { return nil, errUnsupported }
