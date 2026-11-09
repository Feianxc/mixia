//go:build windows

package main

import (
	"errors"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32dll        = windows.NewLazySystemDLL("user32.dll")
	kernel32dll      = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClip     = user32dll.NewProc("OpenClipboard")
	procCloseClip    = user32dll.NewProc("CloseClipboard")
	procEmptyClip    = user32dll.NewProc("EmptyClipboard")
	procSetClipData  = user32dll.NewProc("SetClipboardData")
	procRegisterFmt  = user32dll.NewProc("RegisterClipboardFormatW")
	procClipSeq      = user32dll.NewProc("GetClipboardSequenceNumber")
	procGlobalAlloc  = kernel32dll.NewProc("GlobalAlloc")
	procGlobalLock   = kernel32dll.NewProc("GlobalLock")
	procGlobalUnlock = kernel32dll.NewProc("GlobalUnlock")
	procGlobalFree   = kernel32dll.NewProc("GlobalFree")
)

const (
	gmemMoveable  = 0x0002
	cfUnicodeText = 13
)

func globalBytes(data []byte) (uintptr, error) {
	size := len(data)
	if size == 0 {
		size = 1
	}
	h, _, _ := procGlobalAlloc.Call(gmemMoveable, uintptr(size))
	if h == 0 {
		return 0, errors.New("GlobalAlloc")
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return 0, errors.New("GlobalLock")
	}
	copy(unsafe.Slice(*(**byte)(unsafe.Pointer(&p)), size), data)
	procGlobalUnlock.Call(h)
	return h, nil
}

func setClip(format uintptr, data []byte) error {
	h, err := globalBytes(data)
	if err != nil {
		return err
	}
	if r, _, _ := procSetClipData.Call(format, h); r == 0 {
		procGlobalFree.Call(h)
		return errors.New("SetClipboardData")
	}
	return nil
}

func registerFormat(name string) uintptr {
	p, _ := windows.UTF16PtrFromString(name)
	r, _, _ := procRegisterFmt.Call(uintptr(unsafe.Pointer(p)))
	return r
}

func openClipboard() error {
	for i := 0; i < 20; i++ {
		if r, _, _ := procOpenClip.Call(0); r != 0 {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("OpenClipboard")
}

func clipSequence() uint32 {
	r, _, _ := procClipSeq.Call()
	return uint32(r)
}

// writeClipboard 写入文本，同时声明不进入 Win+V 剪贴板历史、不上传到云剪贴板。
// 这些格式必须和文本在同一次 Open/Close 里写入，这也是 Electron 的剪贴板接口做不到的。
// 返回写入后的系统序列号，到时清除时用它判断内容有没有被别人换过。
func writeClipboard(text string) (uint32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := openClipboard(); err != nil {
		return 0, err
	}
	err := fillClipboard(text)
	procCloseClip.Call()
	if err != nil {
		return 0, err
	}
	return clipSequence(), nil
}

func fillClipboard(text string) error {
	procEmptyClip.Call()
	u, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2)
	if err := setClip(cfUnicodeText, raw); err != nil {
		return err
	}
	zero := make([]byte, 4)
	for _, name := range []string{"CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"} {
		if err := setClip(registerFormat(name), zero); err != nil {
			return err
		}
	}
	return setClip(registerFormat("ExcludeClipboardContentFromMonitorProcessing"), nil)
}

// clearClipboard 只在序列号没变时清空：用户期间复制了别的内容就不动它。
func clearClipboard(seq uint32) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if clipSequence() != seq {
		return false, nil
	}
	if err := openClipboard(); err != nil {
		return false, err
	}
	defer procCloseClip.Call()
	procEmptyClip.Call()
	return true, nil
}
