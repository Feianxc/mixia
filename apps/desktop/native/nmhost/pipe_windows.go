//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pipeBuffer   = 64 << 10
	maxInstances = 8
)

// 管道名含用户 SID：多用户机器上互不抢名字。
func pipeName() (string, error) {
	sid, err := userSID()
	if err != nil {
		return "", err
	}
	return `\\.\pipe\mixia-fill-` + sid, nil
}

func userSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// pipeSDDL 只给当前用户。不写 DACL 时默认 Everyone 可读，这也是管道不放在 Node 里建的原因。
func pipeSDDL(sid string) string {
	return "D:P(A;;GA;;;" + sid + ")"
}

type pipeFile struct {
	h windows.Handle
}

func (p *pipeFile) Read(b []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(p.h, b, &n, nil)
	if err != nil {
		if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
			return int(n), io.EOF
		}
		return int(n), err
	}
	if n == 0 && len(b) > 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

func (p *pipeFile) Write(b []byte) (int, error) {
	var n uint32
	err := windows.WriteFile(p.h, b, &n, nil)
	return int(n), err
}

func (p *pipeFile) Close() error {
	return windows.CloseHandle(p.h)
}

func imagePath(pid uint32) (string, error) {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(p)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(p, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// sameImage 核对对端跑的是不是这个程序本身。正式安装时这个文件在 Program Files，
// 普通用户进程改不了。同用户恶意程序可以直接启动这个程序来冒充，所以这只挡“别的程序直连管道”，
// 真正的防线是桌面端的逐次确认。
func sameImage(pid uint32) error {
	self, err := imagePath(windows.GetCurrentProcessId())
	if err != nil {
		return err
	}
	peer, err := imagePath(pid)
	if err != nil {
		return err
	}
	if !strings.EqualFold(self, peer) {
		return fmt.Errorf("peer image mismatch")
	}
	return nil
}

func verifyClient(h windows.Handle) error {
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		return err
	}
	return sameImage(pid)
}

func verifyServer(h windows.Handle) error {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(h, &pid); err != nil {
		return err
	}
	return sameImage(pid)
}

// listen 建第一个实例。FIRST_PIPE_INSTANCE：名字已被占用时失败，不和别的进程共用。
func listen(name string) (*listener, error) {
	sid, err := userSID()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL(sid))
	if err != nil {
		return nil, err
	}
	l := &listener{sa: windows.SecurityAttributes{SecurityDescriptor: sd}}
	l.sa.Length = uint32(unsafe.Sizeof(l.sa))
	l.name, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	l.next, err = l.create(windows.FILE_FLAG_FIRST_PIPE_INSTANCE)
	if err != nil {
		return nil, err
	}
	return l, nil
}

type listener struct {
	name *uint16
	sa   windows.SecurityAttributes
	next windows.Handle
}

func (l *listener) create(flags uint32) (windows.Handle, error) {
	return windows.CreateNamedPipe(
		l.name,
		windows.PIPE_ACCESS_DUPLEX|flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		maxInstances, pipeBuffer, pipeBuffer, 0, &l.sa,
	)
}

// accept 等下一个客户端，先准备好再下一个实例，然后核对对端。没通过的连接一个字节都不读。
func (l *listener) accept(verify func(windows.Handle) error) (io.ReadWriteCloser, error) {
	for {
		h := l.next
		err := windows.ConnectNamedPipe(h, nil)
		if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			return nil, err
		}
		next, err := l.create(0)
		for errors.Is(err, windows.ERROR_PIPE_BUSY) {
			time.Sleep(200 * time.Millisecond)
			next, err = l.create(0)
		}
		if err != nil {
			windows.CloseHandle(h)
			return nil, err
		}
		l.next = next
		if verify(h) != nil {
			_ = windows.DisconnectNamedPipe(h)
			windows.CloseHandle(h)
			continue
		}
		return &pipeFile{h}, nil
	}
}

func serveDesktop(in io.Reader, out io.Writer) error {
	name, err := pipeName()
	if err != nil {
		return err
	}
	l, err := listen(name)
	if err != nil {
		return err
	}
	h := newHub(out)
	go func() {
		for {
			c, err := l.accept(verifyClient)
			if err != nil {
				os.Exit(1)
			}
			go h.serveClient(c)
		}
	}()
	return h.pump(in)
}

func dialDesktop() (io.ReadWriteCloser, error) {
	name, err := pipeName()
	if err != nil {
		return nil, err
	}
	return dial(name, verifyServer)
}

func dial(name string, verify func(windows.Handle) error) (io.ReadWriteCloser, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		// SQOS：不让对端用这个连接模拟我们的身份
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if errors.Is(err, windows.ERROR_PIPE_BUSY) && attempt < 10 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := verify(h); err != nil {
			windows.CloseHandle(h)
			return nil, err
		}
		return &pipeFile{h}, nil
	}
}
