//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func testPipe(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return `\\.\pipe\mixia-fill-test-` + hex.EncodeToString(b)
}

func allow(windows.Handle) error { return nil }

// echoOnce 接受一个连接，收一帧，原样回。
func echoOnce(t *testing.T, l *listener, verify func(windows.Handle) error) {
	t.Helper()
	go func() {
		c, err := l.accept(verify)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			raw, err := readFrame(c, maxRequestFrame)
			if err != nil {
				return
			}
			if writeFrame(c, raw, maxReplyFrame) != nil {
				return
			}
		}
	}()
}

func TestPipeRoundTrip(t *testing.T) {
	name := testPipe(t)
	l, err := listen(name)
	if err != nil {
		t.Fatal(err)
	}
	echoOnce(t, l, verifyClient)
	c, err := dial(name, verifyServer)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := range 3 {
		msg := fmt.Sprintf(`{"n":%d}`, i)
		if err := writeFrame(c, []byte(msg), maxRequestFrame); err != nil {
			t.Fatal(err)
		}
		got, err := readFrame(c, maxReplyFrame)
		if err != nil || string(got) != msg {
			t.Fatalf("%q %v", got, err)
		}
	}
}

func TestPipeACLOnlyCurrentUser(t *testing.T) {
	name := testPipe(t)
	l, err := listen(name)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetSecurityInfo(l.next, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := userSID()
	if err != nil {
		t.Fatal(err)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("DACL 有 %d 条，%s", dacl.AceCount, sd.String())
	}
	if text := sd.String(); !strings.Contains(text, sid) || strings.Contains(text, ";WD)") || strings.Contains(text, ";AN)") {
		t.Fatalf("DACL 不对：%s", text)
	}
}

func TestPipeNameTakenFails(t *testing.T) {
	name := testPipe(t)
	if _, err := listen(name); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(name); err == nil {
		t.Fatal("名字被占用时不该再建成功")
	}
}

// 别的程序（这里用 PowerShell）连管道：连上也读不到东西，也写不进来。
func TestServerRejectsForeignClient(t *testing.T) {
	name := testPipe(t)
	l, err := listen(name)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan io.ReadWriteCloser, 1)
	go func() {
		c, err := l.accept(verifyClient)
		if err == nil {
			accepted <- c
		}
	}()
	short := strings.TrimPrefix(name, `\\.\pipe\`)
	script := fmt.Sprintf(`$p=[System.IO.Pipes.NamedPipeClientStream]::new('.','%s','InOut'); $p.Connect(5000); Start-Sleep -Milliseconds 300; try { $b=[byte[]](1,0,0,0,65); $p.Write($b,0,5); $p.Flush(); 'wrote' } catch { 'rejected' }`, short)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(string(out), "rejected") {
		t.Fatalf("外部程序不该写进来：%s", out)
	}
	select {
	case <-accepted:
		t.Fatal("外部程序不该通过核对")
	case <-time.After(200 * time.Millisecond):
	}
	// 拒绝之后还能接正常的连接
	c, err := dial(name, verifyServer)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case s := <-accepted:
		s.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("拒绝外部程序后服务不可用")
	}
}

// 别的程序抢先占了管道名，host 不能把请求发给它。
func TestClientRejectsForeignServer(t *testing.T) {
	name := testPipe(t)
	short := strings.TrimPrefix(name, `\\.\pipe\`)
	script := fmt.Sprintf(`$s=[System.IO.Pipes.NamedPipeServerStream]::new('%s','InOut'); 'ready'; $s.WaitForConnection(); $b=New-Object byte[] 1; $n=$s.Read($b,0,1); "read=$n"`, short)
	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	buf := make([]byte, 64)
	if _, err := stdout.Read(buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf), "ready") {
		t.Fatalf("%s", buf)
	}
	var c io.ReadWriteCloser
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err = dial(name, verifyServer)
		if err == nil || !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err == nil {
		c.Close()
		t.Fatal("冒充的服务端不该通过核对")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("错误不是身份不符：%v", err)
	}
	rest, _ := io.ReadAll(stdout)
	if strings.Contains(string(rest), "read=1") {
		t.Fatalf("冒充的服务端不该读到数据：%s", rest)
	}
}

func TestHostEndToEndOverRealPipe(t *testing.T) {
	name := testPipe(t)
	l, err := listen(name)
	if err != nil {
		t.Fatal(err)
	}
	outR, outW := io.Pipe()
	inR, inW := io.Pipe()
	h := newHub(outW)
	go func() { _ = h.pump(inR) }()
	go func() {
		c, err := l.accept(verifyClient)
		if err == nil {
			h.serveClient(c)
		}
	}()
	go func() {
		line := make([]byte, 4096)
		n, err := outR.Read(line)
		if err != nil {
			return
		}
		if !strings.Contains(string(line[:n]), `"op":"status"`) {
			return
		}
		_, _ = inW.Write([]byte(`{"conn":1,"msg":{"id":5,"ok":true,"state":"ready"}}` + "\n"))
	}()
	send, stop := browser(t, func() (io.ReadWriteCloser, error) { return dial(name, verifyServer) })
	if got := send(`{"id":5,"op":"status"}`); got != `{"id":5,"ok":true,"state":"ready"}` {
		t.Fatalf("得到 %s", got)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}
