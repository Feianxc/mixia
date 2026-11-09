package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

const site = "https://example.com"

func TestRole(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{extensionOrigin, "--parent-window=12"}, "host"},
		{[]string{"--serve"}, "serve"},
		{nil, ""},
		{[]string{"chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"}, ""},
		{[]string{"chrome-extension://" + extensionID}, ""},
		{[]string{"--parent-window=12", extensionOrigin}, ""},
	} {
		if got := role(c.args); got != c.want {
			t.Errorf("%v 得到 %q", c.args, got)
		}
	}
}

func TestParseRequestAccepts(t *testing.T) {
	for _, raw := range []string{
		`{"id":1,"op":"status"}`,
		`{"id":2,"op":"list","origin":"https://example.com"}`,
		`{"id":3,"op":"pick","origin":"http://127.0.0.1:4000"}`,
		`{"id":4,"op":"fill","origin":"https://a.b-c.example.com:8443","ref":"vault_1/item-2"}`,
		`{"id":5,"op":"list","origin":"http://[::1]:4000"}`,
	} {
		if _, err := parseRequest([]byte(raw)); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestParseRequestRejects(t *testing.T) {
	long := strings.Repeat("a", 300)
	for _, raw := range []string{
		`not json`,
		`[]`,
		`{}`,
		`{"op":"status"}`,
		`{"id":0,"op":"status"}`,
		`{"id":1,"op":"status"}{"id":2,"op":"status"}`,
		`{"id":1,"op":"dump"}`,
		`{"id":1,"op":"sign","data":"x"}`,
		`{"id":1,"op":"exec","cmd":"calc.exe"}`,
		`{"id":1,"op":"status","origin":"https://example.com"}`,
		`{"id":1,"op":"status","ref":"a/b"}`,
		`{"id":1,"op":"status","extra":1}`,
		`{"id":1,"op":"list"}`,
		`{"id":1,"op":"list","origin":"https://example.com","ref":"a/b"}`,
		`{"id":1,"op":"list","origin":"https://example.com/"}`,
		`{"id":1,"op":"list","origin":"https://example.com/path"}`,
		`{"id":1,"op":"list","origin":"https://user@example.com"}`,
		`{"id":1,"op":"list","origin":"file:///c:/x"}`,
		`{"id":1,"op":"list","origin":"chrome-extension://abc"}`,
		`{"id":1,"op":"list","origin":"null"}`,
		`{"id":1,"op":"list","origin":"https://EXAMPLE.com"}`,
		`{"id":1,"op":"list","origin":"https://` + long + `.com"}`,
		`{"id":1,"op":"list","origin":"https://example.com\n"}`,
		`{"id":1,"op":"pick","origin":"https://example.com","username":"x"}`,
		`{"id":1,"op":"fill","origin":"https://example.com"}`,
		`{"id":1,"op":"fill","ref":"a/b"}`,
		`{"id":1,"op":"fill","origin":"https://example.com","ref":"nope"}`,
		`{"id":1,"op":"fill","origin":"https://example.com","ref":"a/b/c"}`,
		`{"id":1,"op":"fill","origin":"https://example.com","ref":"../a/b"}`,
		`{"id":1,"op":"fill","origin":"https://example.com","ref":"a/b","password":"x"}`,
	} {
		if r, err := parseRequest([]byte(raw)); err == nil {
			t.Errorf("%s 不该通过：%+v", raw, r)
		}
	}
}

func TestFilterReply(t *testing.T) {
	status := request{ID: 7, Op: "status"}
	list := request{ID: 7, Op: "list", Origin: site}
	fill := request{ID: 7, Op: "fill", Origin: site, Ref: "a/b"}
	pick := request{ID: 7, Op: "pick", Origin: site}
	good := []struct {
		req request
		raw string
	}{
		{status, `{"id":7,"ok":true,"state":"ready"}`},
		{status, `{"id":7,"ok":true,"state":"locked"}`},
		{list, `{"id":7,"ok":true,"items":[]}`},
		{list, `{"id":7,"ok":true,"items":[{"ref":"a/b","title":"t","username":"u"}]}`},
		{fill, `{"id":7,"ok":true,"username":"","password":"p"}`},
		{pick, `{"id":7,"ok":true,"username":"u","password":"p"}`},
		{fill, `{"id":7,"ok":false,"error":"denied"}`},
		{list, `{"id":7,"ok":false,"error":"locked"}`},
	}
	for _, c := range good {
		if _, err := filterReply(c.req, []byte(c.raw)); err != nil {
			t.Errorf("%s: %v", c.raw, err)
		}
	}
	bad := []struct {
		req request
		raw string
	}{
		{list, `{"id":8,"ok":true,"items":[]}`},
		{list, `{"id":7,"ok":true,"items":[],"password":"p"}`},
		{list, `{"id":7,"ok":true,"items":[],"username":"u"}`},
		{list, `{"id":7,"ok":true,"items":[{"ref":"a/b","title":"t","username":"u","password":"p"}]}`},
		{list, `{"id":7,"ok":true,"items":[{"ref":"nope","title":"t","username":"u"}]}`},
		{list, `{"id":7,"ok":true}`},
		{status, `{"id":7,"ok":true,"state":"ready","password":"p"}`},
		{status, `{"id":7,"ok":true,"state":"odd"}`},
		{status, `{"id":7,"ok":true,"state":"ready","items":[]}`},
		{fill, `{"id":7,"ok":true,"username":"u"}`},
		{fill, `{"id":7,"ok":true,"password":"p"}`},
		{fill, `{"id":7,"ok":true,"username":"u","password":""}`},
		{fill, `{"id":7,"ok":true,"username":"u","password":"p","items":[]}`},
		{fill, `{"id":7,"ok":true,"username":"u","password":"p","extra":1}`},
		{fill, `{"id":7,"ok":false,"error":"denied","password":"p"}`},
		{fill, `{"id":7,"ok":false,"error":"custom"}`},
		{fill, `{"id":7,"ok":false}`},
		{fill, `{"id":7,"ok":true,"error":"denied","username":"u","password":"p"}`},
		{fill, `nonsense`},
	}
	for _, c := range bad {
		if out, err := filterReply(c.req, []byte(c.raw)); err == nil {
			t.Errorf("%s 不该通过：%s", c.raw, out)
		}
	}
	many := reply{ID: 7, OK: true, Items: &[]listItem{}}
	for range maxListItems + 1 {
		*many.Items = append(*many.Items, listItem{"a/b", "t", "u"})
	}
	raw, _ := json.Marshal(many)
	if _, err := filterReply(list, raw); err == nil {
		t.Error("超过条数上限不该通过")
	}
	long := strings.Repeat("p", maxPasswordLen+1)
	raw, _ = json.Marshal(reply{ID: 7, OK: true, Username: new(string), Password: &long})
	if _, err := filterReply(fill, raw); err == nil {
		t.Error("超长密码不该通过")
	}
}

func TestFrames(t *testing.T) {
	var b bytes.Buffer
	if err := writeFrame(&b, []byte(`{"a":1}`), 100); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(b.Bytes()); got != 7 {
		t.Fatalf("长度前缀 %d", got)
	}
	data, err := readFrame(&b, 100)
	if err != nil || string(data) != `{"a":1}` {
		t.Fatalf("%q %v", data, err)
	}
	if err := writeFrame(&b, make([]byte, 101), 100); !errors.Is(err, errFrameTooLarge) {
		t.Fatal(err)
	}
	b.Reset()
	_ = binary.Write(&b, binary.LittleEndian, uint32(101))
	if _, err := readFrame(&b, 100); !errors.Is(err, errFrameTooLarge) {
		t.Fatal(err)
	}
	b.Reset()
	_ = binary.Write(&b, binary.LittleEndian, uint32(10))
	b.WriteString("abc")
	if _, err := readFrame(&b, 100); err == nil {
		t.Fatal("截断的帧不该通过")
	}
}

// desktop 是假的桌面端：记录收到什么，按函数回复。
type desktop struct {
	got   chan []byte
	reply func(raw []byte) []byte
}

func (d *desktop) dial() (io.ReadWriteCloser, error) {
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		for {
			raw, err := readFrame(b, maxRequestFrame)
			if err != nil {
				return
			}
			d.got <- raw
			if writeFrame(b, d.reply(raw), maxReplyFrame) != nil {
				return
			}
		}
	}()
	return a, nil
}

// browser 启动一个 host 循环，返回发一条收一条的函数。
func browser(t *testing.T, dial dialFunc) (func(string) string, func() error) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- runHost(inR, outW, dial, nil) }()
	send := func(raw string) string {
		t.Helper()
		if err := writeFrame(inW, []byte(raw), maxRequestFrame*4); err != nil {
			t.Fatal(err)
		}
		data, err := readFrame(outR, maxReplyFrame)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	stop := func() error {
		inW.Close()
		select {
		case err := <-done:
			return err
		case <-time.After(3 * time.Second):
			return errors.New("host 没有退出")
		}
	}
	return send, stop
}

func TestHostForwardsOnlyValidatedRequests(t *testing.T) {
	d := &desktop{got: make(chan []byte, 8), reply: func(raw []byte) []byte {
		return []byte(`{"id":` + itoa(requestID(raw)) + `,"ok":true,"state":"ready"}`)
	}}
	send, stop := browser(t, d.dial)
	for _, raw := range []string{
		`{"id":1,"op":"dump"}`,
		`{"id":2,"op":"status","cmd":"calc.exe"}`,
		`{"id":3,"op":"list","origin":"https://example.com/x"}`,
	} {
		if got := send(raw); !strings.Contains(got, `"error":"bad_request"`) {
			t.Errorf("%s 得到 %s", raw, got)
		}
	}
	if got := send(`{"id":9,"op":"status"}`); got != `{"id":9,"ok":true,"state":"ready"}` {
		t.Errorf("得到 %s", got)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if len(d.got) != 1 {
		t.Fatalf("只有合法请求能进管道，实际 %d 条", len(d.got))
	}
	if forwarded := string(<-d.got); forwarded != `{"id":9,"op":"status"}` {
		t.Fatalf("转发的是 %s", forwarded)
	}
}

func TestHostDropsPasswordOnListReply(t *testing.T) {
	d := &desktop{got: make(chan []byte, 8), reply: func(raw []byte) []byte {
		return []byte(`{"id":` + itoa(requestID(raw)) + `,"ok":true,"items":[],"password":"LEAK"}`)
	}}
	send, stop := browser(t, d.dial)
	got := send(`{"id":1,"op":"list","origin":"https://example.com"}`)
	if strings.Contains(got, "LEAK") || !strings.Contains(got, codeBadReply) {
		t.Fatalf("得到 %s", got)
	}
	_ = stop()
}

func TestHostDesktopNotRunning(t *testing.T) {
	calls := 0
	send, stop := browser(t, func() (io.ReadWriteCloser, error) {
		calls++
		return nil, errors.New("no pipe")
	})
	if got := send(`{"id":1,"op":"status"}`); !strings.Contains(got, codeUnavailable) {
		t.Fatalf("得到 %s", got)
	}
	if got := send(`{"id":2,"op":"status"}`); !strings.Contains(got, codeUnavailable) {
		t.Fatalf("得到 %s", got)
	}
	if calls != 2 {
		t.Fatalf("每次请求都该重新连：%d", calls)
	}
	_ = stop()
}

func TestHostReconnectsAfterDesktopRestart(t *testing.T) {
	reply := func(raw []byte) []byte {
		return []byte(`{"id":` + itoa(requestID(raw)) + `,"ok":true,"state":"ready"}`)
	}
	d := &desktop{got: make(chan []byte, 8), reply: reply}
	first := true
	send, stop := browser(t, func() (io.ReadWriteCloser, error) {
		c, err := d.dial()
		if first {
			first = false
			return &brokenAfterOne{ReadWriteCloser: c}, err
		}
		return c, err
	})
	if got := send(`{"id":1,"op":"status"}`); !strings.Contains(got, `"ok":true`) {
		t.Fatalf("得到 %s", got)
	}
	if got := send(`{"id":2,"op":"status"}`); !strings.Contains(got, `"ok":true`) {
		t.Fatalf("得到 %s", got)
	}
	_ = stop()
}

// brokenAfterOne 模拟桌面端重启：第一次写之后再写就失败。
type brokenAfterOne struct {
	io.ReadWriteCloser
	writes int
}

func (b *brokenAfterOne) Write(p []byte) (int, error) {
	b.writes++
	if b.writes > 1 {
		return 0, io.ErrClosedPipe
	}
	return b.ReadWriteCloser.Write(p)
}

func TestHostStopsOnOversizedFrame(t *testing.T) {
	var head bytes.Buffer
	_ = binary.Write(&head, binary.LittleEndian, uint32(maxRequestFrame+1))
	err := runHost(&head, io.Discard, func() (io.ReadWriteCloser, error) {
		return nil, errors.New("不该连")
	}, nil)
	if !errors.Is(err, errFrameTooLarge) {
		t.Fatal(err)
	}
}

func TestHostNoticesBrowserClosing(t *testing.T) {
	closed := make(chan struct{})
	inR, inW := io.Pipe()
	blocked := make(chan struct{})
	go func() {
		_ = runHost(inR, io.Discard, func() (io.ReadWriteCloser, error) {
			a, b := net.Pipe()
			go func() {
				_, _ = readFrame(b, maxRequestFrame)
				close(blocked)
				select {} // 用户迟迟不确认
			}()
			return a, nil
		}, func() { close(closed) })
	}()
	if err := writeFrame(inW, []byte(`{"id":1,"op":"fill","origin":"https://example.com","ref":"a/b"}`), maxRequestFrame); err != nil {
		t.Fatal(err)
	}
	<-blocked
	inW.Close()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("等确认时没发现浏览器已关闭")
	}
}

func TestServeRevalidatesAndRoutesReplies(t *testing.T) {
	outR, outW := io.Pipe()
	h := newHub(outW)
	inR, inW := io.Pipe()
	go func() { _ = h.pump(inR) }()
	a, b := net.Pipe()
	go h.serveClient(b)

	if err := writeFrame(a, []byte(`{"id":1,"op":"dump"}`), maxRequestFrame); err != nil {
		t.Fatal(err)
	}
	data, err := readFrame(a, maxReplyFrame)
	if err != nil || !strings.Contains(string(data), "bad_request") {
		t.Fatalf("%s %v", data, err)
	}

	if err := writeFrame(a, []byte(`{"id":2,"op":"status"}`), maxRequestFrame); err != nil {
		t.Fatal(err)
	}
	line := make([]byte, 4096)
	n, err := outR.Read(line)
	if err != nil {
		t.Fatal(err)
	}
	var w wire
	if err := json.Unmarshal(line[:n], &w); err != nil {
		t.Fatal(err)
	}
	if string(w.Msg) != `{"id":2,"op":"status"}` {
		t.Fatalf("主进程收到 %s", w.Msg)
	}
	// 回给不存在的连接不影响正确的连接
	_, _ = inW.Write([]byte(`{"conn":9999,"msg":{"id":2,"ok":true,"state":"locked"}}` + "\n"))
	_, _ = inW.Write([]byte("nonsense\n"))
	_, _ = inW.Write([]byte(`{"conn":` + itoa(w.Conn) + `,"msg":{"id":2,"ok":true,"state":"ready"}}` + "\n"))
	data, err = readFrame(a, maxReplyFrame)
	if err != nil || string(data) != `{"id":2,"ok":true,"state":"ready"}` {
		t.Fatalf("%s %v", data, err)
	}
	a.Close()
}

// 钉死的扩展 ID 三处必须一致：Go 常量、native messaging 清单、扩展公钥算出来的 ID。
func TestExtensionIDPinned(t *testing.T) {
	raw, err := os.ReadFile("../../../extension/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(m.Key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	id := make([]byte, 0, 32)
	for _, b := range sum[:16] {
		id = append(id, 'a'+b>>4, 'a'+b&15)
	}
	if string(id) != extensionID {
		t.Fatalf("公钥算出的 ID 是 %s，常量是 %s", id, extensionID)
	}
	raw, err = os.ReadFile("online.feian.mixia.json")
	if err != nil {
		t.Fatal(err)
	}
	var host struct {
		Name    string   `json:"name"`
		Path    string   `json:"path"`
		Type    string   `json:"type"`
		Origins []string `json:"allowed_origins"`
	}
	if err := json.Unmarshal(raw, &host); err != nil {
		t.Fatal(err)
	}
	if len(host.Origins) != 1 || host.Origins[0] != extensionOrigin {
		t.Fatalf("allowed_origins: %v", host.Origins)
	}
	if host.Name != "online.feian.mixia" || host.Type != "stdio" || host.Path != "mixia-nmhost.exe" {
		t.Fatalf("清单：%+v", host)
	}
}

func itoa(n uint32) string {
	b, _ := json.Marshal(n)
	return string(b)
}
