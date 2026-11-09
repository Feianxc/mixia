package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const (
	// 请求只有 origin 和 ref。native messaging 的回复上限是 1 MB。
	maxRequestFrame = 4 << 10
	maxReplyFrame   = 1000 * 1000
	maxListItems    = 50
	maxTitleLen     = 512
	maxUsernameLen  = 1024
	maxPasswordLen  = 16 << 10
)

var (
	originRE = regexp.MustCompile(`^https?://(\[[0-9a-f:.]+\]|[a-z0-9_]([a-z0-9._-]{0,251}[a-z0-9_])?)(:[0-9]{1,5})?$`)
	refRE    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}/[A-Za-z0-9_-]{1,64}$`)

	errFrameTooLarge = errors.New("frame too large")
	errBadMessage    = errors.New("bad message")
)

// 错误码。扩展只认这几个，桌面回别的一律当坏回复。
var replyErrors = map[string]bool{
	"bad_request": true,
	"locked":      true,
	"no_match":    true,
	"denied":      true,
	"busy":        true,
	"timeout":     true,
}

// request 是管道上全部的请求形状。这里没有的字段不会进管道。
type request struct {
	ID     uint32 `json:"id"`
	Op     string `json:"op"`
	Origin string `json:"origin,omitempty"`
	Ref    string `json:"ref,omitempty"`
}

type listItem struct {
	Ref      string `json:"ref"`
	Title    string `json:"title"`
	Username string `json:"username"`
}

type reply struct {
	ID       uint32      `json:"id"`
	OK       bool        `json:"ok"`
	Error    string      `json:"error,omitempty"`
	State    string      `json:"state,omitempty"`
	Items    *[]listItem `json:"items,omitempty"`
	Username *string     `json:"username,omitempty"`
	Password *string     `json:"password,omitempty"`
}

func decodeStrict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errBadMessage
	}
	if d.More() {
		return errBadMessage
	}
	return nil
}

// parseRequest 是网页内容到本机之前的闸门：操作名和字段都是固定的，
// 通过之后转发的是重新编码的结构，不是收到的字节。
func parseRequest(raw []byte) (request, error) {
	var r request
	if err := decodeStrict(raw, &r); err != nil {
		return request{}, err
	}
	if r.ID == 0 {
		return request{}, errBadMessage
	}
	needOrigin, needRef := false, false
	switch r.Op {
	case "status":
	case "list", "pick":
		needOrigin = true
	case "fill":
		needOrigin, needRef = true, true
	default:
		return request{}, errBadMessage
	}
	if needOrigin != (r.Origin != "") || needRef != (r.Ref != "") {
		return request{}, errBadMessage
	}
	if needOrigin && !originRE.MatchString(r.Origin) {
		return request{}, errBadMessage
	}
	if needRef && !refRE.MatchString(r.Ref) {
		return request{}, errBadMessage
	}
	return r, nil
}

// filterReply 按操作收紧回复：只有 fill 和 pick 能带密码，
// 桌面端的 bug 不会让 list 把密码送进浏览器。
func filterReply(req request, raw []byte) ([]byte, error) {
	var r reply
	if err := decodeStrict(raw, &r); err != nil {
		return nil, err
	}
	if r.ID != req.ID {
		return nil, errBadMessage
	}
	hasCred := r.Username != nil || r.Password != nil
	if !r.OK {
		if !replyErrors[r.Error] || r.State != "" || r.Items != nil || hasCred {
			return nil, errBadMessage
		}
		return json.Marshal(r)
	}
	if r.Error != "" {
		return nil, errBadMessage
	}
	switch req.Op {
	case "status":
		if (r.State != "ready" && r.State != "locked") || r.Items != nil || hasCred {
			return nil, errBadMessage
		}
	case "list":
		if r.State != "" || r.Items == nil || hasCred || !validItems(*r.Items) {
			return nil, errBadMessage
		}
	case "fill", "pick":
		if r.State != "" || r.Items != nil || r.Username == nil || r.Password == nil {
			return nil, errBadMessage
		}
		if *r.Password == "" || len(*r.Password) > maxPasswordLen || len(*r.Username) > maxUsernameLen {
			return nil, errBadMessage
		}
	default:
		return nil, errBadMessage
	}
	return json.Marshal(r)
}

func validItems(items []listItem) bool {
	if len(items) > maxListItems {
		return false
	}
	for _, it := range items {
		if !refRE.MatchString(it.Ref) || len(it.Title) > maxTitleLen || len(it.Username) > maxUsernameLen {
			return false
		}
	}
	return true
}

func failure(id uint32, code string) []byte {
	data, _ := json.Marshal(reply{ID: id, Error: code})
	return data
}

// requestID 只用来给坏请求回一个能对上的 id，内容不做别的用途。
func requestID(raw []byte) uint32 {
	var r struct {
		ID uint32 `json:"id"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return 0
	}
	return r.ID
}

// readFrame 读 4 字节本机序（小端）长度加 JSON。超长时不读内容，调用方必须断开：流已经对不齐了。
func readFrame(r io.Reader, limit int) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(head[:])
	if n > uint32(limit) {
		return nil, errFrameTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeFrame(w io.Writer, data []byte, limit int) error {
	if len(data) > limit {
		return errFrameTooLarge
	}
	buf := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(buf, uint32(len(data)))
	copy(buf[4:], data)
	_, err := w.Write(buf)
	return err
}
