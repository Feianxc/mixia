package main

import (
	"bufio"
	"encoding/json"
	"io"
	"sync"
)

// wire 是管道服务和 Electron 主进程之间的一行。conn 区分同时连着的 host。
type wire struct {
	Conn uint32          `json:"conn"`
	Msg  json.RawMessage `json:"msg"`
}

// hub 把多个 host 连接汇到 Electron 的 stdio。它不看回复内容，
// 回复由 host 那一侧按请求的操作过滤。
type hub struct {
	mu    sync.Mutex
	out   io.Writer
	next  uint32
	conns map[uint32]chan json.RawMessage
}

func newHub(out io.Writer) *hub {
	return &hub{out: out, conns: map[uint32]chan json.RawMessage{}}
}

func (h *hub) add() (uint32, chan json.RawMessage) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	ch := make(chan json.RawMessage, 1)
	h.conns[h.next] = ch
	return h.next, ch
}

func (h *hub) remove(id uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.conns, id)
}

func (h *hub) send(id uint32, msg []byte) error {
	line, err := json.Marshal(wire{id, msg})
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err = h.out.Write(append(line, '\n'))
	return err
}

// serveClient 处理一个已通过身份核对的 host。这里再过一遍 parseRequest：
// 管道这一端不假定对面一定做过校验。
func (h *hub) serveClient(c io.ReadWriteCloser) {
	defer c.Close()
	id, ch := h.add()
	defer h.remove(id)
	for {
		raw, err := readFrame(c, maxRequestFrame)
		if err != nil {
			return
		}
		req, err := parseRequest(raw)
		if err != nil {
			if writeFrame(c, failure(requestID(raw), "bad_request"), maxReplyFrame) != nil {
				return
			}
			continue
		}
		msg, err := json.Marshal(req)
		if err != nil || h.send(id, msg) != nil {
			return
		}
		data, ok := <-ch
		if !ok || writeFrame(c, data, maxReplyFrame) != nil {
			return
		}
	}
}

// pump 把 Electron 的回复分给对应连接。stdin 关闭说明主进程没了，返回后进程退出。
func (h *hub) pump(in io.Reader) error {
	s := bufio.NewScanner(in)
	s.Buffer(make([]byte, 64<<10), 2*maxReplyFrame)
	for s.Scan() {
		var w wire
		if json.Unmarshal(s.Bytes(), &w) != nil {
			continue
		}
		h.mu.Lock()
		ch := h.conns[w.Conn]
		h.mu.Unlock()
		if ch == nil {
			continue
		}
		select {
		case ch <- w.Msg:
		default: // 这个连接没有在等回复
		}
	}
	return s.Err()
}
