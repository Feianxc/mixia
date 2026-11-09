package main

import (
	"encoding/json"
	"errors"
	"io"
)

const (
	codeUnavailable = "desktop_unavailable"
	codeBadReply    = "bad_reply"
)

type dialFunc func() (io.ReadWriteCloser, error)

// runHost 是 native messaging host 的主循环。请求严格串行：Windows 同步管道上
// 读写不能并发，等用户确认期间这个连接不处理别的请求。
// stdin 在另一个 goroutine 读，这样等待确认时也能发现浏览器已经关掉端口。
func runHost(in io.Reader, out io.Writer, dial dialFunc, onClose func()) error {
	type frame struct {
		raw []byte
		err error
	}
	frames := make(chan frame, 4)
	go func() {
		for {
			raw, err := readFrame(in, maxRequestFrame)
			if err != nil {
				if onClose != nil && errors.Is(err, io.EOF) {
					onClose()
				}
				frames <- frame{err: err}
				return
			}
			frames <- frame{raw: raw}
		}
	}()

	h := link{dial: dial}
	defer h.close()
	for f := range frames {
		if errors.Is(f.err, io.EOF) {
			return nil
		}
		if f.err != nil {
			return f.err
		}
		req, err := parseRequest(f.raw)
		var data []byte
		if err != nil {
			data = failure(requestID(f.raw), "bad_request")
		} else {
			data = h.exchange(req)
		}
		if err := writeFrame(out, data, maxReplyFrame); err != nil {
			return err
		}
	}
	return nil
}

// link 是到桌面端的连接，用的时候才连：桌面端可能晚于浏览器启动，也可能中途重启。
type link struct {
	dial dialFunc
	pipe io.ReadWriteCloser
}

func (l *link) close() {
	if l.pipe != nil {
		_ = l.pipe.Close()
		l.pipe = nil
	}
}

func (l *link) exchange(req request) []byte {
	msg, err := json.Marshal(req)
	if err != nil {
		return failure(req.ID, codeBadReply)
	}
	// 桌面端重启过的话旧连接写不进去，重连一次
	for attempt := 0; ; attempt++ {
		if l.pipe == nil {
			c, err := l.dial()
			if err != nil {
				return failure(req.ID, codeUnavailable)
			}
			l.pipe = c
		}
		if err := writeFrame(l.pipe, msg, maxRequestFrame); err != nil {
			l.close()
			if attempt == 0 {
				continue
			}
			return failure(req.ID, codeUnavailable)
		}
		break
	}
	raw, err := readFrame(l.pipe, maxReplyFrame)
	if err != nil {
		l.close()
		return failure(req.ID, codeUnavailable)
	}
	data, err := filterReply(req, raw)
	if err != nil {
		return failure(req.ID, codeBadReply)
	}
	return data
}
