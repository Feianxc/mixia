package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const (
	maxSignData = 1 << 20
	maxSealData = 190
	sealBlobLen = 256 // RSA-2048 密文长度
	// 单行上限：1 MiB 数据的 base64url 约 1.34 MiB，留足 JSON 外壳。
	maxLineLen = 2 << 20
)

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	b64    = base64.RawURLEncoding.Strict()
)

type request struct {
	ID   json.RawMessage `json:"id"`
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args"`
}

type requestArgs struct {
	Name string  `json:"name"`
	Data *string `json:"data"`
	Blob *string `json:"blob"`
	Alg  string  `json:"alg"`
}

type response struct {
	ID      json.RawMessage `json:"id"`
	OK      bool            `json:"ok"`
	Result  any             `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
	Message string          `json:"message,omitempty"`
}

type pubResult struct {
	AuthPub string `json:"authPub"`
}

type signResult struct {
	Sig string `json:"sig"`
}

type sealResult struct {
	Blob string `json:"blob"`
	Alg  string `json:"alg"`
}

type unsealResult struct {
	Data string `json:"data"`
}

// serve 串行处理请求，直到 stdin EOF。TPM 本身也是串行的，这里不做并发，也不设超时。
func serve(in io.Reader, out io.Writer, b backend) error {
	r := bufio.NewReaderSize(in, 64<<10)
	w := bufio.NewWriter(out)
	for {
		line, tooLong, readErr := readLine(r)
		if tooLong {
			if err := writeResponse(w, failure(nil, errBadRequest("request line too long"))); err != nil {
				return err
			}
		} else if !isBlank(line) {
			if err := writeResponse(w, handle(b, line)); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

// readLine 读一行。超长的行读完丢弃并置 tooLong，下一行仍可正常处理。
// 到 EOF 时可能同时返回最后一段没有换行符的内容。
func readLine(r *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		chunk, e := r.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > maxLineLen {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if !errors.Is(e, bufio.ErrBufferFull) {
			return line, tooLong, e
		}
	}
}

func isBlank(line []byte) bool {
	for _, c := range line {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}

func writeResponse(w *bufio.Writer, resp response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		data, err = json.Marshal(failure(nil, &apiError{codeFailed, "response encoding failed"}))
		if err != nil {
			return err
		}
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return err
	}
	return w.Flush()
}

// handle 处理一行请求。错误消息都是固定文本：encoding/json 的错误会带上输入里的
// 字面量，而输入可能是待封存的秘密，所以不转发。
func handle(b backend, line []byte) (resp response) {
	var req request
	if json.Unmarshal(line, &req) != nil {
		return failure(nil, errBadRequest("invalid JSON"))
	}
	defer func() {
		if recover() != nil {
			resp = failure(req.ID, &apiError{codeFailed, "internal error"})
		}
	}()
	result, err := dispatch(b, req)
	if err != nil {
		return failure(req.ID, err)
	}
	return response{ID: req.ID, OK: true, Result: result}
}

func failure(id json.RawMessage, err error) response {
	var ae *apiError
	if !errors.As(err, &ae) {
		ae = &apiError{codeFailed, "internal error"}
	}
	return response{ID: id, OK: false, Error: ae.code, Message: ae.message}
}

func dispatch(b backend, req request) (any, error) {
	if req.Cmd == "status" {
		return b.Status(), nil
	}

	if req.Cmd == "clip" {
		var c struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(req.Args, &c) != nil || c.Text == "" {
			return nil, errBadRequest("invalid args")
		}
		seq, err := writeClipboard(c.Text)
		if err != nil {
			return nil, &apiError{codeFailed, "clipboard unavailable"}
		}
		return map[string]uint32{"seq": seq}, nil
	}

	if req.Cmd == "clipclear" {
		var c struct {
			Seq uint32 `json:"seq"`
		}
		if json.Unmarshal(req.Args, &c) != nil {
			return nil, errBadRequest("invalid args")
		}
		cleared, err := clearClipboard(c.Seq)
		if err != nil {
			return nil, &apiError{codeFailed, "clipboard unavailable"}
		}
		return map[string]bool{"cleared": cleared}, nil
	}

	var a requestArgs
	if len(req.Args) > 0 && json.Unmarshal(req.Args, &a) != nil {
		return nil, errBadRequest("invalid args")
	}

	switch req.Cmd {
	case "create", "pub", "sign", "seal", "unseal", "delete":
		if !nameRE.MatchString(a.Name) {
			return nil, errBadRequest("invalid name")
		}
	default:
		return nil, errBadRequest("unknown command")
	}

	switch req.Cmd {
	case "create":
		pub, err := b.Create(a.Name)
		if err != nil {
			return nil, err
		}
		return pubResult{b64.EncodeToString(pub)}, nil

	case "pub":
		pub, err := b.Pub(a.Name)
		if err != nil {
			return nil, err
		}
		return pubResult{b64.EncodeToString(pub)}, nil

	case "sign":
		data, err := decodeField(a.Data, "data", maxSignData)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(data)
		sig, err := b.Sign(a.Name, digest[:])
		if err != nil {
			return nil, err
		}
		return signResult{b64.EncodeToString(sig)}, nil

	case "seal":
		data, err := decodeField(a.Data, "data", maxSealData)
		if err != nil {
			return nil, err
		}
		defer clear(data)
		blob, alg, err := b.Seal(a.Name, data)
		if err != nil {
			return nil, err
		}
		return sealResult{b64.EncodeToString(blob), alg}, nil

	case "unseal":
		blob, err := decodeField(a.Blob, "blob", sealBlobLen)
		if err != nil {
			return nil, err
		}
		if len(blob) != sealBlobLen {
			return nil, errBadRequest("blob must be 256 bytes")
		}
		switch a.Alg {
		case "", algOAEPSHA256, algOAEPSHA1:
		default:
			return nil, errBadRequest("unknown alg")
		}
		data, err := b.Unseal(a.Name, blob, a.Alg)
		if err != nil {
			return nil, err
		}
		defer clear(data)
		return unsealResult{b64.EncodeToString(data)}, nil
	}

	res, err := b.Delete(a.Name)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func decodeField(v *string, field string, limit int) ([]byte, error) {
	if v == nil {
		return nil, errBadRequest("missing " + field)
	}
	if len(*v) > b64.EncodedLen(limit) {
		return nil, errBadRequest(field + " too large")
	}
	data, err := b64.DecodeString(*v)
	if err != nil {
		return nil, errBadRequest(field + " is not base64url")
	}
	if len(data) > limit {
		return nil, errBadRequest(field + " too large")
	}
	return data, nil
}
