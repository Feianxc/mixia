package main

const (
	providerName = "Microsoft Platform Crypto Provider"

	algOAEPSHA256 = "oaep-sha256"
	algOAEPSHA1   = "oaep-sha1"

	levelHardware = "hardware"
	levelNone     = "none"
)

type statusResult struct {
	Provider  string `json:"provider"`
	Available bool   `json:"available"`
	Level     string `json:"level"`
}

type deleteResult struct {
	Auth bool `json:"auth"`
	Seal bool `json:"seal"`
}

// backend 是硬件密钥的实际实现。Sign 收到的是已算好的 SHA-256 摘要。
// Unseal 的 alg 为空表示调用方不知道算法。
type backend interface {
	Status() statusResult
	Create(name string) (authPub []byte, err error)
	Pub(name string) (authPub []byte, err error)
	Sign(name string, digest []byte) (sig []byte, err error)
	Seal(name string, data []byte) (blob []byte, alg string, err error)
	Unseal(name string, blob []byte, alg string) (data []byte, err error)
	Delete(name string) (deleteResult, error)
}

// unavailableBackend 用于没有硬件密钥能力的平台：明确报告不可用，绝不用软件顶替。
type unavailableBackend struct{}

var errUnavailable = &apiError{codeTPMUnavailable, "hardware key provider is not available on this platform"}

func (unavailableBackend) Status() statusResult {
	return statusResult{Provider: providerName, Available: false, Level: levelNone}
}
func (unavailableBackend) Create(string) ([]byte, error)       { return nil, errUnavailable }
func (unavailableBackend) Pub(string) ([]byte, error)          { return nil, errUnavailable }
func (unavailableBackend) Sign(string, []byte) ([]byte, error) { return nil, errUnavailable }
func (unavailableBackend) Seal(string, []byte) ([]byte, string, error) {
	return nil, "", errUnavailable
}
func (unavailableBackend) Unseal(string, []byte, string) ([]byte, error) {
	return nil, errUnavailable
}
func (unavailableBackend) Delete(string) (deleteResult, error) {
	return deleteResult{}, errUnavailable
}
