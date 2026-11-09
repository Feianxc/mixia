package main

const (
	codeNoKey          = "no_key"
	codeExists         = "exists"
	codeTPMUnavailable = "tpm_unavailable"
	codeFailed         = "failed"
	codeBadRequest     = "bad_request"
)

type apiError struct {
	code    string
	message string
}

func (e *apiError) Error() string { return e.message }

func errBadRequest(msg string) error { return &apiError{codeBadRequest, msg} }

// statusCode 把 NCrypt 返回的 SECURITY_STATUS 映射到协议错误码。
//
// 不能把 0x8028xxxx 整段当成 tpm_unavailable：TPM 拒绝一次具体操作（例如篡改过的
// 密文）也落在这一段，那种情况 TPM 工作正常，只是这次操作失败，应归 failed。
func statusCode(status uint32) string {
	switch status {
	case 0x80090016, // NTE_BAD_KEYSET
		0x8009000D, // NTE_NO_KEY
		0x80090011: // NTE_NOT_FOUND
		return codeNoKey

	case 0x8009000F: // NTE_EXISTS
		return codeExists

	case 0x80090013, // NTE_BAD_PROVIDER
		0x80090014, // NTE_BAD_PROV_TYPE
		0x80090017, // NTE_PROV_TYPE_NOT_DEF
		0x8009001D, // NTE_PROVIDER_DLL_FAIL
		0x8009001E, // NTE_PROV_DLL_NOT_FOUND
		0x80090030, // NTE_DEVICE_NOT_READY
		0x80090035, // NTE_DEVICE_NOT_FOUND
		0x80290401, // TPM_E_PCP_DEVICE_NOT_READY
		0x80280006, // TPM_E_DEACTIVATED
		0x80280007, // TPM_E_DISABLED
		0x8028001C, // TPM_E_FAILEDSELFTEST
		0x80280800, // TPM_E_RETRY
		0x80280801, // TPM_E_NEEDS_SELFTEST
		0x80280802, // TPM_E_DOING_SELFTEST
		0x80280803, // TPM_E_DEFEND_LOCK_RUNNING
		0x8028090A, // TPM_20_E_TESTING
		0x80280921, // TPM_20_E_LOCKOUT
		0x80280922, // TPM_20_E_RETRY
		0x80280923, // TPM_20_E_NV_UNAVAILABLE
		0x80284001, // TBS_E_INTERNAL_ERROR
		0x80284006, // TBS_E_IOERROR
		0x80284008, // TBS_E_SERVICE_NOT_RUNNING
		0x80284009, // TBS_E_TOO_MANY_TBS_CONTEXTS
		0x8028400A, // TBS_E_TOO_MANY_RESOURCES
		0x8028400B, // TBS_E_SERVICE_START_PENDING
		0x8028400F, // TBS_E_TPM_NOT_FOUND
		0x80284010, // TBS_E_SERVICE_DISABLED
		0x80284012: // TBS_E_ACCESS_DENIED
		return codeTPMUnavailable
	}
	return codeFailed
}
