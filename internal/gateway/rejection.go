package gateway

import "errors"

// RequestRejected is proof that this invocation was rejected before a remote
// mutation could start. Transport failures and unknown acknowledgements must
// never be wrapped in this type merely because readback still looks unchanged.
type RequestRejected struct {
	Code   string
	Detail string
	Cause  error
}

func (e *RequestRejected) Error() string { return e.Detail }
func (e *RequestRejected) Unwrap() error { return e.Cause }
func IsDefiniteRejection(err error) bool {
	var rejected *RequestRejected
	return errors.As(err, &rejected)
}

func RejectBeforeMutation(code, detail string, cause error) error {
	return &RequestRejected{Code: code, Detail: detail, Cause: cause}
}
