package authentication_pool

type ProviderError struct {
	Err     error
	Message string
}

func NewProviderError(err error, message string) *ProviderError {
	return &ProviderError{Err: err, Message: message}
}

func (e *ProviderError) Error() string {
	return e.Message
}

type ValidationInputFailed struct {
	Message string
}

func NewValidationInputFailed(error string) *ValidationInputFailed {
	return &ValidationInputFailed{error}
}

func (e *ValidationInputFailed) Error() string {
	return e.Message
}
