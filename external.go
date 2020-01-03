package authentication_pool

type ExternalProvider struct {
	api ExternalProviderAPI
}

type ExternalTokenContent struct {
	ID        string
	Email     string
	FirstName string
	LastName  string
	PhotoURL  *string
}

type ExternalProviderAPI interface {
	user(token string) (*ExternalTokenContent, error)
}

func (g ExternalProvider) Validate(input *ValidationInput) (*ValidationOutput, error) {
	content, err := g.api.user(input.Secret)
	if err != nil {
		return nil, NewProviderError(err, "could not validate the given Token")
	}

	if content.Email != input.Email {
		return nil, NewValidationInputFailed("the given email does not match with the Token content")
	}

	return NewValidationOutput(content.ID, content.FirstName, content.LastName, content.Email, content.PhotoURL, true), nil
}
