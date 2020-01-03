package authentication_pool

type AuthenticationPoolProvider struct {
	tokenProvider TokenProvider
}

func NewAuthenticationPoolProvider(tokenProvider TokenProvider) *AuthenticationPoolProvider {
	return &AuthenticationPoolProvider{tokenProvider: tokenProvider}
}

func (a AuthenticationPoolProvider) Authenticate(handler AccountRetriever, input *AuthenticateInput) (*AuthenticateOutput, error) {
	account, err := handler.Retrieve(&InitializeAccountInput{
		Email:  input.Email,
		Secret: input.Secret,
	})

	if err != nil {
		return nil, err
	}

	tokens, err := a.tokenProvider.CreateToken(&CreateTokenInput{
		ID:            account.ID,
		Name:          account.Name,
		GivenName:     account.FirstName,
		FamilyName:    account.LastName,
		Email:         account.Email,
		EmailVerified: account.EmailVerified,
		Picture:       account.PhotoURL,
	})

	if err != nil {
		return nil, err
	}

	return &AuthenticateOutput{
		Account:      account,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (a AuthenticationPoolProvider) Verify(input string) error {
	output, err := a.tokenProvider.Verify(input)
	if err != nil {
		return err
	}

	if !output.Valid {
		return ErrInvalidToken
	}

	return nil
}
