package authentication_pool

type AuthenticationPoolProvider struct {
	tokenProvider         TokenProvider
	localCustomerRegister LocalCustomerRegister
}

func NewAuthenticationPoolProvider(tokenProvider TokenProvider, localCustomerRegister LocalCustomerRegister) *AuthenticationPoolProvider {
	return &AuthenticationPoolProvider{tokenProvider: tokenProvider, localCustomerRegister: localCustomerRegister}
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

func (a AuthenticationPoolProvider) Verify(input string) (*AuthenticationVerifyOutput, error) {
	output, err := a.tokenProvider.Verify(input)
	if err != nil {
		return nil, err
	}

	if !output.Valid {
		return nil, ErrInvalidToken
	}

	customer, err := a.localCustomerRegister.Find(&FindLocalAccountInput{Email: *output.CustomerEmail})
	if err != nil {
		return nil, err
	}

	return &AuthenticationVerifyOutput{Account: customer}, nil
}
