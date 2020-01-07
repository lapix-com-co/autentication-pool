package authentication_pool

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"
)

var authenticationProvider *AuthenticationPoolProvider

var localAccountRetriever *LocalAccountRetriever

var localProvider *LocalProvider

var idsSlice = []string{
	"AAAA",
	"BBBB",
	"CCCC",
	"DDDD",
	"EEEE",
	"FFFF",
	"GGGG",
	"HHHH",
}

func id() string {
	element, clone := idsSlice[len(idsSlice)-1], idsSlice[:len(idsSlice)-1]
	idsSlice = clone

	return element
}

func init() {
	date := time.Date(1974, 12, 5, 0, 0, 0, 0, time.UTC)
	timeProvider := newFixedTimeProvider(date)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	jwtHandler := &PascalDeKloeJWTHandler{
		algorithm:    "EdDSA",
		publicKey:    publicKey,
		privateKey:   privateKey,
		timeProvider: timeProvider.Now,
		idProvider:   id,
		timeToLive:   time.Minute * 10,
	}

	obscureTokenHandler := &ObscureUUIDTokenHandler{
		idProvider:      id,
		stringGenerator: func(length int) string { return "AAA" },
	}
	inMemoryTokenRepo := NewInMemoryTokenPersistence()
	tokenProvider := &JWTTokenProvider{
		issuer:         "app",
		audience:       []string{},
		jwtHandler:     jwtHandler,
		obscureHandler: obscureTokenHandler,
		timeProvider:   timeProvider.Now,
		persistence:    inMemoryTokenRepo,
	}

	federatedAccountRepository := NewInMemoryFederatedAccountRepository()
	customerRepository := NewInMemoryCustomerRepository(id)
	localAccountSync := NewLocalSynchronization(customerRepository, federatedAccountRepository)
	authenticationProvider = NewAuthenticationPoolProvider(tokenProvider, customerRepository)

	localProvider = NewLocalProvider(NewInMemoryLocalAPI(id))

	// Those are the available providers.
	providerFactory := NewProviderFactory(map[ProviderName]Provider{
		Google:   GoogleProvider{googlePeople{}},
		Local:    localProvider,
		Facebook: FacebookProvider{handuFacebook{}},
	})

	// Retrieves the provider based on the constant.
	provider, _ := providerFactory.New(Local)
	localAccountRetriever = NewLocalAccountRetriever(provider, localAccountSync)
}

func ExampleAuthenticationPoolProvider_Authenticate() {
	var email = "any@gmail.com"
	var password = "aA123456%"

	var authenticate = func() (*AuthenticateOutput, error) {
		return authenticationProvider.Authenticate(localAccountRetriever, &AuthenticateInput{Email: email, Secret: password})
	}

	// The given User is not authenticated.
	_, err := authenticate()
	fmt.Println(err.Error())

	_, err = localProvider.SignUp(&SignUpInput{Email: email, Secret: password, Validated: false})
	if err != nil {
		panic(err)
	}

	// The given User email needs to be validated.
	_, err = authenticate()
	fmt.Println(err.Error())

	_, err = localProvider.ValidatedEmail(&ValidateEmailInput{email})
	if err != nil {
		panic(err)
	}

	// Returns an access token and a refresh token. The last part of the
	// access token changes based in the ed25519 generated key.
	output, err := authenticate()
	if err != nil {
		panic(err)
	}
	parts := strings.Split(output.AccessToken.Content, ".")
	fmt.Println(fmt.Sprintf("%s.%s", parts[0], parts[1]))
	fmt.Println(output.RefreshToken.Token)

	// Output: the given user does not exists
	// the given user needs to be validated
	// eyJhbGciOiJFZERTQSJ9.eyJlbWFpbCI6ImFueUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImV4cCI6MTU1NDM0MjAwLCJmYW1pbHlfbmFtZSI6IiIsImdpdmVuX25hbWUiOiIiLCJpYXQiOjE1NTQzMzYwMCwiaXNzIjoiYXBwIiwianRpIjoiR0dHRzpGRkZGIiwibmFtZSI6IiAiLCJuYmYiOjE1NTQzMzYwMCwicGhvbmVfbnVtYmVyIjoiIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIjpmYWxzZSwicGljdHVyZSI6bnVsbCwic3ViIjoiR0dHRyJ9
	// RUVFRTpHR0dHOkFBQQ==
}

func ExampleAuthenticationPoolProvider_Verify() {
	var email = "john.doe@gmail.com"
	var password = "aA123456#"

	var authenticate = func() (*AuthenticateOutput, error) {
		return authenticationProvider.Authenticate(localAccountRetriever, &AuthenticateInput{Email: email, Secret: password})
	}

	_, err := localProvider.SignUp(&SignUpInput{Email: email, Secret: password, Validated: true})
	if err != nil {
		panic(err)
	}

	output, err := authenticate()
	if err != nil {
		panic(err)
	}

	// The given User has valid credentials.
	verifyOutput, err := authenticationProvider.Verify(output.AccessToken.Content)
	if err != nil {
		panic(err)
	}
	fmt.Print(verifyOutput.Account.Email)
	// Output: john.doe@gmail.com
}
