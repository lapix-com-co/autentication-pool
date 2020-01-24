package authentication_pool

import (
	"crypto/ed25519"
	"fmt"
	"github.com/lapix-com-co/authentication-pool/codes"
	"strings"
	"time"
)

var authenticationProvider *AuthenticationPoolProvider

var localAccountRetriever *LocalAccountRetriever

var localProvider *LocalProvider

var tokenProvider TokenProvider

var idsSlice = []string{
	"AAAA",
	"BBBB",
	"CCCC",
	"DDDD",
	"EEEE",
	"FFFF",
	"GGGG",
	"HHHH",
	"IIII",
	"JJJJ",
	"KKKK",
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
	tokenProvider = &JWTTokenProvider{
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

	localProvider = NewLocalProvider(NewInMemoryLocalAPI(id), true, localAccountSync, []OnSignUp{})

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

	// The given user is not authenticated.
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

	// Output: the given user does not exist
	// the given user needs to be validated
	// eyJhbGciOiJFZERTQSJ9.eyJlbWFpbCI6ImFueUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImV4cCI6MTU1NDM0MjAwLCJmYW1pbHlfbmFtZSI6IiIsImdpdmVuX25hbWUiOiIiLCJpYXQiOjE1NTQzMzYwMCwiaXNzIjoiYXBwIiwianRpIjoiSkpKSjpJSUlJIiwibmFtZSI6IiAiLCJuYmYiOjE1NTQzMzYwMCwicGhvbmVfbnVtYmVyIjoiIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIjpmYWxzZSwicGljdHVyZSI6bnVsbCwic3ViIjoiSkpKSiJ9
	// SkpKSj1ISEhIOkFBQTpKSkpK
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

func ExampleJWTTokenProvider_Refresh() {
	token, err := tokenProvider.CreateToken(&CreateTokenInput{
		ID: "identifier",
	})
	if err != nil {
		panic(err)
	}

	_, err = tokenProvider.Refresh(&RefreshTokenInput{
		RefreshToken: token.RefreshToken.Token,
		AccessToken:  token.AccessToken.Content,
	})

	fmt.Print(err.Error())
	// Output: the given access token has not expired
}

func ExampleLocalAccountManager_SendValidationCode() {
	localAPI := NewInMemoryLocalAPI(id)
	federatedAccountRepository := NewInMemoryFederatedAccountRepository()
	customerRepository := NewInMemoryCustomerRepository(id)
	localAccountSync := NewLocalSynchronization(customerRepository, federatedAccountRepository)
	localProvider := NewLocalProvider(localAPI, true, localAccountSync, []OnSignUp{})
	codesPolicy := codes.NewLimitIssuerPolicy(codes.NewInMemoryTriesRepository(), 5, time.Hour)
	codeHandler := codes.NewHandler(func() string { return "123456" }, codes.NewInMemoryRepository(), codesPolicy, time.Hour/2)
	codeSender := NewTestCodeSender()
	manager := NewLocalAccountManager(localAPI, localProvider, codeHandler, codeSender)

	email := "john.doe@gmail.com"
	pass := "qwerty"

	localAPI.Register(&RegisterInput{
		Email:     email,
		Password:  pass,
		Validated: false,
	})

	manager.SendValidationCode(&SendValidationCodeInput{Nickname: email})
	send := codeSender.store[email]
	fmt.Printf("code sent %s\n", send.code.Content)

	account, err := manager.ValidateAccount(&ValidateAccountInput{Nickname: email, Code: "123456"})
	if err != nil {
		panic(err)
	}

	fmt.Printf("validated %v\n", account.EmailVerified)

	_, err = manager.ValidateAccount(&ValidateAccountInput{Nickname: email, Code: "123456"})
	fmt.Println(err.Error())

	err = manager.RemindPassword(&RemindPasswordInput{Nickname: email})
	if err != nil {
		panic(err)
	}

	_, err = manager.ResetPassword(&ResetPasswordInput{Nickname: email, Code: "123456", Password: "newPassword$1"})
	if err != nil {
		panic(err)
	}

	// Output: code sent 123456
	// validated true
	// the given code is not available
}
