package authentication_pool

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"regexp"
	"time"
)

var _ Provider = &LocalProvider{}
var _ ProviderWithStore = &LocalProvider{}
var _ passwordHandler = &BCRYPTHandler{}

type OnSignUp func(output *SignUpOutput)

type LocalProvider struct {
	alias            string
	api              LocalAPI
	synchronizer     AccountSynchronization
	passwordPolicy   PasswordPolicy
	passwordCypher   passwordHandler
	timeProvider     timeProvider
	onSignUp         []OnSignUp
	checkCredentials bool
}

func NewLocalProvider(api LocalAPI, checkCredentials bool, synchronizer AccountSynchronization, onSignUp []OnSignUp) *LocalProvider {
	return &LocalProvider{
		alias:            "local",
		api:              api,
		synchronizer:     synchronizer,
		passwordPolicy:   NewBasicPasswordPolicy(),
		passwordCypher:   NewBCRYPTHandler(),
		timeProvider:     osTimeProvider,
		onSignUp:         onSignUp,
		checkCredentials: checkCredentials,
	}
}

type passwordHandler interface {
	Make(password string) (result string, err error)
	Compare(givenValue string, target string) (valid bool, err error)
}

type PasswordPolicy interface {
	Valid(password string) bool
	Message() string
}

func (g LocalProvider) UpdatePassword(input *UpdatePasswordInput) (*CustomerAccount, error) {
	user, err := g.api.User(input.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, NewValidationInputFailed("the given User does not exists")
	}

	password, err := g.createHashedPassword(input.Password)
	if err != nil {
		return nil, err
	}

	err = g.api.Update(&UpdateInput{
		ID:          user.ID,
		Password:    &password,
		ValidatedAt: user.ValidatedAt,
	})

	if err != nil {
		return nil, err
	}

	return &CustomerAccount{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.ValidatedAt != nil,
		Name:          user.Name(),
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		PhotoURL:      nil,
	}, nil
}

func (g LocalProvider) ValidatedEmail(input *ValidateEmailInput) (*CustomerAccount, error) {
	user, err := g.api.User(input.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, NewValidationInputFailed("the given User does not exist")
	}

	now := g.timeProvider()
	err = g.api.Update(&UpdateInput{
		ID:          user.ID,
		Password:    nil,
		ValidatedAt: &now,
	})

	if err != nil {
		return nil, err
	}

	return &CustomerAccount{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.ValidatedAt != nil,
		Name:          user.Name(),
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		PhotoURL:      nil,
	}, nil
}

func (g LocalProvider) Retrieve(input *ValidationInput) (*ValidationOutput, error) {
	content, err := g.api.User(input.Email)
	if err != nil {
		return nil, NewProviderError(err, "could not validate the given user")
	}

	if content == nil {
		return nil, NewValidationInputFailed("the given user does not exist")
	}

	if content.ValidatedAt == nil {
		return nil, NewValidationInputFailed("the given user needs to be validated")
	}

	if g.checkCredentials {
		correctPassword, err := g.passwordCypher.Compare(content.Password, input.Secret)
		if err != nil {
			return nil, NewProviderError(err, "could not compare the passwords")
		}

		if !correctPassword {
			return nil, NewValidationInputFailed("then credentials are not valid")
		}
	}

	return NewValidationOutput(content.ID, content.FirstName, content.LastName, content.Email, nil, content.ValidatedAt != nil), nil
}

func (g LocalProvider) Name() string {
	return g.alias
}

func (g LocalProvider) ValidateSignUp(input *SignUpInput) (*ValidateSignUpOutput, error) {
	user, err := g.api.User(input.Email)
	if err != nil {
		return nil, err
	}

	if user != nil {
		return &ValidateSignUpOutput{Err: NewValidationInputFailed("user already registered")}, nil
	}

	if err = g.validatePasswordPolicy(input.Secret); err != nil {
		return &ValidateSignUpOutput{Err: err}, nil
	}

	return &ValidateSignUpOutput{}, nil
}

func (g LocalProvider) SignUp(input *SignUpInput) (*SignUpOutput, error) {
	validationResult, err := g.ValidateSignUp(input)
	if err != nil {
		return nil, err
	}

	if validationResult.Err != nil {
		return nil, validationResult.Err
	}

	encryptedPassword, err := g.createHashedPassword(input.Secret)
	if err != nil {
		return nil, err
	}

	output, err := g.api.Register(&RegisterInput{
		Email:     input.Email,
		Password:  encryptedPassword,
		Validated: input.Validated,
	})

	if err != nil {
		return nil, err
	}

	syncOutput, err := g.synchronizer.Synchronize(&SynchronizeInput{
		Provider: g.Name(),
		ID:       output.ID,
		Email:    input.Email,
	})
	if err != nil {
		return nil, err
	}

	result := &SignUpOutput{
		ID:          syncOutput.CustomerID,
		Email:       input.Email,
		CreatedAt:   output.CreatedAt,
		UpdatedAt:   output.UpdatedAt,
		ValidatedAt: output.ValidatedAt,
	}

	for _, callback := range g.onSignUp {
		callback(result)
	}

	return result, nil
}

func (g LocalProvider) validatePasswordPolicy(password string) error {
	if !g.passwordPolicy.Valid(password) {
		return NewValidationInputFailed(g.passwordPolicy.Message())
	}

	return nil
}

func (g LocalProvider) createHashedPassword(password string) (string, error) {
	if err := g.validatePasswordPolicy(password); err != nil {
		return "", err
	}

	encryptedPassword, err := g.passwordCypher.Make(password)
	if err != nil {
		return "", NewProviderError(err, "could not encrypt the password")
	}

	return encryptedPassword, nil
}

type LocalAPI interface {
	// User returns a user by her email. If the User does not exist returns nil, nil.
	User(email string) (*LocalUser, error)
	Register(input *RegisterInput) (*RegisterOutput, error)
	Update(input *UpdateInput) error
}

type LocalUser struct {
	ID          string
	Email       string
	FirstName   string
	LastName    string
	Password    string
	ValidatedAt *time.Time
}

func (l *LocalUser) Name() string {
	return fmt.Sprintf("%s %s", l.FirstName, l.LastName)
}

type RegisterInput struct {
	Email     string
	Password  string
	Validated bool
}

type RegisterOutput struct {
	ID          string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ValidatedAt *time.Time
}

type UpdateInput struct {
	ID          string
	Password    *string
	ValidatedAt *time.Time
}

type BCRYPTHandler struct {
	cost int
}

func NewBCRYPTHandler() *BCRYPTHandler {
	return &BCRYPTHandler{cost: 10}
}

func (b BCRYPTHandler) Make(password string) (string, error) {
	content := []byte(password)
	result, err := bcrypt.GenerateFromPassword(content, b.cost)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func (b BCRYPTHandler) Compare(givenValue string, target string) (valid bool, err error) {
	err = bcrypt.CompareHashAndPassword([]byte(string(givenValue)), []byte(target))
	return err == nil, nil
}

type BasicPasswordPolicy struct {
	pattern *regexp.Regexp
}

// Basic password validation policy:
// - At least 8 characters.
// - Must contain at least 1 uppercase letter, 1 lowercase letter, 1 special character, and 1 number.
func NewBasicPasswordPolicy() *BasicPasswordPolicy {
	passwordPattern := regexp.MustCompile("^(.{0,7}|[^0-9]*|[^A-Z]*|[^a-z]*|[a-zA-Z0-9]*)$")
	return &BasicPasswordPolicy{passwordPattern}
}

func (b BasicPasswordPolicy) Valid(password string) bool {
	if len(password) < 8 || len(password) > 30 {
		return false
	}

	return !b.pattern.MatchString(password)
}

func (b BasicPasswordPolicy) Message() string {
	return "The password can contain special characters. Must have at least 8 characters. Must contain " +
		"at least: 1 uppercase letter, 1 lowercase letter, 1 special character and 1 number"
}
