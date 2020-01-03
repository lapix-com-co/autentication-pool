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

type LocalProvider struct {
	alias          string
	api            localAPI
	passwordPolicy PasswordPolicy
	passwordCypher passwordHandler
	timeProvider   timeProvider
}

func NewLocalProvider(api localAPI) *LocalProvider {
	return &LocalProvider{
		alias:          "local",
		api:            api,
		passwordPolicy: NewBasicPasswordPolicy(),
		passwordCypher: NewBCRYPTHandler(),
		timeProvider:   osTimeProvider,
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

func (g LocalProvider) UpdatePassword(input *UpdatePasswordInput) (*InitializeAccountOutput, error) {
	user, err := g.api.user(input.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, NewValidationInputFailed("the given user does not exists")
	}

	password, err := g.createHashedPassword(input.Password)
	if err != nil {
		return nil, err
	}

	err = g.api.update(&UpdateInput{
		ID:          user.ID,
		Password:    &password,
		ValidatedAt: user.ValidatedAt,
	})

	if err != nil {
		return nil, err
	}

	return &InitializeAccountOutput{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.ValidatedAt != nil,
		Name:          user.Name(),
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		PhotoURL:      nil,
	}, nil
}

func (g LocalProvider) ValidatedEmail(input *ValidateEmailInput) (*InitializeAccountOutput, error) {
	user, err := g.api.user(input.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, NewValidationInputFailed("the given user does not exists")
	}

	now := g.timeProvider()
	err = g.api.update(&UpdateInput{
		ID:          user.ID,
		Password:    nil,
		ValidatedAt: &now,
	})

	if err != nil {
		return nil, err
	}

	return &InitializeAccountOutput{
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
	content, err := g.api.user(input.Email)
	if err != nil {
		return nil, NewProviderError(err, "could not validate the given user")
	}

	if content == nil {
		return nil, NewValidationInputFailed("the given user does not exists")
	}

	if content.ValidatedAt == nil {
		return nil, NewValidationInputFailed("the given user needs to be validated")
	}

	correctPassword, err := g.passwordCypher.Compare(input.Secret, content.Password)
	if err != nil {
		return nil, NewProviderError(err, "could not compare the passwords")
	}

	if !correctPassword {
		return nil, NewValidationInputFailed("then given password is not valid")
	}

	return NewValidationOutput(content.ID, content.FirstName, content.LastName, content.Email, nil, content.ValidatedAt != nil), nil
}

func (g LocalProvider) Name() string {
	return g.alias
}

func (g LocalProvider) SignUp(input *SignUpInput) (*SignUpOutput, error) {
	user, err := g.api.user(input.Email)
	if err != nil {
		return nil, err
	}

	if user != nil {
		return nil, NewValidationInputFailed("a user with the same email already exists")
	}

	encryptedPassword, err := g.createHashedPassword(input.Secret)
	if err != nil {
		return nil, err
	}

	output, err := g.api.register(&RegisterInput{
		Email:     input.Email,
		Password:  encryptedPassword,
		Validated: input.Validated,
	})

	if err != nil {
		return nil, err
	}

	return &SignUpOutput{
		ID:          output.ID,
		CreatedAt:   output.CreatedAt,
		UpdatedAt:   output.UpdatedAt,
		ValidatedAt: output.ValidatedAt,
	}, nil
}

func (g LocalProvider) createHashedPassword(password string) (string, error) {
	if !g.passwordPolicy.Valid(password) {
		return "", NewValidationInputFailed(g.passwordPolicy.Message())
	}

	encryptedPassword, err := g.passwordCypher.Make(password)
	if err != nil {
		return "", NewProviderError(err, "could not encrypt the password")
	}
	return encryptedPassword, nil
}

type localAPI interface {
	// user returns a user by it's email. If the user does not exists returns nil, nil
	user(email string) (*localUser, error)
	register(input *RegisterInput) (*RegisterOutput, error)
	update(input *UpdateInput) error
}

type localUser struct {
	ID          string
	Email       string
	FirstName   string
	LastName    string
	Password    string
	ValidatedAt *time.Time
}

func (l *localUser) Name() string {
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
	hashedPassword := []byte(target)
	password := []byte(givenValue)
	err = bcrypt.CompareHashAndPassword(hashedPassword, password)
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
	return "The password can container special characters. Must to have at least 6 characters. Must container " +
		"at least: 1 uppercase letter, 1 lowercase letter, 1 special character and 1 number"
}
