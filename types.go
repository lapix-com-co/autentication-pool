package authentication_pool

import (
	"errors"
	"time"
)

var ErrInvalidToken = errors.New("the given Token is not valid")

var ErrExpiredToken = errors.New("the given Token has expired")

var ErrDisabledToken = errors.New("the given token has been revoked")

var ErrDuplicatedEntityExists = errors.New("the given user already exists")

var ErrNotFound = errors.New("the given user does not exists")

type AuthenticationHandler interface {
	// Authenticate finds a user by the credentials. If the given user is valid
	// in the provider but does not exists in the application thus
	// the federated account must be created. At the end the 
	// access Token are created.
	Authenticate(handler AccountRetriever, input *AuthenticateInput) (*AuthenticateOutput, error)
	// Verify takes an access token and validates if it exists and is
	//enabled, then it validates if it has expired.
	Verify(input string) error
}

type AuthenticateInput struct {
	Email  string
	Secret string
}

type AuthenticateOutput struct {
	AccessToken  *Token
	RefreshToken *RefreshToken
}

type AccountRetriever interface {
	// Retrieve returns the user from the provider
	// and synchronize the account data.
	Retrieve(input *InitializeAccountInput) (*InitializeAccountOutput, error)
}

type InitializeAccountInput struct {
	Email  string
	Secret string
}

type InitializeAccountOutput struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	FirstName     string
	LastName      string
	PhotoURL      *string
}

type UpdatePasswordInput struct {
	Email    string
	Password string
}

type ValidatedInput struct {
	UserID string
	Time   time.Time
}

type AccountSynchronization interface {
	// Synchronize create the customer account and the federated account if needed.
	Synchronize(input *SynchronizeInput) (*SynchronizeOutput, error)
}

type SynchronizeInput struct {
	Provider  string
	ID        string
	FirstName string
	LastName  string
	Email     string
	PhotoURL  *string
}

type SynchronizeOutput struct {
	CustomerID          string
	ReferenceInProvider string
	FirstName           string
	LastName            string
	Email               string
	PhotoURL            *string
}

type Provider interface {
	// Retrieve checks that the given credentials are correct.
	// The provider validates the secret provided by the
	// user, secret can ve a password, access Token, etc.
	Retrieve(input *ValidationInput) (*ValidationOutput, error)
	// Name returns the provider name like, google, facebook, local.
	Name() string
}

type ValidationInput struct {
	Email  string
	Secret string
}

func NewValidationInput(email string, secret string) *ValidationInput {
	return &ValidationInput{Email: email, Secret: secret}
}

type ValidationOutput struct {
	ID             string
	FirstName      string
	LastName       string
	Email          string
	PhotoURL       *string
	EmailValidated bool
}

func NewValidationOutput(ID, firstName, lastName, email string, photo *string, validated bool) *ValidationOutput {
	return &ValidationOutput{ID, firstName, lastName, email, photo, validated}
}

type ProviderWithStore interface {
	// SignUp allows to register a new user.
	SignUp(input *SignUpInput) (*SignUpOutput, error)
	// UpdatePassword updates the password to the given value.
	UpdatePassword(input *UpdatePasswordInput) (*InitializeAccountOutput, error)
	// ValidatedEmail mark the users as with validated email.
	ValidatedEmail(input *ValidateEmailInput) (*InitializeAccountOutput, error)
}

type ValidateEmailInput struct {
	Email string
}

type SignUpInput struct {
	Email     string
	Secret    string
	Validated bool
}

type SignUpOutput struct {
	ID          string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ValidatedAt *time.Time
}

// LocalCustomerRegister handle the creation of the user in the local repository as a user. The 
// difference between LocalCustomerRegister and FederatedAccountRegister is that a LocalCustomer can
// have many FederatedAccounts because you can be registered with facebook, google, with local credentials, etc.
type LocalCustomerRegister interface {
	Create(input *CreateLocalAccountInput) (*CreateLocalAccountOutput, error)
	// Find retrieve the account by email, if there are no valid accounts return nil, nil.
	Find(input *FindLocalAccountInput) (*FindLocalAccountOutput, error)
}

type CreateLocalAccountInput struct {
	Email string
}

type CreateLocalAccountOutput struct {
	ID        string
	Status    string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type FindLocalAccountInput struct {
	Email string
}

type FindLocalAccountOutput struct {
	ID        string
	Status    string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type FederatedAccountRegister interface {
	Create(input *CreateFederatedAccountInput) (*CreateFederatedAccountOutput, error)
	// Find retrieves a user by provider and user id. If the given user does not exists returns nil, nil.
	Find(input *FindFederatedAccountInput) (*FindFederatedAccountOutput, error)
}

type CreateFederatedAccountInput struct {
	UserID string
	// ReferenceInProvider stand for the id that the provider retrieves in the result
	ReferenceInProvider string
	Provider            string
	FirstName           string
	LastName            string
	PhotoURL            *string
}

type FindFederatedAccountOutput struct {
	ID                  string
	Provider            string
	UserID              string
	CreatedAt           time.Time
	ReferenceInProvider string
	FirstName           string
	LastName            string
}

type FindFederatedAccountInput struct {
	Provider string
	UserID   string
}

type CreateFederatedAccountOutput struct {
	ID        string
	CreatedAt time.Time
}

type TokenProvider interface {
	// CreateToken retrieves a new Token based in the user properties.
	CreateToken(input *CreateTokenInput) (*CreateTokenOutput, error)
	// Refresh takes a refresh Token, the refreshed token and creates a new one if its valid.
	Refresh(input *RefreshTokenInput) (*RefreshTokenOutput, error)
	// Verify takes a token and validate it. Does not read the status property from the storage.
	Verify(input string) (*VerifyTokenOutput, error)
}

type VerifyTokenOutput struct {
	Valid bool
}

type CreateTokenInput struct {
	ID            string
	Name          string
	GivenName     string
	FamilyName    string
	Email         string
	EmailVerified bool
	Picture       *string
}

type RefreshTokenOutput struct {
	AccessToken *Token
}

type CreateTokenOutput struct {
	AccessToken  *Token
	RefreshToken *RefreshToken
}

type Token struct {
	ID        string
	TokenType string
	Content   string
	ExpireAt  time.Time
}

type RefreshToken struct {
	ID      string
	Content string
	Token   string
}

type RefreshTokenInput struct {
	RefreshToken string
	AccessToken  string
}

type TokenPersistence interface {
	Save(entity *Entity) error
	// Find retrieves a token by its ID. If the given token
	// is not available returns nil, and ErrNotFound.
	Find(tokenID string) (*Entity, error)
}

type Entity struct {
	ID             string
	Type           string
	Status         string
	UserID         string
	Content        string
	RelatedTokenID *string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	ExpiredAt      *time.Time
}

func NewEntity(ID, tokenType, userID, content string, relatedTokenID *string, expiredAt *time.Time) *Entity {
	return &Entity{
		ID:             ID,
		Type:           tokenType,
		UserID:         userID,
		Content:        content,
		ExpiredAt:      expiredAt,
		Status:         "enabled",
		RelatedTokenID: relatedTokenID,
		CreatedAt:      time.Now(),
	}
}

type JWTHandler interface {
	Issue(input *IssueInput) (*IssueOutput, error)
	Verify(input *VerifyInput) (*VerifyOutput, error)
}

type IssueInput struct {
	RegisteredClaims RegisteredClaims
	PublicClaims     PublicClaims
	PrivateClaims    PrivateClaims
}

type IssueOutput struct {
	Token     *Token
	CreatedAt time.Time
}

type RegisteredClaims struct {
	Issuer         string
	Subject        string
	Audience       []string
	JsonWebTokenID string
}

type PublicClaims struct {
	Name                 string
	GivenName            string
	FamilyName           string
	Email                string
	EmailVerified        bool
	Picture              *string
	PhoneNumber          string
	PhoneNumberVerified  bool
	AdditionalProperties map[string]interface{}
}

type PrivateClaims struct {
	// Not Defined by now
}

type VerifyInput struct {
	Token string
}

type VerifyOutput struct {
	ExpiredAt        time.Time
	RegisteredClaims *RegisteredClaims
	PublicClaims     *PublicClaims
	PrivateClaims    *PrivateClaims
}
