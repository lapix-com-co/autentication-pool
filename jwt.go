package authentication_pool

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/lapix-com-co/authentication-pool/random"
	"github.com/pascaldekloe/jwt"
	"strings"
	"time"
)

type JWTTokenProvider struct {
	issuer   string
	audience []string

	jwtHandler     JWTHandler
	obscureHandler ObscureTokenHandler
	timeProvider   timeProvider
	persistence    TokenPersistence
}

func NewJWTTokenProvider(issuer string, audience []string, jwtHandler JWTHandler, obscureHandler ObscureTokenHandler, persistence TokenPersistence) *JWTTokenProvider {
	return &JWTTokenProvider{
		issuer:         issuer,
		audience:       audience,
		jwtHandler:     jwtHandler,
		obscureHandler: obscureHandler,
		persistence:    persistence,
		timeProvider:   osTimeProvider,
	}
}

func (j JWTTokenProvider) CreateToken(input *CreateTokenInput) (*CreateTokenOutput, error) {
	issueInput := &IssueInput{
		RegisteredClaims: RegisteredClaims{
			Issuer:   j.issuer,
			Subject:  input.ID,
			Audience: j.audience,
		},
		PublicClaims: PublicClaims{
			Name:                 input.Name,
			GivenName:            input.GivenName,
			FamilyName:           input.FamilyName,
			Email:                input.Email,
			EmailVerified:        input.EmailVerified,
			Picture:              input.Picture,
			PhoneNumber:          "",
			PhoneNumberVerified:  false,
			AdditionalProperties: nil,
		},
		PrivateClaims: PrivateClaims{},
	}

	output, err := j.jwtHandler.Issue(issueInput)
	if err != nil {
		return nil, err
	}

	obscure, err := j.obscureHandler.Issue(input.ID)
	if err != nil {
		return nil, err
	}

	tokens := &CreateTokenOutput{
		AccessToken: output.Token,
		RefreshToken: &RefreshToken{
			ID:      obscure.ObscureToken.ID(),
			Content: obscure.ObscureToken.Value(),
			Token:   obscure.ObscureToken.Token(),
		},
	}

	err = j.persistTokens(tokens, input.ID)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

func (j JWTTokenProvider) persistTokens(tokens *CreateTokenOutput, accountID string) (err error) {
	accessToken := NewEntity(
		tokens.AccessToken.ID,
		tokens.AccessToken.TokenType,
		accountID,
		tokens.AccessToken.Content,
		nil,
		&tokens.AccessToken.ExpireAt)
	refreshToken := NewEntity(
		tokens.RefreshToken.ID,
		"refresh",
		accountID,
		tokens.RefreshToken.Content,
		&tokens.AccessToken.ID,
		nil)

	if err = j.persistence.Save(accessToken); err != nil {
		return
	}
	if err = j.persistence.Save(refreshToken); err != nil {
		return
	}

	return
}

func (j JWTTokenProvider) Verify(input string) (*VerifyTokenOutput, error) {
	result, err := j.jwtHandler.Verify(&VerifyInput{input})
	if err != nil {
		return nil, err
	}

	if !j.validTime(result.ExpiredAt) {
		return nil, ErrExpiredToken
	}

	return &VerifyTokenOutput{Valid: true, CustomerEmail: &result.PublicClaims.Email}, nil
}

func (j JWTTokenProvider) validTime(input time.Time) bool {
	now := j.timeProvider()

	return input.After(now)
}

func (j JWTTokenProvider) Refresh(input *RefreshTokenInput) (*RefreshTokenOutput, error) {
	result, err := j.jwtHandler.Verify(&VerifyInput{input.AccessToken})
	if err != nil {
		return nil, err
	}

	if j.validTime(result.ExpiredAt) {
		return nil, errors.New("the given access token has not expired")
	}

	obscureToken, err := NewObscureTokenFromRawContent(input.RefreshToken)
	if err != nil {
		return nil, err
	}

	refreshToken, err := j.persistence.Find(obscureToken.ID())
	if err != nil {
		return nil, err
	}

	if refreshToken.Status != "enabled" {
		return nil, ErrDisabledToken
	}

	if refreshToken.Content != obscureToken.Value() {
		return nil, ErrInvalidToken
	}

	issueTokenOutput, err := j.jwtHandler.Issue(&IssueInput{
		RegisteredClaims: *result.RegisteredClaims,
		PublicClaims:     *result.PublicClaims,
		PrivateClaims:    PrivateClaims{},
	})

	if err != nil {
		return nil, err
	}

	return &RefreshTokenOutput{AccessToken: issueTokenOutput.Token}, nil
}

type PascalDeKloeJWTHandler struct {
	algorithm     string
	publicKey     []byte
	privateKey    []byte
	timeProvider  timeProvider
	idProvider    IDGenerator
	timeToLive    time.Duration
	timeToBeValid time.Duration
}

func NewPascalDeKloeJWTHandler(algorithm string, publicKey, privateKey []byte, timeToLive time.Duration, timeToBeValid time.Duration) *PascalDeKloeJWTHandler {
	return &PascalDeKloeJWTHandler{
		algorithm:     algorithm,
		publicKey:     publicKey,
		privateKey:    privateKey,
		timeProvider:  osTimeProvider,
		idProvider:    UUIDGenerator,
		timeToLive:    timeToLive,
		timeToBeValid: timeToBeValid,
	}
}

type timeProvider func() time.Time

type fixedTimeProvider struct {
	now time.Time
}

func newFixedTimeProvider(now time.Time) *fixedTimeProvider {
	return &fixedTimeProvider{now: now}
}

func (f *fixedTimeProvider) Now() time.Time {
	return f.now
}

func osTimeProvider() time.Time {
	return time.Now()
}

func UUIDGenerator() string {
	return uuid.New().String()
}

func (p PascalDeKloeJWTHandler) Issue(input *IssueInput) (*IssueOutput, error) {
	now := p.timeProvider()
	expireAt := now.Add(p.timeToLive)
	input.RegisteredClaims.JsonWebTokenID = fmt.Sprintf("%s:%s", input.RegisteredClaims.Subject, p.idProvider())

	c := jwt.Claims{
		Registered: jwt.Registered{
			ID:        input.RegisteredClaims.JsonWebTokenID,
			Issuer:    input.RegisteredClaims.Issuer,
			Subject:   input.RegisteredClaims.Subject,
			Audiences: input.RegisteredClaims.Audience,
			Issued:    jwt.NewNumericTime(now),
			Expires:   jwt.NewNumericTime(expireAt),
			NotBefore: jwt.NewNumericTime(now.Add(p.timeToBeValid)),
		},
		Set: map[string]interface{}{
			"email":                 input.PublicClaims.Email,
			"name":                  input.PublicClaims.Name,
			"family_name":           input.PublicClaims.FamilyName,
			"email_verified":        input.PublicClaims.EmailVerified,
			"given_name":            input.PublicClaims.GivenName,
			"phone_number":          input.PublicClaims.PhoneNumber,
			"phone_number_verified": input.PublicClaims.PhoneNumberVerified,
			"picture":               input.PublicClaims.Picture,
		},
	}

	token, err := c.EdDSASign(p.privateKey)
	if err != nil {
		return nil, err
	}

	return &IssueOutput{
		Token: &Token{
			ID:         input.RegisteredClaims.JsonWebTokenID,
			TokenType:  "Bearer",
			Content:    string(token),
			ExpireAt:   expireAt,
			TimeToLive: int64(p.timeToLive),
		},
		CreatedAt: now,
	}, nil
}

func (p PascalDeKloeJWTHandler) Verify(input *VerifyInput) (*VerifyOutput, error) {
	claims, err := jwt.EdDSACheck([]byte(input.Token), p.publicKey)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var public PublicClaims
	public.Name, _ = claims.String("name")
	public.GivenName, _ = claims.String("given_name")
	public.FamilyName, _ = claims.String("family_name")
	public.Email, _ = claims.String("email")
	public.EmailVerified, _ = claims.Set["email_verified"].(bool)
	if s, ok := claims.String("photo"); ok {
		public.Picture = &s
	}
	public.PhoneNumber, _ = claims.String("phone_number")
	public.PhoneNumberVerified, _ = claims.Set["phone_number_verified"].(bool)

	return &VerifyOutput{
		ExpiredAt: claims.Expires.Time(),
		RegisteredClaims: &RegisteredClaims{
			Issuer:         claims.Issuer,
			Subject:        claims.Subject,
			Audience:       claims.Audiences,
			JsonWebTokenID: claims.ID,
		},
		PublicClaims:  &public,
		PrivateClaims: &PrivateClaims{},
	}, nil
}

type ObscureVerifyTokenInput struct {
	Token string
}

type ObscureVerifyTokenOutput struct {
	Subject string
	ID      string
}

type ObscureTokenHandler interface {
	Issue(owner string) (*IssueObscureTokenOutput, error)
}

type IssueObscureTokenOutput struct {
	ObscureToken *ObscureToken
}

type ObscureUUIDTokenHandler struct {
	idProvider      IDGenerator
	stringGenerator StringGenerator
}

func NewObscureUUIDTokenHandler() *ObscureUUIDTokenHandler {
	return &ObscureUUIDTokenHandler{
		idProvider:      UUIDGenerator,
		stringGenerator: random.Str,
	}
}

func (o ObscureUUIDTokenHandler) Issue(owner string) (*IssueObscureTokenOutput, error) {
	return &IssueObscureTokenOutput{
		ObscureToken: NewObscureToken(o.idProvider(), o.stringGenerator(450), owner),
	}, nil
}

type ObscureToken struct {
	id      string
	content string
	subject string
}

type StringGenerator func(length int) string

type IDGenerator func() string

func (o *ObscureToken) ID() string {
	return o.id
}

func (o *ObscureToken) Value() string {
	return o.content
}

func (o *ObscureToken) Token() string {
	token := fmt.Sprintf("%s:%s:%s", o.ID(), o.Value(), o.subject)
	return base64.URLEncoding.EncodeToString([]byte(token))
}

func NewObscureToken(id, token, subject string) *ObscureToken {
	return &ObscureToken{
		id:      fmt.Sprintf("%s=%s", subject, id),
		content: token,
		subject: subject,
	}
}

func NewObscureTokenFromRawContent(token string) (*ObscureToken, error) {
	result, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(string(result), ":")

	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	return &ObscureToken{
		id:      parts[0],
		content: parts[1],
		subject: parts[2],
	}, nil
}
