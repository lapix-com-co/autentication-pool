package authentication_pool

import (
	"crypto/ed25519"
	"reflect"
	"testing"
	"time"
)

func mockIDProvider() string {
	return "generated.id"
}

type mockTimeProvider struct {
	defaultTime time.Time
}

func (m mockTimeProvider) Now() time.Time {
	return m.defaultTime
}

func TestPascalDeKloeJWTHandler_Issue(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	type fields struct {
		algorithm  string
		publicKey  []byte
		privateKey []byte
	}
	type args struct {
		input *IssueInput
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *IssueOutput
		wantErr bool
	}{
		{
			name: "Token signed",
			fields: fields{
				algorithm:  "EdDSA",
				publicKey:  publicKey,
				privateKey: privateKey,
			},
			args: args{
				input: &IssueInput{
					RegisteredClaims: RegisteredClaims{
						Issuer:   "custom-app",
						Subject:  "123456",
						Audience: []string{"app-ID"},
					},
					PublicClaims: PublicClaims{
						Name:       "john doe",
						GivenName:  "john",
						FamilyName: "doe",
					},
					PrivateClaims: PrivateClaims{},
				},
			},
			want: &IssueOutput{
				CreatedAt: mockTimeProvider{time.Date(1974, 12, 4, 6-5, 0, 0, 0, time.UTC)}.Now(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeProvider := &mockTimeProvider{time.Date(1974, 12, 4, 6-5, 0, 0, 0, time.UTC)}
			p := PascalDeKloeJWTHandler{
				algorithm:     tt.fields.algorithm,
				publicKey:     tt.fields.publicKey,
				privateKey:    tt.fields.privateKey,
				timeProvider:  timeProvider.Now,
				idProvider:    mockIDProvider,
				timeToLive:    time.Minute * 5,
				timeToBeValid: 0,
			}
			got, err := p.Issue(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Issue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if !reflect.DeepEqual(got.CreatedAt, tt.want.CreatedAt) {
				t.Errorf("Issue() got = %v, want %v", got, tt.want)
			}

			_, err = p.Verify(&VerifyInput{Token: got.Token.Content})
			if err != nil {
				t.Errorf("Verify() error = %v", err)
				return
			}
		})
	}
}

func TestPascalDeKloeJWTHandler_Verify(t *testing.T) {
	defaultTime := time.Date(1974, 12, 4, 6-5, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	prov := PascalDeKloeJWTHandler{
		algorithm:     "EdDSA",
		publicKey:     publicKey,
		privateKey:    privateKey,
		timeProvider:  mockTimeProvider{defaultTime}.Now,
		idProvider:    mockIDProvider,
		timeToLive:    time.Second * 10,
		timeToBeValid: 0,
	}
	validTokenOutput, err := prov.Issue(&IssueInput{
		RegisteredClaims: RegisteredClaims{JsonWebTokenID: "generated.id"},
		PublicClaims:     PublicClaims{},
		PrivateClaims:    PrivateClaims{},
	})

	if err != nil {
		panic(err)
	}

	type fields struct {
		algorithm     string
		publicKey     []byte
		privateKey    []byte
		timeProvider  timeProvider
		timeToLive    time.Duration
		timeToBeValid time.Duration
	}
	type args struct {
		input *VerifyInput
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *VerifyOutput
		wantErr bool
	}{
		{
			name: "is valid",
			fields: fields{
				algorithm:    "EdDSA",
				publicKey:    publicKey,
				privateKey:   privateKey,
				timeProvider: mockTimeProvider{defaultTime}.Now,
			},
			args: args{
				input: &VerifyInput{
					Token: validTokenOutput.Token.Content,
				},
			},
			want: &VerifyOutput{
				RegisteredClaims: &RegisteredClaims{JsonWebTokenID: validTokenOutput.Token.ID},
				PublicClaims:     &PublicClaims{},
				PrivateClaims:    &PrivateClaims{},
				ExpiredAt:        defaultTime.Add(time.Second * 10),
			},
			wantErr: false,
		},
		{
			name: "Token is not valid",
			fields: fields{
				algorithm:    "EdDSA",
				publicKey:    publicKey,
				privateKey:   privateKey,
				timeProvider: mockTimeProvider{}.Now,
			},
			args:    args{input: &VerifyInput{Token: "any-string"}},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PascalDeKloeJWTHandler{
				algorithm:     tt.fields.algorithm,
				publicKey:     tt.fields.publicKey,
				privateKey:    tt.fields.privateKey,
				timeProvider:  tt.fields.timeProvider,
				idProvider:    mockIDProvider,
				timeToLive:    tt.fields.timeToLive,
				timeToBeValid: tt.fields.timeToBeValid,
			}
			got, err := p.Verify(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if !reflect.DeepEqual(got.ExpiredAt, tt.want.ExpiredAt) {
				t.Errorf("Verify() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got.RegisteredClaims, tt.want.RegisteredClaims) {
				t.Errorf("Verify() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got.PublicClaims, tt.want.PublicClaims) {
				t.Errorf("Verify() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_uuidGenerator_New(t *testing.T) {
	tests := []struct{ name string }{
		{
			name: "returns a valid uuid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := UUIDGenerator
			if got := u(); len(got) == 0 {
				t.Errorf("New() = %v", got)
			}
		})
	}
}

func TestJWTTokenProvider_CreateToken(t *testing.T) {
	type fields struct {
		issuer         string
		audience       []string
		jwtHandler     JWTHandler
		obscureHandler ObscureTokenHandler
		timeProvider   timeProvider
		persistence    TokenPersistence
	}
	type args struct {
		input *CreateTokenInput
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *CreateTokenOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := JWTTokenProvider{
				issuer:         tt.fields.issuer,
				audience:       tt.fields.audience,
				jwtHandler:     tt.fields.jwtHandler,
				obscureHandler: tt.fields.obscureHandler,
				timeProvider:   tt.fields.timeProvider,
				persistence:    tt.fields.persistence,
			}
			got, err := j.CreateToken(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateToken() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewObscureTokenFromRawContent(t *testing.T) {
	type args struct {
		token string
	}
	tests := []struct {
		name    string
		args    args
		want    *ObscureToken
		wantErr bool
	}{
		{
			name: "returns the token",
			args: args{
				token: "Y3VzdG9tZXJJZDp0b2tlbklkOmFkZGl0aW9uYWw=",
			},
			want: &ObscureToken{
				id:      "customerId",
				content: "tokenId",
				subject: "additional",
			},
			wantErr: false,
		},
		{
			name: "returns the with invalid token",
			args: args{
				token: "ERROR",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewObscureTokenFromRawContent(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewObscureTokenFromRawContent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewObscureTokenFromRawContent() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestObscureToken_Token(t *testing.T) {
	type fields struct {
		id      string
		content string
		subject string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "can build the token",
			fields: fields{
				id:      "ID",
				content: "token-content",
				subject: "owner",
			},
			want: "SUQ6dG9rZW4tY29udGVudDpvd25lcg==",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &ObscureToken{
				id:      tt.fields.id,
				content: tt.fields.content,
				subject: tt.fields.subject,
			}
			if got := o.Token(); got != tt.want {
				t.Errorf("Token() = %v, want %v", got, tt.want)
			}
		})
	}
}
