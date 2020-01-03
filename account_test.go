package authentication_pool

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

type MockProvider struct {
	mock.Mock
}

func (f MockProvider) Retrieve(input *ValidationInput) (*ValidationOutput, error) {
	args := f.Called(input)
	return args.Get(0).(*ValidationOutput), args.Error(1)
}

func (f MockProvider) Name() string {
	args := f.Called()
	return args.String(0)
}

type MockAccountSynchronization struct {
	mock.Mock
}

func (m MockAccountSynchronization) Synchronize(input *SynchronizeInput) (*SynchronizeOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*SynchronizeOutput), args.Error(1)
}
func TestLocalAccountHandler_Register(t *testing.T) {
	type fields struct {
		provider           *MockProvider
		synchronizeAccount *MockAccountSynchronization
	}
	type args struct {
		input             *InitializeAccountInput
		customerID        string
		providerName      string
		providerReference string
		firstName         string
		lastName          string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *InitializeAccountOutput
		wantErr bool
	}{
		{
			name: "returns a valid account",
			fields: fields{
				provider:           new(MockProvider),
				synchronizeAccount: new(MockAccountSynchronization),
			},
			args: args{
				input: &InitializeAccountInput{
					Email:  "example@google.com",
					Secret: "secret",
				},
				customerID:        "customerID",
				providerName:      "mock",
				providerReference: "external-reference",
				firstName:         "john",
				lastName:          "doe",
			},
			want: &InitializeAccountOutput{
				ID:        "customerID",
				Email:     "example@google.com",
				Name:      "john doe",
				FirstName: "john",
				LastName:  "doe",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fields.provider.On("Name").Return(tt.args.providerName)
			tt.fields.provider.On("Retrieve", &ValidationInput{tt.args.input.Email, tt.args.input.Secret}).Return(&ValidationOutput{
				ID:        tt.args.providerReference,
				FirstName: tt.args.firstName,
				LastName:  tt.args.lastName,
				Email:     tt.args.input.Email,
				PhotoURL:  nil}, nil)

			tt.fields.synchronizeAccount.On("Synchronize", &SynchronizeInput{
				Provider:  tt.args.providerName,
				ID:        tt.args.providerReference,
				FirstName: tt.args.firstName,
				LastName:  tt.args.lastName,
				Email:     tt.args.input.Email,
				PhotoURL:  nil,
			}).Return(&SynchronizeOutput{CustomerID: tt.args.customerID}, nil)

			a := LocalAccountRetriever{
				provider:           tt.fields.provider,
				synchronizeAccount: tt.fields.synchronizeAccount,
			}
			got, err := a.Retrieve(tt.args.input)
			if (err != nil) && !tt.wantErr {
				t.Errorf("got err %v", err)
				return
			}

			tt.fields.provider.AssertExpectations(t)
			tt.fields.synchronizeAccount.AssertExpectations(t)
			assert.ObjectsAreEqualValues(got, tt.want)
		})
	}
}
