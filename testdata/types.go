package testdata

import (
	"authentication-pool"
	"github.com/stretchr/testify/mock"
)

type MockLocalCustomerProvider struct {
	mock.Mock
}

func (f MockLocalCustomerProvider) Create(input *authentication_pool.CreateLocalAccountInput) (*authentication_pool.CreateLocalAccountOutput, error) {
	args := f.Called(input)
	return args.Get(0).(*authentication_pool.CreateLocalAccountOutput), args.Error(1)
}

func (f MockLocalCustomerProvider) Find(input *authentication_pool.FindLocalAccountInput) (*authentication_pool.FindLocalAccountOutput, error) {
	args := f.Called(input)
	return args.Get(0).(*authentication_pool.FindLocalAccountOutput), args.Error(1)
}

type MockFederatedAccountProvider struct {
	mock.Mock
}

func (m MockFederatedAccountProvider) Create(input *authentication_pool.CreateFederatedAccountInput) (*authentication_pool.CreateFederatedAccountOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*authentication_pool.CreateFederatedAccountOutput), args.Error(1)
}

func (m MockFederatedAccountProvider) Find(input *authentication_pool.FindFederatedAccountInput) (*authentication_pool.FindFederatedAccountOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*authentication_pool.FindFederatedAccountOutput), args.Error(1)
}
