package authentication_pool

type LocalSynchronization struct {
	localCustomerRegister    LocalCustomerRegister
	federatedAccountRegister FederatedAccountRegister
}

func NewLocalSynchronization(customerRegister LocalCustomerRegister, accountRegister FederatedAccountRegister) *LocalSynchronization {
	return &LocalSynchronization{
		localCustomerRegister:    customerRegister,
		federatedAccountRegister: accountRegister,
	}
}

func (l LocalSynchronization) Synchronize(input *SynchronizeInput) (*SynchronizeOutput, error) {
	output, err := l.initializeLocalAccount(input)
	if err != nil {
		return nil, err
	}

	federatedOutput, err := l.initializeFederatedAccount(output.CustomerID, input)
	if err != nil {
		return nil, err
	}

	return &SynchronizeOutput{
		NewUser:             output.NewUser,
		NewAccount:          federatedOutput.NewUser,
		CustomerID:          output.CustomerID,
		ReferenceInProvider: input.ID,
		FirstName:           input.FirstName,
		LastName:            input.LastName,
		Email:               input.Email,
		PhotoURL:            input.PhotoURL,
	}, nil
}

type initializeFederatedAccountOutput struct {
	NewUser bool
}

func (l LocalSynchronization) initializeFederatedAccount(customerID string, validationResult *SynchronizeInput) (*initializeFederatedAccountOutput, error) {
	account, err := l.federatedAccountRegister.Find(&FindFederatedAccountInput{
		Provider: validationResult.Provider,
		UserID:   customerID,
	})

	if err != nil || account != nil {
		return &initializeFederatedAccountOutput{NewUser: false}, err
	}

	_, err = l.federatedAccountRegister.Create(&CreateFederatedAccountInput{
		UserID:              customerID,
		Provider:            validationResult.Provider,
		ReferenceInProvider: validationResult.ID,
		FirstName:           validationResult.FirstName,
		LastName:            validationResult.LastName,
		PhotoURL:            validationResult.PhotoURL,
	})

	return &initializeFederatedAccountOutput{NewUser: true}, err
}

func (l LocalSynchronization) initializeLocalAccount(validationResult *SynchronizeInput) (*initializeLocalAccountOutput, error) {
	customer, err := l.localCustomerRegister.Find(&FindLocalAccountInput{Email: validationResult.Email})
	if err != nil {
		return nil, err
	}

	if customer != nil {
		return &initializeLocalAccountOutput{
			CustomerID: customer.ID,
			NewUser:    false,
		}, nil
	}

	result, err := l.localCustomerRegister.Create(&CreateLocalAccountInput{Email: validationResult.Email})
	if err != nil {
		return nil, err
	}

	return &initializeLocalAccountOutput{
		CustomerID: result.ID,
		NewUser:    true,
	}, nil
}

type initializeLocalAccountOutput struct {
	CustomerID string
	NewUser    bool
}
