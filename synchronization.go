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
	customerID, err := l.initializeLocalAccount(input)
	if err != nil {
		return nil, err
	}

	err = l.initializeFederatedAccount(customerID, input)
	if err != nil {
		return nil, err
	}

	return &SynchronizeOutput{
		CustomerID:          *customerID,
		ReferenceInProvider: input.ID,
		FirstName:           input.FirstName,
		LastName:            input.LastName,
		Email:               input.Email,
		PhotoURL:            input.PhotoURL,
	}, nil
}

func (l LocalSynchronization) initializeFederatedAccount(customerID *string, validationResult *SynchronizeInput) error {
	account, err := l.federatedAccountRegister.Find(&FindFederatedAccountInput{
		Provider: validationResult.Provider,
		UserID:   *customerID,
	})

	if err != nil || account != nil {
		return err
	}

	_, err = l.federatedAccountRegister.Create(&CreateFederatedAccountInput{
		UserID:              *customerID,
		Provider:            validationResult.Provider,
		ReferenceInProvider: validationResult.ID,
		FirstName:           validationResult.FirstName,
		LastName:            validationResult.LastName,
		PhotoURL:            validationResult.PhotoURL,
	})

	return err
}

func (l LocalSynchronization) initializeLocalAccount(validationResult *SynchronizeInput) (*string, error) {
	customer, err := l.localCustomerRegister.Find(&FindLocalAccountInput{Email: validationResult.Email})
	if err != nil {
		return nil, err
	}

	if customer != nil {
		return &customer.ID, nil
	}

	result, err := l.localCustomerRegister.Create(&CreateLocalAccountInput{Email: validationResult.Email})
	if err != nil {
		return nil, err
	}

	return &result.ID, nil
}
