package authentication_pool

import "fmt"

type LocalAccountRetriever struct {
	provider           Provider
	synchronizeAccount AccountSynchronization
}

func NewLocalAccountRetriever(provider Provider, synchronizeAccount AccountSynchronization) *LocalAccountRetriever {
	return &LocalAccountRetriever{provider: provider, synchronizeAccount: synchronizeAccount}
}

// Retrieve validates if the given credentials are valid for the provider, if the user is valid
// created the given user account and the federated account.
func (a LocalAccountRetriever) Retrieve(input *InitializeAccountInput) (*InitializeAccountOutput, error) {
	validationResult, err := a.provider.Retrieve(NewValidationInput(input.Email, input.Secret))
	if err != nil {
		return nil, err
	}

	output, err := a.synchronizeAccount.Synchronize(&SynchronizeInput{
		Provider:  a.provider.Name(),
		ID:        validationResult.ID,
		FirstName: validationResult.FirstName,
		LastName:  validationResult.LastName,
		Email:     validationResult.Email,
		PhotoURL:  validationResult.PhotoURL,
	})
	if err != nil {
		return nil, err
	}

	return &InitializeAccountOutput{
		ID:        output.CustomerID,
		Email:     validationResult.Email,
		Name:      fmt.Sprintf("%s %s", validationResult.FirstName, validationResult.LastName),
		FirstName: validationResult.FirstName,
		LastName:  validationResult.LastName,
		PhotoURL:  validationResult.PhotoURL,
	}, nil
}
