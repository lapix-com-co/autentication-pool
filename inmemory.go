package authentication_pool

import "time"

type InMemoryLocalAPI struct {
	emailSet    map[string]*LocalUser
	idSet       map[string]*LocalUser
	idGenerator IDGenerator
}

func NewInMemoryLocalAPI(provider IDGenerator) *InMemoryLocalAPI {
	return &InMemoryLocalAPI{
		idGenerator: provider,
		emailSet:    map[string]*LocalUser{},
		idSet:       map[string]*LocalUser{},
	}
}

func (i InMemoryLocalAPI) User(email string) (*LocalUser, error) {
	if v, ok := i.emailSet[email]; ok {
		return v, nil
	}
	return nil, nil
}

func (i InMemoryLocalAPI) Register(input *RegisterInput) (*RegisterOutput, error) {
	if _, ok := i.emailSet[input.Email]; ok {
		return nil, ErrDuplicatedEntityExists
	}

	user := &LocalUser{
		ID:        i.idGenerator(),
		Email:     input.Email,
		FirstName: "",
		LastName:  "",
		Password:  input.Password,
		Enabled:   true,
	}

	if input.Validated {
		date := osTimeProvider()
		user.ValidatedAt = &date
	}

	i.emailSet[input.Email] = user
	i.idSet[user.ID] = user

	return &RegisterOutput{
		ID:          user.ID,
		CreatedAt:   osTimeProvider(),
		UpdatedAt:   osTimeProvider(),
		ValidatedAt: user.ValidatedAt,
	}, nil
}

func (i InMemoryLocalAPI) Update(input *UpdateInput) error {
	if user, ok := i.idSet[input.ID]; !ok {
		return ErrNotFound
	} else {
		if input.ValidatedAt != nil {
			user.ValidatedAt = input.ValidatedAt
		}

		if input.Password != nil {
			user.Password = *input.Password
		}

		i.idSet[input.ID] = user

		return nil
	}
}

type CustomerEntity struct {
	ID        string
	Status    string
	Enabled   bool
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type InMemoryCustomerRepository struct {
	set         map[string]*CustomerEntity
	idGenerator IDGenerator
}

func NewInMemoryCustomerRepository(generator IDGenerator) *InMemoryCustomerRepository {
	return &InMemoryCustomerRepository{
		idGenerator: generator,
		set:         map[string]*CustomerEntity{},
	}
}

func (i InMemoryCustomerRepository) Create(input *CreateLocalAccountInput) (*LocalAccount, error) {
	if _, ok := i.set[input.Email]; ok {
		return nil, ErrDuplicatedEntityExists
	}

	entity := &CustomerEntity{
		ID:        i.idGenerator(),
		Status:    "enabled",
		Email:     input.Email,
		CreatedAt: osTimeProvider(),
		UpdatedAt: osTimeProvider(),
	}

	i.set[input.Email] = entity
	return modelToEntity(entity), nil
}

func (i InMemoryCustomerRepository) Find(input *FindLocalAccountInput) (*LocalAccount, error) {
	if user, ok := i.set[input.Email]; !ok {
		return nil, nil
	} else {
		return modelToEntity(user), nil
	}
}

func (i InMemoryCustomerRepository) Delete(input *DeleteLocalAccountInput) (*LocalAccount, error) {
	if v, ok := i.set[input.Email]; !ok {
		delete(i.set, input.Email)
		return modelToEntity(v), nil
	}

	return nil, ErrNotFound
}

func (i InMemoryCustomerRepository) Enable(input *EnableLocalAccountInput) (*LocalAccount, error) {
	if user, ok := i.set[input.Email]; !ok {
		return nil, ErrNotFound
	} else {
		user.Enabled = true
		return modelToEntity(user), nil
	}
}

func (i InMemoryCustomerRepository) Disable(input *DisableLocalAccountInput) (*LocalAccount, error) {
	if user, ok := i.set[input.Email]; !ok {
		return nil, ErrNotFound
	} else {
		user.Enabled = false
		return modelToEntity(user), nil
	}
}

func modelToEntity(entity *CustomerEntity) *LocalAccount {
	return &LocalAccount{
		ID:        entity.ID,
		Status:    entity.Status,
		Email:     entity.Email,
		Enabled:   entity.Enabled,
		CreatedAt: entity.CreatedAt,
		UpdatedAt: entity.UpdatedAt,
	}
}

type FederatedAccountModel struct {
	ID                  string
	Provider            string
	UserID              string
	ReferenceInProvider string
	FirstName           string
	LastName            string
	CreatedAt           time.Time
}

type InMemoryFederatedAccountRepository struct {
	// Providers -> UserID
	userIDSet map[string]map[string]*FederatedAccountModel
}

func NewInMemoryFederatedAccountRepository() *InMemoryFederatedAccountRepository {
	return &InMemoryFederatedAccountRepository{
		userIDSet: map[string]map[string]*FederatedAccountModel{},
	}
}

func (i InMemoryFederatedAccountRepository) Create(input *CreateFederatedAccountInput) (*CreateFederatedAccountOutput, error) {
	if users, ok := i.userIDSet[input.Provider]; ok {
		if _, ok := users[input.UserID]; ok {
			return nil, ErrDuplicatedEntityExists
		}
	} else {
		i.userIDSet[input.Provider] = map[string]*FederatedAccountModel{}
	}

	entity := &FederatedAccountModel{
		ID:                  UUIDGenerator(),
		Provider:            input.Provider,
		UserID:              input.UserID,
		ReferenceInProvider: input.ReferenceInProvider,
		FirstName:           input.FirstName,
		LastName:            input.LastName,
		CreatedAt:           osTimeProvider(),
	}

	i.userIDSet[input.Provider][input.UserID] = entity
	return &CreateFederatedAccountOutput{
		ID:        entity.ID,
		CreatedAt: entity.CreatedAt,
	}, nil
}

func (i InMemoryFederatedAccountRepository) Find(input *FindFederatedAccountInput) (*FindFederatedAccountOutput, error) {
	if users, ok := i.userIDSet[input.Provider]; !ok {
		return nil, nil
	} else {
		if user, ok := users[input.UserID]; ok {
			return &FindFederatedAccountOutput{
				ID:                  user.ID,
				Provider:            input.Provider,
				UserID:              input.UserID,
				CreatedAt:           user.CreatedAt,
				ReferenceInProvider: user.ReferenceInProvider,
				FirstName:           user.FirstName,
				LastName:            user.LastName,
			}, nil
		}

		return nil, nil
	}
}

type InMemoryTokenPersistence struct {
	set map[string]*Entity
}

func NewInMemoryTokenPersistence() *InMemoryTokenPersistence {
	return &InMemoryTokenPersistence{set: map[string]*Entity{}}
}

func (i InMemoryTokenPersistence) Save(entity *Entity) error {
	if _, ok := i.set[entity.ID]; ok {
		return ErrDuplicatedEntityExists
	}

	i.set[entity.ID] = entity
	return nil
}

func (i InMemoryTokenPersistence) Find(tokenID string) (*Entity, error) {
	if t, ok := i.set[tokenID]; ok {
		return t, nil
	}

	return nil, ErrNotFound
}
