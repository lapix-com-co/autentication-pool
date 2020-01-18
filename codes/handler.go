package codes

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var _ Manager = &Handler{}

type Handler struct {
	generator    Generator
	repository   Repository
	policy       SendPolicy
	timeToLive   time.Duration
	timeProvider timeProvider
}

func NewHandler(generator Generator, repository Repository, policy SendPolicy, timeToLive time.Duration) *Handler {
	return &Handler{generator, repository, policy, timeToLive, func() time.Time { return time.Now() }}
}

func (h Handler) Issue(input *IssueInput) (*IssueOutput, error) {
	output, err := h.policy.Check(&CheckInput{Issuer: input.Issuer})
	if err != nil {
		return nil, err
	}

	if !output.Valid {
		return nil, errors.New(h.policy.Message())
	}

	code, err := h.repository.Create(&CreateInput{
		Issuer:    input.Issuer,
		Status:    string(Enabled),
		Code:      h.generator(),
		ExpiredAt: h.timeProvider().Add(h.timeToLive),
	})

	if err != nil {
		return nil, err
	}

	return &IssueOutput{Code: code}, nil
}

func (h Handler) Used(input *CheckCodeInput) (*CheckCodeOutput, error) {
	code, err := h.repository.Find(&FindInput{
		Issuer: input.Issuer,
		Code:   input.Code,
	})

	if err != nil {
		return nil, err
	}

	if err := code.MarkAsUsed(); err != nil {
		return nil, err
	}

	if h.timeProvider().After(code.ExpiredAt) {
		return nil, UnavailableCodeError
	}

	_, err = h.repository.Update(&UpdateInput{
		ID:     code.ID,
		Status: string(code.Status),
	})

	return &CheckCodeOutput{Code: code}, nil
}

type InMemoryRepository struct {
	issuerIndex  map[string]map[string]*Code
	idIndex      map[string]*Code
	mx           sync.Mutex
	timeProvider timeProvider
}

func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{
		issuerIndex:  map[string]map[string]*Code{},
		idIndex:      map[string]*Code{},
		timeProvider: func() time.Time { return time.Now() },
	}
}

func (i InMemoryRepository) Find(input *FindInput) (*Code, error) {
	i.mx.Lock()
	defer i.mx.Unlock()

	v, ok := i.issuerIndex[input.Issuer]
	if !ok {
		return nil, nil
	}

	t, _ := v[input.Code]
	return t, nil
}

func (i *InMemoryRepository) Create(input *CreateInput) (*Code, error) {
	i.mx.Lock()
	defer i.mx.Unlock()

	v, ok := i.issuerIndex[input.Issuer]
	if !ok {
		i.issuerIndex[input.Issuer] = map[string]*Code{}
		v = i.issuerIndex[input.Issuer]
	}

	code := &Code{
		ID:        fmt.Sprintf("%s-%d", input.Issuer, len(v)),
		Status:    Status(input.Status),
		Content:   input.Code,
		Issuer:    input.Issuer,
		ExpiredAt: input.ExpiredAt,
	}

	v[input.Code] = code
	i.idIndex[code.ID] = code
	return code, nil
}

func (i InMemoryRepository) Update(input *UpdateInput) (*Code, error) {
	i.mx.Lock()
	defer i.mx.Unlock()

	v, ok := i.idIndex[input.ID]
	if !ok {
		return nil, nil
	}

	v.Status = Status(input.Status)

	return v, nil
}

func (i InMemoryRepository) Last(input *LastInput) ([]*Code, error) {
	result := make([]*Code, 0)
	now := i.timeProvider()

	i.mx.Lock()
	defer i.mx.Unlock()

	v, ok := i.issuerIndex[input.Issuer]
	if !ok {
		return result, nil
	}

	for _, code := range v {
		if code.ExpiredAt.Add(input.Duration).After(now) {
			result = append(result, code)
		}
	}

	return result, nil
}
