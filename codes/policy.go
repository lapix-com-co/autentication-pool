package codes

import (
	"fmt"
	"sync"
	"time"
)

type LimitIssuerPolicy struct {
	repository   TriesRepository
	limit        int
	threshold    time.Duration
	timeProvider timeProvider
}

func NewLimitIssuerPolicy(repository TriesRepository, limit int, threshold time.Duration) *LimitIssuerPolicy {
	return &LimitIssuerPolicy{repository, limit, threshold, func() time.Time { return time.Now() }}
}

func (l LimitIssuerPolicy) Check(input *CheckInput) (*CheckOutput, error) {
	tries, err := l.repository.CountTries(&CountTriesInput{
		Issuer: input.Issuer,
		After:  l.timeProvider().Add(-l.threshold),
	})

	if err != nil {
		return nil, err
	}

	return &CheckOutput{
		Valid:      tries < l.limit,
		ValidAfter: nil,
	}, nil
}

func (l LimitIssuerPolicy) Message() string {
	return fmt.Sprintf("The user cannot send more that %d in %d minutes", l.limit, l.threshold/time.Minute)
}

type tryRecord struct {
	lastEntry *Try
	total     int
}

type InMemoryTriesRepository struct {
	store map[string]*tryRecord
	mx    sync.Mutex
}

func NewInMemoryTriesRepository() *InMemoryTriesRepository {
	return &InMemoryTriesRepository{
		store: map[string]*tryRecord{},
	}
}

func (i *InMemoryTriesRepository) Add(input *AddTryInput) error {
	i.mx.Lock()
	defer i.mx.Unlock()

	v, ok := i.store[input.Issuer]
	if !ok {
		v = &tryRecord{
			lastEntry: nil,
			total:     0,
		}
	}

	v.lastEntry = &Try{
		Issuer:    input.Issuer,
		CreatedAt: input.CreatedAt,
	}

	v.total = v.total + 1

	i.store[input.Issuer] = v
	return nil
}

func (i InMemoryTriesRepository) CountTries(input *CountTriesInput) (int, error) {
	i.mx.Lock()
	defer i.mx.Unlock()

	v, ok := i.store[input.Issuer]
	if !ok {
		return 0, nil
	}

	return v.total, nil
}

func (i InMemoryTriesRepository) LastTry(input *LastTryInput) (*Try, error) {
	i.mx.Lock()
	defer i.mx.Unlock()

	v, ok := i.store[input.Issuer]
	if !ok {
		return nil, nil
	}

	return v.lastEntry, nil
}
