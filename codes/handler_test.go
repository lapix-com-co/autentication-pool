package codes

import (
	"fmt"
	"testing"
	"time"
)

func NewFixedGenerator() *FixedGenerator {
	return &FixedGenerator{}
}

type FixedGenerator struct {
	next string
}

func (g *FixedGenerator) Next(code string) {
	g.next = code
}

func (g *FixedGenerator) Pull() string {
	value := g.next
	g.next = ""
	return value
}

type StubMemoryRepository struct {
	store *Code
}

func NewInMemoryRepository() *StubMemoryRepository {
	return &StubMemoryRepository{}
}

func (i StubMemoryRepository) Find(*FindInput) (*Code, error) {
	return i.store, nil
}

func (i *StubMemoryRepository) Create(input *CreateInput) (*Code, error) {
	i.store = &Code{
		Status:    Status(input.Status),
		Content:   input.Code,
		Issuer:    input.Issuer,
		ExpiredAt: time.Time{},
	}

	return i.store, nil
}

func (i StubMemoryRepository) Update(input *UpdateInput) (*Code, error) {
	i.store.Status = Status(input.Status)
	return i.store, nil
}

func (i StubMemoryRepository) Last(*LastInput) ([]*Code, error) {
	return []*Code{i.store}, nil
}

type LimitPolicy struct {
	limit int
	store map[string][]*Code
}

func NewLimitPolicy(limit int) *LimitPolicy {
	return &LimitPolicy{limit: limit, store: map[string][]*Code{}}
}

func (l LimitPolicy) Message() string {
	return fmt.Sprintf("the user cannot have more than %d codes", l.limit)
}

func (l LimitPolicy) Check(input *CheckInput) (*CheckOutput, error) {
	valid := true

	if v, ok := l.store[input.Issuer]; ok {
		valid = len(v) < l.limit
	}

	return &CheckOutput{
		Valid:      valid,
		ValidAfter: nil,
	}, nil
}

func Test_Issue(t *testing.T) {
	t.Run("should create a code", func(t *testing.T) {
		newCode := "qwerty"
		generator := NewFixedGenerator()
		generator.Next(newCode)

		repository := NewInMemoryRepository()
		codePolicy := NewLimitPolicy(1)

		handler := &Handler{
			generator:    generator.Pull,
			repository:   repository,
			policy:       codePolicy,
			timeProvider: func() time.Time { return time.Now() },
			timeToLive:   time.Minute,
		}

		output, err := handler.Issue(&IssueInput{Issuer: "seeealejandro@gmail.com"})
		if err != nil {
			t.Errorf("expect err = nil but got = %v", err)
			return
		}

		if output.Code.Content != newCode {
			t.Errorf("the given code is not valid, expect '%s' got %s", newCode, output.Code.Content)
		}
	})

	t.Run("should not create a code if the policy rules does not match", func(t *testing.T) {
		newCode := "qwerty"
		generator := NewFixedGenerator()
		generator.Next(newCode)

		repository := NewInMemoryRepository()
		repository.store = &Code{}
		codePolicy := NewLimitPolicy(0)

		handler := &Handler{
			generator:    generator.Pull,
			repository:   repository,
			policy:       codePolicy,
			timeProvider: func() time.Time { return time.Now() },
			timeToLive:   time.Minute,
		}

		_, err := handler.Issue(&IssueInput{Issuer: "seeealejandro@gmail.com"})
		if err != nil {
			t.Errorf("expect err != nil but got = nil")
			return
		}
	})
}
