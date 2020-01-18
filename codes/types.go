package codes

import (
	"errors"
	"time"
)

var (
	UnavailableCodeError = errors.New("the given code is not available")
)

type Status string

const (
	Enabled  Status = "enabled"
	Disabled        = "disabled"
	Used            = "used"
)

type Manager interface {
	// Issue created a code and set the respective expiration time.
	Issue(input *IssueInput) (*IssueOutput, error)
	// Used checks if the code is valid and mark it as used.
	Used(input *CheckCodeInput) (*CheckCodeOutput, error)
}

type Repository interface {
	Find(input *FindInput) (*Code, error)
	Create(input *CreateInput) (*Code, error)
	Update(input *UpdateInput) (*Code, error)
	Last(input *LastInput) ([]*Code, error)
}

type SendPolicy interface {
	Check(*CheckInput) (*CheckOutput, error)
	Message() string
}

type TriesRepository interface {
	Add(*AddTryInput) error
	CountTries(*CountTriesInput) (int, error)
	LastTry(*LastTryInput) (*Try, error)
}

type Code struct {
	ID        string
	Status    Status
	Content   string
	Issuer    string
	ExpiredAt time.Time
}

func (a *Code) Valid() bool {
	return a.Status == Enabled
}

func (a *Code) MarkAsUsed() error {
	if a.Status != Enabled {
		return UnavailableCodeError
	}

	a.Status = Used
	return nil
}

type CreateInput struct {
	Issuer    string
	Status    string
	Code      string
	ExpiredAt time.Time
}

type UpdateInput struct {
	ID     string
	Status string
}

type FindInput struct {
	Issuer string
	Code   string
}

type LastInput struct {
	Duration time.Duration
	Issuer   string
}

type CheckInput struct {
	Issuer string
}

type CheckOutput struct {
	Valid      bool
	ValidAfter *time.Time
}

type Generator func() string

type IssueInput struct {
	Issuer string
}

type UsedInput struct {
	Code *Code
}

type IssueOutput struct {
	Code *Code
}

type CheckCodeInput struct {
	Issuer, Code string
}

type CheckCodeOutput struct {
	Code *Code
}

type timeProvider func() time.Time

type AddTryInput struct {
	Issuer    string
	CreatedAt time.Time
}

type CountTriesInput struct {
	Issuer string
	After  time.Time
}

type Try struct {
	Issuer    string
	CreatedAt time.Time
}

type LastTryInput struct {
	Issuer string
}
