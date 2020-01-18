package codes

import (
	"reflect"
	"testing"
	"time"
)

type fakeTriesRepository struct {
	next int
	last *Try
}

func newFakeTriesRepository(next int, last *Try) *fakeTriesRepository {
	return &fakeTriesRepository{next: next, last: last}
}

func (f *fakeTriesRepository) Add(*AddTryInput) error {
	f.next = f.next + 1
	return nil
}

func (f fakeTriesRepository) CountTries(*CountTriesInput) (int, error) {
	return f.next, nil
}

func (f fakeTriesRepository) LastTry(*LastTryInput) (*Try, error) {
	return f.last, nil
}

func TestLimitIssuerPolicy_Check(t *testing.T) {
	type fields struct {
		repository   TriesRepository
		limit        int
		threshold    time.Duration
		timeProvider timeProvider
	}
	type args struct {
		input *CheckInput
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *CheckOutput
		wantErr bool
	}{
		{
			name: "should be valid if does not have tries",
			fields: fields{
				repository:   newFakeTriesRepository(0, nil),
				limit:        1,
				threshold:    time.Minute * 60,
				timeProvider: func() time.Time { return time.Now() },
			},
			args: args{
				input: &CheckInput{Issuer: "any"},
			},
			want:    &CheckOutput{Valid: true},
			wantErr: false,
		},
		{
			name: "should not be valid if return more than the valid tries",
			fields: fields{
				repository: newFakeTriesRepository(1, &Try{
					Issuer:    "any",
					CreatedAt: time.Now(),
				}),
				limit:        1,
				threshold:    time.Minute * 60,
				timeProvider: func() time.Time { return time.Now() },
			},
			args: args{
				input: &CheckInput{Issuer: "any"},
			},
			want:    &CheckOutput{Valid: false},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := LimitIssuerPolicy{
				repository:   tt.fields.repository,
				limit:        tt.fields.limit,
				threshold:    tt.fields.threshold,
				timeProvider: tt.fields.timeProvider,
			}
			got, err := l.Check(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Check() got = %v, want %v", got, tt.want)
			}
		})
	}
}
