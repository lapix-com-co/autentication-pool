package authentication_pool

import (
	"golang.org/x/crypto/bcrypt"
	"reflect"
	"regexp"
	"testing"
)

func encrypt(val string) string {
	res, err := bcrypt.GenerateFromPassword([]byte(val), 10)
	if err != nil {
		panic(err)
	}

	return string(res)
}

func TestLocalProvider_Validate(t *testing.T) {
	type fields struct {
		applicationID   string
		secret          string
		passwordHandler passwordHandler
		api             LocalAPI
	}
	type args struct {
		input *ValidationInput
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *ValidationOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := LocalProvider{
				passwordCypher: tt.fields.passwordHandler,
				api:            tt.fields.api,
			}
			got, err := g.Retrieve(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Validate() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBCRYPTHandler_Make(t *testing.T) {
	type fields struct {
		cost int
	}
	type args struct {
		password string
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantResult string
		wantErr    bool
	}{
		{
			name:    "passwords match",
			fields:  fields{cost: 10},
			args:    args{password: "qwerty"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BCRYPTHandler{
				cost: tt.fields.cost,
			}
			gotResult, err := b.Make(tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Make() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if bcrypt.CompareHashAndPassword([]byte(gotResult), []byte(tt.args.password)) != nil {
				t.Errorf("the given hashed password is not valid, got %s", gotResult)
			}
		})
	}
}

func TestBCRYPTHandler_Compare(t *testing.T) {
	type fields struct {
		cost int
	}
	type args struct {
		givenValue string
		target     string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantValid bool
		wantErr   bool
	}{
		{
			name:   "two passwords are valid",
			fields: fields{cost: 10},
			args: args{
				givenValue: encrypt("qwerty"),
				target:     "qwerty",
			},
			wantValid: true,
			wantErr:   false,
		},
		{
			name:   "two passwords are not valid",
			fields: fields{cost: 10},
			args: args{
				givenValue: encrypt("qwerty"),
				target:     "123456",
			},
			wantValid: false,
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BCRYPTHandler{
				cost: tt.fields.cost,
			}
			gotValid, err := b.Compare(tt.args.givenValue, tt.args.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("Compare() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotValid != tt.wantValid {
				t.Errorf("Compare() gotValid = %v, want %v", gotValid, tt.wantValid)
			}
		})
	}
}

func TestBasicPasswordPolicy_Valid(t *testing.T) {
	type fields struct {
		pattern *regexp.Regexp
	}
	type args struct {
		password string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name:   "must be valid",
			fields: fields{regexp.MustCompile("[0-9]{10,15}")},
			args:   args{password: "aA123456"},
			want:   true,
		},
		{
			name:   "must be in valid",
			fields: fields{regexp.MustCompile("a{5}")},
			args:   args{password: "aaaaa"},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BasicPasswordPolicy{
				pattern: tt.fields.pattern,
			}
			if got := b.Valid(tt.args.password); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}
