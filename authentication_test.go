package authentication_pool

import (
	"reflect"
	"testing"
)

func TestAuthenticationPoolProvider_Authenticate(t *testing.T) {
	type fields struct {
		tokenProvider TokenProvider
	}
	type args struct {
		handler AccountRetriever
		input   *AuthenticateInput
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *AuthenticateOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AuthenticationPoolProvider{
				tokenProvider: tt.fields.tokenProvider,
			}
			got, err := a.Authenticate(tt.args.handler, tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authenticate() got = %v, want %v", got, tt.want)
			}
		})
	}
}