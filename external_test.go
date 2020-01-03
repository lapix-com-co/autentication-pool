package authentication_pool

import (
	"reflect"
	"testing"
)

func TestExternalProvider_Validate(t *testing.T) {
	type fields struct {
		api ExternalProviderAPI
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
			g := ExternalProvider{
				api: tt.fields.api,
			}
			got, err := g.Validate(tt.args.input)
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