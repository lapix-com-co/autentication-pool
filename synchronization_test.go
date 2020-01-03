package authentication_pool

import (
	"reflect"
	"testing"
)

func TestLocalSynchronization_Synchronize(t *testing.T) {
	type fields struct {
		localCustomerRegister    LocalCustomerRegister
		federatedAccountRegister FederatedAccountRegister
	}
	type args struct {
		input *SynchronizeInput
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *SynchronizeOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := LocalSynchronization{
				localCustomerRegister:    tt.fields.localCustomerRegister,
				federatedAccountRegister: tt.fields.federatedAccountRegister,
			}
			got, err := l.Synchronize(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Synchronize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Synchronize() got = %v, want %v", got, tt.want)
			}
		})
	}
}
