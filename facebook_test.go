package authentication_pool

import (
	"reflect"
	"testing"
)

func Test_handuFacebook_GetUser(t *testing.T) {
	type args struct {
		accessToken string
	}
	tests := []struct {
		name    string
		args    args
		want    *FacebookUser
		wantErr bool
	}{
		{
			name: "retrieves a User",
			args: args{
				accessToken: "EAAhs5q2FmIgBALIu7bcEbtE8l1rbVH69Ukd4dmMCBF6QiQBzmOM29vStCgOQlzslWb5k24KJBCpPNGgYA1S9zI6BZA5ZCtKRckFNOWQLnHoZATNVWF5FtoubFVluoTYfLFfNwdsxUjHu38TrIdtRZCaR7JvZC0QRaDs6lmgLctfcsCleZCwwCP",
			},
			want: &FacebookUser{
				ID:        "143090040460812",
				FirstName: "Alejandro",
				LastName:  "Rivera",
				Email:     "alejo@lapix.com.co",
				Picture: picture{
					Data: data{
						Url: "https://scontent.xx.fbcdn.net/v/t31.0-1/c15.0.50.50a/p50x50/10733713_10150004552801937_4553731092814901385_o.jpg?_nc_cat=1&_nc_ohc=HmqDuJl0O6YAQloUEqYJkW4qVHwrcolJDb7FwP-TTjeNM7M9ce7aVwtAg&_nc_ht=scontent.xx&oh=b0ab90348ec1c64439653fd8853e088b&oe=5EB40545",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := handuFacebook{}
			got, err := h.GetUser(tt.args.accessToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetUser() got = %v, want %v", got, tt.want)
			}
		})
	}
}
