package authentication_pool

import (
	"reflect"
	"testing"
)

func Test_googlePeople_GetUser(t *testing.T) {
	type args struct {
		accessToken string
	}
	tests := []struct {
		name     string
		args     args
		wantUser *GoogleUser
		wantErr  bool
	}{
		{
			name: "get a valid User",
			args: args{
				accessToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNkMjM0OTg4ZTNhYWU2N2FmYmMwMmNiMWM0MTQwYjNjZjk2ODJjYWEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3MzA4NDA3MzQ3MzYtaGZua3VlZzFyYTd2aGhoOTJramRkZGNjZ2I5OTF1M28uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3MzA4NDA3MzQ3MzYtNGNkZnBmdG43Z2FnN21uajhqZWk4b2pob3UyaHNxY2guYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDExNDgzNTM3OTU5Mzc2NjkzODYiLCJlbWFpbCI6InNlZWVhbGVqYW5kcm9AZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGVqYW5kcm8gUml2ZXJhIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hLS9BQXVFN21EQWtVS1lGYUFCRjlmVXE5N3I5TEhEa1NLVXhFVG4xMTdQWHhQX1pBPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkFsZWphbmRybyIsImZhbWlseV9uYW1lIjoiUml2ZXJhIiwibG9jYWxlIjoiZXMiLCJpYXQiOjE1NzgwNzQ2ODksImV4cCI6MTU3ODA3ODI4OX0.eG_FaubFxiqAi18SFnFRx0cR1vQx22mOJaDSO0FCVl0sKpoEOzKGwV9FecWbmEAGPZJc18lbQpUWPyeSjxOveu-JUlQNXsHM9DGI-utsHJIHqq3qid8QVquDHJC_CRkiz_W89ZWxTNh_VYEpvJZhUsez-VFV4vdqu5QWBoqcC5rSu_cmdzwQRHJRzZ1jrjv8Q1IiN-jlxyR0vh3ctyDZFldHYUlUZHc8kWYh5UD3Oe58O48Ph_GZYfrgiQfYJ6AwgT9eLsuv-cAOQKIs9BpFsO2vXnRu10wxsUuzWEXHjgx9WYamJdqUwC9OGjV3BzTFWUDPskJO2HxzX4vA0Fv2TA",
			},
			wantUser: nil,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := googlePeople{}
			gotUser, err := h.GetUser(tt.args.accessToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotUser, tt.wantUser) {
				t.Errorf("GetUser() gotUser = %v, want %v", gotUser, tt.wantUser)
			}
		})
	}
}
