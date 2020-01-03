package authentication_pool

import (
	"github.com/huandu/facebook"
)

type FacebookProvider struct {
	api facebookAPI
}

type facebookAPI interface {
	GetUser(accessToken string) (*facebookUser, error)
}

type handuFacebook struct{}

func (h handuFacebook) GetUser(accessToken string) (user *facebookUser, err error) {
	user = &facebookUser{}

	res, err := facebook.Get(
		"/me?fields=id,picture{url},first_name,last_name,email",
		facebook.Params{"access_token": accessToken},
	)

	if err != nil {
		return
	}

	if err = res.Decode(user); err != nil {
		return
	}

	return
}

type facebookUser struct {
	ID        string
	FirstName string
	LastName  string
	Email     string
	Picture   picture
}

type picture struct {
	Data data
}

type data struct {
	Url string
}

func (f FacebookProvider) Retrieve(input *ValidationInput) (*ValidationOutput, error) {
	user, err := f.api.GetUser(input.Secret)
	if err != nil {
		return nil, err
	}

	return &ValidationOutput{
		ID:             user.ID,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Email:          user.Email,
		PhotoURL:       &user.Picture.Data.Url,
		EmailValidated: true,
	}, nil
}

func (f FacebookProvider) Name() string {
	return "facebook"
}
