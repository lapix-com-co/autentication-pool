package authentication_pool

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type GoogleProvider struct {
	api googleAPI
}

type googleAPI interface {
	GetUser(accessToken string) (*googleUser, error)
}

type googlePeople struct{}

func (h googlePeople) GetUser(accessToken string) (user *googleUser, err error) {
	url := fmt.Sprintf("https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=%s", accessToken)
	res, err := http.Get(url)

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("invalid response from server: %s", string(data))
	}

	user = &googleUser{}
	if err = json.Unmarshal(data, user); err != nil {
		return nil, err
	}

	return user, err
}

type googleUser struct {
	ID        string `json:"sub"`
	FirstName string `json:"given_name"`
	LastName  string `json:"family_name"`
	Email     string `json:"email"`
	Picture   string `json:"picture"`
}

func (f GoogleProvider) Retrieve(input *ValidationInput) (*ValidationOutput, error) {
	user, err := f.api.GetUser(input.Secret)
	if err != nil {
		return nil, err
	}

	return &ValidationOutput{
		ID:             user.ID,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Email:          user.Email,
		PhotoURL:       &user.Picture,
		EmailValidated: true,
	}, nil
}

func (f GoogleProvider) Name() string {
	return "google"
}
