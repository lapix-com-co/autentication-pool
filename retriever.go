package authentication_pool

type ProviderName string

const (
	Google   ProviderName = "google"
	Facebook              = "facebook"
	Local                 = "local"
)

type ProviderFactory struct {
	providers map[ProviderName]Provider
}

func NewProviderFactory(providers map[ProviderName]Provider) *ProviderFactory {
	return &ProviderFactory{providers: providers}
}

func (f *ProviderFactory) New(providerName ProviderName) (Provider, error) {
	if p, ok := f.providers[providerName]; ok {
		return p, nil
	}

	return nil, ErrNotFound
}
