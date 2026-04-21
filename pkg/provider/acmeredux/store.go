package acmeredux

import "context"

// StoredData represents the data managed by Store.
type StoredData struct {
	Account      *Account
	Certificates []*CertAndStore
}

// Store is a generic interface that represents a storage.
type Store interface {
	GetResolverState(resolverName string, force ...bool) (*StoredData, error)
	SaveAccountLocked(ctx context.Context, resolverName string, account *Account) error
	UpsertCertificateLocked(ctx context.Context, resolverName string, cert Certificate, tlsStore string) ([]*CertAndStore, error)
	WithResolverLease(ctx context.Context, resolverName string, f func(context.Context, *StoredData) error) error
	IsLocked(ctx context.Context) (bool, error)
}
