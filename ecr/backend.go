package aws

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rootConfigPath        = "config/root"
	minAwsUserRollbackAge = 5 * time.Minute
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config/root",
			},
		},

		Paths: []*framework.Path{
			pathConfigRoot(&b),
			pathConfigRotateRoot(&b),
			pathConfigLease(&b),
			pathRoles(&b),
			pathListRoles(&b),
			pathUser(&b),
		},

		Secrets: []*framework.Secret{
			secretAccessKeys(&b),
		},

		Invalidate:        b.invalidate,
		WALRollback:       b.walRollback,
		WALRollbackMinAge: minAwsUserRollbackAge,
		BackendType:       logical.TypeLogical,
	}

	return &b
}

type backend struct {
	*framework.Backend

	// Mutex to protect access to reading and writing policies
	roleMutex sync.RWMutex

	// Mutex to protect access to iam/sts clients and client configs
	clientMutex sync.RWMutex

	// hold configured clients for reuse, and
	// to enable mocking with AWS iface for tests
	iamClient iamiface.IAMAPI
	ecrClient ecriface.ECRAPI
}

const backendHelp = `
The AWS backend dynamically generates AWS access keys for a set of
IAM policies. The AWS access keys have a configurable lease set and
are automatically revoked at the end of the lease.

After mounting this backend, credentials to generate IAM keys must
be configured with the "root" path and policies must be written using
the "roles/" endpoints before any access keys can be generated.
`

func (b *backend) invalidate(ctx context.Context, key string) {
	switch {
	case key == rootConfigPath:
		b.clearClients()
	}
}

// clearClients clears the backend's IAM and STS clients
func (b *backend) clearClients() {
	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()
	b.iamClient = nil
	b.ecrClient = nil
}

// clientIAM returns the configured IAM client. If nil, it constructs a new one
// and returns it, setting it the internal variable
func (b *backend) clientIAM(ctx context.Context, s logical.Storage) (iamiface.IAMAPI, error) {
	b.clientMutex.RLock()
	if b.iamClient != nil {
		b.clientMutex.RUnlock()
		return b.iamClient, nil
	}

	// Upgrade the lock for writing
	b.clientMutex.RUnlock()
	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	// check client again, in the event that a client was being created while we
	// waited for Lock()
	if b.iamClient != nil {
		return b.iamClient, nil
	}

	iamClient, err := nonCachedClientIAM(ctx, s, b.Logger())
	if err != nil {
		return nil, err
	}
	b.iamClient = iamClient

	return b.iamClient, nil
}

func (b *backend) clientECR(ctx context.Context, s logical.Storage, auth *logical.Response) (ecriface.ECRAPI, error) {
	b.clientMutex.RLock()
	if b.ecrClient != nil {
		b.clientMutex.RUnlock()
		return b.ecrClient, nil
	}

	// Upgrade the lock for writing
	b.clientMutex.RUnlock()
	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	// check client again, in the event that a client was being created while we
	// waited for Lock()
	if b.ecrClient != nil {
		return b.ecrClient, nil
	}

	ecrClient, err := nonCachedClientECR(ctx, s, auth, b.Logger())
	if err != nil {
		return nil, err
	}
	b.ecrClient = ecrClient

	return b.ecrClient, nil
}
