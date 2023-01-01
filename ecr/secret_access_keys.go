package aws

import (
	"context"
	"time"

	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/aws/aws-sdk-go/service/ecr"
)

const (
	secretAccessKeyType = "access_keys"
	storageKey          = "config/root"
)

func (b *backend) getAuthorizationToken(ctx context.Context, s logical.Storage) (*logical.Response, error) {
	ecrClient, err := b.clientECR(ctx, s)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	getTokenInput := &ecr.GetAuthorizationTokenInput{}

	tokenResp, err := ecrClient.GetAuthorizationToken(getTokenInput)
	if err != nil {
		return logical.ErrorResponse("Error generating ECR token: %s", err), awsutil.CheckAWSError(err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"auth_token":   *tokenResp.AuthorizationData[0].AuthorizationToken,
			"registry_url": *tokenResp.AuthorizationData[0].ProxyEndpoint,
			"ttl":          uint64(tokenResp.AuthorizationData[0].ExpiresAt.Sub(time.Now()).Seconds()),
		},
	}, nil
}

func readConfig(ctx context.Context, storage logical.Storage) (rootConfig, error) {
	entry, err := storage.Get(ctx, storageKey)
	if err != nil {
		return rootConfig{}, err
	}
	if entry == nil {
		return rootConfig{}, nil
	}

	var connConfig rootConfig
	if err := entry.DecodeJSON(&connConfig); err != nil {
		return rootConfig{}, err
	}
	return connConfig, nil
}
