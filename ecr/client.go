package aws

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/iam"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// NOTE: The caller is required to ensure that b.clientMutex is at least read locked
func getRootConfig(ctx context.Context, s logical.Storage, clientType string, logger hclog.Logger) (*aws.Config, error) {
	credsConfig := &awsutil.CredentialsConfig{}
	var maxRetries int = aws.UseServiceDefaultRetries

	entry, err := s.Get(ctx, "config/root")
	if err != nil {
		return nil, err
	}
	if entry != nil {
		var config rootConfig
		if err := entry.DecodeJSON(&config); err != nil {
			return nil, fmt.Errorf("error reading root configuration: %w", err)
		}

		credsConfig.AccessKey = config.AccessKey
		credsConfig.SecretKey = config.SecretKey
		credsConfig.Region = config.Region
		maxRetries = config.MaxRetries
	}

	if credsConfig.Region == "" {
		credsConfig.Region = os.Getenv("AWS_REGION")
		if credsConfig.Region == "" {
			credsConfig.Region = os.Getenv("AWS_DEFAULT_REGION")
			if credsConfig.Region == "" {
				credsConfig.Region = "us-east-1"
			}
		}
	}

	credsConfig.HTTPClient = cleanhttp.DefaultClient()

	credsConfig.Logger = logger

	creds, err := credsConfig.GenerateCredentialChain()
	if err != nil {
		return nil, err
	}

	return &aws.Config{
		Credentials: creds,
		Region:      aws.String(credsConfig.Region),
		HTTPClient:  cleanhttp.DefaultClient(),
		MaxRetries:  aws.Int(maxRetries),
	}, nil
}

func nonCachedClientIAM(ctx context.Context, s logical.Storage, logger hclog.Logger) (*iam.IAM, error) {
	awsConfig, err := getRootConfig(ctx, s, "iam", logger)
	if err != nil {
		return nil, err
	}
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}
	client := iam.New(sess)
	if client == nil {
		return nil, fmt.Errorf("could not obtain iam client")
	}
	return client, nil
}

func getSecretConfig(ctx context.Context, s logical.Storage, clientType string, auth *logical.Response, logger hclog.Logger) (*aws.Config, error) {
	credsConfig := &awsutil.CredentialsConfig{}
	var maxRetries int = aws.UseServiceDefaultRetries

	entry, err := s.Get(ctx, "config/root")
	if err != nil {
		return nil, err
	}
	if entry != nil {
		var config rootConfig
		if err := entry.DecodeJSON(&config); err != nil {
			return nil, fmt.Errorf("error reading root configuration: %w", err)
		}

		credsConfig.Region = config.Region
		maxRetries = config.MaxRetries
	}

	if credsConfig.Region == "" {
		credsConfig.Region = os.Getenv("AWS_REGION")
		if credsConfig.Region == "" {
			credsConfig.Region = os.Getenv("AWS_DEFAULT_REGION")
			if credsConfig.Region == "" {
				credsConfig.Region = "us-east-1"
			}
		}
	}

	accessKeyRaw, ok := auth.Secret.InternalData["access_key"]
	if !ok {
		return nil, fmt.Errorf("secret is missing accessKey internal data")
	}
	accessKey, ok := accessKeyRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing accessKey internal data")
	}
	secretKeyRaw, ok := auth.Secret.InternalData["secret_key"]
	if !ok {
		return nil, fmt.Errorf("secret is missing secretKey internal data")
	}
	secretKey, ok := secretKeyRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing secretKey internal data")
	}

	credsConfig.AccessKey = accessKey
	credsConfig.SecretKey = secretKey
	credsConfig.HTTPClient = cleanhttp.DefaultClient()
	credsConfig.Logger = logger

	creds, err := credsConfig.GenerateCredentialChain(awsutil.WithEnvironmentCredentials(false), awsutil.WithSharedCredentials(false))
	if err != nil {
		return nil, err
	}

	return &aws.Config{
		Credentials: creds,
		Region:      aws.String(credsConfig.Region),
		HTTPClient:  cleanhttp.DefaultClient(),
		MaxRetries:  aws.Int(maxRetries),
	}, nil
}

func nonCachedClientECR(ctx context.Context, s logical.Storage, auth *logical.Response, logger hclog.Logger) (*ecr.ECR, error) {
	awsConfig, err := getSecretConfig(ctx, s, "ecr", auth, logger)
	if err != nil {
		return nil, err
	}
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}
	client := ecr.New(sess)
	if client == nil {
		return nil, fmt.Errorf("could not obtain ecr client")
	}
	return client, nil
}
