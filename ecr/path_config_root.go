package aws

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// A single default template that supports both the different credential types (IAM/STS) that are capped at differing length limits (64 chars/32 chars respectively)
const defaultUserNameTemplate = `{{ if (eq .Type "STS") }}{{ printf "vault-%s-%s"  (unix_time) (random 20) | truncate 32 }}{{ else }}{{ printf "vault-%s-%s-%s" (printf "%s-%s" (.DisplayName) (.PolicyName) | truncate 42) (unix_time) (random 20) | truncate 64 }}{{ end }}`

func pathConfigRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/root",
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "Access key with permission to create new keys.",
			},

			"secret_key": {
				Type:        framework.TypeString,
				Description: "Secret key with permission to create new keys.",
			},

			"region": {
				Type:        framework.TypeString,
				Description: "Region for API calls.",
			},
			"max_retries": {
				Type:        framework.TypeInt,
				Default:     aws.UseServiceDefaultRetries,
				Description: "Maximum number of retries for recoverable exceptions of AWS APIs",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigRootRead,
			logical.UpdateOperation: b.pathConfigRootWrite,
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func (b *backend) pathConfigRootRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.clientMutex.RLock()
	defer b.clientMutex.RUnlock()

	entry, err := req.Storage.Get(ctx, "config/root")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var config rootConfig

	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	configData := map[string]interface{}{
		"access_key":  config.AccessKey,
		"region":      config.Region,
		"max_retries": config.MaxRetries,
	}
	return &logical.Response{
		Data: configData,
	}, nil
}

func (b *backend) pathConfigRootWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	region := data.Get("region").(string)
	maxretries := data.Get("max_retries").(int)

	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	entry, err := logical.StorageEntryJSON("config/root", rootConfig{
		AccessKey:  data.Get("access_key").(string),
		SecretKey:  data.Get("secret_key").(string),
		Region:     region,
		MaxRetries: maxretries,
	})
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// clear possible cached clients after successfully updating
	// config/root
	b.ecrClient = nil

	return nil, nil
}

type rootConfig struct {
	AccessKey        string `json:"access_key"`
	SecretKey        string `json:"secret_key"`
	Region           string `json:"region"`
	MaxRetries       int    `json:"max_retries"`
	UsernameTemplate string `json:"username_template"`
}

const pathConfigRootHelpSyn = `
Configure the root credentials that are used to manage IAM.
`

const pathConfigRootHelpDesc = `
Before doing anything, the AWS backend needs credentials that are able
to manage IAM policies, users, access keys, etc. This endpoint is used
to configure those credentials. They don't necessarily need to be root
keys as long as they have permission to manage IAM.
`
