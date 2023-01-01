package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var userPathRegex = regexp.MustCompile(`^\/([\x21-\x7F]{0,510}\/)?$`)

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameWithAtRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the policy",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Policy Name",
				},
			},

			"credential_type": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf("Type of credential to retrieve. Must be %s", authorizationTokenCred),
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathRolesDelete,
			logical.ReadOperation:   b.pathRolesRead,
			logical.UpdateOperation: b.pathRolesWrite,
		},

		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.roleMutex.RLock()
	defer b.roleMutex.RUnlock()
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	for _, prefix := range []string{"role/"} {
		err := req.Storage.Delete(ctx, prefix+d.Get("name").(string))
		if err != nil {
			return nil, err
		}
	}

	return nil, nil
}

func (b *backend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.roleRead(ctx, req.Storage, d.Get("name").(string), true)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

func (b *backend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var resp logical.Response

	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	b.roleMutex.Lock()
	defer b.roleMutex.Unlock()
	roleEntry, err := b.roleRead(ctx, req.Storage, roleName, false)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		roleEntry = &awsRoleEntry{}
	}

	if credentialTypeRaw, ok := d.GetOk("credential_type"); ok {
		roleEntry.CredentialTypes = []string{credentialTypeRaw.(string)}
	}

	err = roleEntry.validate()
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("error(s) validating supplied role data: %q", err)), nil
	}

	err = setAwsRole(ctx, req.Storage, roleName, roleEntry)
	if err != nil {
		return nil, err
	}

	if len(resp.Warnings) == 0 {
		return nil, nil
	}

	return &resp, nil
}

func (b *backend) roleRead(ctx context.Context, s logical.Storage, roleName string, shouldLock bool) (*awsRoleEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role name")
	}
	if shouldLock {
		b.roleMutex.RLock()
	}
	entry, err := s.Get(ctx, "role/"+roleName)
	if shouldLock {
		b.roleMutex.RUnlock()
	}
	if err != nil {
		return nil, err
	}
	var roleEntry awsRoleEntry
	if entry != nil {
		if err := entry.DecodeJSON(&roleEntry); err != nil {
			return nil, err
		}
		return &roleEntry, nil
	}

	if shouldLock {
		b.roleMutex.Lock()
		defer b.roleMutex.Unlock()
	}
	entry, err = s.Get(ctx, "role/"+roleName)
	if err != nil {
		return nil, err
	}

	if entry != nil {
		if err := entry.DecodeJSON(&roleEntry); err != nil {
			return nil, err
		}
		return &roleEntry, nil
	}

	return nil, nil
}

func setAwsRole(ctx context.Context, s logical.Storage, roleName string, roleEntry *awsRoleEntry) error {
	if roleName == "" {
		return fmt.Errorf("empty role name")
	}
	if roleEntry == nil {
		return fmt.Errorf("nil roleEntry")
	}
	entry, err := logical.StorageEntryJSON("role/"+roleName, roleEntry)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("nil result when writing to storage")
	}
	if err := s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

type awsRoleEntry struct {
	CredentialTypes []string `json:"credential_types"` // Entries must all be in the set of ("iam_user", "assumed_role", "federation_token", "authorization_token")
	Version         int      `json:"version"`          // Version number of the role format
}

func (r *awsRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"credential_type": strings.Join(r.CredentialTypes, ","),
	}

	return respData
}

func (r *awsRoleEntry) validate() error {
	var errors *multierror.Error

	if len(r.CredentialTypes) == 0 {
		errors = multierror.Append(errors, fmt.Errorf("did not supply credential_type"))
	}

	allowedCredentialTypes := []string{authorizationTokenCred}
	for _, credType := range r.CredentialTypes {
		if !strutil.StrListContains(allowedCredentialTypes, credType) {
			errors = multierror.Append(errors, fmt.Errorf("unrecognized credential type: %s", credType))
		}
	}

	return errors.ErrorOrNil()
}

func compactJSON(input string) (string, error) {
	var compacted bytes.Buffer
	err := json.Compact(&compacted, []byte(input))
	return compacted.String(), err
}

const (
	authorizationTokenCred = "authorization_token"
)

const pathListRolesHelpSyn = `List the existing roles in this backend`

const pathListRolesHelpDesc = `Roles will be listed by the role name.`

const pathRolesHelpSyn = `
Read, write and reference IAM policies that access keys can be made for.
`

const pathRolesHelpDesc = `
This path allows you to read and write roles that are used to
create access keys. These roles are associated with IAM policies that
map directly to the route to read the access keys. For example, if the
backend is mounted at "aws" and you create a role at "aws/roles/deploy"
then a user could request access credentials at "aws/creds/deploy".

You can either supply a user inline policy (via the policy argument), or
provide a reference to an existing AWS policy by supplying the full arn
reference (via the arn argument). Inline user policies written are normal
IAM policies. Vault will not attempt to parse these except to validate
that they're basic JSON. No validation is performed on arn references.

To validate the keys, attempt to read an access key after writing the policy.
`
