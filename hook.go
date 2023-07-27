// Package vipervaultinjector is a package help you inject vault secret in viper config automatically.
//
// It will replace the secret url with the secret vaule in vault automatically, when you unmarshal the map to the struct.
//
// So it can be used anywhere that uses mapstructure for unmarshal, not just viper.
package vipervaultinjector

import (
	"context"
	"net/url"
	"reflect"
	"strings"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
)

// VaultSchema you should use this as your secret url scheme
// for example, vault://xxx.com/namespace/mountpath/secretname/field1
const VaultSchema = "vault"

var cached = true

// Is there any risk in the cache?
var responseCache = make(map[string]schema.KvV2ReadResponse)

// SetCacheOpt set the cache option.
//
// If True, we cache the whole secret response in memory,if we get a new field in the same secret, we get it in cache directly.
//
// If False, we will request the secret every time when we get a field.
func SetCacheOpt(flag bool) {
	cached = flag
}

// GetVaultKVResponse Get Vault KV response
func GetVaultKVResponse(client *vault.Client, namespaces, mountpath, secretname string) (resp schema.KvV2ReadResponse, err error) {
	if cached {
		cachekey := strings.Join([]string{namespaces, mountpath, secretname}, "-")
		resp, ok := responseCache[cachekey]
		if ok {
			return resp, nil
		}
	}

	options := []vault.RequestOption{}
	if namespaces != "_" {
		options = append(options, vault.WithNamespace(namespaces))
	}
	if mountpath != "_" {
		options = append(options, vault.WithMountPath(mountpath))
	}

	response, err := client.Secrets.KvV2Read(context.Background(), secretname, options...)
	if err != nil {
		return schema.KvV2ReadResponse{}, err
	}

	return response.Data, nil
}

// GetVaultSecret Get secret for specified url
func GetVaultSecret(client *vault.Client, u *url.URL) (secret string, err error) {
	dirs := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")

	if len(dirs) != 4 {
		return "", errors.Errorf("invalid vault path[%s]", u.Path)
	}

	namespaces := dirs[0]
	mountpath := dirs[1]
	secretname := dirs[2]
	field := dirs[3]

	// We can't get the specific field, because api only supports get whole secret response one time
	// refer to https://github.com/hashicorp/vault/issues/2421#issuecomment-283506323
	resp, err := GetVaultKVResponse(client, namespaces, mountpath, secretname)
	if err != nil {
		return "", errors.Wrap(err, "vault kv request failed")
	}

	value, ok := resp.Data[field]
	if !ok {
		return "", errors.Errorf("cannot found field in secret[%s]", secretname)
	}

	secret, ok = value.(string)
	if !ok {
		return "", errors.Errorf("invalid secret type with field[%s] in secret[%s]", field, secretname)
	}

	return
}

// StringToVaultSecretHookFunc Hook function for convert vault url string to vault secret.
//
// For example, set {vault://vault.example/_/test/foo/password1} in vault string, and it will replace it to password1 value in vault when unmarshalled by mapstructure
func StringToVaultSecretHookFunc(client *vault.Client) mapstructure.DecodeHookFunc {
	return func(
		f reflect.Kind,
		t reflect.Kind,
		data interface{}) (interface{}, error) {
		if f != reflect.String || t != reflect.String {
			return data, nil
		}

		// eg. vault://vault.com/security/
		raw := data.(string)
		if raw == "" && !(strings.HasPrefix(raw, "{") || strings.HasSuffix(raw, "}")) {
			return raw, nil
		}

		value := strings.TrimPrefix(raw, "{")
		value = strings.TrimPrefix(value, " ")
		value = strings.TrimSuffix(value, "}")
		value = strings.TrimSuffix(value, " ")

		if !strings.HasPrefix(value, VaultSchema) {
			return raw, nil
		}

		u, err := url.Parse(value)
		if err != nil {
			return raw, errors.Wrap(err, "url parse failed")
		}

		if u.Scheme != VaultSchema {
			return raw, nil
		}

		return GetVaultSecret(client, u)
	}
}
