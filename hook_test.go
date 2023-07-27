package vipervaultinjector_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	vipervaultinjector "wanmail.github.com/viper-vault-injector"
)

const (
	mountpath  = "test"
	secretname = "foo"
	field1     = "password1"
	field2     = "password2"
	value1     = "abc123"
	value2     = "correct horse battery staple"
)

func initClient() (client *vault.Client, err error) {
	client, err = vault.New(
		vault.WithAddress("https://127.0.0.1:8200"),
		vault.WithRequestTimeout(30*time.Second),
	)

	return
}

func setupSecret(client *vault.Client) (err error) {
	_, err = client.Secrets.KvV2Write(context.Background(), secretname, schema.KvV2WriteRequest{
		Data: map[string]any{
			field1: value1,
			field2: value2,
		}},
		vault.WithMountPath(mountpath),
	)

	return
}

func teardownSecret(client *vault.Client) (err error) {
	_, err = client.Secrets.KvV2Delete(context.Background(), secretname,
		vault.WithMountPath(mountpath),
	)
	return
}

func TestGetVaultKVResponse(t *testing.T) {
	client, err := initClient()
	if err != nil {
		t.Fatal(err)
	}

	err = setupSecret(client)
	if err != nil {
		t.Fatal(err)
	}
	defer teardownSecret(client)

	response, err := vipervaultinjector.GetVaultKVResponse(client, "_", mountpath, secretname)
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range response.Data {
		if k == field1 {
			if v != value1 {
				t.Fatalf("value1[%s] incorrect", v)
			}
			continue
		}
		if k == field2 {
			if v != value2 {
				t.Fatalf("value2[%s] incorrect", v)
			}
			continue
		}

		t.Fatalf("unexpected field[%s]", k)
	}
}

func TestGetVaultSecret(t *testing.T) {
	client, err := initClient()
	if err != nil {
		t.Fatal(err)
	}

	err = setupSecret(client)
	if err != nil {
		t.Fatal(err)
	}
	defer teardownSecret(client)

	{
		s1 := fmt.Sprintf("vault://vault.org/_/%s/%s/%s", mountpath, secretname, field1)
		u1, err := url.Parse(s1)
		if err != nil {
			t.Fatal(err)
		}
		v1, err := vipervaultinjector.GetVaultSecret(client, u1)
		if err != nil {
			t.Fatal(err)
		}
		if v1 != value1 {
			t.Fatalf("value1[%s] incorrect", v1)
		}
	}

	{
		s2 := fmt.Sprintf("vault://vault.org/_/%s/%s/%s", mountpath, secretname, field2)
		u2, err := url.Parse(s2)
		if err != nil {
			t.Fatal(err)
		}
		v2, err := vipervaultinjector.GetVaultSecret(client, u2)
		if err != nil {
			t.Fatal(err)
		}
		if v2 != value2 {
			t.Fatalf("value2[%s] incorrect", v2)
		}
	}
}
