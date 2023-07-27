package vipervaultinjector_test

import (
	"bytes"
	"log"

	"github.com/spf13/viper"
	vipervaultinjector "wanmail.github.com/viper-vault-injector"
)

func ExampleStringToVaultSecretHookFunc() {
	client, err := initClient()
	if err != nil {
		log.Fatal(err)
	}

	err = setupSecret(client)
	if err != nil {
		log.Fatal(err)
	}
	defer teardownSecret(client)

	viper.SetConfigType("yaml") // or viper.SetConfigType("YAML")

	type DBExample struct {
		Address  string `mapstructure:"address"`
		Database string `mapstructure:"database"`
		Username string `mapstructure:"username"`
		Password string `mapstructure:"password"`
	}

	// any approach to require this configuration into your program.
	var yamlExample = []byte(`
	address: 127.0.0.1
	database: example
	username: root
	password: {vault://vault.org/_/test/foo/password1}
	`)

	err = viper.ReadConfig(bytes.NewBuffer(yamlExample))
	if err != nil {
		log.Fatal(err)
	}

	var db DBExample
	err = viper.Unmarshal(&db, viper.DecodeHook(vipervaultinjector.StringToVaultSecretHookFunc(client)))
	if err != nil {
		log.Fatal(err)
	}

	if db.Password != value1 {
		log.Fatalf("value1[%s] incorrect", db.Password)
	}
}
