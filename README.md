# vipervaultinjector

Package vipervaultinjector is a package help you inject vault secret in viper config automatically.

It will replace the secret url with the secret vaule in vault automatically, when you unmarshal the map to the struct.

So it can be used anywhere that uses mapstructure for unmarshal, not just viper.

## Examples

### StringToVaultSecretHookFunc

StringToVaultSecretHookFunc Hook function for convert vault url string to vault secret.

For example, set {vault://vault.example/_/test/foo/password1} in vault string, and it will replace it to password1 value in vault when unmarshalled by mapstructure

```golang

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

```

---