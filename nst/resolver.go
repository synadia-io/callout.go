package nst

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

type Resolver struct {
	Type           string        `json:"type"`
	Dir            string        `json:"dir"`
	AllowDelete    bool          `json:"allow_delete"`
	UpdateInterval time.Duration `json:"interval"`
	Timeout        time.Duration `json:"timeout"`
}

func (r *Resolver) MarshalJSON() ([]byte, error) {
	type RC struct {
		Resolver
		SInterval string `json:"interval"`
		STimeout  string `json:"timeout"`
	}

	rc := RC{Resolver: *r}
	rc.SInterval = r.UpdateInterval.String()
	rc.STimeout = r.Timeout.String()

	return json.Marshal(rc)
}

type ResolverConfig struct {
	t             *testing.T
	Listen        string            `json:"listen"`
	Identities    *Identities       `json:"-"`
	Operator      string            `json:"operator"`
	SystemAccount string            `json:"system_account"`
	Resolver      Resolver          `json:"resolver"`
	Preload       map[string]string `json:"resolver_preload"`
}

func NewResolverConfig(t *testing.T, dir string) *ResolverConfig {
	v := &ResolverConfig{
		t:          t,
		Listen:     "127.0.0.1:-1",
		Identities: NewIdentities(t),
		Resolver: Resolver{
			Type:           "full",
			Dir:            filepath.Join(dir, "jwts"),
			UpdateInterval: time.Minute,
			Timeout:        time.Millisecond * 1900,
		},
	}

	v.Operator = v.Identities.Operator.Token
	v.SystemAccount = v.Identities.System.PublicKey()

	for _, a := range v.Identities.Accounts {
		v.addAccount(a)
	}

	require.NoError(t, os.MkdirAll(v.Resolver.Dir, 0o777))

	return v
}

func (r *ResolverConfig) Store(parentDir string) string {
	f, err := os.CreateTemp(parentDir, "server.conf")
	require.NoError(r.t, err)
	defer func() {
		_ = f.Close()
	}()

	d, err := json.MarshalIndent(r, "", " ")
	require.NoError(r.t, err)

	_, err = f.Write(d)
	require.NoError(r.t, err)

	return f.Name()
}

func (r *ResolverConfig) NewAccount(name string) *TokenKP {
	a := r.Identities.AddAccount(name)
	r.addAccount(a)
	return a
}

func (r *ResolverConfig) addAccount(acc *TokenKP) {
	if r.Preload == nil {
		r.Preload = make(map[string]string)
	}
	r.Preload[acc.PublicKey()] = acc.Token
}

type TokenKP struct {
	Token  string
	KP     nkeys.KeyPair
	bearer bool
}

func (kp *TokenKP) ConnectOptions() nats.Option {
	return func(options *nats.Options) error {
		options.UserJWT = func() (string, error) {
			return kp.Token, nil
		}
		options.SignatureCB = func(nonce []byte) ([]byte, error) {
			if kp.bearer {
				return nil, nil
			}
			return kp.KP.Sign(nonce)
		}
		return nil
	}
}

func (t *TokenKP) PublicKey() string {
	pk, _ := t.KP.PublicKey()
	return pk
}

type Identities struct {
	t        *testing.T
	Operator *TokenKP
	System   *TokenKP
	Accounts map[string]*TokenKP
}

func NewIdentities(t *testing.T) *Identities {
	v := &Identities{
		t:        t,
		Accounts: make(map[string]*TokenKP),
	}
	v.Operator = v.CreateOperator("O")
	v.System = v.AddAccount("SYS")

	return v
}

func (i *Identities) AddAccount(name string) *TokenKP {
	a := i.CreateAccount(name)
	i.Accounts[name] = a
	return a
}

func (i *Identities) GetAccount(name string) *TokenKP {
	return i.Accounts[name]
}

func (i *Identities) CreateUser(account string, name string, bearer bool) *TokenKP {
	tkp := i.Accounts[account]
	require.NotNil(i.t, tkp)

	kp, err := nkeys.CreateUser()
	require.NoError(i.t, err)

	tk := TokenKP{KP: kp, bearer: bearer}
	uc := jwt.NewUserClaims(tk.PublicKey())
	uc.Name = name
	uc.BearerToken = bearer
	tk.Token, err = uc.Encode(tkp.KP)
	require.NoError(i.t, err)

	return &tk
}

func (i *Identities) CreateOperator(name string) *TokenKP {
	kp, err := nkeys.CreateOperator()
	require.NoError(i.t, err)

	pk, err := kp.PublicKey()
	require.NoError(i.t, err)

	oc := jwt.NewOperatorClaims(pk)
	oc.Name = name
	token, err := oc.Encode(kp)
	require.NoError(i.t, err)

	return &TokenKP{token, kp, false}
}

func (i *Identities) CreateAccount(name string) *TokenKP {
	kp, err := nkeys.CreateAccount()
	require.NoError(i.t, err)

	pk, err := kp.PublicKey()
	require.NoError(i.t, err)

	ac := jwt.NewAccountClaims(pk)
	ac.Name = name

	token, err := ac.Encode(i.Operator.KP)
	require.NoError(i.t, err)

	return &TokenKP{token, kp, false}
}
