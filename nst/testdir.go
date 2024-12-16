package nst

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

type TestDir struct {
	t       *testing.T
	Dir     string
	Cleanup func()
}

func (td *TestDir) WriteServerConf(conf string) string {
	fp := path.Join(td.Dir, "server.conf")
	require.NoError(td.t, os.WriteFile(fp, []byte(conf), 0o644))
	return fp
}

func NewTestDir(t *testing.T) *TestDir {
	dir, err := os.MkdirTemp("", "callout_test")
	require.NoError(t, err)
	cleanup := func() {
		if t.Failed() {
			t.Logf("test dir location: %s", dir)
		} else {
			_ = os.RemoveAll(dir)
		}
	}

	return &TestDir{Dir: dir, t: t, Cleanup: cleanup}
}
