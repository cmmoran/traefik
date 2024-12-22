package cli

import (
	"github.com/traefik/paerser/cli"
	tcmd "github.com/traefik/traefik/v3/cmd"
	"github.com/traefik/traefik/v3/pkg/config/static"
)

type RaftLoader struct {
	ResourceLoaders []cli.ResourceLoader
}

type RaftContextKey struct{}

func (r RaftLoader) Load(args []string, cmd *cli.Command) (bool, error) {
	var (
		ok  bool
		err error
	)
	for _, ldr := range r.ResourceLoaders {
		if ok, err = ldr.Load(args, cmd); ok && err == nil {
			if ok, err = r.buildCluster(cmd); ok && err == nil {
				return ok, err
			} else {
				return true, nil
			}
		}
	}

	return ok, err
}

func (r RaftLoader) buildCluster(cmd *cli.Command) (bool, error) {
	var (
		cfg *tcmd.TraefikCmdConfiguration
		ok  bool
		err error
	)
	if cfg, ok = cmd.Configuration.(*tcmd.TraefikCmdConfiguration); ok {
		if cfg.Configuration.Cluster != nil {
			if store, rerr := static.NewClusterStore(&cfg.Configuration, cfg.Configuration.Cluster); rerr != nil {
				return false, rerr
			} else {
				cmd.WithValue(RaftContextKey{}, store)
				return true, nil
			}
		}
	}

	return false, err
}
