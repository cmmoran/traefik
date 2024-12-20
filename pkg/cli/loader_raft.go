package cli

import (
	"github.com/traefik/paerser/cli"
	tcmd "github.com/traefik/traefik/v3/cmd"
	"github.com/traefik/traefik/v3/pkg/config/static"
)

type RaftLoader struct {
	ResourceLoaders []cli.ResourceLoader
}

func (r RaftLoader) Load(args []string, cmd *cli.Command) (bool, error) {
	var (
		ok  bool
		err error
	)
	for _, ldr := range r.ResourceLoaders {
		if ok, err = ldr.Load(args, cmd); ok && err == nil {
			if ok, err = r.buildRaft(cmd); ok && err == nil {
				return ok, err
			} else {
				return true, nil
			}
		}
	}

	return ok, err
}

func (r RaftLoader) buildRaft(cmd *cli.Command) (bool, error) {
	var (
		cfg *tcmd.TraefikCmdConfiguration
		ok  bool
		err error
	)
	if cfg, ok = cmd.Configuration.(*tcmd.TraefikCmdConfiguration); ok {
		if cfg.Raft != nil {
			if _, rerr := static.NewRaftStore(&cfg.Configuration, cfg.Raft); rerr != nil {
				return false, rerr
			} else {
				return true, nil
			}
		}
	}

	return false, err
}
