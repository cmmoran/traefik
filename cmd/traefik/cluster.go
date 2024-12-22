package main

import (
	"errors"
	"github.com/hashicorp/raft"
	"github.com/rs/zerolog/log"
	"github.com/traefik/paerser/cli"
	"github.com/traefik/traefik/v3/cmd"
	traefikcli "github.com/traefik/traefik/v3/pkg/cli"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"reflect"
)

func runCluster(raftCmd *cli.Command, tConfig *cmd.TraefikCmdConfiguration, configurationChan chan *static.Configuration) error {
	tconfiguration := &tConfig.Configuration
	rawValue := raftCmd.Value(traefikcli.RaftContextKey{})
	if rawValue == nil {
		return errors.New("raft node not found")
	}
	if raftNode, ok := rawValue.(*static.ClusterStore); ok {
		go raftNode.OnLeader(func(id raft.ServerID, addr raft.ServerAddress) {
			log.Info().Msgf("Leader elected: %s", id)
			if raftNode.IsLeader() {
				tconfiguration.SetEffectiveConfiguration()
				if leaderConfig, err := raftNode.GetConfig(); err != nil {
					log.Err(err).Msg("unable to get leader static configuration from raft")
				} else if reflect.DeepEqual(tconfiguration, leaderConfig) {
					configurationChan <- tconfiguration
					return
				}
				log.Info().Any("config", tconfiguration).Msgf("Leader has new configuration")
				if err := raftNode.ApplyConfig(tconfiguration); err != nil {
					log.Err(err).Msg("unable to apply leader static configuration to raft")
					return
				}
				configurationChan <- tconfiguration
			} else {
				if raftStaticConfig, err := raftNode.GetConfig(); err != nil {
					log.Err(err).Msg("unable to get leader static configuration from raft")
					return
				} else {
					log.Info().Any("config", raftStaticConfig).Msgf("Not Leader, applying leader configuration")
					configurationChan <- raftStaticConfig
				}
			}
		})
		go raftNode.OnChange(func(config *static.Configuration) {
			configurationChan <- config
		})
		if err := raftNode.WaitForLeader(); err != nil {
			log.Err(err).Msg("unable to wait for raft leader")
			return err
		}
	}

	return runCmd(configurationChan)
}
