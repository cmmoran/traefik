package static

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"github.com/rs/zerolog/log"
	ptypes "github.com/traefik/paerser/types"
	"io"
	stdlog "log"
	"net"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/hashicorp/raft-boltdb"
)

func init() {
	gob.Register(&configBundle{})
}

type ClusterStore struct {
	raftNode    *raft.Raft
	fsm         *finiteStateMachine
	options     *Cluster
	changes     chan *configBundleChange
	initialized bool
}

// NewClusterStore creates a new ClusterStore instance with the given options.
func NewClusterStore(cfg *Configuration, clusterOpts *Cluster) (*ClusterStore, error) {
	if clusterOpts.SnapshotMax == 0 {
		clusterOpts.SnapshotMax = 1
	}
	if clusterOpts.TcpTimeout == 0 {
		clusterOpts.TcpTimeout = ptypes.Duration(3 * time.Second)
	}

	// Validate required options
	if clusterOpts.DataDir == "" || clusterOpts.NodeID == "" || clusterOpts.BindAddress == "" {
		return nil, fmt.Errorf("dataDir, nodeID, and bindAddress must be set")
	}

	opts := clusterOpts.Resolve()

	rs := &ClusterStore{
		options: opts,
		changes: make(chan *configBundleChange, 1),
	}

	// Initialize FSM
	rs.fsm = &finiteStateMachine{
		state: &configBundle{
			version:       0,
			configuration: cfg,
		},
		changes: rs.changes,
	}

	// Setup Raft log and stable store
	logStore, err := raftboltdb.NewBoltStore(fmt.Sprintf("%s/raft-log.db", opts.DataDir))
	if err != nil {
		return nil, fmt.Errorf("failed to create bolt log store: %w", err)
	}

	// Setup Raft log and stable store
	stableStore, err := raftboltdb.NewBoltStore(fmt.Sprintf("%s/raft-stable.db", opts.DataDir))
	if err != nil {
		return nil, fmt.Errorf("failed to create bolt stable store: %w", err)
	}

	// Setup Raft snapshot store
	snapshotStore, err := raft.NewFileSnapshotStore(opts.DataDir, opts.SnapshotMax, stdlog.Writer())
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot store: %w", err)
	}

	var advAddr net.Addr
	if len(opts.AdvertiseAddress) > 0 {
		advAddr, err = net.ResolveTCPAddr("tcp", opts.AdvertiseAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve advertise address: %w", err)
		}
	}
	// Setup TCP transport
	transport, err := raft.NewTCPTransport(opts.BindAddress, advAddr, 3, time.Duration(opts.TcpTimeout), os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP transport: %w", err)
	}

	// Initialize Raft node
	config := raft.DefaultConfig()
	config.HeartbeatTimeout = 3 * time.Second
	config.ElectionTimeout = 10 * time.Second
	config.LocalID = raft.ServerID(opts.NodeID)
	config.Logger = hclog.New(&hclog.LoggerOptions{
		Name:       "traefik-raft",
		Level:      hclog.Info,
		Color:      hclog.ForceColor,
		TimeFormat: "[2006-01-02 15:04:05.009]",
	})

	raftNode, err := raft.NewRaft(config, rs.fsm, logStore, stableStore, snapshotStore, transport)
	if err != nil {
		return nil, fmt.Errorf("failed to create raft instance: %w", err)
	}
	rs.raftNode = raftNode

	initialServers := make([]raft.Server, 0)
	for _, v := range opts.Peers {
		initialServers = append(initialServers, raft.Server{
			ID:      raft.ServerID(v.NodeID),
			Address: raft.ServerAddress(v.Address),
		})
	}

	future := raftNode.GetConfiguration()
	if err = future.Error(); err != nil {
		log.Error().Err(err).Msg("unable to bootstrap raft cluster")
	} else {
		log.Info().Msg("raft appears to be bootstrapped")
		futureConfiguration := future.Configuration()
		if len(futureConfiguration.Servers) == 0 {
			log.Info().Msg("Bootstrapping Raft cluster")
			raftConfig := raft.Configuration{
				Servers: initialServers,
			}
			if err = raftNode.BootstrapCluster(raftConfig).Error(); err != nil {
				log.Err(err).Msg("failed to bootstrap cluster")
			} else {
				log.Info().Msg("raft cluster bootstrapped")
			}
		} else {
			log.Info().Msgf("Raft cluster already exists with %d nodes", len(futureConfiguration.Servers))
			for _, server := range initialServers {
				indexFuture := raftNode.AddVoter(server.ID, server.Address, 0, 0)
				if err = indexFuture.Error(); err != nil {
					log.Error().Err(err).Msgf("failed to join cluster at address: %s", server.Address)
					continue
				} else {
					log.Info().Msg("Successfully joined Raft cluster")
					break
				}
			}
		}
	}

	rs.initialized = true

	return rs, nil
}

func (rs *ClusterStore) OnChange(on func(*Configuration)) {
	for {
		select {
		case conf := <-rs.changes:
			if conf.WasInitial() || conf.WasUpdated() {
				on(conf.to.configuration)
			} else {
				log.Info().Any("data", conf).Msgf("NO Config change")
			}
		}
	}
}
func (rs *ClusterStore) OnLeader(on func(raft.ServerID, raft.ServerAddress)) {
	obsChan := make(chan raft.Observation)
	lastAddr, lastID := rs.raftNode.LeaderWithID()
	obs := raft.NewObserver(obsChan, false, func(rft *raft.Observation) bool {
		addr, id := rft.Raft.LeaderWithID()
		if lastAddr != addr || lastID != id {
			lastAddr = addr
			lastID = id
			return true
		}

		return false
	})
	rs.raftNode.RegisterObserver(obs)
	defer rs.raftNode.DeregisterObserver(obs)
	select {
	case observation := <-obsChan:
		addr, id := observation.Raft.LeaderWithID()
		on(id, addr)
	}
}

func (rs *ClusterStore) WaitForLeader() error {
	ticker := time.NewTicker(1 * time.Second) // Check every second
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if leaderID, leaderAddress := rs.raftNode.LeaderWithID(); leaderID != "" {
				log.Info().Msgf("Leader elected: %s@%s", leaderID, leaderAddress)
				return nil
			}
		}
	}
}

func (rs *ClusterStore) IsLeader() bool {
	return rs.raftNode.State() == raft.Leader
}

// GetConfig fetches the current static configuration state.
func (rs *ClusterStore) GetConfig() (*Configuration, error) {
	if !rs.initialized {
		return nil, fmt.Errorf("ClusterStore is not initialized")
	}

	return rs.fsm.GetConfiguration(), nil
}

// ApplyConfig applies a new static configuration through Raft.
func (rs *ClusterStore) ApplyConfig(config *Configuration) error {
	if !rs.initialized {
		return fmt.Errorf("ClusterStore is not initialized")
	}
	if !rs.IsLeader() {
		return fmt.Errorf("not leader")
	}

	if config != nil && rs.fsm.state.configuration != nil && reflect.DeepEqual(config, rs.fsm.state.configuration) {
		return nil
	}

	// Serialize the new configuration
	var buf bytes.Buffer
	bundle := &configBundle{
		version:       rs.fsm.state.version + 1,
		configuration: config,
	}
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(bundle); err != nil {
		return fmt.Errorf("failed to encode configuration: %w", err)
	}

	// Apply the configuration through Raft
	log.Info().Any("configuration", config).Uint64("version", bundle.version).Msgf("applying config to cluster")
	future := rs.raftNode.Apply(buf.Bytes(), time.Duration(rs.options.TcpTimeout))
	if err := future.Error(); err != nil {
		return fmt.Errorf("failed to apply configuration: %w", err)
	}
	log.Info().Any("configuration", config).Uint64("version", bundle.version).Msgf("applied config to cluster")

	return nil
}

type configBundleChange struct {
	from *configBundle
	to   *configBundle
}

func (x *configBundleChange) WasInitial() bool {
	return x.from == nil && x.to != nil
}

func (x *configBundleChange) WasUpdated() bool {
	return x.from != nil && x.to != nil && x.from.version < x.to.version
}

type configBundle struct {
	version       uint64
	configuration *Configuration
}

// FSM implements the Raft FSM interface to manage dynamic configuration.
type finiteStateMachine struct {
	mu      sync.Mutex
	changes chan *configBundleChange
	state   *configBundle
}

// Apply applies a Raft log to the FSM.
func (f *finiteStateMachine) Apply(log *raft.Log) interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()

	buf := bytes.NewBuffer(log.Data)
	decoder := gob.NewDecoder(buf)

	var newState *configBundle
	if err := decoder.Decode(&newState); err != nil {
		return err
	}

	var oldState configBundle
	if f.state != nil {
		oldState = *f.state
	}
	// Replace the current state with the new state
	f.state = newState

	f.changes <- &configBundleChange{
		from: &oldState,
		to:   f.state,
	}
	return nil
}

// Snapshot creates a snapshot of the FSM state.
func (f *finiteStateMachine) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	if err := encoder.Encode(f.state); err != nil {
		return nil, err
	}

	return &fsmSnapshot{data: buf.Bytes()}, nil
}

// Restore restores the FSM from a snapshot.
func (f *finiteStateMachine) Restore(rc io.ReadCloser) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	decoder := gob.NewDecoder(rc)
	var restoredState *configBundle
	if err := decoder.Decode(&restoredState); err != nil {
		return err
	}

	var oldState configBundle
	if f.state != nil {
		oldState = *f.state
	}
	f.state = restoredState
	f.changes <- &configBundleChange{
		from: &oldState,
		to:   f.state,
	}
	return nil
}

func (f *finiteStateMachine) GetConfiguration() *Configuration {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.state.configuration
}

// fsmSnapshot implements the FSMSnapshot interface.
type fsmSnapshot struct {
	data []byte
}

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	_, err := sink.Write(s.data)
	if err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *fsmSnapshot) Release() {}
