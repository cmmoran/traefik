package static

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/google/go-cmp/cmp"
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

var raftRegistry map[string]*RaftStore

func init() {
	gob.Register(&Configuration{})
	raftRegistry = make(map[string]*RaftStore)
}

func GetRaftStore(nodeID string) (raftStore *RaftStore, ok bool) {
	if len(nodeID) == 0 {
		for k := range raftRegistry {
			raftStore, ok = raftRegistry[k]
			if ok {
				return raftStore, ok
			}
		}
	}
	raftStore, ok = raftRegistry[nodeID]
	return raftStore, ok
}

type RaftStore struct {
	raftNode    *raft.Raft
	fsm         *finiteStateMachine
	options     *RaftOptions
	changes     chan *Configuration
	initialized bool
}

// NewRaftStore creates a new RaftStore instance with the given options.
func NewRaftStore(cfg *Configuration, opts *RaftOptions) (*RaftStore, error) {
	if opts.SnapshotMax == 0 {
		opts.SnapshotMax = 1
	}
	if opts.TcpTimeout == 0 {
		opts.TcpTimeout = ptypes.Duration(3 * time.Second)
	}

	// Validate required options
	if opts.DataDir == "" || opts.NodeID == "" || opts.BindAddress == "" {
		return nil, fmt.Errorf("dataDir, nodeID, and bindAddress must be set")
	}

	rs := &RaftStore{
		options: opts,
		changes: make(chan *Configuration, 1),
	}

	// Initialize FSM
	rs.fsm = &finiteStateMachine{
		state:   cfg,
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
	config.ElectionTimeout = 90 * time.Second
	config.LocalID = raft.ServerID(opts.NodeID)
	config.Logger = hclog.New(&hclog.LoggerOptions{
		Name:       "traefik-raft",
		Level:      hclog.Trace,
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
			Suffrage: raft.ServerSuffrage(v.Suffrage),
			ID:       raft.ServerID(v.ID),
			Address:  raft.ServerAddress(v.Address),
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
	raftRegistry[opts.NodeID] = rs

	return rs, nil
}

func (rs *RaftStore) OnChange(on func(*Configuration)) {
	var lastConf *Configuration
	for {
		select {
		case conf := <-rs.changes:
			if lastConf == nil || !reflect.DeepEqual(lastConf, conf) {
				diff := cmp.Diff(lastConf, conf, cmp.Options{})
				log.Info().Any("data", conf).Msgf("Config change: %s", diff)
				lastConf = conf
				on(lastConf)
			} else {
				log.Info().Any("data", conf).Msgf("NO Config change")
				lastConf = conf

			}
		}
	}
}
func (rs *RaftStore) OnLeader(on func(raft.ServerID, raft.ServerAddress)) {
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

func (rs *RaftStore) WaitForLeader() error {
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

func (rs *RaftStore) IsLeader() bool {
	return rs.raftNode.State() == raft.Leader
}

// GetConfig fetches the current static configuration state.
func (rs *RaftStore) GetConfig() (*Configuration, error) {
	if !rs.initialized {
		return nil, fmt.Errorf("RaftStore is not initialized")
	}

	return rs.fsm.GetState(), nil
}

// ApplyConfig applies a new static configuration through Raft.
func (rs *RaftStore) ApplyConfig(config *Configuration) error {
	if !rs.initialized {
		return fmt.Errorf("RaftStore is not initialized")
	}
	if !rs.IsLeader() {
		return fmt.Errorf("not the leader")
	}

	// Serialize the new configuration
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("failed to encode configuration: %w", err)
	}

	// Apply the configuration through Raft
	log.Info().Any("data", config).Msgf("Applying configuration to raft...")
	future := rs.raftNode.Apply(buf.Bytes(), time.Duration(rs.options.TcpTimeout))
	if err := future.Error(); err != nil {
		return fmt.Errorf("failed to apply configuration: %w", err)
	}
	log.Info().Any("data", config).Msgf("Done applying configuration to raft.")

	return nil
}

// FSM implements the Raft FSM interface to manage dynamic configuration.
type finiteStateMachine struct {
	mu      sync.Mutex
	changes chan *Configuration
	state   *Configuration
}

// Apply applies a Raft log to the FSM.
func (f *finiteStateMachine) Apply(log *raft.Log) interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()

	buf := bytes.NewBuffer(log.Data)
	decoder := gob.NewDecoder(buf)

	var newState *Configuration
	if err := decoder.Decode(&newState); err != nil {
		return err
	}

	// Replace the current state with the new state
	f.state = newState

	f.changes <- newState
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
	var restoredState *Configuration
	if err := decoder.Decode(&restoredState); err != nil {
		return err
	}

	f.state = restoredState
	f.changes <- restoredState
	return nil
}

func (f *finiteStateMachine) GetState() *Configuration {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.state
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
