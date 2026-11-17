package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/health"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/account"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/accountnoop"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/aptosorbital"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/auth"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/authnoop"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/beacon"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/ipfs"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/jwks"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/kms"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/masterseed"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/patissuer"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/policy"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/plugin/threshold"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func main() {
	// distroless images have no shell or curl, so container healthchecks run the binary itself
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck())
	}

	utils.GetLogger("orbitport:plugin").Info("Initializing")

	cfg := core.ReadFromEnv()

	logger := utils.GetLogger(fmt.Sprintf("orbitport:plugin:%s", cfg.Plugin))

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(core.UnaryMetricsInterceptor(cfg.Plugin)),
	)

	logger.Infof("Starting plugin %s", cfg.Plugin)

	healthCheck := func(_ context.Context) (health.HealthState, error) {
		return health.HealthStateHealthy, nil
	}

	switch cfg.Plugin {
	case "aptosorbital":
		plugin, err := aptosorbital.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterRandomnessPluginServer(grpcServer, plugin)
		logger.Info("Aptos Orbital plugin ready")
	case "auth":
		plugin, err := auth.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterAuthPluginServer(grpcServer, plugin)
		logger.Info("Auth plugin ready")
	case "authnoop":
		plugin, err := authnoop.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterAuthPluginServer(grpcServer, plugin)
		logger.Info("Noop auth plugin ready")
	case "accountnoop":
		plugin, err := accountnoop.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterAccountPluginServer(grpcServer, plugin)
		logger.Info("Noop account plugin ready")
	case "ipfs":
		plugin, err := ipfs.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterIpfsPluginServer(grpcServer, plugin)

		// Override health check for IPFS plugin
		healthCheck = beacon.IpfsHealthCheck

		logger.Info("IPFS plugin ready")
	case "beacon":
		beaconpn, err := beacon.NewPlugin()
		if err != nil {
			panic(err)
		}

		logger.Info("Beacon plugin ready")

		err = beaconpn.Start(context.Background())
		if err != nil {
			logger.Errorf("error starting beacon plugin: %v", err)
		}
		defer func() {
			err := beaconpn.Close()
			if err != nil {
				logger.Errorf("error closing beacon plugin: %v", err)
			}
		}()

	case "masterseed":
		plugin, err := masterseed.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterMasterSeedPluginServer(grpcServer, plugin)
		logger.Info("MasterSeed plugin ready")

		defer func() {
			err := plugin.Close()
			if err != nil {
				logger.Errorf("error closing masterseed plugin: %v", err)
			}
		}()
	case "patissuer":
		plugin, err := patissuer.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterPatIssuerPluginServer(grpcServer, plugin)
		logger.Info("PatIssuer plugin ready")
	case "jwks":
		plugin, err := jwks.NewPlugin()
		if err != nil {
			panic(err)
		}
		// Serves HTTP rather than gRPC, so it registers nothing here. The
		// health server registered below still backs the k8s probes.
		go func() {
			logger.Infof("Starting JWKS http server on port %d", plugin.HTTPPort())
			// Staying up with a dead listener would keep passing probes while
			// serving nothing, so take the process down and let it restart.
			panic(plugin.ListenHTTP())
		}()
		logger.Info("JWKS plugin ready")
	case "kms":
		plugin, err := kms.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterKmsPluginServer(grpcServer, plugin)
		logger.Info("KMS plugin ready")
	case "policy":
		plugin, err := policy.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterPolicyPluginServer(grpcServer, plugin)
		logger.Info("Policy plugin ready")
	case "account":
		plugin, err := account.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterAccountPluginServer(grpcServer, plugin)
		logger.Info("Account plugin ready")

		defer plugin.Close()
	case "threshold":
		plugin, err := threshold.NewPlugin()
		if err != nil {
			panic(err)
		}
		proto.RegisterThresholdPluginServer(grpcServer, plugin)
		logger.Info("Threshold plugin ready")
	default:
		panic("unknown plugin")
	}

	healthServer := health.NewHealthServer(healthCheck)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	go func() {
		logger.Infof("Starting metrics server on port %d", cfg.MetricsPort)
		err := core.ListenMetrics(cfg.MetricsPort)
		if err != nil {
			logger.Errorf("failed to start metrics server: %v", err)
		}
	}()

	logger.Infof("Starting gRPC server on port %d", cfg.GrpcPort)

	err := core.ListenGrpc(grpcServer, cfg.GrpcPort)
	if err != nil {
		panic(err)
	}
}

// runHealthcheck probes this container's own gRPC health service and returns the exit code
func runHealthcheck() int {
	cfg := core.ReadFromEnv()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := health.Check(ctx, fmt.Sprintf("127.0.0.1:%d", cfg.GrpcPort)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
