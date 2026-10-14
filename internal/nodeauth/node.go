package nodeauth

// Adapted from github.com/virtual-kubelet/virtual-kubelet node/nodeutil (Apache-2.0).
// Differences: Secrets and ConfigMaps come from namespaced GETs instead of cluster-wide
// informers, which the Node authorizer denies, and route attachment is passed in because
// nodeutil keeps it in an unexported field.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/pkg/errors"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"github.com/virtual-kubelet/virtual-kubelet/node"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	"github.com/virtual-kubelet/virtual-kubelet/node/nodeutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"
)

// RouteAttacher registers the provider's HTTP routes once the provider exists.
type RouteAttacher func(p nodeutil.Provider, cfg nodeutil.NodeConfig, pods corev1listers.PodLister)

// ProviderRoutes attaches the standard kubelet API routes to mux (same as nodeutil.AttachProviderRoutes).
func ProviderRoutes(mux api.ServeMux) RouteAttacher {
	return func(p nodeutil.Provider, cfg nodeutil.NodeConfig, pods corev1listers.PodLister) {
		mux.Handle("/", api.PodHandler(api.PodHandlerConfig{
			RunInContainer:    p.RunInContainer,
			AttachToContainer: p.AttachToContainer,
			GetContainerLogs:  p.GetContainerLogs,
			GetPods:           p.GetPods,
			GetPodsFromKubernetes: func(context.Context) ([]*v1.Pod, error) {
				return pods.List(labels.Everything())
			},
			GetStatsSummary:       p.GetStatsSummary,
			GetMetricsResource:    p.GetMetricsResource,
			StreamIdleTimeout:     cfg.StreamIdleTimeout,
			StreamCreationTimeout: cfg.StreamCreationTimeout,
			PortForward:           p.PortForward,
		}, true))
	}
}

// Node helps manage the startup/shutdown procedure for other controllers.
// It is intended as a convenience to reduce boiler plate code for starting up controllers.
//
// Must be created with constructor `NewNode`.
type Node struct {
	nc *node.NodeController
	pc *node.PodController

	readyCb func(context.Context) error

	ready chan struct{}
	done  chan struct{}
	err   error

	podInformerFactory informers.SharedInformerFactory
	svcInformerFactory informers.SharedInformerFactory
	client             kubernetes.Interface

	listenAddr string
	h          http.Handler
	tlsConfig  *tls.Config

	workers int

	eb record.EventBroadcaster
}

// NodeController returns the configured node controller.
func (n *Node) NodeController() *node.NodeController {
	return n.nc
}

// PodController returns the configured pod controller.
func (n *Node) PodController() *node.PodController {
	return n.pc
}

func (n *Node) runHTTP(ctx context.Context) (func(), error) {
	if n.tlsConfig == nil {
		log.G(ctx).Warn("TLS config not provided, not starting up http service")
		return func() {}, nil
	}
	if n.h == nil {
		log.G(ctx).Debug("No http handler, not starting up http service")
		return func() {}, nil
	}

	l, err := tls.Listen("tcp", n.listenAddr, n.tlsConfig)
	if err != nil {
		return nil, errors.Wrap(err, "error starting http listener")
	}

	log.G(ctx).Debug("Started TLS listener")

	srv := &http.Server{Handler: n.h, TLSConfig: n.tlsConfig, ReadHeaderTimeout: 30 * time.Second}
	go srv.Serve(l) //nolint:errcheck
	log.G(ctx).Debug("HTTP server running")

	return func() {
		/* #nosec */
		srv.Close()
		/* #nosec */
		l.Close()
	}, nil
}

// Run starts all the underlying controllers
func (n *Node) Run(ctx context.Context) (retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()

		n.err = retErr
		close(n.done)
	}()

	if n.eb != nil {
		n.eb.StartLogging(log.G(ctx).Infof)
		n.eb.StartRecordingToSink(&corev1client.EventSinkImpl{Interface: n.client.CoreV1().Events(v1.NamespaceAll)})
		defer n.eb.Shutdown()
		log.G(ctx).Debug("Started event broadcaster")
	}

	cancelHTTP, err := n.runHTTP(ctx)
	if err != nil {
		return err
	}
	defer cancelHTTP()

	go n.podInformerFactory.Start(ctx.Done())
	go n.svcInformerFactory.Start(ctx.Done())
	go n.pc.Run(ctx, n.workers) //nolint:errcheck

	defer func() {
		cancel()
		<-n.pc.Done()
	}()

	select {
	case <-ctx.Done():
		return n.err
	case <-n.pc.Ready():
	case <-n.pc.Done():
		return n.pc.Err()
	}

	log.G(ctx).Debug("pod controller ready")

	go n.nc.Run(ctx) //nolint:errcheck

	defer func() {
		cancel()
		<-n.nc.Done()
	}()

	select {
	case <-ctx.Done():
		n.err = ctx.Err()
		return n.err
	case <-n.nc.Ready():
	case <-n.nc.Done():
		return n.nc.Err()
	}

	log.G(ctx).Debug("node controller ready")

	if n.readyCb != nil {
		if err := n.readyCb(ctx); err != nil {
			return err
		}
	}
	close(n.ready)

	select {
	case <-n.nc.Done():
		cancel()
		return n.nc.Err()
	case <-n.pc.Done():
		cancel()
		return n.pc.Err()
	}
}

// WaitReady waits for the specified timeout for the controller to be ready.
//
// The timeout is for convenience so the caller doesn't have to juggle an extra context.
func (n *Node) WaitReady(ctx context.Context, timeout time.Duration) error {
	if timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	select {
	case <-n.ready:
		return nil
	case <-n.done:
		return fmt.Errorf("controller exited before ready: %w", n.err)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Ready returns a channel that will be closed after the controller is ready.
func (n *Node) Ready() <-chan struct{} {
	return n.ready
}

// Done returns a channel that will be closed when the controller has exited.
func (n *Node) Done() <-chan struct{} {
	return n.done
}

// NewNode creates a node like nodeutil.NewNode, but Secrets and ConfigMaps are fetched by name
// (namespaced GET with a short TTL cache) instead of through cluster-wide informers. Pods are
// filtered to this node, and only Services (which nodes may list) keep a shared informer.
func NewNode(name string, newProvider nodeutil.NewProviderFunc, routes RouteAttacher, opts ...nodeutil.NodeOpt) (*Node, error) {
	cfg := nodeutil.NodeConfig{
		NumWorkers:           4,
		InformerResyncPeriod: time.Minute,
		KubeconfigPath:       os.Getenv("KUBECONFIG"),
		HTTPListenAddr:       ":10250",
		NodeSpec: v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"type":                   "virtual-kubelet",
					"kubernetes.io/role":     "agent",
					"kubernetes.io/hostname": name,
				},
			},
			Status: v1.NodeStatus{
				Phase: v1.NodePending,
				Conditions: []v1.NodeCondition{
					{Type: v1.NodeReady},
					{Type: v1.NodeDiskPressure},
					{Type: v1.NodeMemoryPressure},
					{Type: v1.NodePIDPressure},
					{Type: v1.NodeNetworkUnavailable},
				},
			},
		},
	}

	for _, o := range opts {
		if err := o(&cfg); err != nil {
			return nil, err
		}
	}

	if _, _, err := net.SplitHostPort(cfg.HTTPListenAddr); err != nil {
		return nil, errors.Wrap(err, "error parsing http listen address")
	}
	if cfg.Client == nil {
		return nil, errors.New("no client provided")
	}

	podInformerFactory := informers.NewSharedInformerFactoryWithOptions(
		cfg.Client,
		cfg.InformerResyncPeriod,
		nodeutil.PodInformerFilter(name), // spec.nodeName=<node>
	)
	// Nodes may list and watch Services cluster-wide (the kubelet does, for env vars).
	svcInformerFactory := informers.NewSharedInformerFactoryWithOptions(cfg.Client, cfg.InformerResyncPeriod)

	podInformer := podInformerFactory.Core().V1().Pods()
	serviceInformer := svcInformerFactory.Core().V1().Services()
	secrets := SecretInformer{NewSecretLister(cfg.Client, DefaultTTL)}
	configMaps := ConfigMapInformer{NewConfigMapLister(cfg.Client, DefaultTTL)}

	p, np, err := newProvider(nodeutil.ProviderConfig{
		Pods:       podInformer.Lister(),
		ConfigMaps: configMaps.Lister(),
		Secrets:    secrets.Lister(),
		Services:   serviceInformer.Lister(),
		Node:       &cfg.NodeSpec,
	})
	if err != nil {
		return nil, errors.Wrap(err, "error creating provider")
	}

	if routes != nil {
		routes(p, cfg, podInformer.Lister())
	}

	var readyCb func(context.Context) error
	if np == nil {
		nnp := node.NewNaiveNodeProvider()
		np = nnp

		readyCb = func(ctx context.Context) error {
			setNodeReady(&cfg.NodeSpec)
			err := nnp.UpdateStatus(ctx, &cfg.NodeSpec)
			return errors.Wrap(err, "error marking node as ready")
		}
	}

	nodeControllerOpts := []node.NodeControllerOpt{
		node.WithNodeEnableLeaseV1(nodeutil.NodeLeaseV1Client(cfg.Client), node.DefaultLeaseDuration),
	}
	if cfg.NodeStatusUpdateErrorHandler != nil {
		nodeControllerOpts = append(nodeControllerOpts, node.WithNodeStatusUpdateErrorHandler(cfg.NodeStatusUpdateErrorHandler))
	}

	nc, err := node.NewNodeController(np, &cfg.NodeSpec, cfg.Client.CoreV1().Nodes(), nodeControllerOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "error creating node controller")
	}

	var eb record.EventBroadcaster
	if cfg.EventRecorder == nil {
		eb = record.NewBroadcaster()
		cfg.EventRecorder = eb.NewRecorder(scheme.Scheme, v1.EventSource{Component: path.Join(name, "pod-controller")})
	}

	pc, err := node.NewPodController(node.PodControllerConfig{
		PodClient:                 cfg.Client.CoreV1(),
		EventRecorder:             cfg.EventRecorder,
		Provider:                  p,
		PodInformer:               podInformer,
		SecretInformer:            secrets,
		ConfigMapInformer:         configMaps,
		ServiceInformer:           serviceInformer,
		SkipDownwardAPIResolution: cfg.SkipDownwardAPIResolution,
	})
	if err != nil {
		return nil, errors.Wrap(err, "error creating pod controller")
	}

	return &Node{
		nc:                 nc,
		pc:                 pc,
		readyCb:            readyCb,
		ready:              make(chan struct{}),
		done:               make(chan struct{}),
		eb:                 eb,
		podInformerFactory: podInformerFactory,
		svcInformerFactory: svcInformerFactory,
		client:             cfg.Client,
		tlsConfig:          cfg.TLSConfig,
		h:                  cfg.Handler,
		listenAddr:         cfg.HTTPListenAddr,
		workers:            cfg.NumWorkers,
	}, nil
}

func setNodeReady(n *v1.Node) {
	n.Status.Phase = v1.NodeRunning
	for i, c := range n.Status.Conditions {
		if c.Type != "Ready" {
			continue
		}
		c.Message = "Kubelet is ready"
		c.Reason = "KubeletReady"
		c.Status = v1.ConditionTrue
		c.LastHeartbeatTime = metav1.Now()
		c.LastTransitionTime = metav1.Now()
		n.Status.Conditions[i] = c
		return
	}
}
