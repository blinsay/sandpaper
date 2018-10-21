package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/blinsay/sandpaper/internal/protocol"
	"github.com/heptio/workgroup"
	"golang.org/x/crypto/ed25519"
)

const (
	defaultRadius           = uint32(1 * time.Second / time.Microsecond)
	defaultReadTimout       = 250 * time.Millisecond
	defaultPacketQueueSize  = 500
	defaultBatchSize        = 10
	defaultWorkerCount      = 10
	defaultKeyLifetimeHours = 1
)

var (
	seed64               = flag.String("seed", "", "the private key seed for the server")
	roughtimeBindAddress = flag.String("bind-address", "0.0.0.0", "the ip address to listen on")
	roughtimePort        = flag.Int("port", 2002, "the port to listen for roughtime traffic on")
	defaultGremlin       = flag.String("gremlin", "NONE", "the default gremlin to adjust responses with")

	printInfoDump = flag.Bool("info-dump", false, "instead of serving, print server info and exit")
)

var gremlins = map[string]protocol.Encoder{
	// be nice
	"NONE": protocol.Encode,

	// mess with the contents of the response
	"BACK": reverseTags,
	"ODD_BODY": addTags(map[uint32][]byte{
		protocol.TagPAD: []byte{0x0, 0xd, 0xd},
	}),

	// mess with signatures
	"JMBL_CRT": modifyTag(protocol.TagCERT, scramble),

	// mess with midpoint and radius
	"BAD_RADI": addTags(map[uint32][]byte{
		protocol.TagRADI: []byte{3, 5, 8, 13},
	}),
	"BAD_MIDP": addTags(map[uint32][]byte{
		protocol.TagMIDP: []byte{1, 1, 3, 5, 8, 13, 21, 34},
	}),

	// drop some tags
	"DRP_TIME": dropTags([]uint32{protocol.TagMIDP, protocol.TagRADI}),
	"DRP_MIDP": dropTags([]uint32{protocol.TagMIDP}),
	"DRP_RADI": dropTags([]uint32{protocol.TagRADI}),
}

func main() {
	flag.Parse()

	if *seed64 == "" {
		log.Fatal("--seed is required")
	}
	seed, err := base64.StdEncoding.DecodeString(*seed64)
	if err != nil || len(seed) != ed25519.SeedSize {
		log.Fatal("--seed must be exactly 32 bytes and valid base64")
	}

	if *printInfoDump {
		fmt.Printf("   seed public key = %s\n", base64.StdEncoding.EncodeToString(pubKey(seed)))
		return
	}

	s := Server{
		Address: *roughtimeBindAddress,
		Port:    *roughtimePort,
		Seed:    seed,
	}

	gremlin, found := gremlins[*defaultGremlin]
	if !found {
		log.Fatalf("no gremlin named %q", *defaultGremlin)
	}
	s.DefaultGremlin = gremlin

	var g workgroup.Group

	g.Add(func(<-chan struct{}) error {
		return s.ListenAndServe()
	})
	g.Add(func(stop <-chan struct{}) error {
		sigs := make(chan os.Signal, 2)
		signal.Notify(sigs, syscall.SIGINT)

		select {
		case <-stop:
		case <-sigs:
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return s.Shutdown(ctx)
	})

	if err := g.Run(); err != nil {
		log.Printf("exited with an error: %s", err)
	}
}

type Server struct {
	// required
	Address        string
	Port           int
	Seed           []byte
	DefaultGremlin protocol.Encoder

	//optional
	ReadTimeout      time.Duration
	QueueSize        int
	BatchSize        int
	Workers          int
	KeyLifetimeHours int

	//internal
	started  int32
	conn     *net.UDPConn
	incoming chan *request
	shutdown chan struct{}
	served   chan struct{}
	// auth is an auth struct, set by Server.setKeys and fetched every batch
	// of replies
	auth atomic.Value
}

type auth struct {
	cert []byte
	key  []byte
}

type request struct {
	packet []byte
	addr   *net.UDPAddr
}

func (s *Server) Shutdown(ctx context.Context) error {
	if atomic.LoadInt32(&s.started) == 0 {
		return nil
	}

	close(s.shutdown)

	var err error
	select {
	case <-s.served:
	case <-ctx.Done():
		err = ctx.Err()
	}

	s.conn.Close()
	return err
}

func (s *Server) ListenAndServe() error {
	ip := net.ParseIP(s.Address)
	if ip == nil {
		return fmt.Errorf("invalid ip address: %q", s.Address)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   ip,
		Port: s.Port,
	})
	if err != nil {
		return err
	}

	return s.Serve(conn)
}

func (s *Server) Serve(conn *net.UDPConn) error {
	if s.ReadTimeout == 0 {
		s.ReadTimeout = defaultReadTimout
	}
	if s.QueueSize == 0 {
		s.QueueSize = defaultPacketQueueSize
	}
	if s.BatchSize <= 0 {
		s.BatchSize = defaultBatchSize
	}
	if s.Workers <= 0 {
		s.Workers = defaultWorkerCount
	}
	if s.KeyLifetimeHours <= 0 {
		s.KeyLifetimeHours = defaultKeyLifetimeHours
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	s.conn = conn
	s.incoming = make(chan *request, s.QueueSize)
	s.shutdown = make(chan struct{})
	s.served = make(chan struct{})

	// key rotation. setKeys must be called before any handler goroutines are
	// started so that s.auth has a value
	wg.Add(1)
	keyLifetime := time.Duration(s.KeyLifetimeHours) * time.Hour
	s.setKeys(keyLifetime)
	go s.rotateKeys(&wg, stop, keyLifetime)

	// handler threads
	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go s.handler(&wg, stop, conn)
	}

	atomic.StoreInt32(&s.started, 1)

LISTEN:
	for {
		select {
		case <-s.shutdown:
			break LISTEN
		default:
			// fall through
		}

		// packets that are too large get silently truncated. they'll fail to be
		// valid Roughtime messages. tracking errors is the only way to know that
		// this buffer is too small.
		//
		// https://github.com/golang/go/issues/18056
		//
		// TODO(benl): use a sync.Pool for bufs
		// TODO(benl): is ReadMsgUDP and oob data and ipv4/ipv6 socket options a thing
		//             worth considering? not sure why miekg/dns does it.
		var buf [protocol.MinRequestSize * 2]byte

		conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			if netErr, isNetErr := err.(net.Error); isNetErr && netErr.Temporary() {
				continue
			}
			return err
		}

		if n < protocol.MinRequestSize {
			log.Printf("dropped invalid request: too small")
			continue
		}

		request := &request{
			packet: buf[:n],
			addr:   addr,
		}

		select {
		case s.incoming <- request:
		default:
			log.Printf("dropped incoming packet: queue was full")
		}
	}

	conn.Close()
	close(stop)

	wg.Wait()
	close(s.served)

	return nil
}

func (s *Server) handler(wg *sync.WaitGroup, stop chan struct{}, w *net.UDPConn) {
	defer wg.Done()

	for {
		auth, ok := s.auth.Load().(auth)
		if !ok {
			panic("handler started without certs and keys")
		}

		requests, interrupted := batch(s.BatchSize, s.incoming, stop)
		if interrupted {
			return
		}

		nonces := make([][]byte, 0, len(requests))
		addrs := make([]*net.UDPAddr, 0, len(requests))

		gremlin := s.DefaultGremlin
		for i := range requests {
			packet, err := protocol.Decode(requests[i].packet)
			if err != nil {
				log.Printf("error decoding packet: %s", err)
				continue
			}
			nonces = append(nonces, packet[protocol.TagNonce])
			addrs = append(addrs, requests[i].addr)

			if gremlinName, requestedGremlin := packet[protocol.TagGremlin]; requestedGremlin {
				if f, found := gremlins[string(gremlinName)]; found {
					gremlin = f
					log.Printf("replying with gremlin=%s p=%p", string(gremlinName), gremlin)
				}
			}
		}

		midpoint := uint64(time.Now().UnixNano() / int64(time.Microsecond))
		replies, err := protocol.CreateReplies(gremlin, nonces, midpoint, defaultRadius, auth.cert, auth.key)
		if err != nil {
			log.Printf("error creating replies: %s", err)
			continue
		}

		for i := range replies {
			go func(i int) {
				n, err := w.WriteToUDP(replies[i], addrs[i])
				if err != nil {
					log.Printf("reply: write failed: %s", err)
				}
				if n < len(replies[i]) {
					log.Printf("reply: partial write: %s", err)
				}
			}(i)
		}
	}
}

func (s *Server) setKeys(lifetime time.Duration) {
	cert, key, err := generateSecrets(rand.Reader, s.Seed, lifetime)
	if err != nil {
		log.Fatalf("FATAL: unable to generate secrets: %s", err)
	}
	s.auth.Store(auth{
		cert: cert,
		key:  key,
	})
}

func (s *Server) rotateKeys(wg *sync.WaitGroup, stop chan struct{}, lifetime time.Duration) {
	defer wg.Done()

	ticker := time.NewTicker(lifetime)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.setKeys(lifetime)
		}
	}
}
func batch(size int, incoming <-chan *request, interrupt <-chan struct{}) (requests []*request, timedOut bool) {
	select {
	case request := <-incoming:
		requests = append(requests, request)
	case <-interrupt:
		timedOut = true
		return
	}

	for i := 0; i < size-1; i++ {
		select {
		case request := <-incoming:
			requests = append(requests, request)
		default:
			return
		}
	}
	return
}

func pubKey(seed []byte) []byte {
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey)
}

func generateSecrets(r io.Reader, seed []byte, lifetime time.Duration) (_cert, _key []byte, err error) {
	rootPrivateKey := ed25519.NewKeyFromSeed(seed)

	onlinePubKey, onlinePrivateKey, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, nil, err
	}

	nowMicros := uint64(time.Now().UnixNano() / int64(time.Microsecond))
	start := nowMicros - uint64((1*time.Minute)/time.Microsecond)
	end := nowMicros + uint64((lifetime+2*time.Minute)/time.Microsecond)

	cert, err := protocol.CreateCertificate(protocol.Encode, start, end, onlinePubKey, rootPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return cert, onlinePrivateKey, nil
}
