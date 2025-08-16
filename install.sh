package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/valyala/fasthttp"
	"golang.org/x/time/rate"
)

var (
	// BufferPool for reuse of byte slices
	BufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 4096) // Adjust the size according to your needs
		},
	}
	config  *Config
	limiter *rate.Limiter
)

// Config represents the structure of the configuration file.
type Config struct {
	Host    string            `json:"host"`
	Domains map[string]string `json:"domains"`
}

// LoadConfig loads the configuration from a JSON file.
func LoadConfig(filename string) (*Config, error) {
	var config Config
	cfgBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	if err := json.Unmarshal(cfgBytes, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}
	return &config, nil
}

func findValueByKeyContains(m map[string]string, substr string) (string, bool) {
	for key, value := range m {
		if strings.Contains(strings.ToLower(substr), strings.ToLower(key)) {
			return value, true
		}
	}
	return "", false // Return empty string and false if no key contains the substring
}

// processDNSQuery processes the DNS query and returns a response.
func processDNSQuery(query []byte) ([]byte, error) {
	var msg dns.Msg
	if err := msg.Unpack(query); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("no DNS question found in the request")
	}

	domain := msg.Question[0].Name
	if ip, ok := findValueByKeyContains(config.Domains, domain); ok {
		// Create proper response message
		response := new(dns.Msg)
		response.SetReply(&msg)
		
		hdr := dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600, // example TTL
		}
		
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return nil, fmt.Errorf("invalid IP address: %s", ip)
		}
		
		// Ensure we have IPv4 address
		if ipv4 := parsedIP.To4(); ipv4 != nil {
			rr := &dns.A{
				Hdr: hdr,
				A:   ipv4,
			}
			response.Answer = append(response.Answer, rr)
		} else {
			return nil, fmt.Errorf("IPv6 addresses not supported yet")
		}
		
		return response.Pack()
	}

	// Forward to upstream DNS
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	resp, err := client.Post("https://1.1.1.1/dns-query", "application/dns-message", bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("failed to forward DNS query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream DNS returned status: %d", resp.StatusCode)
	}

	// Use buffer pool for efficient memory usage
	buffer := BufferPool.Get().([]byte)
	defer BufferPool.Put(buffer)

	// Read the initial chunk of the response
	n, err := resp.Body.Read(buffer)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read DNS response: %w", err)
	}

	// If the buffer was large enough to hold the entire response, return it
	if err == io.EOF || n < len(buffer) {
		result := make([]byte, n)
		copy(result, buffer[:n])
		return result, nil
	}

	// If the response is larger than our buffer, we need to read the rest
	var dynamicBuffer bytes.Buffer
	dynamicBuffer.Write(buffer[:n])
	if _, err := dynamicBuffer.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read remaining DNS response: %w", err)
	}

	return dynamicBuffer.Bytes(), nil
}

// handleDoTConnection handles a single DoT connection.
func handleDoTConnection(conn net.Conn) {
	defer conn.Close()

	if !limiter.Allow() {
		log.Println("DoT rate limit exceeded")
		return
	}

	// Set connection timeout
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		log.Printf("Failed to set connection deadline: %v", err)
		return
	}

	// Use a fixed-size buffer from the pool for the initial read
	poolBuffer := BufferPool.Get().([]byte)
	defer BufferPool.Put(poolBuffer)

	// Read the first two bytes to determine the length of the DNS message
	if _, err := io.ReadFull(conn, poolBuffer[:2]); err != nil {
		log.Printf("Failed to read DNS message length: %v", err)
		return
	}

	// Parse the length of the DNS message
	dnsMessageLength := binary.BigEndian.Uint16(poolBuffer[:2])
	
	// Validate message length
	if dnsMessageLength == 0 || dnsMessageLength > 65535 {
		log.Printf("Invalid DNS message length: %d", dnsMessageLength)
		return
	}

	// Prepare a buffer to read the full DNS message
	var buffer []byte
	if int(dnsMessageLength) > len(poolBuffer) {
		// If pool buffer is too small, allocate a new buffer
		buffer = make([]byte, dnsMessageLength)
	} else {
		// Use the pool buffer directly
		buffer = poolBuffer[:dnsMessageLength]
	}

	// Read the DNS message
	if _, err := io.ReadFull(conn, buffer); err != nil {
		log.Printf("Failed to read DNS message: %v", err)
		return
	}

	// Process the DNS query and generate a response
	response, err := processDNSQuery(buffer)
	if err != nil {
		log.Printf("Failed to process DNS query: %v", err)
		return
	}

	// Validate response length
	if len(response) > 65535 {
		log.Printf("Response too large: %d bytes", len(response))
		return
	}

	// Prepare the response with the length header
	responseLength := make([]byte, 2)
	binary.BigEndian.PutUint16(responseLength, uint16(len(response)))

	// Write the length of the response followed by the response itself
	if _, err := conn.Write(responseLength); err != nil {
		log.Printf("Failed to write response length: %v", err)
		return
	}

	if _, err := conn.Write(response); err != nil {
		log.Printf("Failed to write response: %v", err)
		return
	}
}

// startDoTServer starts the DNS-over-TLS server.
func startDoTServer() {
	// Load TLS credentials
	certPrefix := "/etc/letsencrypt/live/" + config.Host
	certFile := certPrefix + "/fullchain.pem"
	keyFile := certPrefix + "/privkey.pem"
	
	cer, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v", err)
	}
	
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", ":853", tlsConfig)
	if err != nil {
		log.Fatalf("Failed to start DoT server: %v", err)
	}
	defer listener.Close()

	log.Println("DoT server started on :853")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept DoT connection: %v", err)
			continue
		}
		go handleDoTConnection(conn)
	}
}

func serveSniProxy() {
	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("Failed to start SNI proxy: %v", err)
	}
	defer listener.Close()

	log.Println("SNI proxy started on :443")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept SNI connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	hello, err := readClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return nil, nil, err
	}
	return hello, peekedBytes, nil
}

type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(_ []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo
	var wg sync.WaitGroup
	wg.Add(1)

	config := &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = argHello
			wg.Done()
			return nil, fmt.Errorf("intentional handshake abort")
		},
	}

	tlsConn := tls.Server(readOnlyConn{reader: reader}, config)
	_ = tlsConn.Handshake() // Expected to fail, we only need SNI

	wg.Wait()

	if hello == nil {
		return nil, fmt.Errorf("failed to read ClientHello")
	}

	return hello, nil
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Set read deadline for ClientHello
	if err := clientConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("Failed to set read deadline: %v", err)
		return
	}

	clientHello, clientHelloBytes, err := peekClientHello(clientConn)
	if err != nil {
		log.Printf("Failed to read ClientHello: %v", err)
		return
	}

	sni := strings.ToLower(strings.TrimSpace(clientHello.ServerName))
	if sni == "" {
		log.Println("Empty SNI not allowed")
		response := "HTTP/1.1 502 Bad Gateway\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"Content-Length: 21\r\n" +
			"\r\n" +
			"nginx, malformed data"
		_, _ = clientConn.Write([]byte(response))
		return
	}

	var targetHost string

	// Check if SNI is in config.Domains → forward to specific IP
	if _, found := config.Domains[sni]; found {
		targetHost = "45.76.198.248:443"
	} else if sni == config.Host {
		// Special case: reverse proxy for own domain
		targetHost = "127.0.0.1:8443"
	} else {
		// Default: connect to the original domain
		targetHost = net.JoinHostPort(sni, "443")
	}

	// Connect to backend with timeout
	backendConn, err := net.DialTimeout("tcp", targetHost, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetHost, err)
		return
	}
	defer backendConn.Close()

	// Remove read deadline
	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to reset deadline: %v", err)
		return
	}

	// Relay data between connections
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy from backend to client
	go func() {
		defer wg.Done()
		_, err := io.Copy(clientConn, backendConn)
		if err != nil {
			log.Printf("Error copying from backend to client: %v", err)
		}
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Copy from client (starting with ClientHello) to backend
	go func() {
		defer wg.Done()
		// First send the captured ClientHello
		_, err := io.Copy(backendConn, clientHelloBytes)
		if err != nil {
			log.Printf("Error sending ClientHello to backend: %v", err)
			return
		}
		// Then copy the rest of the client data
		_, err = io.Copy(backendConn, clientConn)
		if err != nil {
			log.Printf("Error copying from client to backend: %v", err)
		}
		if tcpConn, ok := backendConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}

// handleDoHRequest processes the DoH request with rate limiting using fasthttp.
func handleDoHRequest(ctx *fasthttp.RequestCtx) {
	if !limiter.Allow() {
		ctx.Error("Rate limit exceeded", fasthttp.StatusTooManyRequests)
		return
	}

	var body []byte
	var err error

	switch string(ctx.Method()) {
	case fasthttp.MethodGet:
		dnsQueryParam := ctx.QueryArgs().Peek("dns")
		if dnsQueryParam == nil {
			ctx.Error("Missing 'dns' query parameter", fasthttp.StatusBadRequest)
			return
		}
		body, err = base64.RawURLEncoding.DecodeString(string(dnsQueryParam))
		if err != nil {
			ctx.Error("Invalid 'dns' query parameter", fasthttp.StatusBadRequest)
			return
		}
	case fasthttp.MethodPost:
		body = ctx.PostBody()
		if len(body) == 0 {
			ctx.Error("Empty request body", fasthttp.StatusBadRequest)
			return
		}
	default:
		ctx.Error("Only GET and POST methods are allowed", fasthttp.StatusMethodNotAllowed)
		return
	}

	// Validate DNS query size
	if len(body) > 512 {
		ctx.Error("DNS query too large", fasthttp.StatusBadRequest)
		return
	}

	dnsResponse, err := processDNSQuery(body)
	if err != nil {
		log.Printf("Failed to process DNS query: %v", err)
		ctx.Error("Failed to process DNS query", fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetContentType("application/dns-message")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Write(dnsResponse)
}

// runDOHServer starts the DNS-over-HTTPS server using fasthttp.
func runDOHServer() {
	server := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			switch string(ctx.Path()) {
			case "/dns-query":
				handleDoHRequest(ctx)
			default:
				ctx.Error("Unsupported path", fasthttp.StatusNotFound)
			}
		},
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxRequestBodySize: 1024, // 1KB should be enough for DNS queries
	}

	log.Println("DoH server starting on 127.0.0.1:8080")

	if err := server.ListenAndServe("127.0.0.1:8080"); err != nil {
		log.Fatalf("Error in DoH Server: %s", err)
	}
}

func main() {
	// Aggressive GC tuning
	if err := os.Setenv("GOGC", "50"); err != nil {
		log.Fatalf("Failed to set GOGC: %v", err)
	}

	cfg, err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	config = cfg

	// Validate configuration
	if config.Host == "" {
		log.Fatal("Host field is required in configuration")
	}

	log.Printf("Starting smartSNI proxy server for host: %s", config.Host)
	log.Println("Listening on ports: :443 (SNI), :853 (DoT), :8080 (DoH)")

	// Rate limiter: 100 req/sec, burst 200
	limiter = rate.NewLimiter(100, 200)

	var wg sync.WaitGroup
	wg.Add(3)

	// Start DoH server
	go func() {
		defer wg.Done()
		runDOHServer()
	}()

	// Start DoT server
	go func() {
		defer wg.Done()
		startDoTServer()
	}()

	// Start SNI proxy
	go func() {
		defer wg.Done()
		serveSniProxy()
	}()

	wg.Wait()
}
