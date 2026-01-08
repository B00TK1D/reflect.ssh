package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

type tunnelManager struct {
	mu             sync.RWMutex
	reverseTunnels map[string]*reverseTunnel
}

type reverseTunnel struct {
	username     string
	port         uint32
	originalAddr string
	conn         *ssh.ServerConn
	done         chan struct{}
}

func newTunnelManager() *tunnelManager {
	return &tunnelManager{
		reverseTunnels: make(map[string]*reverseTunnel),
	}
}

func tunnelKey(username string, port uint32) string {
	return fmt.Sprintf("%s:%d", username, port)
}

func (tm *tunnelManager) registerReverseTunnel(username string, port uint32, originalAddr string, conn *ssh.ServerConn) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	key := tunnelKey(username, port)
	if _, exists := tm.reverseTunnels[key]; exists {
		return fmt.Errorf("username %s port %d already in use", username, port)
	}

	rt := &reverseTunnel{
		username:     username,
		port:         port,
		originalAddr: originalAddr,
		conn:         conn,
		done:         make(chan struct{}),
	}
	tm.reverseTunnels[key] = rt

	go func() {
		<-rt.done
		tm.mu.Lock()
		delete(tm.reverseTunnels, key)
		tm.mu.Unlock()
	}()

	return nil
}

func handleCancelTcpipForward(req *ssh.Request, username string, tm *tunnelManager) {
	var payload struct {
		Addr string
		Port uint32
	}
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		req.Reply(false, []byte("invalid payload"))
		return
	}
	tm.removeReverseTunnel(username, payload.Port)
	req.Reply(true, nil)
}

func (tm *tunnelManager) getReverseTunnel(username string, port uint32) (*reverseTunnel, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	key := tunnelKey(username, port)
	rt, exists := tm.reverseTunnels[key]
	if !exists {
		return nil, fmt.Errorf("no reverse tunnel found for username %s port %d", username, port)
	}
	return rt, nil
}

func (tm *tunnelManager) removeReverseTunnel(username string, port uint32) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	key := tunnelKey(username, port)
	if rt, exists := tm.reverseTunnels[key]; exists {
		close(rt.done)
		delete(tm.reverseTunnels, key)
	}
}

func handleChannel(newChannel ssh.NewChannel, username string, tm *tunnelManager, conn *ssh.ServerConn, port int) {
	switch newChannel.ChannelType() {
	case "session":
		handleSessionChannel(newChannel, username, port)
	case "direct-tcpip":
		handleForwardTunnel(newChannel, username, tm)
	default:
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType()))
	}
}

func handleSessionChannel(newChannel ssh.NewChannel, username string, port int) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}

	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				req.Reply(false, nil)
			case "shell":
				req.Reply(true, nil)
				portFlag := ""
				if port != 22 {
					portFlag = fmt.Sprintf(" -p %d", port)
				}
				instructions := fmt.Sprintf("SSH Tunnel Redirector\n\nUsername: %s\n\nTo create a reverse tunnel:\n  ssh -R 0:localhost:PORT %s@HOST%s\n\nTo create a forward tunnel:\n  ssh -L LOCAL_PORT:localhost:REMOTE_PORT %s@HOST%s\n\nPress Ctrl+C to exit.\n", username, username, portFlag, username, portFlag)
				channel.Write([]byte(instructions))
			case "signal":
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
		channel.Close()
	}()

	buf := make([]byte, 1)
	for {
		n, err := channel.Read(buf)
		if err != nil || n == 0 {
			break
		}
		if buf[0] == 3 {
			break
		}
	}
	channel.Close()
}

func handleForwardTunnel(newChannel ssh.NewChannel, username string, tm *tunnelManager) {
	log.Printf("[forward] Received direct-tcpip channel request from %s", username)

	var payload struct {
		Addr       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		log.Printf("[forward] Invalid payload from %s: %v", username, err)
		newChannel.Reject(ssh.ConnectionFailed, "invalid payload")
		return
	}

	log.Printf("[forward] Request from %s: connecting to %s:%d (origin: %s:%d)", username, payload.Addr, payload.Port, payload.OriginAddr, payload.OriginPort)

	rt, err := tm.getReverseTunnel(username, payload.Port)
	if err != nil {
		log.Printf("[forward] No reverse tunnel found: %v", err)
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	log.Printf("[forward] Found reverse tunnel for %s:%d", username, payload.Port)

	channel, reqs, err := newChannel.Accept()
	if err != nil {
		log.Printf("[forward] Failed to accept channel: %v", err)
		return
	}
	defer channel.Close()

	go ssh.DiscardRequests(reqs)

	originAddr := payload.OriginAddr
	originPort := payload.OriginPort
	if originAddr == "" {
		originAddr = "127.0.0.1"
	}
	if originPort == 0 {
		originPort = 0
	}

	forwardPayload := ssh.Marshal(struct {
		Addr       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}{
		Addr:       rt.originalAddr,
		Port:       rt.port,
		OriginAddr: originAddr,
		OriginPort: originPort,
	})

	log.Printf("[forward] Opening forwarded-tcpip channel to reverse tunnel client (addr: %s, port: %d, origin: %s:%d)", rt.originalAddr, rt.port, originAddr, originPort)
	reverseChannel, reqs, err := rt.conn.OpenChannel("forwarded-tcpip", forwardPayload)
	if err != nil {
		log.Printf("[forward] Failed to open channel to reverse tunnel: %v", err)
		log.Printf("[forward] Payload was: Addr=%s, Port=%d, OriginAddr=%s, OriginPort=%d", rt.originalAddr, rt.port, originAddr, originPort)
		channel.Write([]byte(fmt.Sprintf("Failed to connect to reverse tunnel: %v\n", err)))
		return
	}
	defer reverseChannel.Close()

	go ssh.DiscardRequests(reqs)

	log.Printf("[forward] Successfully opened channel, bridging")
	go func() {
		io.Copy(channel, reverseChannel)
		channel.Close()
		reverseChannel.Close()
	}()
	io.Copy(reverseChannel, channel)
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig, tm *tunnelManager, port int) {
	defer conn.Close()

	serverConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("[connection] Failed to create server connection: %v", err)
		return
	}
	defer serverConn.Close()

	username := serverConn.User()
	log.Printf("[connection] New connection from user: %s (remote: %s)", username, conn.RemoteAddr())

	go func() {
		for req := range reqs {
			log.Printf("[connection] Request type: %s from %s", req.Type, username)
			switch req.Type {
			case "tcpip-forward":
				handleTcpipForward(req, username, tm, serverConn)
			case "cancel-tcpip-forward":
				handleCancelTcpipForward(req, username, tm)
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
		log.Printf("[connection] Request stream closed for %s", username)
	}()

	for newChannel := range chans {
		log.Printf("[connection] New channel type: %s from %s", newChannel.ChannelType(), username)
		go handleChannel(newChannel, username, tm, serverConn, port)
	}
	log.Printf("[connection] Channel stream closed for %s", username)
}

func handleTcpipForward(req *ssh.Request, username string, tm *tunnelManager, conn *ssh.ServerConn) {
	var payload struct {
		Addr string
		Port uint32
	}
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		log.Printf("[reverse] Invalid payload from %s: %v", username, err)
		req.Reply(false, []byte("invalid payload"))
		return
	}

	port := payload.Port
	originalAddr := payload.Addr

	log.Printf("[reverse] Request from %s to register reverse tunnel on port %d (addr: %s)", username, port, originalAddr)

	if err := tm.registerReverseTunnel(username, port, originalAddr, conn); err != nil {
		log.Printf("[reverse] Registration failed: %v", err)
		req.Reply(false, []byte(err.Error()))
		return
	}

	log.Printf("[reverse] Registered reverse tunnel for %s:%d", username, port)
	req.Reply(true, ssh.Marshal(struct {
		Port uint32
	}{Port: port}))
}

func main() {
	port := flag.Int("port", 2222, "SSH server listening port")
	flag.Parse()

	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	privateKey, err := loadOrGenerateHostKey("host_key")
	if err != nil {
		log.Fatalf("Failed to load/generate host key: %v", err)
	}

	private, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	config.AddHostKey(private)

	tm := newTunnelManager()

	addr := fmt.Sprintf(":%d", *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}
	defer listener.Close()

	log.Printf("SSH tunnel redirector listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn, config, tm, *port)
	}
}

func loadOrGenerateHostKey(filename string) ([]byte, error) {
	if data, err := os.ReadFile(filename); err == nil {
		return data, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyDER := x509.MarshalPKCS1PrivateKey(key)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	}

	data := pem.EncodeToMemory(privateKeyBlock)
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to save host key: %v", err)
	}

	return data, nil
}
