// Package proto defines the wire contract between the tunnel server and an
// agent: the control messages they exchange, and the framing that carries
// tunneled TCP connections and UDP packets over a transport session.
//
// The contract is deliberately transport-agnostic. Everything here is written
// against plain streams and opaque byte frames, so the same encoding runs over
// QUIC (a stream per tunneled connection, datagrams for UDP) and over the
// WebSocket fallback (yamux streams, UDP frames on a dedicated stream).
package proto

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/atvirokodosprendimai/v46-tunnelv1/internal/portspec"
)

// Version is the protocol version an agent announces in its Hello. The server
// refuses a mismatch outright rather than guessing at compatibility.
const Version = 1

// StreamKind is the first byte of every stream, naming what the stream carries.
// Without it the receiver would have to infer a stream's purpose from its
// arrival order, which stops being true the moment anything reconnects.
type StreamKind uint8

// The stream kinds. Control and UDP are opened by the agent once per session;
// TCP streams are opened by the server, one per accepted connection.
const (
	KindControl StreamKind = 1
	KindUDP     StreamKind = 2
	KindTCP     StreamKind = 3
)

// String names the kind for logs and errors.
func (k StreamKind) String() string {
	switch k {
	case KindControl:
		return "control"
	case KindUDP:
		return "udp"
	case KindTCP:
		return "tcp"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(k))
	}
}

// Hello is the agent's opening control message: who it is, and which of its
// local ports it wants published on the address it is about to be leased.
type Hello struct {
	Version int               `json:"version"`
	Token   string            `json:"token"`
	OS      string            `json:"os"`
	Arch    string            `json:"arch"`
	Ports   []portspec.Spec   `json:"ports"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// Refusal explains why one declared port was not published. A refusal is
// reported rather than silently dropped: an agent whose port never came up has
// to be able to say which one, and why, without reading the server's logs.
type Refusal struct {
	Spec   portspec.Spec `json:"spec"`
	Reason string        `json:"reason"`
}

// Lease is the server's answer: the address the agent was given, the ports it
// actually bound there, and the ones it would not.
type Lease struct {
	IP           string          `json:"ip"`
	AgentID      string          `json:"agent_id"`
	Bound        []portspec.Spec `json:"bound"`
	Refused      []Refusal       `json:"refused,omitempty"`
	KeepaliveSec int             `json:"keepalive_sec"`
}

// Error is a terminal control message: the session is over and this is why.
//
// It is sent as a message rather than by dropping the connection because a
// dropped connection is indistinguishable from a network failure, and a
// well-behaved agent retries those — so a refusal delivered that way becomes a
// reconnect loop against a server that will never accept it.
type Error struct {
	Message string `json:"error"`
}

// Control is the envelope for every control-stream message. Exactly one field
// is set; the envelope exists so the reader never has to guess which message
// shape arrived.
type Control struct {
	Hello *Hello `json:"hello,omitempty"`
	Lease *Lease `json:"lease,omitempty"`
	Error *Error `json:"err,omitempty"`
	Ping  bool   `json:"ping,omitempty"`
	Pong  bool   `json:"pong,omitempty"`
}

// ControlConn reads and writes control messages as newline-delimited JSON over
// one stream. Control traffic is a handful of messages per session, so it is
// worth far more that an operator can read it off the wire than that it is
// compact.
type ControlConn struct {
	rw  io.ReadWriter
	br  *bufio.Reader
	enc *json.Encoder
}

// NewControlConn wraps a stream for control-message exchange.
func NewControlConn(rw io.ReadWriter) *ControlConn {
	return &ControlConn{rw: rw, br: bufio.NewReader(rw), enc: json.NewEncoder(rw)}
}

// Send writes one control message.
func (c *ControlConn) Send(msg Control) error { return c.enc.Encode(msg) }

// Recv reads the next control message. It returns io.EOF when the peer closed
// the stream cleanly.
func (c *ControlConn) Recv() (Control, error) {
	line, err := c.br.ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return Control{}, io.EOF
		}
		if !errors.Is(err, io.EOF) {
			return Control{}, err
		}
	}
	var msg Control
	if err := json.Unmarshal(line, &msg); err != nil {
		return Control{}, fmt.Errorf("proto: malformed control message: %w", err)
	}
	return msg, nil
}

// maxSrcLen bounds the textual client address carried in a TCP open header. It
// is a length byte on the wire, so this is the format's own ceiling rather than
// a policy choice; "[ipv6]:port" fits inside it with room to spare.
const maxSrcLen = 255

// TCPOpen is the header the server writes after KindTCP, telling the agent
// which of its local ports to dial and who is calling.
type TCPOpen struct {
	// Port is the published port the client connected to. The agent dials this
	// same port on its own target host, which is the whole premise: a
	// connection to :1234 on the leased address becomes a connection to :1234
	// on the agent's localhost.
	Port uint16
	// Src is the remote client's address, carried for the agent's logs. It is
	// advisory: nothing authenticates it and nothing should authorise on it.
	Src string
}

// OpenResult is the agent's one-byte verdict on a TCP open, sent before any
// payload so the server can reset the client connection instead of holding it
// open against a local port that is not listening.
type OpenResult uint8

// The open verdicts.
const (
	OpenOK       OpenResult = 0
	OpenRefused  OpenResult = 1 // the agent's local dial failed
	OpenNotAllow OpenResult = 2 // the agent's own policy declined this port
)

// String names the verdict for logs and errors.
func (r OpenResult) String() string {
	switch r {
	case OpenOK:
		return "ok"
	case OpenRefused:
		return "refused by local dial"
	case OpenNotAllow:
		return "not allowed by agent policy"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(r))
	}
}

// WriteStreamKind writes the leading kind byte of a stream.
func WriteStreamKind(w io.Writer, k StreamKind) error {
	_, err := w.Write([]byte{byte(k)})
	return err
}

// ReadStreamKind reads the leading kind byte of a stream.
func ReadStreamKind(r io.Reader) (StreamKind, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return StreamKind(b[0]), nil
}

// WriteTCPOpen writes a TCP open header.
func WriteTCPOpen(w io.Writer, open TCPOpen) error {
	src := open.Src
	if len(src) > maxSrcLen {
		src = src[:maxSrcLen]
	}
	buf := make([]byte, 0, 3+len(src))
	buf = binary.BigEndian.AppendUint16(buf, open.Port)
	buf = append(buf, byte(len(src)))
	buf = append(buf, src...)
	_, err := w.Write(buf)
	return err
}

// ReadTCPOpen reads a TCP open header.
func ReadTCPOpen(r io.Reader) (TCPOpen, error) {
	var head [3]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return TCPOpen{}, err
	}
	open := TCPOpen{Port: binary.BigEndian.Uint16(head[:2])}
	if n := int(head[2]); n > 0 {
		src := make([]byte, n)
		if _, err := io.ReadFull(r, src); err != nil {
			return TCPOpen{}, err
		}
		open.Src = string(src)
	}
	return open, nil
}

// WriteOpenResult writes the agent's verdict on a TCP open.
func WriteOpenResult(w io.Writer, res OpenResult) error {
	_, err := w.Write([]byte{byte(res)})
	return err
}

// ReadOpenResult reads the agent's verdict on a TCP open.
func ReadOpenResult(r io.Reader) (OpenResult, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return OpenResult(b[0]), nil
}

// UDPHeaderLen is the fixed overhead a UDP frame carries: an 8-byte flow id and
// the 2-byte published port.
const UDPHeaderLen = 10

// ErrShortUDPFrame reports a UDP frame too short to contain its own header.
var ErrShortUDPFrame = errors.New("proto: truncated UDP frame")

// AppendUDPFrame appends a framed UDP packet to dst and returns the extended
// slice. The frame is self-describing in both directions: the flow id lets each
// side find its socket for this client, and the port is repeated so a receiver
// that has lost the flow (a restart, an eviction) can recreate it rather than
// dropping the packet.
func AppendUDPFrame(dst []byte, flowID uint64, port uint16, payload []byte) []byte {
	dst = binary.BigEndian.AppendUint64(dst, flowID)
	dst = binary.BigEndian.AppendUint16(dst, port)
	return append(dst, payload...)
}

// ParseUDPFrame splits a framed UDP packet. The returned payload aliases frame;
// copy it if it must outlive the buffer.
func ParseUDPFrame(frame []byte) (flowID uint64, port uint16, payload []byte, err error) {
	if len(frame) < UDPHeaderLen {
		return 0, 0, nil, ErrShortUDPFrame
	}
	return binary.BigEndian.Uint64(frame[:8]), binary.BigEndian.Uint16(frame[8:10]), frame[UDPHeaderLen:], nil
}

// MaxUDPPayload is the largest UDP payload a single frame may carry. It is the
// theoretical IPv4 UDP maximum, so the tunnel never truncates a packet the
// kernel was willing to deliver.
const MaxUDPPayload = 65507

// WriteUDPStreamFrame writes a length-prefixed UDP frame onto the fallback
// stream, used when the transport has no datagram support or the frame is too
// large for one. The prefix is needed because a stream has no packet boundaries
// of its own.
func WriteUDPStreamFrame(w io.Writer, frame []byte) error {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(frame)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err := w.Write(frame)
	return err
}

// ReadUDPStreamFrame reads one length-prefixed UDP frame from the fallback
// stream.
func ReadUDPStreamFrame(r io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n < UDPHeaderLen || n > UDPHeaderLen+MaxUDPPayload {
		return nil, fmt.Errorf("proto: UDP stream frame length %d out of range", n)
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}
