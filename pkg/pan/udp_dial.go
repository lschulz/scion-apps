// Copyright 2021 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pan

import (
	"context"
	"net"
	"net/netip"

	"github.com/scionproto/scion/pkg/snet"
)

// Conn represents a _dialed_ connection.
type Conn interface {
	net.Conn
	// SetPolicy allows to set the path policy for paths used by Write, at any
	// time.
	SetPolicy(policy Policy)
	// WriteWithCtx writes a message to the remote address using a path from the
	// path policy and selector. ctx is passed to the path selector where it can
	// provide additional user-defined information, e.g., whether the packet is
	// urgent or not.
	WriteWithCtx(ctx context.Context, b []byte) (n int, err error)
	// WriteVia writes a message to the remote address via the given path.
	// This bypasses the path policy and selector used for Write.
	WriteVia(path *Path, b []byte) (int, error)
	// ReadVia reads a message and returns the (return-)path via which the
	// message was received.
	ReadVia(b []byte) (int, *Path, error)

	GetPath() *Path
	GetPathWithCtx(ctx context.Context) *Path
}

// DialUDP opens a SCION/UDP socket, connected to the remote address.
// If the local address, or either its IP or port, are left unspecified, they
// will be automatically chosen.
//
// DialUDP looks up SCION paths to the destination AS. The policy defines the
// allowed paths and their preference order. The selector dynamically selects
// a path among this set for each Write operation.
// If the policy is nil, all paths are allowed.
// If the selector is nil, a DefaultSelector is used.
func DialUDP(
	ctx context.Context,
	local netip.AddrPort,
	remote UDPAddr,
	opts ...ConnOptions,
) (Conn, error) {
	o := applyConnOpts(opts)

	host, err := getHost()
	if err != nil {
		return nil, err
	}

	local, err = defaultLocalAddr(local)
	if err != nil {
		return nil, err
	}
	sn := snet.SCIONNetwork{
		Topology:    host.sciond,
		SCMPHandler: o.scmpHandler,
	}
	conn, err := sn.OpenRaw(ctx, net.UDPAddrFromAddrPort(local))
	if err != nil {
		return nil, err
	}
	ipport := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	localUDPAddr := UDPAddr{
		IA:   host.ia,
		IP:   ipport.Addr(),
		Port: ipport.Port(),
	}
	var subscriber *pathRefreshSubscriber
	if remote.IA != localUDPAddr.IA {
		subscriber, err = openPathRefreshSubscriber(ctx, localUDPAddr, remote, o.policy, o.selector)
		if err != nil {
			return nil, err
		}
	}
	return &dialedConn{
		baseUDPConn: baseUDPConn{
			raw: conn,
		},
		local:      localUDPAddr,
		remote:     remote,
		subscriber: subscriber,
		selector:   o.selector,
	}, nil
}

type ConnOptions func(*connOptions)

// WithDialSCMPHandler sets the SCMP handler for the connection.
func WithDialSCMPHandler(handler snet.SCMPHandler) ConnOptions {
	return func(o *connOptions) {
		if handler == nil {
			panic("nil SCMP handler not allowed")
		}
		o.scmpHandler = handler
	}
}

// WithSelector sets the path selector for the connection.
func WithSelector(selector Selector) ConnOptions {
	return func(o *connOptions) {
		if selector == nil {
			panic("nil selector not allowed")
		}
		o.selector = selector
	}
}

// WithPolicy sets the path policy for the connection.
func WithPolicy(policy Policy) ConnOptions {
	return func(o *connOptions) {
		o.policy = policy
	}
}

type connOptions struct {
	scmpHandler snet.SCMPHandler
	selector    Selector
	policy      Policy
}

func applyConnOpts(opts []ConnOptions) connOptions {
	o := connOptions{
		scmpHandler: DefaultSCMPHandler{},
		selector:    NewDefaultSelector(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

type dialedConn struct {
	baseUDPConn

	local      UDPAddr
	remote     UDPAddr
	subscriber *pathRefreshSubscriber
	selector   Selector
}

func (c *dialedConn) SetPolicy(policy Policy) {
	if c.subscriber != nil {
		c.subscriber.setPolicy(policy)
	}
}

func (c *dialedConn) LocalAddr() net.Addr {
	return c.local
}

func (c *dialedConn) GetPath() *Path {
	return c.GetPathWithCtx(context.TODO())
}

func (c *dialedConn) GetPathWithCtx(ctx context.Context) *Path {
	return c.selector.Path(ctx)
}

func (c *dialedConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *dialedConn) Write(b []byte) (int, error) {
	return c.WriteWithCtx(context.TODO(), b)
}

func (c *dialedConn) WriteWithCtx(ctx context.Context, b []byte) (int, error) {
	var path *Path
	if c.local.IA != c.remote.IA {
		path = c.selector.Path(ctx)
		if path == nil {
			return 0, errNoPathTo(c.remote.IA)
		}
	}
	return c.baseUDPConn.writeMsg(c.local, c.remote, path, b)
}

func (c *dialedConn) WriteVia(path *Path, b []byte) (int, error) {
	return c.baseUDPConn.writeMsg(c.local, c.remote, path, b)
}

func (c *dialedConn) Read(b []byte) (int, error) {
	for {
		n, remote, _, err := c.baseUDPConn.readMsg(b)
		if err != nil {
			return n, err
		}
		if remote != c.remote {
			continue // connected! Ignore spurious packets from wrong source
		}
		return n, err
	}
}

func (c *dialedConn) ReadVia(b []byte) (int, *Path, error) {
	for {
		n, remote, fwPath, err := c.baseUDPConn.readMsg(b)
		if err != nil {
			return n, nil, err
		}
		if remote != c.remote {
			continue // connected! Ignore spurious packets from wrong source
		}
		path, err := reversePathFromForwardingPath(c.remote.IA, c.local.IA, fwPath)
		if err != nil {
			continue // just drop the packet if there is something wrong with the path
		}
		return n, path, nil
	}
}

func (c *dialedConn) Close() error {
	if c.subscriber != nil {
		_ = c.subscriber.Close()
	}
	if c.selector != nil {
		_ = c.selector.Close()
	}
	return c.baseUDPConn.Close()
}

// pathRefreshSubscriber is the glue between a connection and the global path
// pool. It gets the paths to dst and sets the filtered path set on the
// target Selector.
type pathRefreshSubscriber struct {
	remoteIA IA
	policy   Policy
	target   Selector
}

func openPathRefreshSubscriber(ctx context.Context, local, remote UDPAddr, policy Policy,
	target Selector) (*pathRefreshSubscriber, error) {

	s := &pathRefreshSubscriber{
		remoteIA: remote.IA,
		policy:   policy,
		target:   target,
	}
	paths, err := pool.subscribe(ctx, remote.IA, s)
	if err != nil {
		return nil, err
	}
	s.target.Initialize(local, remote, filtered(s.policy, paths))
	return s, nil
}

func (s *pathRefreshSubscriber) Close() error {
	pool.unsubscribe(s.remoteIA, s)
	return nil
}

func (s *pathRefreshSubscriber) setPolicy(policy Policy) {
	s.policy = policy
	paths := pool.cachedPaths(s.remoteIA)
	s.target.Refresh(filtered(s.policy, paths))
}

func (s *pathRefreshSubscriber) refresh(dst IA, paths []*Path) {
	s.target.Refresh(filtered(s.policy, paths))
}

func (s *pathRefreshSubscriber) PathDown(pf PathFingerprint, pi PathInterface) {
	s.target.PathDown(pf, pi)
}

func filtered(policy Policy, paths []*Path) []*Path {
	if policy != nil {
		return policy.Filter(paths)
	}
	return paths
}
