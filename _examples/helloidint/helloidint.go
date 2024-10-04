// Copyright 2018 ETH Zurich
// Copyright 2024 OVGU Magdeburg
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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
)

func main() {
	var err error
	// get local and remote addresses from program arguments:
	var listen pan.IPPortValue
	flag.Var(&listen, "listen", "[Server] local IP:port to listen on")
	remoteAddr := flag.String("remote", "", "[Client] Remote (i.e. the server's) SCION Address (e.g. 17-ffaa:1:1,[127.0.0.1]:12345)")
	count := flag.Uint("count", 1, "[Client] Number of messages to send")
	flag.Parse()

	if (listen.Get().Port() > 0) == (len(*remoteAddr) > 0) {
		check(fmt.Errorf("either specify -listen for server or -remote for client"))
	}

	if listen.Get().Port() > 0 {
		err = runServer(listen.Get())
		check(err)
	} else {
		err = runClient(*remoteAddr, int(*count))
		check(err)
	}
}

type IdIntSelector struct {
}

func (s *IdIntSelector) IdIntRequest(ctx interface{}, dst pan.UDPAddr, path *pan.Path) *pan.IdIntReq {
	return &pan.IdIntReq{
		IntRequest: snet.IntRequest{
			MaxStackLen: 500,
			ReqNodeId:   true,
			Instructions: [4]uint8{
				slayers.IdIntIIngressTstamp,
				slayers.IdIntIIngressLinkRx,
				slayers.IdIntIEgressLinkTx,
				slayers.IdIntINop,
			},
			Verifier: slayers.IdIntVerifDst,
		},
	}
}

func (s *IdIntSelector) IdIntReceived(src pan.UDPAddr, path *pan.Path, idint pan.IdIntData) {
	d, ok := idint.(*pan.IdIntValid)
	if !ok || d.ValidationErr != nil {
		if d.ValidationErr != nil {
			fmt.Printf("Telemetry not verified: %v\n", d.ValidationErr)
		}
		return
	}
	fmt.Printf("Telemetry from %v\n", src)
	for _, hop := range d.Data {
		if hop.Source {
			fmt.Print("Src:")
		} else {
			fmt.Printf("Hop %d:", hop.HopIndex)
		}
		if path != nil && path.Metadata != nil && path.Metadata.Interfaces != nil {
			ia := path.Metadata.Interfaces[hop.HopIndex].IA
			fmt.Printf(" AS%v", ia)
		}
		if hop.HasNodeId() {
			fmt.Printf(" ID:%d", hop.NodeId)
		}
		if hop.DataLength(0) > 0 {
			fmt.Printf(" Time:%x", hop.DataSlots[0])
		}
		if hop.DataLength(1) > 0 {
			rx := 100.0 * float64(hop.DataSlots[1]) / float64(^uint32(0))
			fmt.Printf(" LinkRX:%.2f%%", rx)
		}
		if hop.DataLength(2) > 0 {
			tx := 100.0 * float64(hop.DataSlots[2]) / float64(^uint32(0))
			fmt.Printf(" LinkTX:%.2f%%", tx)
		}
		fmt.Println()
	}
}

type PathSelector struct {
	IdIntSelector
	mutex sync.Mutex
	path  *pan.Path
}

func (s *PathSelector) Path(ctx interface{}) *pan.Path {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.path
}

func (s *PathSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.path = paths[0]
}

func (s *PathSelector) Refresh(paths []*pan.Path) {
}

func (s *PathSelector) PathDown(pf pan.PathFingerprint, pi pan.PathInterface) {
}

func (s *PathSelector) Close() error {
	return nil
}

type ReplyPathSelector struct {
	IdIntSelector
	mtx     sync.RWMutex
	remotes map[pan.UDPAddr]*pan.Path
}

func (s *ReplyPathSelector) Initialize(local pan.UDPAddr) {
	s.remotes = make(map[pan.UDPAddr]*pan.Path)
}

func (s *ReplyPathSelector) Path(ctx interface{}, remote pan.UDPAddr) *pan.Path {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if path, ok := s.remotes[remote]; ok {
		return path
	}
	return nil
}

func (s *ReplyPathSelector) Record(remote pan.UDPAddr, path *pan.Path) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.remotes[remote] = path
}

func (s *ReplyPathSelector) PathDown(pan.PathFingerprint, pan.PathInterface) {
}

func (s *ReplyPathSelector) Close() error {
	return nil
}

func runServer(listen netip.AddrPort) error {
	conn, err := pan.ListenUDP(context.Background(), listen, &ReplyPathSelector{})
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Println(conn.LocalAddr())

	buffer := make([]byte, 16*1024)
	for {
		n, from, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}
		data := buffer[:n]
		fmt.Printf("Received %s: %s\n", from, data)
		msg := fmt.Sprintf("take it back! %s", time.Now().Format("15:04:05.0"))
		n, err = conn.WriteTo([]byte(msg), from)
		if err != nil {
			return err
		}
		fmt.Printf("Wrote %d bytes.\n", n)
	}
}

func runClient(address string, count int) error {
	addr, err := pan.ResolveUDPAddr(context.TODO(), address)
	if err != nil {
		return err
	}
	conn, err := pan.DialUDP(context.Background(), netip.AddrPort{}, addr, nil, &PathSelector{})
	if err != nil {
		return err
	}
	defer conn.Close()

	for i := 0; i < count; i++ {
		nBytes, err := conn.Write([]byte(fmt.Sprintf("hello world %s", time.Now().Format("15:04:05.0"))))
		if err != nil {
			return err
		}
		fmt.Printf("Wrote %d bytes.\n", nBytes)

		buffer := make([]byte, 16*1024)
		if err = conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			return err
		}
		n, err := conn.Read(buffer)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		} else if err != nil {
			return err
		}
		data := buffer[:n]
		fmt.Printf("Received reply: %s\n", data)
	}
	return nil
}

// Check just ensures the error is nil, or complains and quits
func check(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, "Fatal error:", e)
		os.Exit(1)
	}
}
