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

package pan

import (
	"context"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
)

// IdIntHandler provides callbacks for sending and receiving ID-INT headers.
type IdIntHandler interface {
	// IdIntRequest is invoked for each packet sent to determines whether the
	// packet will contain an ID-INT header and if so what telemetry data to
	// request.
	IdIntRequest(ctx interface{}, dst UDPAddr, path *Path) *IdIntReq
	// IdIntReceived is invoked for every received packet that contains an
	// ID-INT telemetry header. The context returned by this function is
	// returned by
	IdIntReceived(src UDPAddr, path *Path, idint IdIntData)
}

// DefaultIdIntHandler never sends ID-INT packets and ignores received ID-INT
// data.
type DefaultIdIntHandler struct {
}

func (h *DefaultIdIntHandler) IdIntRequest(ctx interface{}, dst UDPAddr, path *Path) *IdIntReq {
	return nil
}

func (h *DefaultIdIntHandler) IdIntReceived(src UDPAddr, path *Path, idint IdIntData) {
}

type IdIntReq struct {
	snet.IntRequest
}

// stamp sets the source timestamp and DRKey based on the verifier type and
// verifier address.
func (r *IdIntReq) stamp(pktSrc addr.Addr, pktDst addr.Addr) error {
	host, err := getHost()
	if err != nil {
		return err
	}

	now := time.Now()
	r.SourceTS = now

	var key drkey.Key
	switch r.Verifier {
	case slayers.IdIntVerifDst:
		key, err = host.drkeyProvider.GetHostHostKey(context.TODO(), now, pktSrc, pktDst)
	case slayers.IdIntVerifSrc:
		key, err = host.drkeyProvider.GetHostHostKey(context.TODO(), now, pktSrc, pktSrc)
	case slayers.IdIntVerifOther:
		key, err = host.drkeyProvider.GetHostHostKey(context.TODO(), now, pktSrc, r.VerifierAddr)
	}
	if err != nil {
		return err
	}

	r.SourceKey = key
	return nil
}

// IdIntData is received from packets containing the ID-INT header. The data can
// either be validated and decoded (IdIntValid) or raw (IdIntRaw). If the
// ID-INT validator in the received packet was set to destination, the data is
// validated, otherwise it is passed to the application in raw format.
type IdIntData interface {
	// Returns true for validated data and false for raw data.
	Validated() bool
}

// IdIntValid contains decoded and validated ID-INT telemetry.
type IdIntValid struct {
	ValidationErr error
	snet.IntReport
}

func (d *IdIntValid) Validated() bool {
	return d.ValidationErr == nil
}

// IdIntRaw contains ID-INT telemetry that could not be validated yet, because
// it is supposed to be validated by another host.
type IdIntRaw struct {
	snet.RawIntReport
}

func (d *IdIntRaw) Validated() bool {
	return false
}

func tryVerifyIdInt(
	ctx context.Context,
	rawIdInt *snet.RawIntReport,
	remote UDPAddr,
	path *Path,
) (*Path, IdIntData, error) {

	if rawIdInt.Header.Verifier != slayers.IdIntVerifDst {
		return path, &IdIntRaw{
			RawIntReport: *rawIdInt,
		}, nil
	}

	host, err := getHost()
	if err != nil {
		return nil, nil, err
	}
	idint := &IdIntValid{}

	// must find a matching reverse path in order to know which keys
	// are required to verify ID-INT
	fullPath := (&pool).findPath(ctx, remote.IA, path.Fingerprint)
	if fullPath == nil {
		idint.ValidationErr = fmt.Errorf("verification failed because path is unknown")
		return path, idint, nil
	}
	hopToIA := func(i uint) (addr.IA, error) {
		n := uint(len(fullPath.Metadata.Interfaces))
		if i < n {
			return addr.IA(fullPath.Metadata.Interfaces[n-i-1].IA), nil
		}
		return 0, fmt.Errorf("hop index out of range")
	}

	source := addr.Addr{
		IA:   addr.IA(remote.IA),
		Host: addr.HostIP(remote.IP),
	}
	idint.ValidationErr = rawIdInt.VerifyAndDecrypt(
		ctx, &idint.IntReport, source, host.drkeyProvider, hopToIA)
	return fullPath, idint, nil
}
