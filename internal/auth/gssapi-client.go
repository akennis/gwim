// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
)

type gssChannelBindings struct {
	InitiatorAddrType      uint32
	InitiatorAddressLen    uint32
	InitiatorAddressOffset uint32
	AcceptorAddrType       uint32
	AcceptorAddressLen     uint32
	AcceptorAddressOffset  uint32
	ApplicationDataLen     uint32
	ApplicationDataOffset  uint32
}

const (
	saslHeaderLen          = 4
	saslSecurityLayerIndex = 0
	saslMaxBufferSizeStart = 1
	saslMaxBufferSizeEnd   = 4
	saslSecurityLayerNone  = 1 // bit 0 (value 1) means "No security layer"
)

type sspiGssapiClient struct {
	cred            *sspi.Credentials
	clientCtx       *kerberos.ClientContext
	channelBindings []byte
}

func (c *sspiGssapiClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	sspiFlags := uint32(sspi.ISC_REQ_INTEGRITY | sspi.ISC_REQ_CONFIDENTIALITY | sspi.ISC_REQ_MUTUAL_AUTH |
		sspi.ISC_REQ_CONNECTION | sspi.ISC_REQ_REPLAY_DETECT | sspi.ISC_REQ_SEQUENCE_DETECT | sspi.ISC_REQ_EXTENDED_ERROR)

	if c.clientCtx == nil {
		ctx, authDone, otoken, err := kerberos.NewClientContextWithChannelBindings(c.cred, target, sspiFlags, c.channelBindings)
		if err != nil {
			return nil, false, err
		}
		c.clientCtx = ctx
		return otoken, !authDone, nil
	}
	authDone, otoken, err := c.clientCtx.Update(token)
	return otoken, !authDone, err
}

func (c *sspiGssapiClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	_, decrypted, err := c.clientCtx.DecryptMessage(token, 0)
	if err != nil {
		return nil, err
	}

	resp := make([]byte, saslHeaderLen+len(authzid))
	resp[saslSecurityLayerIndex] = saslSecurityLayerNone
	if len(decrypted) >= saslHeaderLen {
		copy(resp[saslMaxBufferSizeStart:saslMaxBufferSizeEnd], decrypted[saslMaxBufferSizeStart:saslMaxBufferSizeEnd])
	}
	if authzid != "" {
		copy(resp[saslHeaderLen:], []byte(authzid))
	}

	wrapped, err := c.clientCtx.EncryptMessage(resp, 0, 0)
	return wrapped, err
}

func (c *sspiGssapiClient) DeleteSecContext() error {
	if c.clientCtx != nil {
		c.clientCtx.Release()
	}
	return nil
}
