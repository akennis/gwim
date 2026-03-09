package integration_tests

import (
	"encoding/base64"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
	"github.com/alexbrainman/sspi/ntlm"
)

type SSPIClient struct {
	cred    *sspi.Credentials
	krbCtx  *kerberos.ClientContext
	ntlmCtx *ntlm.ClientContext
	pkg     string
}

func NewNTLMClient(domain, user, password string) (*SSPIClient, error) {
	var creds *sspi.Credentials
	var err error
	if user == "" {
		creds, err = sspi.AcquireCredentials("", "NTLM", sspi.SECPKG_CRED_OUTBOUND, nil)
	} else {
		creds, err = ntlm.AcquireUserCredentials(domain, user, password)
	}
	if err != nil {
		return nil, err
	}
	return &SSPIClient{
		cred: creds,
		pkg:  "NTLM",
	}, nil
}

func NewKerberosClient() (*SSPIClient, error) {
	creds, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}
	return &SSPIClient{
		cred: creds,
		pkg:  "Kerberos",
	}, nil
}

func (c *SSPIClient) GenerateToken(target string, inputToken []byte) ([]byte, bool, error) {
	if c.pkg == "Kerberos" {
		if c.krbCtx == nil {
			// Based on lint: kerberos.NewClientContext(cred, target)
			ctx, authDone, otoken, err := kerberos.NewClientContext(c.cred, target)
			if err != nil {
				return nil, false, err
			}
			c.krbCtx = ctx
			return otoken, authDone, nil
		}
		authDone, otoken, err := c.krbCtx.Update(inputToken)
		return otoken, authDone, err
	}

	// NTLM
	if c.ntlmCtx == nil {
		// Based on lint feedback: returns (ctx, token, err)
		ctx, otoken, err := ntlm.NewClientContext(c.cred)
		if err != nil && err != sspi.SEC_I_CONTINUE_NEEDED {
			return nil, false, err
		}
		c.ntlmCtx = ctx
		return otoken, (err == nil), nil
	}
	// Based on lint feedback: returns (token, err)
	otoken, err := c.ntlmCtx.Update(inputToken)
	if err != nil && err != sspi.SEC_I_CONTINUE_NEEDED {
		return nil, false, err
	}
	return otoken, (err == nil), nil
}

func (c *SSPIClient) Release() {
	if c.krbCtx != nil {
		c.krbCtx.Release()
	}
	if c.ntlmCtx != nil {
		c.ntlmCtx.Release()
	}
	if c.cred != nil {
		c.cred.Release()
	}
}

func (c *SSPIClient) GetAuthHeader(target string, inputToken []byte) (string, bool, error) {
	otoken, authDone, err := c.GenerateToken(target, inputToken)
	if err != nil {
		return "", false, err
	}
	if otoken == nil {
		return "", authDone, nil
	}

	prefix := "Negotiate"
	if c.pkg == "NTLM" {
		prefix = "NTLM"
	}

	return prefix + " " + base64.StdEncoding.EncodeToString(otoken), authDone, nil
}
