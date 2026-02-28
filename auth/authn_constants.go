package auth

const (
	AUTHORIZATION = "Authorization"
	NEGOTIATE     = "Negotiate"
	NEGOTIATE_SPC = NEGOTIATE + " "
	TOKEN_OFFSET  = len(NEGOTIATE_SPC)
	WWW_AUTH      = "WWW-Authenticate"
)
