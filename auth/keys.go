package auth

type ContextKey string

const (
	ContextKeyUserGroups ContextKey = "userGroups"
	ContextKeyUsername   ContextKey = "username"
	ContextKeyConnID     ContextKey = "connId"
)
