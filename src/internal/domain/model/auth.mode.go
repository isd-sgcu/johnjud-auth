package model

import "github.com/google/uuid"

type AuthSession struct {
	Base
	UserID    uuid.UUID `json:"user_id"`
	Hostname  string    `json:"hostname"`
	UserAgent string    `json:"user_agent"`
	IPAddress string    `json:"ip_address"`
}
