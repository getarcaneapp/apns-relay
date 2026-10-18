// Package push defines the platform-neutral types shared by the APNs and FCM senders.
package push

import (
	"context"
	"time"
)

// Platforms an installation can register for.
const (
	PlatformAPNS = "apns"
	PlatformFCM  = "fcm"
)

// Notification is a single push request.
type Notification struct {
	DeviceToken string
	// Environment is the APNs environment (sandbox or production); empty for FCM.
	Environment string
	Payload     []byte
	CollapseID  string
	Expiration  time.Time
}

// Outcome classifies a push service response for the delivery worker.
type Outcome int

const (
	// OutcomeSent means the push service accepted the notification.
	OutcomeSent Outcome = iota
	// OutcomeRetry means a transient failure; try again later.
	OutcomeRetry
	// OutcomeInvalidToken means the device token is dead; remove the installation.
	OutcomeInvalidToken
	// OutcomeFailed means a permanent, non-token failure.
	OutcomeFailed
)

// Result describes what the push service said.
type Result struct {
	Outcome    Outcome
	StatusCode int
	Reason     string
	// ID is the service's message id (apns-id or the FCM message name).
	ID string
}

// Sender is implemented by each platform's live client and log-only client.
type Sender interface {
	Send(ctx context.Context, n Notification) (Result, error)
}
