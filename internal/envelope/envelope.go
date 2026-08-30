// Package envelope defines the signed v1 event envelope and its APNs projection.
package envelope

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Version is the only envelope version the relay accepts.
const Version = 1

// MaxAPNSPayloadBytes is Apple's hard limit for alert pushes.
const MaxAPNSPayloadBytes = 4096

// Field limits enforced on incoming envelopes.
const (
	MaxEventIDLen         = 64 // also used as apns-collapse-id, which Apple caps at 64 bytes
	MaxTitleLen           = 120
	MaxBodyLen            = 500
	MaxEnvironmentNameLen = 100
	MaxResourceNameLen    = 200
	MaxResourceIDLen      = 128
	MaxRecipients         = 500
)

// EventTypes mirrors Arcane's NotificationEventType values (plus "test").
var EventTypes = map[string]bool{
	"image_update":        true,
	"container_update":    true,
	"vulnerability_found": true,
	"prune_report":        true,
	"auto_heal":           true,
	"test":                true,
}

// Severities lists the severities the app knows how to render.
var Severities = map[string]bool{
	"info":     true,
	"success":  true,
	"warning":  true,
	"error":    true,
	"critical": true,
}

// Route kinds understood by the iOS PendingRoute enum.
const (
	RouteTab         = "tab"
	RouteContainer   = "container"
	RouteImage       = "image"
	RouteActivities  = "activities"
	RouteEvents      = "events"
	RouteEnvironment = "environment"
)

var (
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	eventIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	tabPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// Errors returned by Parse and BuildAPNSPayload.
var (
	ErrInvalid      = errors.New("invalid envelope")
	ErrPayloadLimit = errors.New("apns payload exceeds 4096 bytes")
)

// Resource identifies the object an event is about.
type Resource struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Route is the typed deep link the app should open on tap.
type Route struct {
	Kind          string `json:"kind"`
	Tab           string `json:"tab,omitempty"`
	EnvironmentID string `json:"environmentId,omitempty"`
	ID            string `json:"id,omitempty"`
}

// Envelope is the v1 signed event body sent by the manager.
type Envelope struct {
	Version         int       `json:"v"`
	EventID         string    `json:"eventId"`
	OccurredAt      time.Time `json:"occurredAt"`
	Type            string    `json:"type"`
	Severity        string    `json:"severity"`
	EnvironmentID   string    `json:"environmentId"`
	EnvironmentName string    `json:"environmentName"`
	Resource        *Resource `json:"resource,omitempty"`
	Title           string    `json:"title"`
	Body            string    `json:"body"`
	Route           Route     `json:"route"`
	ChannelID       string    `json:"channelId"`
	RecipientIDs    []string  `json:"recipientIds"`
}

// Parse decodes and validates a raw envelope body.
func Parse(raw []byte, now time.Time, maxAge time.Duration) (*Envelope, error) {
	var env Envelope
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if err := env.Validate(now, maxAge); err != nil {
		return nil, err
	}
	return &env, nil
}

// Validate checks structural limits and freshness.
func (e *Envelope) Validate(now time.Time, maxAge time.Duration) error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if e.Version != Version {
		add("v must be %d", Version)
	}
	if !eventIDPattern.MatchString(e.EventID) {
		add("eventId must match %s", eventIDPattern)
	}
	if e.OccurredAt.IsZero() {
		add("occurredAt is required")
	} else {
		age := now.Sub(e.OccurredAt)
		if age > maxAge {
			add("occurredAt is older than %s", maxAge)
		}
		if age < -maxAge {
			add("occurredAt is in the future")
		}
	}
	if !EventTypes[e.Type] {
		add("type %q is not supported", e.Type)
	}
	if !Severities[e.Severity] {
		add("severity %q is not supported", e.Severity)
	}
	if !idPattern.MatchString(e.ChannelID) {
		add("channelId is invalid")
	}
	problems = append(problems, e.contentProblems()...)
	problems = append(problems, e.recipientProblems()...)
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

func (e *Envelope) contentProblems() []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	if e.EnvironmentID != "" && !idPattern.MatchString(e.EnvironmentID) {
		add("environmentId is invalid")
	}
	if utf8.RuneCountInString(e.EnvironmentName) > MaxEnvironmentNameLen {
		add("environmentName exceeds %d characters", MaxEnvironmentNameLen)
	}
	if e.Resource != nil {
		if e.Resource.Kind == "" || utf8.RuneCountInString(e.Resource.Kind) > 32 {
			add("resource.kind is invalid")
		}
		if e.Resource.ID == "" || utf8.RuneCountInString(e.Resource.ID) > MaxResourceIDLen {
			add("resource.id is invalid")
		}
		if utf8.RuneCountInString(e.Resource.Name) > MaxResourceNameLen {
			add("resource.name exceeds %d characters", MaxResourceNameLen)
		}
	}
	if strings.TrimSpace(e.Title) == "" || utf8.RuneCountInString(e.Title) > MaxTitleLen {
		add("title is required and must be at most %d characters", MaxTitleLen)
	}
	if strings.TrimSpace(e.Body) == "" || utf8.RuneCountInString(e.Body) > MaxBodyLen {
		add("body is required and must be at most %d characters", MaxBodyLen)
	}
	if err := e.Route.Validate(); err != nil {
		add("route: %v", err)
	}
	return problems
}

func (e *Envelope) recipientProblems() []string {
	var problems []string
	if len(e.RecipientIDs) == 0 {
		problems = append(problems, "recipientIds must not be empty")
	}
	if len(e.RecipientIDs) > MaxRecipients {
		problems = append(problems, fmt.Sprintf("recipientIds exceeds %d entries", MaxRecipients))
	}
	seen := make(map[string]struct{}, len(e.RecipientIDs))
	for _, r := range e.RecipientIDs {
		if !idPattern.MatchString(r) {
			problems = append(problems, "recipientIds contains an invalid id")
			break
		}
		if _, dup := seen[r]; dup {
			problems = append(problems, "recipientIds contains duplicates")
			break
		}
		seen[r] = struct{}{}
	}
	return problems
}

// Validate checks that the route is one the app can consume.
func (r Route) Validate() error {
	switch r.Kind {
	case RouteTab:
		if !tabPattern.MatchString(r.Tab) {
			return errors.New("tab is required for kind=tab")
		}
	case RouteContainer, RouteImage:
		if !idPattern.MatchString(r.EnvironmentID) || !idPattern.MatchString(r.ID) {
			return fmt.Errorf("environmentId and id are required for kind=%s", r.Kind)
		}
	case RouteEnvironment:
		if !idPattern.MatchString(r.EnvironmentID) {
			return errors.New("environmentId is required for kind=environment")
		}
	case RouteActivities, RouteEvents:
	default:
		return fmt.Errorf("unknown kind %q", r.Kind)
	}
	return nil
}

// APNSAlert is the aps.alert dictionary.
type APNSAlert struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// APS is the Apple-defined portion of the payload.
type APS struct {
	Alert             APNSAlert `json:"alert"`
	Sound             string    `json:"sound,omitempty"`
	ThreadID          string    `json:"thread-id,omitempty"`
	InterruptionLevel string    `json:"interruption-level,omitempty"`
}

// ArcaneData is the custom portion the app uses for routing.
type ArcaneData struct {
	Version         int       `json:"v"`
	EventID         string    `json:"eventId"`
	OccurredAt      time.Time `json:"occurredAt"`
	Type            string    `json:"type"`
	Severity        string    `json:"severity"`
	EnvironmentID   string    `json:"environmentId,omitempty"`
	EnvironmentName string    `json:"environmentName,omitempty"`
	Resource        *Resource `json:"resource,omitempty"`
	Route           Route     `json:"route"`
	ChannelID       string    `json:"channelId"`
}

// APNSPayload is the full push payload.
type APNSPayload struct {
	APS    APS        `json:"aps"`
	Arcane ArcaneData `json:"arcane"`
}

// BuildAPNSPayload projects the envelope into a compact alert payload.
// Recipient ids are intentionally omitted: a device must not learn about other recipients.
func BuildAPNSPayload(e *Envelope) ([]byte, error) {
	p := APNSPayload{
		APS: APS{
			Alert:             APNSAlert{Title: e.Title, Body: e.Body},
			Sound:             "default",
			ThreadID:          e.EnvironmentID,
			InterruptionLevel: "active",
		},
		Arcane: ArcaneData{
			Version:         Version,
			EventID:         e.EventID,
			OccurredAt:      e.OccurredAt.UTC(),
			Type:            e.Type,
			Severity:        e.Severity,
			EnvironmentID:   e.EnvironmentID,
			EnvironmentName: e.EnvironmentName,
			Resource:        e.Resource,
			Route:           e.Route,
			ChannelID:       e.ChannelID,
		},
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxAPNSPayloadBytes {
		return nil, ErrPayloadLimit
	}
	return b, nil
}
