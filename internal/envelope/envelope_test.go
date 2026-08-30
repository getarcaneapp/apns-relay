package envelope

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func valid(now time.Time) Envelope {
	return Envelope{
		Version:         1,
		EventID:         "evt-1",
		OccurredAt:      now,
		Type:            "container_update",
		Severity:        "info",
		EnvironmentID:   "env-1",
		EnvironmentName: "Prod",
		Resource:        &Resource{Kind: "container", ID: "abc", Name: "web"},
		Title:           "Container updated",
		Body:            "web was updated to nginx:1.27",
		Route:           Route{Kind: RouteContainer, EnvironmentID: "env-1", ID: "abc"},
		ChannelID:       "ch_1",
		RecipientIDs:    []string{"rcp_1", "rcp_2"},
	}
}

func TestParseValid(t *testing.T) {
	now := time.Now()
	raw, _ := json.Marshal(valid(now))
	env, err := Parse(raw, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if env.EventID != "evt-1" || len(env.RecipientIDs) != 2 {
		t.Fatalf("unexpected parse: %+v", env)
	}
	payload, err := BuildAPNSPayload(env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "rcp_") {
		t.Fatal("payload must not contain recipient ids")
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["aps"].(map[string]any)["alert"].(map[string]any)["title"] != "Container updated" {
		t.Fatalf("unexpected payload: %s", payload)
	}
}

func TestParseRejects(t *testing.T) {
	now := time.Now()
	cases := map[string]func(e *Envelope){
		"stale":            func(e *Envelope) { e.OccurredAt = now.Add(-10 * time.Minute) },
		"future":           func(e *Envelope) { e.OccurredAt = now.Add(10 * time.Minute) },
		"version":          func(e *Envelope) { e.Version = 2 },
		"type":             func(e *Envelope) { e.Type = "bogus" },
		"severity":         func(e *Envelope) { e.Severity = "loud" },
		"title":            func(e *Envelope) { e.Title = strings.Repeat("x", 121) },
		"body":             func(e *Envelope) { e.Body = "" },
		"route kind":       func(e *Envelope) { e.Route = Route{Kind: "nope"} },
		"route container":  func(e *Envelope) { e.Route = Route{Kind: RouteContainer} },
		"no recipients":    func(e *Envelope) { e.RecipientIDs = nil },
		"dup recipients":   func(e *Envelope) { e.RecipientIDs = []string{"a", "a"} },
		"event id too big": func(e *Envelope) { e.EventID = strings.Repeat("e", 65) },
	}
	for name, mutate := range cases {
		e := valid(now)
		mutate(&e)
		raw, _ := json.Marshal(e)
		if _, err := Parse(raw, now, 5*time.Minute); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: expected ErrInvalid, got %v", name, err)
		}
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	now := time.Now()
	e := valid(now)
	raw, _ := json.Marshal(e)
	raw = append(raw[:len(raw)-1], []byte(`,"serverUrl":"https://x"}`)...)
	if _, err := Parse(raw, now, time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func TestPayloadStaysUnderLimitAtMaxLengths(t *testing.T) {
	now := time.Now()
	e := valid(now)
	e.Title = strings.Repeat("T", MaxTitleLen)
	e.Body = strings.Repeat("B", MaxBodyLen)
	e.EnvironmentName = strings.Repeat("E", MaxEnvironmentNameLen)
	e.Resource = &Resource{Kind: strings.Repeat("k", 32), ID: strings.Repeat("i", MaxResourceIDLen), Name: strings.Repeat("n", MaxResourceNameLen)}
	e.EnvironmentID = strings.Repeat("v", 128)
	e.Route = Route{Kind: RouteImage, EnvironmentID: strings.Repeat("v", 128), ID: strings.Repeat("i", 128)}
	e.ChannelID = strings.Repeat("c", 128)
	e.EventID = strings.Repeat("e", 64)
	if err := e.Validate(now, time.Minute); err != nil {
		t.Fatal(err)
	}
	p, err := BuildAPNSPayload(&e)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) > MaxAPNSPayloadBytes {
		t.Fatalf("payload %d bytes exceeds limit", len(p))
	}
}
