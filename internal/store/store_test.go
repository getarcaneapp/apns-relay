package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestChannelLifecycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pk := []byte("pubkey-32-bytes-................")
	ch, created, err := s.CreateChannel(ctx, "ch_a", "ed25519", pk)
	if err != nil || !created || ch.ID != "ch_a" {
		t.Fatalf("create: %v %v %+v", err, created, ch)
	}
	again, created, err := s.CreateChannel(ctx, "ch_b", "ed25519", pk)
	if err != nil || created || again.ID != "ch_a" {
		t.Fatalf("idempotent create: %v %v %+v", err, created, again)
	}
	if err := s.RevokeChannel(ctx, "ch_a"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetChannel(ctx, "ch_a")
	if err != nil || got.RevokedAt == nil {
		t.Fatalf("expected revoked: %v %+v", err, got)
	}
	fresh, created, err := s.CreateChannel(ctx, "ch_c", "ed25519", pk)
	if err != nil || !created || fresh.ID != "ch_c" {
		t.Fatalf("re-register after revoke: %v %v %+v", err, created, fresh)
	}
	if err := s.RevokeChannel(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestPairingAndDeliveries(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, _, err := s.CreateChannel(ctx, "ch_a", "ed25519", []byte("k")); err != nil {
		t.Fatal(err)
	}
	inst := &Installation{ID: "ins_1", SecretHash: []byte("h"), Platform: "apns", APNSEnvironment: "sandbox", DeviceTokenEnc: []byte("enc"), AppVersion: "1.0"}
	if err := s.CreateInstallation(ctx, inst); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(5 * time.Minute)
	b, err := s.Pair(ctx, "rcp_1", "ins_1", "ch_a", "user-1", "n1", exp)
	if err != nil || b.RecipientID != "rcp_1" {
		t.Fatalf("pair: %v %+v", err, b)
	}
	if _, err := s.Pair(ctx, "rcp_2", "ins_1", "ch_a", "user-1", "n1", exp); !errors.Is(err, ErrConflict) {
		t.Fatalf("nonce replay should conflict, got %v", err)
	}
	b2, err := s.Pair(ctx, "rcp_2", "ins_1", "ch_a", "user-2", "n2", exp)
	if err != nil || b2.RecipientID != "rcp_1" || b2.Subject != "user-2" {
		t.Fatalf("re-pair should reuse recipient: %v %+v", err, b2)
	}

	recips, err := s.ResolveRecipients(ctx, "ch_a", []string{"rcp_1", "rcp_unknown"})
	if err != nil || len(recips) != 1 || recips[0].InstallationID != "ins_1" {
		t.Fatalf("resolve: %v %+v", err, recips)
	}
	if err := s.EnqueueEvent(ctx, "ch_a", "evt-1", "evt-1", []NewDelivery{{RecipientID: "rcp_1", InstallationID: "ins_1", Payload: []byte("{}")}}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueEvent(ctx, "ch_a", "evt-1", "evt-1", nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate event should conflict, got %v", err)
	}
	claimed, err := s.ClaimDue(ctx, 10, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v %d", err, len(claimed))
	}
	if again, _ := s.ClaimDue(ctx, 10, time.Minute); len(again) != 0 {
		t.Fatalf("locked delivery should not be reclaimed, got %d", len(again))
	}
	if err := s.MarkRetry(ctx, claimed[0].ID, time.Now().Add(-time.Second), "503"); err != nil {
		t.Fatal(err)
	}
	claimed, err = s.ClaimDue(ctx, 10, time.Minute)
	if err != nil || len(claimed) != 1 || claimed[0].Attempts != 1 {
		t.Fatalf("reclaim after retry: %v %+v", err, claimed)
	}
	if err := s.MarkSent(ctx, claimed[0].ID); err != nil {
		t.Fatal(err)
	}
	d, err := s.GetDelivery(ctx, claimed[0].ID)
	if err != nil || d.Status != DeliverySent || d.Payload != nil {
		t.Fatalf("sent delivery should have no payload: %v %+v", err, d)
	}

	// Deleting the installation drops pending deliveries and bindings.
	if err := s.EnqueueEvent(ctx, "ch_a", "evt-2", "evt-2", []NewDelivery{{RecipientID: "rcp_1", InstallationID: "ins_1", Payload: []byte("{}")}}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteInstallation(ctx, "ins_1"); err != nil {
		t.Fatal(err)
	}
	ds, _ := s.ListDeliveriesByEvent(ctx, "ch_a", "evt-2")
	if len(ds) != 1 || ds[0].Status != DeliveryDropped {
		t.Fatalf("expected dropped delivery, got %+v", ds)
	}
	if r, _ := s.ResolveRecipients(ctx, "ch_a", []string{"rcp_1"}); len(r) != 0 {
		t.Fatal("binding should be gone after installation delete")
	}
	if _, err := s.GetInstallation(ctx, "ins_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestPrune(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	base := time.Now()
	s.now = func() time.Time { return base.Add(-48 * time.Hour) }
	if _, _, err := s.CreateChannel(ctx, "ch_a", "ed25519", []byte("k")); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueEvent(ctx, "ch_a", "old", "old", []NewDelivery{{RecipientID: "r", InstallationID: "i", Payload: []byte("{}")}}); err != nil {
		t.Fatal(err)
	}
	ds, _ := s.ListDeliveriesByEvent(ctx, "ch_a", "old")
	if err := s.MarkTerminal(ctx, ds[0].ID, DeliveryFailed, "x"); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base }
	if err := s.Prune(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if ds, _ := s.ListDeliveriesByEvent(ctx, "ch_a", "old"); len(ds) != 0 {
		t.Fatalf("expected pruned deliveries, got %d", len(ds))
	}
	if err := s.EnqueueEvent(ctx, "ch_a", "old", "old", nil); err != nil {
		t.Fatalf("event id should be reusable after prune: %v", err)
	}
}
