// Package store persists channels, installations, bindings and the delivery queue in SQLite.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" database/sql driver
)

// Sentinel errors returned by Store methods.
var (
	ErrNotFound = errors.New("not found")
	ErrRevoked  = errors.New("channel revoked")
	ErrConflict = errors.New("conflict")
)

// Store wraps the SQLite database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (creating if necessary) the database at path and applies migrations.
// Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	dsn := "file:" + path
	if path == ":memory:" {
		dsn = "file::memory:?cache=shared"
	} else {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Set("_txlock", "immediate")
	sep := "?"
	if path == ":memory:" {
		sep = "&"
	}
	db, err := sql.Open("sqlite", dsn+sep+q.Encode())
	if err != nil {
		return nil, err
	}
	// SQLite allows a single writer; keep the pool small so writes queue in-process
	// instead of hammering busy_timeout.
	db.SetMaxOpenConns(4)
	db.SetConnMaxLifetime(0)
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping verifies connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

var migrations = []string{
	`CREATE TABLE channels (
		id TEXT PRIMARY KEY,
		algorithm TEXT NOT NULL,
		public_key BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		revoked_at INTEGER
	);
	CREATE INDEX channels_public_key ON channels(public_key);

	CREATE TABLE installations (
		id TEXT PRIMARY KEY,
		secret_hash BLOB NOT NULL,
		platform TEXT NOT NULL,
		apns_environment TEXT NOT NULL,
		device_token_enc BLOB NOT NULL,
		app_version TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		last_seen_at INTEGER NOT NULL
	);

	CREATE TABLE bindings (
		recipient_id TEXT PRIMARY KEY,
		installation_id TEXT NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
		channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
		subject TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		UNIQUE(installation_id, channel_id)
	);
	CREATE INDEX bindings_channel ON bindings(channel_id);

	CREATE TABLE pairing_nonces (
		channel_id TEXT NOT NULL,
		nonce TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		PRIMARY KEY(channel_id, nonce)
	);
	CREATE INDEX pairing_nonces_expiry ON pairing_nonces(expires_at);

	CREATE TABLE events (
		channel_id TEXT NOT NULL,
		event_id TEXT NOT NULL,
		received_at INTEGER NOT NULL,
		PRIMARY KEY(channel_id, event_id)
	);
	CREATE INDEX events_received ON events(received_at);

	CREATE TABLE deliveries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		channel_id TEXT NOT NULL,
		event_id TEXT NOT NULL,
		recipient_id TEXT NOT NULL,
		installation_id TEXT NOT NULL,
		collapse_id TEXT NOT NULL,
		payload BLOB,
		status TEXT NOT NULL,
		attempts INTEGER NOT NULL DEFAULT 0,
		next_attempt_at INTEGER NOT NULL,
		locked_until INTEGER NOT NULL DEFAULT 0,
		last_error TEXT,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE INDEX deliveries_due ON deliveries(status, next_attempt_at);
	CREATE INDEX deliveries_installation ON deliveries(installation_id);
	CREATE INDEX deliveries_updated ON deliveries(updated_at);`,
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("init migrations table: %w", err)
	}
	var current int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	for i := current; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, i+1, s.now().Unix()); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ---- Channels -------------------------------------------------------------

// Channel is a registered manager instance identified by its Ed25519 public key.
type Channel struct {
	ID        string
	Algorithm string
	PublicKey []byte
	CreatedAt time.Time
	RevokedAt *time.Time
}

// CreateChannel registers a public key. If an active channel already exists for the
// same key, that channel is returned instead (registration is idempotent).
func (s *Store) CreateChannel(ctx context.Context, id, algorithm string, publicKey []byte) (*Channel, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var existing Channel
	var created int64
	err = tx.QueryRowContext(ctx, `SELECT id, created_at FROM channels WHERE algorithm = ? AND public_key = ? AND revoked_at IS NULL LIMIT 1`, algorithm, publicKey).Scan(&existing.ID, &created)
	switch {
	case err == nil:
		existing.Algorithm, existing.PublicKey = algorithm, publicKey
		existing.CreatedAt = time.Unix(created, 0)
		return &existing, false, tx.Commit()
	case !errors.Is(err, sql.ErrNoRows):
		return nil, false, err
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO channels(id, algorithm, public_key, created_at) VALUES (?, ?, ?, ?)`, id, algorithm, publicKey, now.Unix()); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return &Channel{ID: id, Algorithm: algorithm, PublicKey: publicKey, CreatedAt: now}, true, nil
}

// GetChannel returns a channel by id, including revoked ones (callers check RevokedAt).
func (s *Store) GetChannel(ctx context.Context, id string) (*Channel, error) {
	var c Channel
	var created int64
	var revoked sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, algorithm, public_key, created_at, revoked_at FROM channels WHERE id = ?`, id).Scan(&c.ID, &c.Algorithm, &c.PublicKey, &created, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt = time.Unix(created, 0)
	if revoked.Valid {
		t := time.Unix(revoked.Int64, 0)
		c.RevokedAt = &t
	}
	return &c, nil
}

// RevokeChannel marks the channel revoked, removes its bindings and drops pending deliveries.
func (s *Store) RevokeChannel(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := s.now().Unix()
	res, err := tx.ExecContext(ctx, `UPDATE channels SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM channels WHERE id = ?`, id).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return ErrNotFound
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM bindings WHERE channel_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pairing_nonces WHERE channel_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE deliveries SET status = ?, payload = NULL, last_error = 'channel revoked', updated_at = ? WHERE channel_id = ? AND status = ?`, DeliveryDropped, now, id, DeliveryPending); err != nil {
		return err
	}
	return tx.Commit()
}

// ---- Installations --------------------------------------------------------

// Installation is a device app install known to the relay.
type Installation struct {
	ID              string
	SecretHash      []byte
	Platform        string
	APNSEnvironment string
	DeviceTokenEnc  []byte
	AppVersion      string
	CreatedAt       time.Time
	LastSeenAt      time.Time
}

// CreateInstallation inserts a new installation.
func (s *Store) CreateInstallation(ctx context.Context, in *Installation) error {
	now := s.now()
	in.CreatedAt, in.LastSeenAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO installations(id, secret_hash, platform, apns_environment, device_token_enc, app_version, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		in.ID, in.SecretHash, in.Platform, in.APNSEnvironment, in.DeviceTokenEnc, in.AppVersion, now.Unix(), now.Unix())
	return err
}

// GetInstallation loads an installation by id.
func (s *Store) GetInstallation(ctx context.Context, id string) (*Installation, error) {
	var in Installation
	var created, seen int64
	err := s.db.QueryRowContext(ctx, `SELECT id, secret_hash, platform, apns_environment, device_token_enc, app_version, created_at, last_seen_at FROM installations WHERE id = ?`, id).
		Scan(&in.ID, &in.SecretHash, &in.Platform, &in.APNSEnvironment, &in.DeviceTokenEnc, &in.AppVersion, &created, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	in.CreatedAt, in.LastSeenAt = time.Unix(created, 0), time.Unix(seen, 0)
	return &in, nil
}

// UpdateInstallationToken replaces the device token (and optionally environment/app version).
func (s *Store) UpdateInstallationToken(ctx context.Context, id string, tokenEnc []byte, apnsEnvironment, appVersion string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE installations SET device_token_enc = ?, apns_environment = COALESCE(NULLIF(?, ''), apns_environment), app_version = COALESCE(NULLIF(?, ''), app_version), last_seen_at = ? WHERE id = ?`,
		tokenEnc, apnsEnvironment, appVersion, s.now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchInstallation updates last_seen_at.
func (s *Store) TouchInstallation(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE installations SET last_seen_at = ? WHERE id = ?`, s.now().Unix(), id)
	return err
}

// DeleteInstallation removes an installation, its bindings and pending deliveries.
func (s *Store) DeleteInstallation(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE deliveries SET status = ?, payload = NULL, last_error = 'installation removed', updated_at = ? WHERE installation_id = ? AND status = ?`,
		DeliveryDropped, s.now().Unix(), id, DeliveryPending); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM installations WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// ---- Bindings -------------------------------------------------------------

// Binding links an installation to a channel under an opaque recipient id.
type Binding struct {
	RecipientID    string
	InstallationID string
	ChannelID      string
	Subject        string
	CreatedAt      time.Time
}

// Pair creates a binding, consuming the pairing nonce. If the installation is already
// bound to the channel the existing binding is returned. Returns ErrConflict when the
// nonce was already used.
func (s *Store) Pair(ctx context.Context, recipientID, installationID, channelID, subject, nonce string, nonceExpiry time.Time) (*Binding, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var revoked sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at FROM channels WHERE id = ?`, channelID).Scan(&revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if revoked.Valid {
		return nil, ErrRevoked
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO pairing_nonces(channel_id, nonce, expires_at) VALUES (?, ?, ?)`, channelID, nonce, nonceExpiry.Unix()); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}

	var existing Binding
	var created int64
	err = tx.QueryRowContext(ctx, `SELECT recipient_id, subject, created_at FROM bindings WHERE installation_id = ? AND channel_id = ?`, installationID, channelID).
		Scan(&existing.RecipientID, &existing.Subject, &created)
	switch {
	case err == nil:
		if _, err := tx.ExecContext(ctx, `UPDATE bindings SET subject = ? WHERE recipient_id = ?`, subject, existing.RecipientID); err != nil {
			return nil, err
		}
		existing.InstallationID, existing.ChannelID, existing.Subject = installationID, channelID, subject
		existing.CreatedAt = time.Unix(created, 0)
		return &existing, tx.Commit()
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO bindings(recipient_id, installation_id, channel_id, subject, created_at) VALUES (?, ?, ?, ?, ?)`,
		recipientID, installationID, channelID, subject, now.Unix()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Binding{RecipientID: recipientID, InstallationID: installationID, ChannelID: channelID, Subject: subject, CreatedAt: now}, nil
}

// Unpair deletes a binding owned by installationID.
func (s *Store) Unpair(ctx context.Context, recipientID, installationID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM bindings WHERE recipient_id = ? AND installation_id = ?`, recipientID, installationID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Recipient is a resolved binding plus the installation needed to deliver to it.
type Recipient struct {
	RecipientID     string
	InstallationID  string
	Platform        string
	APNSEnvironment string
	DeviceTokenEnc  []byte
}

// ResolveRecipients returns the recipients of channelID among ids; unknown ids are omitted.
func (s *Store) ResolveRecipients(ctx context.Context, channelID string, ids []string) ([]Recipient, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, channelID)
	for _, id := range ids {
		args = append(args, id)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	const base = `SELECT b.recipient_id, i.id, i.platform, i.apns_environment, i.device_token_enc
		FROM bindings b JOIN installations i ON i.id = b.installation_id
		WHERE b.channel_id = ? AND b.recipient_id IN (%s)`
	query := fmt.Sprintf(base, placeholders) //nolint:gosec // only "?" placeholders are interpolated; values are bound
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Recipient
	for rows.Next() {
		var r Recipient
		if err := rows.Scan(&r.RecipientID, &r.InstallationID, &r.Platform, &r.APNSEnvironment, &r.DeviceTokenEnc); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- Events & deliveries --------------------------------------------------

// Delivery statuses.
const (
	DeliveryPending = "pending"
	DeliverySent    = "sent"
	DeliveryFailed  = "failed"
	DeliveryDropped = "dropped"
)

// Delivery is one queued push to one recipient.
type Delivery struct {
	ID             int64
	ChannelID      string
	EventID        string
	RecipientID    string
	InstallationID string
	CollapseID     string
	Payload        []byte
	Status         string
	Attempts       int
	NextAttemptAt  time.Time
	LastError      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// NewDelivery is the input for enqueueing.
type NewDelivery struct {
	RecipientID    string
	InstallationID string
	Payload        []byte
}

// EnqueueEvent records the event and its per-recipient deliveries atomically.
// It returns ErrConflict if the (channel, event) pair was already accepted.
func (s *Store) EnqueueEvent(ctx context.Context, channelID, eventID, collapseID string, deliveries []NewDelivery) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := s.now().Unix()
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(channel_id, event_id, received_at) VALUES (?, ?, ?)`, channelID, eventID, now); err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO deliveries(channel_id, event_id, recipient_id, installation_id, collapse_id, payload, status, attempts, next_attempt_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, d := range deliveries {
		if _, err := stmt.ExecContext(ctx, channelID, eventID, d.RecipientID, d.InstallationID, collapseID, d.Payload, DeliveryPending, now, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ClaimDue locks up to limit due deliveries for lease and returns them.
func (s *Store) ClaimDue(ctx context.Context, limit int, lease time.Duration) ([]Delivery, error) {
	now := s.now()
	rows, err := s.db.QueryContext(ctx, `UPDATE deliveries SET locked_until = ?
		WHERE id IN (SELECT id FROM deliveries WHERE status = ? AND next_attempt_at <= ? AND locked_until < ? ORDER BY next_attempt_at, id LIMIT ?)
		RETURNING id, channel_id, event_id, recipient_id, installation_id, collapse_id, payload, status, attempts, next_attempt_at, COALESCE(last_error, ''), created_at, updated_at`,
		now.Add(lease).Unix(), DeliveryPending, now.Unix(), now.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		var next, created, updated int64
		if err := rows.Scan(&d.ID, &d.ChannelID, &d.EventID, &d.RecipientID, &d.InstallationID, &d.CollapseID, &d.Payload, &d.Status, &d.Attempts, &next, &d.LastError, &created, &updated); err != nil {
			return nil, err
		}
		d.NextAttemptAt, d.CreatedAt, d.UpdatedAt = time.Unix(next, 0), time.Unix(created, 0), time.Unix(updated, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkSent finalizes a delivery as accepted by APNs and discards the payload.
func (s *Store) MarkSent(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE deliveries SET status = ?, payload = NULL, attempts = attempts + 1, locked_until = 0, last_error = NULL, updated_at = ? WHERE id = ?`, DeliverySent, s.now().Unix(), id)
	return err
}

// MarkRetry schedules another attempt.
func (s *Store) MarkRetry(ctx context.Context, id int64, next time.Time, reason string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE deliveries SET attempts = attempts + 1, next_attempt_at = ?, locked_until = 0, last_error = ?, updated_at = ? WHERE id = ?`, next.Unix(), reason, s.now().Unix(), id)
	return err
}

// MarkTerminal ends a delivery with a final status (failed/dropped) and discards the payload.
func (s *Store) MarkTerminal(ctx context.Context, id int64, status, reason string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE deliveries SET status = ?, payload = NULL, attempts = attempts + 1, locked_until = 0, last_error = ?, updated_at = ? WHERE id = ?`, status, reason, s.now().Unix(), id)
	return err
}

// GetDelivery loads one delivery (tests and diagnostics).
func (s *Store) GetDelivery(ctx context.Context, id int64) (*Delivery, error) {
	var d Delivery
	var next, created, updated int64
	err := s.db.QueryRowContext(ctx, `SELECT id, channel_id, event_id, recipient_id, installation_id, collapse_id, payload, status, attempts, next_attempt_at, COALESCE(last_error, ''), created_at, updated_at FROM deliveries WHERE id = ?`, id).
		Scan(&d.ID, &d.ChannelID, &d.EventID, &d.RecipientID, &d.InstallationID, &d.CollapseID, &d.Payload, &d.Status, &d.Attempts, &next, &d.LastError, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.NextAttemptAt, d.CreatedAt, d.UpdatedAt = time.Unix(next, 0), time.Unix(created, 0), time.Unix(updated, 0)
	return &d, nil
}

// ListDeliveriesByEvent returns deliveries for an event (tests and diagnostics).
func (s *Store) ListDeliveriesByEvent(ctx context.Context, channelID, eventID string) ([]Delivery, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, channel_id, event_id, recipient_id, installation_id, collapse_id, payload, status, attempts, next_attempt_at, COALESCE(last_error, ''), created_at, updated_at FROM deliveries WHERE channel_id = ? AND event_id = ? ORDER BY id`, channelID, eventID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		var next, created, updated int64
		if err := rows.Scan(&d.ID, &d.ChannelID, &d.EventID, &d.RecipientID, &d.InstallationID, &d.CollapseID, &d.Payload, &d.Status, &d.Attempts, &next, &d.LastError, &created, &updated); err != nil {
			return nil, err
		}
		d.NextAttemptAt, d.CreatedAt, d.UpdatedAt = time.Unix(next, 0), time.Unix(created, 0), time.Unix(updated, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// CountPending returns the number of pending deliveries (health/metrics).
func (s *Store) CountPending(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM deliveries WHERE status = ?`, DeliveryPending).Scan(&n)
	return n, err
}

// Prune removes terminal deliveries, old event ids and expired nonces older than retention.
func (s *Store) Prune(ctx context.Context, retention time.Duration) error {
	now := s.now()
	cutoff := now.Add(-retention).Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM deliveries WHERE status != ? AND updated_at < ?`, DeliveryPending, cutoff); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE received_at < ?`, cutoff); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM pairing_nonces WHERE expires_at < ?`, now.Unix()); err != nil {
		return err
	}
	return nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
