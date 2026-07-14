package licverify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// Guard is the in-process license watchdog for products: it re-evaluates the
// license periodically (Eval + VerifyBound), auto-renews online deployments
// ahead of expiry, and reports state transitions. It is deliberately NOT a
// separate OS daemon — enforcement must live in the product process anyway,
// so a killable side process would add operational surface without any
// security gain (client-side anti-tamper is a non-goal).
//
// Usage:
//
//	guard, _ := licverify.NewGuard(licverify.GuardConfig{
//	    Keys: keys,
//	    Load: func() (string, error) { return os.ReadFileString(licPath) },
//	    Store: func(t string) error { return os.WriteFile(licPath, []byte(t), 0o600) },
//	    RenewURL: "https://license.openbkn.ai/api/licenses/renew",
//	    OnChange: func(old, new licverify.Snapshot) { gate.Apply(new) },
//	})
//	go guard.Run(ctx)
//	...
//	if guard.State().State == licverify.StateValid { ... }
type GuardConfig struct {
	// Keys are the embedded verification public keys (kid → key). Required.
	Keys map[string]ed25519.PublicKey
	// Load returns the current license text (from file, DB, …). Required.
	Load func() (string, error)
	// Store persists a replacement license after a successful renewal.
	// Required when RenewURL is set.
	Store func(text string) error
	// RenewURL is the license server's renew endpoint
	// (…/api/licenses/renew). Empty disables auto-renew (pure offline
	// deployments carry a full-contract certificate instead).
	RenewURL string
	// InstanceFP defaults to Fingerprint() of this machine.
	InstanceFP string
	// Interval between re-evaluations. Default 1h; ±10% jitter is applied.
	Interval time.Duration
	// OnChange fires on every state transition (not on steady state).
	OnChange func(old, cur Snapshot)
	// Logf receives operational messages (renew attempts/failures). Optional.
	Logf func(format string, args ...any)
	// HTTPClient defaults to a 30s-timeout client.
	HTTPClient *http.Client
}

// Snapshot is the point-in-time judgement the product gates on.
type Snapshot struct {
	State   State
	Payload *Payload // nil when State is invalid
	// Err explains an invalid/unusable license (gate features off).
	Err error
	// RenewErr reports that a background auto-renew failed while the license
	// itself is still fine — do NOT gate features off on this; surface it as a
	// "renewal pending" warning. Kept separate from Err so `if snap.Err != nil`
	// does not disable a perfectly valid license over a transient network blip.
	RenewErr error
}

type Guard struct {
	cfg GuardConfig

	mu  sync.RWMutex
	cur Snapshot
}

// NewGuard validates the config, fills defaults, and performs the first
// evaluation synchronously so State() is meaningful immediately.
func NewGuard(cfg GuardConfig) (*Guard, error) {
	if len(cfg.Keys) == 0 || cfg.Load == nil {
		return nil, errors.New("licverify: guard needs Keys and Load")
	}
	if cfg.RenewURL != "" && cfg.Store == nil {
		return nil, errors.New("licverify: guard with RenewURL needs Store to persist renewed licenses")
	}
	if cfg.InstanceFP == "" {
		fp, err := Fingerprint()
		if err != nil {
			return nil, err
		}
		cfg.InstanceFP = fp
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Hour
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	g := &Guard{cfg: cfg}
	g.Refresh()
	return g, nil
}

// State returns the current snapshot (atomic read, safe for hot paths).
func (g *Guard) State() Snapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.cur
}

// Refresh re-evaluates the license locally WITHOUT any network renewal, and
// returns the fresh snapshot. Safe to call from the constructor and right
// after importing a new .lic — it never blocks on the license server.
func (g *Guard) Refresh() Snapshot {
	return g.apply(g.evalOnce(time.Now(), false))
}

// RenewNow forces one renewing evaluation immediately (the same work a Run
// tick does), blocking on the network if a renewal is due. Products can call
// it to renew on demand; Run calls it on its schedule. Unlike Refresh, this
// may block — do not call it from a latency-sensitive path.
func (g *Guard) RenewNow() Snapshot {
	return g.apply(g.evalOnce(time.Now(), true))
}

func (g *Guard) apply(next Snapshot) Snapshot {
	g.mu.Lock()
	prev := g.cur
	g.cur = next
	g.mu.Unlock()
	if g.cfg.OnChange != nil && prev.State != next.State {
		g.cfg.OnChange(prev, next)
	}
	return next
}

// Run drives the periodic loop until ctx is cancelled. Call as a goroutine.
// Renewal (a network call) happens only here, never in NewGuard/Refresh.
func (g *Guard) Run(ctx context.Context) {
	for {
		// ±10% jitter so fleets do not renew in lockstep.
		d := g.cfg.Interval + time.Duration((rand.Float64()-0.5)*0.2*float64(g.cfg.Interval))
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
			g.apply(g.evalOnce(time.Now(), true))
		}
	}
}

// evalOnce loads and judges the license. When allowRenew is set and the
// validity window is running out on an online deployment, it renews (a
// blocking network call — only the Run loop passes allowRenew=true, so the
// constructor never blocks). A renewal FAILURE surfaces in Snapshot.RenewErr,
// never Snapshot.Err, and never degrades State below what the license itself
// justifies (grace still gates as grace) — so a caller gating on Err does not
// disable features because of a transient renew blip.
func (g *Guard) evalOnce(now time.Time, allowRenew bool) Snapshot {
	text, err := g.cfg.Load()
	if err != nil {
		return Snapshot{State: StateInvalid, Err: fmt.Errorf("licverify: load license: %w", err)}
	}
	state, p := EvalAt(text, g.cfg.Keys, now)
	if state == StateInvalid {
		return Snapshot{State: StateInvalid, Err: errors.New("licverify: license missing, malformed, or signature invalid")}
	}
	if err := VerifyBound(p, g.cfg.InstanceFP); err != nil {
		return Snapshot{State: StateInvalid, Err: err}
	}

	if allowRenew && g.shouldRenew(p, state, now) {
		fresh, err := g.renew(text)
		if err != nil {
			g.cfg.Logf("license renew failed (state stays %s): %v", state, err)
			return Snapshot{State: state, Payload: p, RenewErr: err}
		}
		// The server has already superseded the old license, so the fresh
		// text IS the current license — persist it unconditionally. Dropping
		// it (e.g. because a skewed local clock makes it look not-yet-valid)
		// would consume the renewal and strand the deployment.
		if err := g.cfg.Store(fresh); err != nil {
			g.cfg.Logf("persisting renewed license failed: %v", err)
			return Snapshot{State: state, Payload: p, RenewErr: err}
		}
		freshState, freshP := EvalAt(fresh, g.cfg.Keys, now)
		g.cfg.Logf("license renewed: %s valid until %s", freshP.LicID,
			time.Unix(freshP.ExpiresAt, 0).UTC().Format("2006-01-02"))
		return Snapshot{State: freshState, Payload: freshP}
	}
	return Snapshot{State: state, Payload: p}
}

// shouldRenew: online deployments renew inside the last third of the
// license window, and whenever already in grace. Perpetual (community)
// licenses and offline deployments never renew.
func (g *Guard) shouldRenew(p *Payload, state State, now time.Time) bool {
	if g.cfg.RenewURL == "" || p.ExpiresAt == 0 {
		return false
	}
	if state == StateGrace {
		return true
	}
	window := p.ExpiresAt - p.IssuedAt
	if window <= 0 {
		return false
	}
	return p.ExpiresAt-now.Unix() < window/3
}

func (g *Guard) renew(text string) (string, error) {
	body, _ := json.Marshal(map[string]string{"license": text, "instance_fp": g.cfg.InstanceFP})
	req, err := http.NewRequest(http.MethodPost, g.cfg.RenewURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		License string `json:"license"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("licverify: renew response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || out.License == "" {
		if out.Error != "" {
			return "", fmt.Errorf("licverify: renew refused: %s", out.Error)
		}
		return "", fmt.Errorf("licverify: renew http %d", resp.StatusCode)
	}
	return out.License, nil
}
