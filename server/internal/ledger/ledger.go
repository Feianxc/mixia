// Package ledger implements the trust ledger of protocol spec section 2: entry
// parsing and the replay state machine. Entry bodies are kept as the exact
// bytes that were signed and are never re-serialized.
package ledger

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"unicode/utf8"
)

const (
	Root     = "root"
	Recovery = "recovery"

	RoleAdmin  = "admin"
	RoleMember = "member"

	TypeGenesis      = "genesis"
	TypeDeviceAdd    = "device_add"
	TypeDeviceRevoke = "device_revoke"
	TypeGrant        = "grant"
	TypeVaultAdd     = "vault_add"
	TypeVaultRotate  = "vault_rotate"
	TypeVaultDelete  = "vault_delete"
	TypeRootRotate   = "root_rotate"

	signPrefix = "mixia/ledger/v1\n"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidID reports whether s may be used as a vaultId, blobId, pairId or change id.
func ValidID(s string) bool { return idPattern.MatchString(s) }

// InvalidError means an entry breaks a ledger rule.
type InvalidError struct{ Reason string }

func (e *InvalidError) Error() string { return "ledger invalid: " + e.Reason }

// ConflictError means an entry's seq does not follow the head.
type ConflictError struct{ Head int64 }

func (e *ConflictError) Error() string { return fmt.Sprintf("ledger conflict at head %d", e.Head) }

func invalid(format string, args ...any) error {
	return &InvalidError{Reason: fmt.Sprintf(format, args...)}
}

// Invalid builds an InvalidError for checks made outside this package.
func Invalid(reason string) error { return &InvalidError{Reason: reason} }

// IsConflict reports whether err is a ConflictError.
func IsConflict(err error) bool {
	var c *ConflictError
	return errors.As(err, &c)
}

// Wire is the JSON form of an entry.
type Wire struct {
	Body B64 `json:"body"`
	Sig  B64 `json:"sig"`
}

// Entry is a parsed ledger entry.
type Entry struct {
	Body []byte
	Sig  []byte

	V      int64
	Seq    int64
	Prev   string
	Ts     int64
	Signer string
	Type   string

	data map[string]json.RawMessage
}

// field reads one member by its exact name. Decoding through a map keeps the
// server's view identical to JSON.parse on the client: encoding/json matches
// struct fields case-insensitively, which would let "Type" shadow "type".
func field[T any](m map[string]json.RawMessage, key string) (T, error) {
	var p *T
	var zero T
	raw, ok := m[key]
	if !ok {
		return zero, invalid("missing field %q", key)
	}
	if err := json.Unmarshal(raw, &p); err != nil || p == nil {
		return zero, invalid("bad field %q", key)
	}
	return *p, nil
}

// Parse decodes the signed body bytes. It validates shape only; Apply enforces
// the rules.
func Parse(w Wire) (*Entry, error) {
	if !utf8.Valid(w.Body) {
		return nil, invalid("body is not UTF-8")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(w.Body, &top); err != nil || top == nil {
		return nil, invalid("body is not a JSON object")
	}
	e := &Entry{Body: w.Body, Sig: w.Sig}
	var err error
	if e.V, err = field[int64](top, "v"); err != nil {
		return nil, err
	}
	if e.Seq, err = field[int64](top, "seq"); err != nil {
		return nil, err
	}
	if e.Prev, err = field[string](top, "prev"); err != nil {
		return nil, err
	}
	if e.Ts, err = field[int64](top, "ts"); err != nil {
		return nil, err
	}
	if e.Signer, err = field[string](top, "signer"); err != nil {
		return nil, err
	}
	if e.Type, err = field[string](top, "type"); err != nil {
		return nil, err
	}
	if e.data, err = field[map[string]json.RawMessage](top, "data"); err != nil {
		return nil, err
	}
	return e, nil
}

// Hash is the entry hash: SHA256 of the body bytes.
func (e *Entry) Hash() []byte {
	h := sha256.Sum256(e.Body)
	return h[:]
}

// VaultID returns the vaultId of a vault_* entry, or "".
func (e *Entry) VaultID() string {
	id, _ := field[string](e.data, "vaultId")
	return id
}

// SnapshotCount returns the snapshotCount of a vault_rotate entry.
func (e *Entry) SnapshotCount() int64 {
	n, _ := field[int64](e.data, "snapshotCount")
	return n
}

// SnapshotHash returns the snapshotHash of a vault_rotate entry (base64url text).
func (e *Entry) SnapshotHash() string {
	v, _ := field[string](e.data, "snapshotHash")
	return v
}

// LogHead returns the logHead of a vault_rotate entry: the vault head the
// client saw when it built the snapshot.
func (e *Entry) LogHead() int64 {
	n, _ := field[int64](e.data, "logHead")
	return n
}

// Device is one device as recorded in the ledger.
type Device struct {
	ID      string
	Role    string
	AuthPub *ecdsa.PublicKey
	SignPub ed25519.PublicKey
	Vaults  []string
	Revoked bool
}

// HasVault reports whether the device's ledger scope includes the vault.
func (d Device) HasVault(id string) bool { return slices.Contains(d.Vaults, id) }

// Vault is one vault as recorded in the ledger.
type Vault struct {
	ID  string
	Gen int64
}

// State is the result of replaying the ledger. A published State is immutable;
// writers Clone, Apply and swap.
type State struct {
	Head        int64 // -1 before genesis
	HeadHash    []byte
	GenesisHash []byte
	RootPub     ed25519.PublicKey
	Devices     map[string]Device
	Vaults      map[string]Vault
}

// New returns the empty pre-genesis state.
func New() *State {
	return &State{Head: -1, Devices: map[string]Device{}, Vaults: map[string]Vault{}}
}

// Clone returns a copy that can be Applied to without affecting s. Device and
// Vault values are never mutated in place, so copying the maps is enough.
func (s *State) Clone() *State {
	c := *s
	c.Devices = maps.Clone(s.Devices)
	c.Vaults = maps.Clone(s.Vaults)
	return &c
}

// Bootstrapped reports whether genesis has been accepted.
func (s *State) Bootstrapped() bool { return s.Head >= 0 }

// ActiveDevice returns a device that exists and is not revoked.
func (s *State) ActiveDevice(id string) (Device, bool) {
	d, ok := s.Devices[id]
	return d, ok && !d.Revoked
}

func (s *State) activeAdmins() int {
	n := 0
	for _, d := range s.Devices {
		if !d.Revoked && d.Role == RoleAdmin {
			n++
		}
	}
	return n
}

// Effect tells the store what an applied entry changes outside the ledger
// table. Action and Detail feed the audit log and hold ids only.
type Effect struct {
	Action string
	Detail string

	AddedVault     string
	DeletedVault   string
	RevokedDevice  string
	NarrowedDevice string
	NarrowedVaults []string
}

// fixedB64 reads a base64url field that must decode to exactly size bytes.
func fixedB64(data map[string]json.RawMessage, key string, size int) ([]byte, error) {
	s, err := field[string](data, key)
	if err != nil {
		return nil, err
	}
	raw, err := DecodeB64(s)
	if err != nil || len(raw) != size {
		return nil, invalid("bad field %q", key)
	}
	return raw, nil
}

// signingKey reads an Ed25519 public key that libsodium will accept. Refusing
// the rest here keeps a key that can never verify out of the ledger.
func signingKey(data map[string]json.RawMessage, key string) (ed25519.PublicKey, error) {
	raw, err := fixedB64(data, key, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	if !validEd25519Pub(raw) {
		return nil, invalid("unusable key %q", key)
	}
	return raw, nil
}

func (s *State) existingVaults(data map[string]json.RawMessage) ([]string, error) {
	vaults, err := field[[]string](data, "vaults")
	if err != nil {
		return nil, err
	}
	for _, id := range vaults {
		if _, ok := s.Vaults[id]; !ok {
			return nil, invalid("vault does not exist")
		}
	}
	return vaults, nil
}

func validRole(r string) bool  { return r == RoleAdmin || r == RoleMember }
func validLevel(l string) bool { return l == "hardware" || l == "os" || l == "software" }

// signerKey resolves the verification key of an entry (rules 2 and 3).
func (s *State) signerKey(e *Entry) (ed25519.PublicKey, error) {
	if e.Type == TypeGenesis {
		if e.Signer != Root {
			return nil, invalid("genesis must be signed by root")
		}
		return signingKey(e.data, "rootPub")
	}
	if e.Signer == Root {
		return s.RootPub, nil
	}
	if e.Type == TypeRootRotate {
		return nil, invalid("root_rotate must be signed by root")
	}
	d, ok := s.ActiveDevice(e.Signer)
	if !ok {
		return nil, invalid("signer is unknown or revoked")
	}
	if d.Role != RoleAdmin {
		return nil, invalid("signer is not an admin")
	}
	return d.SignPub, nil
}

// Apply validates e against the current state and advances it. On error s is
// unchanged, but batch callers should still work on a Clone so that a later
// entry's failure discards the earlier ones.
func (s *State) Apply(e *Entry) (Effect, error) {
	// Rule 1.
	if e.V != 1 {
		return Effect{}, invalid("unsupported version")
	}
	if e.Seq != s.Head+1 {
		return Effect{}, &ConflictError{Head: s.Head}
	}
	wantPrev := ""
	if s.Head >= 0 {
		wantPrev = EncodeB64(s.HeadHash)
	}
	if e.Prev != wantPrev {
		return Effect{}, invalid("prev does not match head hash")
	}
	if (e.Seq == 0) != (e.Type == TypeGenesis) {
		return Effect{}, invalid("genesis must be exactly seq 0")
	}

	// Rules 2 and 3.
	pub, err := s.signerKey(e)
	if err != nil {
		return Effect{}, err
	}
	if !StrictVerify(pub, append([]byte(signPrefix), e.Body...), e.Sig) {
		return Effect{}, invalid("bad signature")
	}

	// Rules 4 to 7. Each case validates fully before it mutates anything.
	eff := Effect{Action: e.Type}
	switch e.Type {
	case TypeGenesis:
		err = s.applyGenesis(e, pub)
	case TypeDeviceAdd:
		err = s.applyDeviceAdd(e, &eff)
	case TypeDeviceRevoke:
		err = s.applyDeviceRevoke(e, &eff)
	case TypeGrant:
		err = s.applyGrant(e, &eff)
	case TypeVaultAdd:
		err = s.applyVaultAdd(e, &eff)
	case TypeVaultRotate:
		err = s.applyVaultRotate(e, &eff)
	case TypeVaultDelete:
		err = s.applyVaultDelete(e, &eff)
	case TypeRootRotate:
		err = s.applyRootRotate(e)
	default:
		err = invalid("unknown entry type")
	}
	if err != nil {
		return Effect{}, err
	}

	s.Head = e.Seq
	s.HeadHash = e.Hash()
	if e.Type == TypeGenesis {
		s.GenesisHash = s.HeadHash
	}
	return eff, nil
}

func (s *State) applyGenesis(e *Entry, rootPub ed25519.PublicKey) error {
	owner, err := field[string](e.data, "ownerId")
	if err != nil {
		return err
	}
	if owner == "" {
		return invalid("empty ownerId")
	}
	if _, err := fixedB64(e.data, "recoveryBoxPub", 32); err != nil {
		return err
	}
	s.RootPub = rootPub
	return nil
}

func (s *State) applyRootRotate(e *Entry) error {
	pub, err := signingKey(e.data, "rootPub")
	if err != nil {
		return err
	}
	if _, err := fixedB64(e.data, "recoveryBoxPub", 32); err != nil {
		return err
	}
	s.RootPub = pub
	return nil
}

// DeviceID derives the deviceId bound to an authPub.
func DeviceID(authPub []byte) string {
	h := sha256.Sum256(authPub)
	return EncodeB64(h[:16])
}

func (s *State) applyDeviceAdd(e *Entry, eff *Effect) error {
	id, err := field[string](e.data, "deviceId")
	if err != nil {
		return err
	}
	// Covers rule 7 as well: revoked devices stay in the map.
	if _, exists := s.Devices[id]; exists {
		return invalid("deviceId already used")
	}
	authRaw, err := fixedB64(e.data, "authPub", 65)
	if err != nil {
		return err
	}
	if id != DeviceID(authRaw) {
		return invalid("deviceId does not match authPub")
	}
	authPub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), authRaw)
	if err != nil {
		return invalid("authPub is not a P-256 point")
	}
	signPub, err := signingKey(e.data, "signPub")
	if err != nil {
		return err
	}
	if _, err := fixedB64(e.data, "boxPub", 32); err != nil {
		return err
	}
	for _, key := range []string{"name", "platform"} {
		if _, err := field[string](e.data, key); err != nil {
			return err
		}
	}
	level, err := field[string](e.data, "level")
	if err != nil {
		return err
	}
	role, err := field[string](e.data, "role")
	if err != nil {
		return err
	}
	if !validLevel(level) || !validRole(role) {
		return invalid("bad level or role")
	}
	vaults, err := s.existingVaults(e.data)
	if err != nil {
		return err
	}
	s.Devices[id] = Device{ID: id, Role: role, AuthPub: authPub, SignPub: signPub, Vaults: vaults}
	eff.Detail = "device=" + id
	return nil
}

// targetDevice implements the shared part of rule 5.
func (s *State) targetDevice(e *Entry) (Device, error) {
	id, err := field[string](e.data, "deviceId")
	if err != nil {
		return Device{}, err
	}
	d, ok := s.ActiveDevice(id)
	if !ok {
		return Device{}, invalid("target device is unknown or revoked")
	}
	return d, nil
}

func (s *State) lastAdminGuard(e *Entry, target Device) error {
	if e.Signer != Root && target.Role == RoleAdmin && s.activeAdmins() == 1 {
		return invalid("cannot remove the last active admin")
	}
	return nil
}

func (s *State) applyDeviceRevoke(e *Entry, eff *Effect) error {
	d, err := s.targetDevice(e)
	if err != nil {
		return err
	}
	if _, err := field[string](e.data, "reason"); err != nil {
		return err
	}
	if err := s.lastAdminGuard(e, d); err != nil {
		return err
	}
	d.Revoked = true
	s.Devices[d.ID] = d
	eff.RevokedDevice = d.ID
	eff.Detail = "device=" + d.ID
	return nil
}

func (s *State) applyGrant(e *Entry, eff *Effect) error {
	d, err := s.targetDevice(e)
	if err != nil {
		return err
	}
	role, err := field[string](e.data, "role")
	if err != nil {
		return err
	}
	if !validRole(role) {
		return invalid("bad role")
	}
	// The spec states this only for device_add; grant follows the same rule.
	vaults, err := s.existingVaults(e.data)
	if err != nil {
		return err
	}
	if role != RoleAdmin {
		if err := s.lastAdminGuard(e, d); err != nil {
			return err
		}
	}
	for _, old := range d.Vaults {
		if !slices.Contains(vaults, old) {
			eff.NarrowedVaults = append(eff.NarrowedVaults, old)
		}
	}
	eff.NarrowedDevice = d.ID
	eff.Detail = "device=" + d.ID
	d.Role = role
	d.Vaults = vaults
	s.Devices[d.ID] = d
	return nil
}

func (s *State) applyVaultAdd(e *Entry, eff *Effect) error {
	id, err := field[string](e.data, "vaultId")
	if err != nil {
		return err
	}
	if !ValidID(id) {
		return invalid("bad vaultId")
	}
	if _, exists := s.Vaults[id]; exists {
		return invalid("vault already exists")
	}
	gen, err := field[int64](e.data, "gen")
	if err != nil {
		return err
	}
	if gen != 1 {
		return invalid("vault_add gen must be 1")
	}
	if _, err := fixedB64(e.data, "keyCommit", 32); err != nil {
		return err
	}
	s.Vaults[id] = Vault{ID: id, Gen: 1}
	eff.AddedVault = id
	eff.Detail = "vault=" + id
	return nil
}

func (s *State) applyVaultRotate(e *Entry, eff *Effect) error {
	id, err := field[string](e.data, "vaultId")
	if err != nil {
		return err
	}
	v, ok := s.Vaults[id]
	if !ok {
		return invalid("vault does not exist")
	}
	gen, err := field[int64](e.data, "gen")
	if err != nil {
		return err
	}
	if gen != v.Gen+1 {
		return invalid("vault_rotate gen must be current+1")
	}
	count, err := field[int64](e.data, "snapshotCount")
	if err != nil {
		return err
	}
	if count < 0 {
		return invalid("negative snapshotCount")
	}
	logHead, err := field[int64](e.data, "logHead")
	if err != nil {
		return err
	}
	if logHead < 0 {
		return invalid("negative logHead")
	}
	// Clients hash an empty snapshot too, so count=0 is no exception.
	for _, key := range []string{"keyCommit", "snapshotHash"} {
		if _, err := fixedB64(e.data, key, 32); err != nil {
			return err
		}
	}
	v.Gen = gen
	s.Vaults[id] = v
	eff.Detail = fmt.Sprintf("vault=%s gen=%d", id, gen)
	return nil
}

func (s *State) applyVaultDelete(e *Entry, eff *Effect) error {
	id, err := field[string](e.data, "vaultId")
	if err != nil {
		return err
	}
	if _, ok := s.Vaults[id]; !ok {
		return invalid("vault does not exist")
	}
	delete(s.Vaults, id)
	// Without this a later vault_add reusing the id would silently hand the
	// new vault to every device that had the old one.
	for devID, d := range s.Devices {
		if d.HasVault(id) {
			d.Vaults = slices.DeleteFunc(slices.Clone(d.Vaults), func(v string) bool { return v == id })
			s.Devices[devID] = d
		}
	}
	eff.DeletedVault = id
	eff.Detail = "vault=" + id
	return nil
}

// Replay rebuilds a State from stored entries in seq order.
func Replay(entries []Wire) (*State, error) {
	s := New()
	for i, w := range entries {
		e, err := Parse(w)
		if err == nil {
			_, err = s.Apply(e)
		}
		if err != nil {
			return nil, fmt.Errorf("ledger entry %d: %w", i, err)
		}
	}
	return s, nil
}
