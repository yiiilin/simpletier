package topology

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
)

// Durable records owned by FactStore. They contain only version floors,
// revocation floors/retention, high-watermark retention metadata and sender
// snapshot floors: no private key, PSK, token, configuration or peer payload,
// and no fact record bytes. The borrowed security.NetworkState is used for
// atomic writes and is never closed here.
const (
	factWatermarksRecord = "fact-watermarks"
	factInitMarkerRecord = "fact-init"

	factPersistenceMagic        = "STFW"
	factPersistenceVersion      = 2
	factPersistenceVersionV1    = 1
	factMarkerMagic             = "STFI"
	factMarkerVersion           = 1
	factMarkerSize              = 4 + 1 + 3 + 32 + 8 + 8 // magic|version|reserved|contextID|wireID|incarnation
	factPersistenceDigestSize   = 32
	factPersistenceBooleanWidth = 1

	// factPersistenceMaxBytes mirrors the approved FactStore <= 32 MiB bound and
	// the NetworkState record ceiling. It is a limit, not a preallocation.
	factPersistenceMaxBytes int64 = 32 << 20

	factWatermarkHeaderSize = 4 + 1 + 3 + 32 + 8 + 8
)

// load reads and strictly validates the durable state. A missing watermark
// record is only a fresh initialization while no established marker exists;
// otherwise it fails closed with ErrFactStoreReset instead of silently
// resetting established high-watermarks.
func (fs *FactStore) load() error {
	// Loading (re)builds the durable maps from scratch, so any reservation a
	// previous state left behind is dropped before the new owned bytes can be
	// booked. NewFactStore calls this before any StateBudget is attached, so in
	// today's flow this is a no-op; it keeps a future reload path from
	// double-counting a store that already holds a reservation.
	if fs.stateBudget != nil {
		fs.stateBudget.ReleaseState()
	}
	data, err := fs.state.ReadRecord(factWatermarksRecord, factPersistenceMaxBytes)
	switch {
	case err == nil:
		hwm, tombstones, senders, decodeErr := decodeFactWatermarks(data, fs.contextID, fs.wireID)
		if decodeErr != nil {
			return decodeErr
		}
		fs.hwm = hwm
		fs.tombstones = tombstones
		fs.senders = senders
		return fs.ensureInitMarker()
	case errors.Is(err, os.ErrNotExist):
		if _, markerErr := fs.state.ReadRecord(factInitMarkerRecord, factPersistenceMaxBytes); markerErr == nil {
			return ErrFactStoreReset
		} else if !errors.Is(markerErr, os.ErrNotExist) {
			return markerErr
		}
		empty, encodeErr := encodeFactWatermarks(fs.contextID, fs.wireID, fs.state.Incarnation(), fs.hwm, fs.tombstones, fs.senders)
		if encodeErr != nil {
			return encodeErr
		}
		if writeErr := fs.state.WriteRecord(factWatermarksRecord, empty, factPersistenceMaxBytes); writeErr != nil {
			return writeErr
		}
		return fs.writeInitMarker()
	default:
		return err
	}
}

// ensureInitMarker repairs a missing marker when the watermark record already
// exists so a later loss of the watermark record cannot silently reset.
func (fs *FactStore) ensureInitMarker() error {
	marker, err := fs.state.ReadRecord(factInitMarkerRecord, factPersistenceMaxBytes)
	if err == nil {
		return validateFactInitMarker(marker, fs.contextID, fs.wireID)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fs.writeInitMarker()
}

func (fs *FactStore) writeInitMarker() error {
	marker := encodeFactInitMarker(fs.contextID, fs.wireID, fs.state.Incarnation())
	return fs.state.WriteRecord(factInitMarkerRecord, marker, factPersistenceMaxBytes)
}

// persistWatermarks writes the advanced floors before the candidate may be
// published. A real failure becomes sticky: the handle will keep failing later
// writes and the store will report explicit failure/stale queries rather than
// claiming the candidate committed.
func (fs *FactStore) persistWatermarks(data []byte) error {
	if err := fs.state.WriteRecord(factWatermarksRecord, data, factPersistenceMaxBytes); err != nil {
		fs.failure = fmt.Errorf("%w: %w", ErrFactStoreFailed, err)
		return fs.failure
	}
	return nil
}

func encodeFactInitMarker(contextID [32]byte, wireID, incarnation uint64) []byte {
	marker := make([]byte, 0, factMarkerSize)
	marker = append(marker, factMarkerMagic...)
	marker = append(marker, factMarkerVersion, 0, 0, 0)
	marker = append(marker, contextID[:]...)
	marker = binary.BigEndian.AppendUint64(marker, wireID)
	return binary.BigEndian.AppendUint64(marker, incarnation)
}

func validateFactInitMarker(data []byte, contextID [32]byte, wireID uint64) error {
	if len(data) != factMarkerSize || !bytes.Equal(data[:4], []byte(factMarkerMagic)) ||
		data[4] != factMarkerVersion || data[5] != 0 || data[6] != 0 || data[7] != 0 {
		return fmt.Errorf("%w: malformed fact init marker", ErrFactStoreReset)
	}
	if !bytes.Equal(data[8:40], contextID[:]) || binary.BigEndian.Uint64(data[40:48]) != wireID {
		return fmt.Errorf("%w: fact init marker binding mismatch", ErrFactStoreReset)
	}
	return nil
}

// encodeFactWatermarks lays out one strict, self-describing STFW v2 record:
//
//	magic "STFW" | version=2 | reserved0 | full ContextID | expected WireID |
//	network incarnation | hwmCount | (keyLen|key|maxInc|maxSeq|retentionUntil|known)* |
//	senderCount | (peer16|incarnation|snapshot|digest32|digestKnown)* |
//	tombstoneCount | (targetKind|targetOrigin|targetKeyLen|targetKey|
//	                  revokedThroughInc|revokedThroughSeq|retentionUntil|
//	                  contributorCount | (ownKeyLen|ownKey|targetInc|targetSeq|
//	                                        retentionUntil)*)*
//
// Keys, sender peers, tombstone identities and contributor keys are emitted in
// strict byte order so decoding can reject duplicates and reordering.
func encodeFactWatermarks(contextID [32]byte, wireID, incarnation uint64, hwm map[string]hwmEntry, tombstones map[string]*tombstoneEntry, senders map[string]senderFloor) ([]byte, error) {
	if len(hwm) > maxFactHWMEntries || len(tombstones) > maxFactHWMEntries || len(senders) > maxFactHWMEntries {
		return nil, ErrFactTooLarge
	}
	record := make([]byte, 0, factWatermarkHeaderSize+len(hwm)*48+len(tombstones)*192+len(senders)*72)
	record = append(record, factPersistenceMagic...)
	record = append(record, factPersistenceVersion, 0, 0, 0)
	record = append(record, contextID[:]...)
	record = binary.BigEndian.AppendUint64(record, wireID)
	record = binary.BigEndian.AppendUint64(record, incarnation)

	hwmKeys := make([]string, 0, len(hwm))
	for key := range hwm {
		hwmKeys = append(hwmKeys, key)
	}
	sort.Strings(hwmKeys)
	record = binary.BigEndian.AppendUint32(record, uint32(len(hwmKeys)))
	for _, key := range hwmKeys {
		if !validPersistedFactKey([]byte(key)) {
			return nil, fmt.Errorf("%w: hwm key len %d", ErrFactMalformed, len(key))
		}
		record = binary.BigEndian.AppendUint16(record, uint16(len(key)))
		record = append(record, key...)
		floor := hwm[key]
		record = binary.BigEndian.AppendUint64(record, floor.version.Incarnation)
		record = binary.BigEndian.AppendUint64(record, floor.version.Sequence)
		record = binary.BigEndian.AppendUint64(record, floor.retentionUntil)
		record = append(record, boolByte(floor.retentionKnown))
	}

	senderKeys := make([]string, 0, len(senders))
	for key := range senders {
		senderKeys = append(senderKeys, key)
	}
	sort.Strings(senderKeys)
	record = binary.BigEndian.AppendUint32(record, uint32(len(senderKeys)))
	for _, key := range senderKeys {
		if len(key) != 16 {
			return nil, fmt.Errorf("%w: sender key len %d", ErrFactMalformed, len(key))
		}
		record = append(record, key...)
		floor := senders[key]
		record = binary.BigEndian.AppendUint64(record, floor.Incarnation)
		record = binary.BigEndian.AppendUint64(record, floor.SnapshotVersion)
		record = append(record, floor.Digest[:]...)
		record = append(record, boolByte(floor.DigestKnown))
	}

	tombstoneKeys := make([]string, 0, len(tombstones))
	for key := range tombstones {
		tombstoneKeys = append(tombstoneKeys, key)
	}
	sort.Strings(tombstoneKeys)
	record = binary.BigEndian.AppendUint32(record, uint32(len(tombstoneKeys)))
	for _, key := range tombstoneKeys {
		tombstone := tombstones[key]
		if len(tombstone.targetKey) > MaxRevocationTargetKey {
			return nil, ErrFactTooLarge
		}
		record = append(record, byte(tombstone.kind))
		record = append(record, tombstone.targetOrigin[:]...)
		record = binary.BigEndian.AppendUint16(record, uint16(len(tombstone.targetKey)))
		record = append(record, tombstone.targetKey...)
		record = binary.BigEndian.AppendUint64(record, tombstone.revokedThrough.Incarnation)
		record = binary.BigEndian.AppendUint64(record, tombstone.revokedThrough.Sequence)
		record = binary.BigEndian.AppendUint64(record, tombstone.retentionUntil)
		contributorKeys := make([]string, 0, len(tombstone.contributors))
		for ownKey := range tombstone.contributors {
			contributorKeys = append(contributorKeys, ownKey)
		}
		sort.Strings(contributorKeys)
		record = binary.BigEndian.AppendUint32(record, uint32(len(contributorKeys)))
		for _, ownKey := range contributorKeys {
			contribution := tombstone.contributors[ownKey]
			record = binary.BigEndian.AppendUint16(record, uint16(len(ownKey)))
			record = append(record, ownKey...)
			record = binary.BigEndian.AppendUint64(record, contribution.targetVersion.Incarnation)
			record = binary.BigEndian.AppendUint64(record, contribution.targetVersion.Sequence)
			record = binary.BigEndian.AppendUint64(record, contribution.retentionUntil)
		}
	}
	if int64(len(record)) > factPersistenceMaxBytes {
		return nil, ErrFactTooLarge
	}
	return record, nil
}

func boolByte(value bool) byte {
	if value {
		return 1
	}
	return 0
}

type decodedWatermarks struct {
	hwm        map[string]hwmEntry
	tombstones map[string]*tombstoneEntry
	senders    map[string]senderFloor
}

func decodeFactWatermarks(data []byte, contextID [32]byte, wireID uint64) (map[string]hwmEntry, map[string]*tombstoneEntry, map[string]senderFloor, error) {
	fail := func() (map[string]hwmEntry, map[string]*tombstoneEntry, map[string]senderFloor, error) {
		return nil, nil, nil, fmt.Errorf("%w: malformed fact high-watermark record", ErrFactMalformed)
	}
	if len(data) < factWatermarkHeaderSize {
		return fail()
	}
	cursor := &factPersistenceCursor{data: data}
	if !bytes.Equal(cursor.take(4), []byte(factPersistenceMagic)) {
		return fail()
	}
	version := cursor.u8()
	if version != factPersistenceVersion && version != factPersistenceVersionV1 {
		return fail()
	}
	if cursor.u8() != 0 || cursor.u8() != 0 || cursor.u8() != 0 ||
		!bytes.Equal(cursor.take(32), contextID[:]) || cursor.u64() != wireID {
		return fail()
	}
	_ = cursor.u64() // network incarnation: diagnostic only, never used to reset state

	decoded, ok := decodeFactWatermarkSections(cursor, version)
	if !ok {
		return fail()
	}
	if cursor.err != nil || cursor.pos != len(data) {
		return fail()
	}
	return decoded.hwm, decoded.tombstones, decoded.senders, nil
}

func decodeFactWatermarkSections(cursor *factPersistenceCursor, version uint8) (decodedWatermarks, bool) {
	decoded := decodedWatermarks{
		hwm:        make(map[string]hwmEntry),
		tombstones: make(map[string]*tombstoneEntry),
		senders:    make(map[string]senderFloor),
	}

	hwmCount := cursor.u32()
	if cursor.err != nil || hwmCount > maxFactHWMEntries {
		return decoded, false
	}
	var previous string
	for index := uint32(0); index < hwmCount; index++ {
		key := cursor.take(int(cursor.u16()))
		floor := hwmEntry{version: FactVersion{Incarnation: cursor.u64(), Sequence: cursor.u64()}}
		if version >= factPersistenceVersion {
			floor.retentionUntil = cursor.u64()
			known := cursor.u8()
			if known > 1 {
				return decoded, false
			}
			floor.retentionKnown = known == 1
		}
		if cursor.err != nil || !validPersistedFactKey(key) || !validVersion(floor.version) {
			return decoded, false
		}
		text := string(key)
		if index > 0 && previous >= text {
			return decoded, false
		}
		previous = text
		decoded.hwm[text] = floor
	}

	senderCount := cursor.u32()
	if cursor.err != nil || senderCount > maxFactHWMEntries {
		return decoded, false
	}
	previous = ""
	for index := uint32(0); index < senderCount; index++ {
		peer := cursor.take(16)
		floor := senderFloor{Incarnation: cursor.u64(), SnapshotVersion: cursor.u64()}
		if version >= factPersistenceVersion {
			copy(floor.Digest[:], cursor.take(factPersistenceDigestSize))
			known := cursor.u8()
			if known > 1 {
				return decoded, false
			}
			floor.DigestKnown = known == 1
		}
		if cursor.err != nil || len(peer) != 16 || !validVersion(FactVersion{Incarnation: floor.Incarnation, Sequence: floor.SnapshotVersion}) {
			return decoded, false
		}
		text := string(peer)
		if index > 0 && previous >= text {
			return decoded, false
		}
		previous = text
		decoded.senders[text] = floor
	}

	tombstoneCount := cursor.u32()
	if cursor.err != nil || tombstoneCount > maxFactHWMEntries {
		return decoded, false
	}
	previous = ""
	for index := uint32(0); index < tombstoneCount; index++ {
		var tombstone *tombstoneEntry
		var identity string
		var ok bool
		if version >= factPersistenceVersion {
			tombstone, identity, ok = decodeFactTombstoneV2(cursor)
		} else {
			tombstone, identity, ok = decodeFactTombstoneV1(cursor)
		}
		if !ok {
			return decoded, false
		}
		if index > 0 && previous >= identity {
			return decoded, false
		}
		previous = identity
		decoded.tombstones[identity] = tombstone
	}
	return decoded, true
}

// decodeFactTombstoneV2 reads one aggregate floor together with every revoker
// contribution that decided it. The stored floor must equal the maximum
// contribution so a corrupt or hand-edited record cannot silently lower a
// retained revocation floor.
func decodeFactTombstoneV2(cursor *factPersistenceCursor) (*tombstoneEntry, string, bool) {
	kind := FactKind(cursor.u8())
	targetOrigin := NodeID(cursor.take(16))
	targetKey := cursor.take(int(cursor.u16()))
	revokedThrough := FactVersion{Incarnation: cursor.u64(), Sequence: cursor.u64()}
	retentionUntil := cursor.u64()
	if cursor.err != nil {
		return nil, "", false
	}
	if kind != FactNode && kind != FactLink && kind != FactAddress {
		return nil, "", false
	}
	if err := validateTarget(kind, targetOrigin, targetKey); err != nil {
		return nil, "", false
	}
	if !validVersion(revokedThrough) {
		return nil, "", false
	}
	identity := string(targetFactKey(kind, targetOrigin, targetKey))

	contributors := make(map[string]revocationContribution)
	contributorCount := cursor.u32()
	if cursor.err != nil || contributorCount > maxFactHWMEntries {
		return nil, "", false
	}
	var previous string
	for index := uint32(0); index < contributorCount; index++ {
		ownKey := cursor.take(int(cursor.u16()))
		contribution := revocationContribution{
			targetVersion:  FactVersion{Incarnation: cursor.u64(), Sequence: cursor.u64()},
			retentionUntil: cursor.u64(),
		}
		if cursor.err != nil || !validRevocationOwnKey(ownKey, identity) || !validVersion(contribution.targetVersion) {
			return nil, "", false
		}
		text := string(ownKey)
		if index > 0 && previous >= text {
			return nil, "", false
		}
		previous = text
		contributors[text] = contribution
	}
	if len(contributors) == 0 {
		return nil, "", false
	}
	var floor FactVersion
	for _, contribution := range contributors {
		if compareFactVersion(contribution.targetVersion, floor) > 0 {
			floor = contribution.targetVersion
		}
	}
	if compareFactVersion(floor, revokedThrough) != 0 {
		return nil, "", false
	}
	return &tombstoneEntry{
		kind:           kind,
		targetOrigin:   targetOrigin,
		targetKey:      append([]byte(nil), targetKey...),
		revokedThrough: revokedThrough,
		retentionUntil: retentionUntil,
		contributors:   contributors,
	}, identity, true
}

// decodeFactTombstoneV1 reads the pre-retention format. It has no contributor
// set, so it is loaded as one synthetic contribution from the recorded revoker
// with the persisted floor; this keeps the floor conservatively in force.
func decodeFactTombstoneV1(cursor *factPersistenceCursor) (*tombstoneEntry, string, bool) {
	kind := FactKind(cursor.u8())
	targetOrigin := NodeID(cursor.take(16))
	targetKey := cursor.take(int(cursor.u16()))
	revoker := NodeID(cursor.take(16))
	targetVersion := FactVersion{Incarnation: cursor.u64(), Sequence: cursor.u64()}
	tombstoneVersion := FactVersion{Incarnation: cursor.u64(), Sequence: cursor.u64()}
	retentionUntil := cursor.u64()
	if cursor.err != nil {
		return nil, "", false
	}
	if kind != FactNode && kind != FactLink && kind != FactAddress {
		return nil, "", false
	}
	if err := validateTarget(kind, targetOrigin, targetKey); err != nil {
		return nil, "", false
	}
	if !validVersion(targetVersion) || !validVersion(tombstoneVersion) {
		return nil, "", false
	}
	identity := string(targetFactKey(kind, targetOrigin, targetKey))
	ownKey := string(revocationOwnKey(revoker, []byte(identity)))
	return &tombstoneEntry{
		kind:           kind,
		targetOrigin:   targetOrigin,
		targetKey:      append([]byte(nil), targetKey...),
		revokedThrough: targetVersion,
		retentionUntil: retentionUntil,
		contributors: map[string]revocationContribution{
			ownKey: {targetVersion: targetVersion, retentionUntil: retentionUntil},
		},
	}, identity, true
}

// validRevocationOwnKey checks that a persisted contributor key is a canonical
// REVOCATION FactKey (4 | revoker:16 | target_len:u16 | nested target) and that
// its nested target rebuilds exactly the tombstone identity it was stored under.
// This matches what mergeRevocation stores (FactKey of the REVOCATION record) and
// rejects a truncated or re-labelled durable key instead of reinterpreting it.
func validRevocationOwnKey(ownKey []byte, identity string) bool {
	if !validPersistedFactKey(ownKey) || FactKind(ownKey[0]) != FactRevocation {
		return false
	}
	length := int(binary.BigEndian.Uint16(ownKey[17:19]))
	if 19+length != len(ownKey) || length < RevocationTargetPrefix {
		return false
	}
	revTarget := ownKey[19:]
	var targetOrigin NodeID
	copy(targetOrigin[:], revTarget[16:32])
	kind := FactKind(revTarget[32])
	targetKey := revTarget[33:]
	if err := validateTarget(kind, targetOrigin, targetKey); err != nil {
		return false
	}
	return string(targetFactKey(kind, targetOrigin, targetKey)) == identity
}

// validPersistedFactKey strictly checks the exact canonical FactKey width per
// kind, including a REVOCATION's nested target kind, so a truncated or
// re-labelled durable key is rejected instead of being reinterpreted.
func validPersistedFactKey(key []byte) bool {
	if len(key) < 35 || len(key) > MaxFactKey {
		return false
	}
	switch FactKind(key[0]) {
	case FactNode:
		return len(key) == 35
	case FactAddress:
		return len(key) == 39
	case FactLink:
		return len(key) == 60
	case FactRevocation:
		if len(key) < 68 {
			return false
		}
		switch FactKind(key[51]) {
		case FactNode:
			return len(key) == 68
		case FactAddress:
			return len(key) == 72
		case FactLink:
			return len(key) == 93
		default:
			return false
		}
	default:
		return false
	}
}

type factPersistenceCursor struct {
	data []byte
	pos  int
	err  error
}

func (c *factPersistenceCursor) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || n > len(c.data)-c.pos {
		c.err = ErrFactMalformed
		return nil
	}
	value := c.data[c.pos : c.pos+n]
	c.pos += n
	return value
}

func (c *factPersistenceCursor) u8() uint8 {
	value := c.take(1)
	if value == nil {
		return 0
	}
	return value[0]
}

func (c *factPersistenceCursor) u16() uint16 {
	value := c.take(2)
	if value == nil {
		return 0
	}
	return binary.BigEndian.Uint16(value)
}

func (c *factPersistenceCursor) u32() uint32 {
	value := c.take(4)
	if value == nil {
		return 0
	}
	return binary.BigEndian.Uint32(value)
}

func (c *factPersistenceCursor) u64() uint64 {
	value := c.take(8)
	if value == nil {
		return 0
	}
	return binary.BigEndian.Uint64(value)
}
