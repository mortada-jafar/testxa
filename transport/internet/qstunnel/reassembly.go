package qstunnel

import (
	"errors"
	"sync"
	"time"
)

var errInvalidFragment = errors.New("invalid fragment")

const (
	maxFragments = 64
	assembleTime = 5 * time.Second
)

// assemblySlot holds fragments for a single data offset.
type assemblySlot struct {
	fragments          [maxFragments][]byte
	receivedCount      int
	biggestIndexPlusOne int
	seenLastFragment   bool
	createdAt          time.Time
	done               bool // true = assembled, false = error/expired
}

// dataHandler manages fragment reassembly across multiple data offsets.
type dataHandler struct {
	slots     []*assemblySlot
	mu        sync.Mutex
	closeCh   chan struct{}
}

// newDataHandler creates a new fragment reassembly handler.
func newDataHandler(offsetsSize int) *dataHandler {
	dh := &dataHandler{
		slots:   make([]*assemblySlot, offsetsSize),
		closeCh: make(chan struct{}),
	}
	go dh.cleanup()
	return dh
}

func (dh *dataHandler) close() {
	close(dh.closeCh)
}

func (dh *dataHandler) cleanup() {
	ticker := time.NewTicker(assembleTime / 2)
	defer ticker.Stop()
	for {
		select {
		case <-dh.closeCh:
			return
		case <-ticker.C:
			dh.mu.Lock()
			now := time.Now()
			for i, slot := range dh.slots {
				if slot != nil && !slot.done && now.Sub(slot.createdAt) > assembleTime {
					dh.slots[i] = nil
				}
			}
			dh.mu.Unlock()
		}
	}
}

// newDataEvent processes a received fragment. Returns reassembled data if complete, nil otherwise.
func (dh *dataHandler) newDataEvent(key int, fragmentPart int, lastFragment bool, data []byte) []byte {
	if key < 0 || key >= len(dh.slots) {
		return nil
	}
	if fragmentPart < 0 || fragmentPart >= maxFragments {
		return nil
	}

	dh.mu.Lock()
	defer dh.mu.Unlock()

	slot := dh.slots[key]

	if slot == nil {
		// New slot
		slot = &assemblySlot{
			receivedCount:      1,
			biggestIndexPlusOne: fragmentPart + 1,
			seenLastFragment:   lastFragment,
			createdAt:          time.Now(),
		}
		slot.fragments[fragmentPart] = data

		// Single-fragment message
		if lastFragment && slot.receivedCount == slot.biggestIndexPlusOne {
			slot.done = true
			dh.slots[key] = slot
			return data
		}

		dh.slots[key] = slot
		return nil
	}

	if slot.done {
		return nil
	}

	// Duplicate fragment
	if slot.fragments[fragmentPart] != nil {
		return nil
	}

	slot.fragments[fragmentPart] = data
	slot.receivedCount++

	fpPlusOne := fragmentPart + 1
	biggestUpdated := false
	if fpPlusOne > slot.biggestIndexPlusOne {
		biggestUpdated = true
		slot.biggestIndexPlusOne = fpPlusOne
	}

	// Detect inconsistency: two last fragments or conflicting biggest
	if (lastFragment && slot.seenLastFragment) ||
		(biggestUpdated && slot.seenLastFragment) ||
		(!biggestUpdated && lastFragment && fpPlusOne < slot.biggestIndexPlusOne) {
		slot.done = true
		return nil
	}

	if lastFragment {
		slot.seenLastFragment = true
	}

	// Check if all fragments received
	if slot.seenLastFragment && slot.receivedCount == slot.biggestIndexPlusOne {
		slot.done = true
		// Concatenate fragments in order
		var total int
		for i := 0; i < slot.receivedCount; i++ {
			total += len(slot.fragments[i])
		}
		result := make([]byte, 0, total)
		for i := 0; i < slot.receivedCount; i++ {
			result = append(result, slot.fragments[i]...)
		}
		return result
	}

	return nil
}
