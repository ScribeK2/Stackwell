package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// broker fans Step updates out to every connected UI over server-sent events.
type broker struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func newBroker() *broker { return &broker{subs: map[chan []byte]struct{}{}} }

func (b *broker) publish(caseID int64, st Step) {
	b.send(map[string]any{"case_id": caseID, "step": st})
}

// publishRun announces a Playbook run's change of status (its Steps announce themselves).
func (b *broker) publishRun(caseID int64, r Run) {
	b.send(map[string]any{"case_id": caseID, "run": r})
}

func (b *broker) send(event map[string]any) {
	msg, _ := json.Marshal(event)
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- msg:
		default:
			// Too slow: disconnect rather than silently drop. The UI re-fetches
			// its Case when EventSource reconnects.
			delete(b.subs, ch)
			close(ch)
		}
	}
}

func (b *broker) serve(w http.ResponseWriter, r *http.Request) {
	ch := make(chan []byte, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
		b.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	rc.Flush()
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			rc.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
