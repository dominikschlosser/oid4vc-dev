// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wallet

// CreateConsentRequest creates a new consent request and notifies subscribers.
func (w *Wallet) CreateConsentRequest(req *ConsentRequest) {
	w.mu.Lock()
	w.Requests[req.ID] = req
	subs := make([]chan *ConsentRequest, 0, len(w.subscribers))
	for _, ch := range w.subscribers {
		subs = append(subs, ch)
	}
	w.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- req:
		default:
		}
	}
}

// GetRequest returns a consent request by ID.
func (w *Wallet) GetRequest(id string) (*ConsentRequest, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	req, ok := w.Requests[id]
	return req, ok
}

// ResolveRequest atomically transitions a consent request from "pending" to
// the given status. It returns false if the request was not found or was
// already resolved.
func (w *Wallet) ResolveRequest(id, status string) (*ConsentRequest, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	req, ok := w.Requests[id]
	if !ok || req.Status != "pending" {
		return req, false
	}
	req.Status = status
	return req, true
}

// GetPendingRequests returns all pending consent requests.
func (w *Wallet) GetPendingRequests() []*ConsentRequest {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var out []*ConsentRequest
	for _, r := range w.Requests {
		if r.Status == "pending" {
			out = append(out, r)
		}
	}
	return out
}

// Subscribe returns a channel for new consent requests and an unsubscribe function.
func (w *Wallet) Subscribe() (<-chan *ConsentRequest, func()) {
	ch := make(chan *ConsentRequest, 16)
	w.mu.Lock()
	w.subID++
	id := w.subID
	w.subscribers[id] = ch
	w.mu.Unlock()

	return ch, func() {
		w.mu.Lock()
		delete(w.subscribers, id)
		w.mu.Unlock()
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}

// SubscribeErrors returns a channel for error events and an unsubscribe function.
func (w *Wallet) SubscribeErrors() (<-chan WalletError, func()) {
	ch := make(chan WalletError, 16)
	w.mu.Lock()
	w.errSubID++
	id := w.errSubID
	if w.errSubscribers == nil {
		w.errSubscribers = make(map[int64]chan WalletError)
	}
	w.errSubscribers[id] = ch
	w.mu.Unlock()

	return ch, func() {
		w.mu.Lock()
		delete(w.errSubscribers, id)
		w.mu.Unlock()
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}

// NotifyError sends an error event to all subscribers and stores it for polling.
func (w *Wallet) NotifyError(err WalletError) {
	w.mu.Lock()
	w.lastError = &err
	subs := make([]chan WalletError, 0, len(w.errSubscribers))
	for _, ch := range w.errSubscribers {
		subs = append(subs, ch)
	}
	w.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- err:
		default:
		}
	}
}

// PopLastError returns and clears the last error, if any.
func (w *Wallet) PopLastError() *WalletError {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.lastError
	w.lastError = nil
	return err
}

// SetNextError sets a one-shot error override for the next presentation request.
func (w *Wallet) SetNextError(e *NextErrorOverride) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.nextError = e
}

// ConsumeNextError returns and clears the next error override, if any.
func (w *Wallet) ConsumeNextError() *NextErrorOverride {
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.nextError
	w.nextError = nil
	return e
}
