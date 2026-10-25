package main

/*
#cgo CFLAGS: -I${SRCDIR}
#include <stdlib.h>
#include <string.h>
#include "include/CoveeEngine.h"
int invoke_persist(covee_persist_callback fn, void *ctx, const char *json);
*/
import "C"

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"unsafe"
)

const (
	codeError   = -1
	codeSmall   = -2
	codeClosed  = -3
	codeInvalid = -4
)

var handles = struct {
	sync.RWMutex
	engines     map[int64]*engine
	createError string
}{engines: make(map[int64]*engine)}

var nextHandle atomic.Int64

func lookup(handle int64) *engine {
	handles.RLock()
	defer handles.RUnlock()
	return handles.engines[handle]
}

func createFailure(message string) C.int64_t {
	handles.Lock()
	handles.createError = message
	handles.Unlock()
	return 0
}

func boundedCString(p *C.char, maximum int) ([]byte, error) {
	if p == nil {
		return nil, errors.New("missing JSON input")
	}
	n := int(C.strnlen(p, C.size_t(maximum+1)))
	if n > maximum {
		return nil, errors.New("JSON input exceeds size limit")
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n)), nil
}

//export GoCoveeCreate
func GoCoveeCreate(configJSON, stateJSON *C.char, persist C.covee_persist_callback, context unsafe.Pointer) C.int64_t {
	raw, err := boundedCString(configJSON, 128<<10)
	if err != nil {
		return createFailure(err.Error())
	}
	cfg, err := parseConfig(raw)
	if err != nil {
		return createFailure(err.Error())
	}
	state, err := boundedCString(stateJSON, maxStateBytes)
	if err != nil {
		return createFailure(err.Error())
	}
	if persist == nil {
		return createFailure("durable state persistence callback is required")
	}
	store, err := newKeychainStore(state, func(raw []byte) error {
		str := C.CString(string(raw))
		defer C.free(unsafe.Pointer(str))
		if C.invoke_persist(persist, context, str) != 0 {
			return errors.New("durable state persistence failed")
		}
		return nil
	})
	if err != nil {
		return createFailure(err.Error())
	}
	e := newEngine(cfg, store)
	handle := nextHandle.Add(1)
	handles.Lock()
	handles.engines[handle] = e
	handles.createError = ""
	handles.Unlock()
	return C.int64_t(handle)
}

//export GoCoveeStart
func GoCoveeStart(handle C.int64_t) C.int {
	e := lookup(int64(handle))
	if e == nil {
		return codeInvalid
	}
	if err := e.start(); err != nil {
		e.recordError(err)
		e.stop()
		return codeError
	}
	return 0
}

//export GoCoveeWritePacket
func GoCoveeWritePacket(handle C.int64_t, packet *C.uint8_t, length C.int) C.int {
	e := lookup(int64(handle))
	if e == nil || packet == nil || length < 20 || length > maxPacketBytes {
		return codeInvalid
	}
	e.deliveryMu.RLock()
	defer e.deliveryMu.RUnlock()
	if e.fatal.Load() {
		return codeClosed
	}
	if err := e.tun.inject(C.GoBytes(unsafe.Pointer(packet), length)); err != nil {
		if errors.Is(err, io.EOF) {
			return codeClosed
		}
		// Invalid and saturated packets are counted as failed submissions;
		// avoid flooding the event queue with per-packet errors.
		return codeError
	}
	return 0
}

//export GoCoveeReadPacket
func GoCoveeReadPacket(handle C.int64_t, packet *C.uint8_t, capacity C.int) C.int {
	e := lookup(int64(handle))
	if e == nil || packet == nil || capacity <= 0 || capacity > maxPacketBytes+1 {
		return codeInvalid
	}
	p, code := e.readPacket(int(capacity))
	e.deliveryMu.RLock()
	defer e.deliveryMu.RUnlock()
	if e.fatal.Load() {
		return codeClosed
	}
	if code > 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(packet)), int(capacity)), p)
	}
	return C.int(code)
}

//export GoCoveeNextEvent
func GoCoveeNextEvent(handle C.int64_t, json *C.char, capacity C.int) C.int {
	e := lookup(int64(handle))
	if e == nil || json == nil || capacity <= 0 || capacity > maxEventBytes+1 {
		return codeInvalid
	}
	raw, code := e.nextEvent(int(capacity))
	e.deliveryMu.RLock()
	// A failure may latch between selection and the C memory copy. Replace a
	// selected stale status/settings event with the retained fatal envelope.
	if e.fatal.Load() && code > 0 && !bytes.Equal(raw, persistenceEvent) {
		e.deliveryMu.RUnlock()
		raw, code = e.nextEvent(int(capacity))
		e.deliveryMu.RLock()
	}
	defer e.deliveryMu.RUnlock()
	if code > 0 {
		buffer := unsafe.Slice((*byte)(unsafe.Pointer(json)), int(capacity))
		copy(buffer, raw)
		buffer[len(raw)] = 0
	}
	return C.int(code)
}

//export GoCoveeAckNetwork
func GoCoveeAckNetwork(handle C.int64_t, generation C.uint64_t, nativeError *C.char) C.int {
	e := lookup(int64(handle))
	if e == nil {
		return codeInvalid
	}
	var message []byte
	if nativeError != nil {
		var err error
		message, err = boundedCString(nativeError, 1024)
		if err != nil {
			return codeInvalid
		}
	}
	// A late acknowledgement is not an engine error: the wait already ended
	// with one, and the provider decides what a refused one means.
	if err := e.acknowledge(uint64(generation), string(message)); err != nil {
		return codeError
	}
	return 0
}

//export GoCoveeSetExitNode
func GoCoveeSetExitNode(handle C.int64_t, requestJSON *C.char, message *C.char, capacity C.int) C.int {
	return request(handle, requestJSON, message, capacity, (*engine).setExitNode)
}

//export GoCoveeSetAcceptRoutes
func GoCoveeSetAcceptRoutes(handle C.int64_t, requestJSON *C.char, message *C.char, capacity C.int) C.int {
	return request(handle, requestJSON, message, capacity, (*engine).setAcceptRoutes)
}

//export GoCoveeSetOfferExitNode
func GoCoveeSetOfferExitNode(handle C.int64_t, requestJSON *C.char, message *C.char, capacity C.int) C.int {
	return request(handle, requestJSON, message, capacity, (*engine).setOfferExitNode)
}

// request runs one small JSON request against an engine and writes a refusal's
// plain-language reason into message.
func request(handle C.int64_t, requestJSON *C.char, message *C.char, capacity C.int, run func(*engine, []byte) error) C.int {
	e := lookup(int64(handle))
	if e == nil || message == nil || capacity <= 0 || capacity > 4096 {
		return codeInvalid
	}
	raw, err := boundedCString(requestJSON, 1024)
	if err == nil {
		err = run(e, raw)
	}
	if err == nil {
		return 0
	}
	if errors.Is(err, io.EOF) {
		return codeClosed
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(message)), int(capacity))
	n := copy(out[:len(out)-1], err.Error())
	out[n] = 0
	return codeError
}

//export GoCoveeStop
func GoCoveeStop(handle C.int64_t) C.int {
	e := lookup(int64(handle))
	if e == nil {
		return codeInvalid
	}
	e.stop()
	return 0
}

//export GoCoveeDestroy
func GoCoveeDestroy(handle C.int64_t) C.int {
	e := lookup(int64(handle))
	if e == nil {
		return codeInvalid
	}
	e.stop()
	handles.Lock()
	delete(handles.engines, int64(handle))
	handles.Unlock()
	return 0
}

//export GoCoveeLastError
func GoCoveeLastError(handle C.int64_t, buffer *C.char, capacity C.int) C.int {
	message := "invalid engine handle"
	if handle == 0 {
		handles.RLock()
		message = handles.createError
		handles.RUnlock()
	} else if e := lookup(int64(handle)); e != nil {
		e.errMu.Lock()
		message = e.lastError
		e.errMu.Unlock()
	}
	if buffer != nil && capacity > 0 && int(capacity) >= len(message)+1 && int(capacity) <= maxEventBytes+1 {
		out := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(capacity))
		copy(out, message)
		out[len(message)] = 0
	}
	return C.int(len(message) + 1)
}

func main() {}
