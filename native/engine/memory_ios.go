//go:build ios

package main

import "runtime/debug"

// iosMemoryLimit is a soft limit on the Go runtime's memory in the iPhone
// network extension. Apple ends an extension that uses more than about 50 MB,
// which drops the connection; near this limit Go collects garbage sooner
// instead of growing toward Apple's, leaving room for the rest of the process.
const iosMemoryLimit = 32 << 20

func init() { debug.SetMemoryLimit(iosMemoryLimit) }
