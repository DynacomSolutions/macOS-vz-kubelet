//go:build darwin && arm64

// Package vzvnc starts Virtualization.framework's private VNC server (_VZVNCServer, the one
// Cirrus tart uses for --vnc-experimental) on a loopback port for one VM, so key presses can be
// injected without a window server session. It is private API: it can break on any macOS update,
// and it is used only by create-base --recovery-sip-off.
package vzvnc

/*
#cgo CFLAGS: -x objective-c -fno-objc-arc
#cgo LDFLAGS: -framework Foundation -framework Virtualization
#include <stdlib.h>
#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>

@interface _VZVNCAuthenticationSecurityConfiguration : NSObject
- (instancetype)initWithPassword:(NSString *)password;
@end
@interface _VZVNCServer : NSObject
- (instancetype)initWithPort:(unsigned short)port queue:(dispatch_queue_t)queue securityConfiguration:(id)sec;
- (void)setVirtualMachine:(id)vm;
- (void)start;
- (void)stop;
- (unsigned short)port;
@end

static void *vncStart(void *vm, const char *password) {
	@autoreleasepool {
	Class sec = NSClassFromString(@"_VZVNCAuthenticationSecurityConfiguration");
	Class srv = NSClassFromString(@"_VZVNCServer");
	if (!sec || !srv) return NULL;
	id cfg = [[sec alloc] initWithPassword:[NSString stringWithUTF8String:password]];
	_VZVNCServer *s = [[srv alloc] initWithPort:0 queue:dispatch_get_global_queue(0, 0) securityConfiguration:cfg];
	[cfg release];
	[s setVirtualMachine:(id)vm];
	[s start];
	return s;
	}
}

// The port is 0 until the server has bound; callers poll.
static int vncPort(void *s) { return (int)[(_VZVNCServer *)s port]; }

static void vncStop(void *s) { [(_VZVNCServer *)s stop]; [(id)s release]; }
*/
import "C"

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"reflect"
	"time"
	"unsafe"

	"github.com/Code-Hex/vz/v3"
)

// Server is a running VNC server. Password is random per server (VNC authentication, first 8
// characters count) because the framework gives no promise to bind loopback only.
type Server struct {
	srv      unsafe.Pointer
	Password string
}

// vmPointer reads the VZVirtualMachine pointer out of Code-Hex/vz's unexported embedded field
// (vz.VirtualMachine -> *objc.Pointer -> _ptr). It returns nil if that layout changed.
func vmPointer(v *vz.VirtualMachine) (p unsafe.Pointer) {
	defer func() {
		if recover() != nil {
			p = nil
		}
	}()
	f := reflect.ValueOf(v).Elem().FieldByName("pointer")
	if !f.IsValid() || f.IsNil() {
		return nil
	}
	return f.Elem().Field(0).UnsafePointer()
}

// Start serves vm's console over VNC on a free port chosen by the framework. Call it before vm.Start.
func Start(v *vz.VirtualMachine) (*Server, error) {
	p := vmPointer(v)
	if p == nil {
		return nil, errors.New("vzvnc: cannot reach the VZVirtualMachine pointer (Code-Hex/vz layout changed)")
	}
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	pwb := make([]byte, 8) // VNC authentication uses 8 characters
	for i := range pwb {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return nil, err
		}
		pwb[i] = alphabet[n.Int64()]
	}
	pw := string(pwb)
	cpw := C.CString(pw)
	defer C.free(unsafe.Pointer(cpw))
	s := C.vncStart(p, cpw)
	if s == nil {
		return nil, errors.New("vzvnc: _VZVNCServer is not available on this macOS")
	}
	return &Server{srv: s, Password: pw}, nil
}

// WaitPort polls (every 50 ms, up to 10 s) until the server has bound a port and returns it.
func (s *Server) WaitPort(ctx context.Context) (int, error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		if p := int(C.vncPort(s.srv)); p > 0 {
			return p, nil
		}
		if time.Now().After(deadline) {
			return 0, errors.New("vzvnc: the VNC server did not bind a port within 10s")
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Stop stops the server.
func (s *Server) Stop() {
	if s.srv != nil {
		C.vncStop(s.srv)
		s.srv = nil
	}
}
