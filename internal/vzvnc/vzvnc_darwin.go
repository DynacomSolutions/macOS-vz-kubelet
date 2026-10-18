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

static void *vncStart(void *vm, const char *password, int *port) {
	Class sec = NSClassFromString(@"_VZVNCAuthenticationSecurityConfiguration");
	Class srv = NSClassFromString(@"_VZVNCServer");
	if (!sec || !srv) return NULL;
	id cfg = [[sec alloc] initWithPassword:[NSString stringWithUTF8String:password]];
	_VZVNCServer *s = [[srv alloc] initWithPort:0 queue:dispatch_get_global_queue(0, 0) securityConfiguration:cfg];
	[s setVirtualMachine:(id)vm];
	[s start];
	*port = (int)[s port];
	return s;
}

static void vncStop(void *s) { [(_VZVNCServer *)s stop]; [(id)s release]; }
*/
import "C"

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"unsafe"

	"github.com/Code-Hex/vz/v3"
)

// Server is a running VNC server. Password is random per server (VNC authentication, first 8
// characters count) because the framework gives no promise to bind loopback only.
type Server struct {
	srv      unsafe.Pointer
	Port     int
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
	f := reflect.ValueOf(v).Elem().FieldByName("Pointer")
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
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	pw := hex.EncodeToString(raw[:])
	cpw := C.CString(pw)
	defer C.free(unsafe.Pointer(cpw))
	var port C.int
	s := C.vncStart(p, cpw, &port)
	if s == nil {
		return nil, errors.New("vzvnc: _VZVNCServer is not available on this macOS")
	}
	return &Server{srv: s, Port: int(port), Password: pw}, nil
}

// Stop stops the server.
func (s *Server) Stop() {
	if s.srv != nil {
		C.vncStop(s.srv)
		s.srv = nil
	}
}
