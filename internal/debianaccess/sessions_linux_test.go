//go:build linux

package debianaccess

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type sessionTestOS struct {
	current                managedSession
	all                    []managedSession
	units                  map[string]managedSessionUnit
	groups                 map[string]managedSessionGroup
	terminated             []string
	ownerErr, terminateErr error
	populateAfter          bool
	keepAfter              bool
	ownerAfter             bool
	driftAfter             bool
	goneBefore             bool
	cancel                 context.CancelFunc
}

func (s *sessionTestOS) owners(context.Context) error { return s.ownerErr }
func (s *sessionTestOS) caller(context.Context, uint32) (managedSession, error) {
	return s.current, nil
}
func (s *sessionTestOS) list(context.Context) ([]managedSession, error) {
	return append([]managedSession(nil), s.all...), nil
}
func (s *sessionTestOS) session(_ context.Context, path string) (managedSession, error) {
	if s.goneBefore && path == "/org/freedesktop/login1/session/2" {
		return managedSession{}, errManagedSessionGone
	}
	for _, v := range s.all {
		if v.path == path {
			return v, nil
		}
	}
	return managedSession{}, errManagedSessionGone
}
func (s *sessionTestOS) unit(_ context.Context, name string) (managedSessionUnit, error) {
	v, ok := s.units[name]
	if !ok {
		return v, errManagedSessionGone
	}
	return v, nil
}
func (s *sessionTestOS) group(_ context.Context, path string) (managedSessionGroup, error) {
	v, ok := s.groups[path]
	if !ok {
		return managedSessionGroup{gone: true}, nil
	}
	return v, nil
}
func (s *sessionTestOS) terminate(_ context.Context, v managedSession) error {
	s.terminated = append(s.terminated, v.id)
	if s.ownerAfter {
		s.ownerErr = errors.New("owner restarted")
	}
	if s.driftAfter {
		s.current.leader++
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.terminateErr != nil {
		return s.terminateErr
	}
	if !s.keepAfter {
		for n, row := range s.all {
			if row.id == v.id {
				s.all = append(s.all[:n], s.all[n+1:]...)
				break
			}
		}
	}
	u := s.units[v.scope]
	u.active = "inactive"
	s.units[v.scope] = u
	g := s.groups[u.cgroup]
	g.populated = s.populateAfter
	s.groups[u.cgroup] = g
	return nil
}
func sessionTestFixture() *sessionTestOS {
	makeSession := func(id string, uid uint32, service string) managedSession {
		return managedSession{id: id, path: "/org/freedesktop/login1/session/" + id, uid: uid, service: service, scope: "session-" + id + ".scope", leader: 42, started: 100, remote: true, state: "online"}
	}
	current := makeSession("1", 22002, "sshd")
	s := &sessionTestOS{current: current, all: []managedSession{current, makeSession("2", 22002, "sshd"), makeSession("3", 22005, "sshd"), makeSession("4", 22002, "login")}, units: map[string]managedSessionUnit{}, groups: map[string]managedSessionGroup{}}
	for _, v := range s.all {
		cg := "/user.slice/user-22002.slice/" + v.scope
		u := managedSessionUnit{id: v.scope, path: "/org/freedesktop/systemd1/unit/" + v.id, active: "active", cgroup: cg}
		s.units[v.scope] = u
		s.groups[cg] = managedSessionGroup{device: 1, inode: uint64(v.leader) + uint64(v.id[0]), populated: true}
	}
	s.units["ssh.service"] = managedSessionUnit{id: "ssh.service", path: "/org/freedesktop/systemd1/unit/ssh", active: "active", cgroup: "/system.slice/ssh.service", pid: 9, started: 20}
	s.groups["/system.slice/ssh.service"] = managedSessionGroup{device: 1, inode: 9, populated: true}
	return s
}
func TestManagedSessionsPreserveCurrentHumanAndUnrelated(t *testing.T) {
	s := sessionTestFixture()
	changed, e := revokeManagedSessions(context.Background(), 22002, 51, s)
	if e != nil || !changed || !reflect.DeepEqual(s.terminated, []string{"2"}) {
		t.Fatalf("changed=%v err=%v targets=%v", changed, e, s.terminated)
	}
	for _, id := range []string{"1", "3", "4"} {
		if _, e = s.session(context.Background(), "/org/freedesktop/login1/session/"+id); e != nil {
			t.Fatal("preserved session missing", id)
		}
	}
}
func TestManagedSessionsRejectBeforeMutation(t *testing.T) {
	for _, name := range []string{"wrong-current-uid", "not-ssh", "unregistered", "shared-scope", "owner-drift", "caller-empty-scope", "master-overlap"} {
		t.Run(name, func(t *testing.T) {
			s := sessionTestFixture()
			switch name {
			case "wrong-current-uid":
				s.current.uid = 22005
			case "not-ssh":
				s.current.service = "login"
			case "unregistered":
				s.current.path = "/missing"
			case "shared-scope":
				s.all[2].scope = s.all[1].scope
			case "owner-drift":
				s.ownerErr = errors.New("owner changed")
			case "caller-empty-scope":
				u := s.units[s.current.scope]
				u.cgroup = ""
				s.units[s.current.scope] = u
			case "master-overlap":
				u := s.units["ssh.service"]
				u.cgroup = s.units[s.all[1].scope].cgroup
				s.units["ssh.service"] = u
			}
			changed, e := revokeManagedSessions(context.Background(), 22002, 51, s)
			if changed || e == nil || len(s.terminated) != 0 {
				t.Fatalf("changed=%v err=%v targets=%v", changed, e, s.terminated)
			}
		})
	}
}
func TestManagedSessionsReportPossibleEffectsOnTerminateFailure(t *testing.T) {
	s := sessionTestFixture()
	s.terminateErr = errors.New("transport lost")
	changed, e := revokeManagedSessions(context.Background(), 22002, 51, s)
	if !changed || e == nil || len(s.terminated) != 1 {
		t.Fatalf("changed=%v err=%v", changed, e)
	}
}
func TestManagedSessionsCancellationAfterIssuedTermination(t *testing.T) {
	s := sessionTestFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.cancel = cancel
	changed, e := revokeManagedSessions(ctx, 22002, 51, s)
	if !changed || e == nil {
		t.Fatalf("changed=%v err=%v", changed, e)
	}
}
func TestManagedSessionsInactiveScopeMustAlsoBeEmpty(t *testing.T) {
	s := sessionTestFixture()
	s.populateAfter = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	changed, e := revokeManagedSessions(ctx, 22002, 51, s)
	if !changed || e == nil {
		t.Fatalf("changed=%v err=%v", changed, e)
	}
	if sessionScopeComplete(s.units["session-2.scope"], s.groups[s.units["session-2.scope"].cgroup]) {
		t.Fatal("inactive populated cgroup accepted")
	}
}

func TestManagedSessionsPreservationDriftAfterMutationIsPartial(t *testing.T) {
	for _, kind := range []string{"owner", "current"} {
		t.Run(kind, func(t *testing.T) {
			s := sessionTestFixture()
			s.ownerAfter = kind == "owner"
			s.driftAfter = kind == "current"
			changed, e := revokeManagedSessions(context.Background(), 22002, 51, s)
			if !changed || e == nil {
				t.Fatalf("changed=%v err=%v", changed, e)
			}
		})
	}
}
func TestManagedSessionsAlreadyRemovedSessionStillNeedsEmptyScope(t *testing.T) {
	s := sessionTestFixture()
	s.goneBefore = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	changed, e := revokeManagedSessions(ctx, 22002, 51, s)
	if changed || e == nil || len(s.terminated) > 0 {
		t.Fatalf("changed=%v err=%v targets=%v", changed, e, s.terminated)
	}
}
func TestManagedSessionsNoOtherSessionIsVerifiedNoop(t *testing.T) {
	s := sessionTestFixture()
	s.all = append(s.all[:1], s.all[2:]...)
	changed, e := revokeManagedSessions(context.Background(), 22002, 51, s)
	if changed || e != nil || len(s.terminated) != 0 {
		t.Fatalf("changed=%v err=%v", changed, e)
	}
}

func TestManagedSessionsDecodeExactLogin1Types(t *testing.T) {
	p := map[string]dbus.Variant{"Id": dbus.MakeVariant("c2"), "User": dbus.MakeVariant([]any{uint32(22002), dbus.ObjectPath("/org/freedesktop/login1/user/_22002")}), "Service": dbus.MakeVariant("sshd"), "Scope": dbus.MakeVariant("session-c2.scope"), "Leader": dbus.MakeVariant(uint32(42)), "TimestampMonotonic": dbus.MakeVariant(uint64(100)), "Remote": dbus.MakeVariant(true), "State": dbus.MakeVariant("online")}
	v, e := decodeManagedSession("/org/freedesktop/login1/session/c2", p)
	if e != nil || !managedSSHSession(v, 22002) {
		t.Fatalf("typed session refused: %v", e)
	}
	p["User"] = dbus.MakeVariant([]any{uint64(22002), dbus.ObjectPath("/org/freedesktop/login1/user/_22002")})
	if _, e = decodeManagedSession(v.path, p); e == nil {
		t.Fatal("wrong UID wire type accepted")
	}
}
