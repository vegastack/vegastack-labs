//go:build linux

package debianaccess

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

var errManagedSessions = errors.New("managed automation session revocation unavailable")
var errManagedSessionGone = errors.New("managed session object absent")
var managedSessionID = regexp.MustCompile(`^[a-zA-Z0-9]{1,64}$`)

type managedSession struct {
	id, path, scope, service, state string
	uid, leader                     uint32
	started                         uint64
	remote                          bool
}
type managedSessionUnit struct {
	id, path, active, cgroup string
	pid                      uint32
	started                  uint64
}
type managedSessionGroup struct {
	device, inode   uint64
	populated, gone bool
}

// This private seam covers only the existing logind/session-scope operations.
// Production always uses the fixed local bus and kernel cgroup filesystem.
type managedSessionOS interface {
	owners(context.Context) error
	caller(context.Context, uint32) (managedSession, error)
	list(context.Context) ([]managedSession, error)
	session(context.Context, string) (managedSession, error)
	unit(context.Context, string) (managedSessionUnit, error)
	group(context.Context, string) (managedSessionGroup, error)
	terminate(context.Context, managedSession) error
}

func revokeManagedAutomationSessions(ctx context.Context, automationUID int64) (bool, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || automationUID <= 0 || automationUID > int64(^uint32(0)) {
		return false, errManagedSessions
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, path := range []string{"/run", "/run/dbus", "/run/dbus/system_bus_socket"} {
		info, e := os.Lstat(path)
		if e != nil {
			return false, errManagedSessions
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || (path != "/run/dbus/system_bus_socket" && (!info.IsDir() || info.Mode().Perm()&0o022 != 0)) || (path == "/run/dbus/system_bus_socket" && info.Mode()&os.ModeSocket == 0) {
			return false, errManagedSessions
		}
	}
	// Dial an explicit address: DBUS_SYSTEM_BUS_ADDRESS and session environment
	// variables cannot redirect privileged observation or termination.
	transport, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if e != nil {
		return false, errManagedSessions
	}
	conn, e := dbus.NewConn(transport, dbus.WithContext(ctx))
	if e != nil {
		transport.Close()
		return false, errManagedSessions
	}
	defer conn.Close()
	if conn.Auth(nil) != nil || conn.Hello() != nil {
		return false, errManagedSessions
	}
	s := &logindSessionOS{conn: conn}
	if s.pin(ctx) != nil {
		return false, errManagedSessions
	}
	return revokeManagedSessions(ctx, uint32(automationUID), uint32(os.Getpid()), s)
}

func managedSSHSession(v managedSession, uid uint32) bool {
	return v.uid == uid && v.remote && v.service == "sshd" && managedSessionID.MatchString(v.id) &&
		v.path != "" && v.scope == "session-"+v.id+".scope" && v.leader > 1 && v.started > 0 && (v.state == "online" || v.state == "active" || v.state == "closing")
}
func sameManagedSession(a, b managedSession) bool { a.state = ""; b.state = ""; return a == b }
func cgroupOverlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
func sessionScopeComplete(u managedSessionUnit, g managedSessionGroup) bool {
	return (u.active == "inactive" || u.active == "failed") && (g.gone || !g.populated)
}

func revokeManagedSessions(ctx context.Context, uid, pid uint32, s managedSessionOS) (changed bool, err error) {
	if ctx == nil || ctx.Err() != nil || uid == 0 || pid <= 1 || s == nil {
		return false, errManagedSessions
	}
	if s.owners(ctx) != nil {
		return false, errManagedSessions
	}
	current, e := s.caller(ctx, pid)
	if e != nil || !managedSSHSession(current, uid) || current.state == "closing" {
		return false, errManagedSessions
	}
	currentUnit, e := s.unit(ctx, current.scope)
	if e != nil || currentUnit.id != current.scope || currentUnit.active != "active" || currentUnit.cgroup == "" {
		return false, errManagedSessions
	}
	master, e := s.unit(ctx, "ssh.service")
	if e != nil || master.id != "ssh.service" || master.active != "active" || master.pid <= 1 || master.started == 0 || master.cgroup == "" || cgroupOverlaps(currentUnit.cgroup, master.cgroup) {
		return false, errManagedSessions
	}
	currentGroup, e := s.group(ctx, currentUnit.cgroup)
	if e != nil || currentGroup.gone || !currentGroup.populated || currentGroup.inode == 0 {
		return false, errManagedSessions
	}
	masterGroup, e := s.group(ctx, master.cgroup)
	if e != nil || masterGroup.gone || !masterGroup.populated || masterGroup.inode == 0 {
		return false, errManagedSessions
	}
	all, e := s.list(ctx)
	if e != nil || len(all) == 0 || len(all) > 128 {
		return false, errManagedSessions
	}
	seenIDs, seenPaths, scopes := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var candidates []managedSession
	foundCurrent := false
	for _, v := range all {
		if seenIDs[v.id] || seenPaths[v.path] || v.id == "" || v.path == "" {
			return false, errManagedSessions
		}
		seenIDs[v.id] = true
		seenPaths[v.path] = true
		if v.scope != "" {
			if scopes[v.scope] {
				return false, errManagedSessions
			}
			scopes[v.scope] = true
		}
		if v.path == current.path || v.id == current.id {
			if !sameManagedSession(v, current) {
				return false, errManagedSessions
			}
			foundCurrent = true
			continue
		}
		if v.uid != uid || v.service != "sshd" || !v.remote {
			continue
		}
		if !managedSSHSession(v, uid) || v.scope == current.scope {
			return false, errManagedSessions
		}
		candidates = append(candidates, v)
	}
	if !foundCurrent {
		return false, errManagedSessions
	}
	// Capture all exact scope/cgroup preimages before issuing any termination.
	units := make([]managedSessionUnit, len(candidates))
	groups := make([]managedSessionGroup, len(candidates))
	for n, v := range candidates {
		u, e := s.unit(ctx, v.scope)
		if e != nil || u.id != v.scope || u.cgroup == "" || cgroupOverlaps(u.cgroup, currentUnit.cgroup) || cgroupOverlaps(u.cgroup, master.cgroup) {
			return false, errManagedSessions
		}
		g, e := s.group(ctx, u.cgroup)
		if e != nil || g.gone || g.inode == 0 {
			return false, errManagedSessions
		}
		units[n], groups[n] = u, g
	}
	preserved := func() error {
		if ctx.Err() != nil || s.owners(ctx) != nil {
			return errManagedSessions
		}
		now, e := s.caller(ctx, pid)
		if e != nil || !sameManagedSession(now, current) || now.state == "closing" {
			return errManagedSessions
		}
		unit, e := s.unit(ctx, current.scope)
		if e != nil || unit != currentUnit {
			return errManagedSessions
		}
		unit, e = s.unit(ctx, "ssh.service")
		if e != nil || unit != master {
			return errManagedSessions
		}
		for _, captured := range []struct {
			path  string
			group managedSessionGroup
		}{{currentUnit.cgroup, currentGroup}, {master.cgroup, masterGroup}} {
			g, e := s.group(ctx, captured.path)
			if e != nil || g.gone || !g.populated || g.device != captured.group.device || g.inode != captured.group.inode {
				return errManagedSessions
			}
		}
		return nil
	}
	for n, v := range candidates {
		if preserved() != nil {
			return changed, errManagedSessions
		}
		now, e := s.session(ctx, v.path)
		alreadyGone := errors.Is(e, errManagedSessionGone)
		if !alreadyGone && (e != nil || !sameManagedSession(now, v)) {
			return changed, errManagedSessions
		}
		if !alreadyGone {
			u, e := s.unit(ctx, v.scope)
			if e != nil || u != units[n] {
				return changed, errManagedSessions
			}
			g, e := s.group(ctx, u.cgroup)
			if e != nil || g.gone || g.device != groups[n].device || g.inode != groups[n].inode {
				return changed, errManagedSessions
			}
			// A transport/cancellation failure after issuance cannot prove no effect.
			changed = true
			if s.terminate(ctx, v) != nil {
				return changed, errManagedSessions
			}
		}
		for {
			if preserved() != nil {
				return changed, errManagedSessions
			}
			_, sessionErr := s.session(ctx, v.path)
			if sessionErr != nil && !errors.Is(sessionErr, errManagedSessionGone) {
				return changed, errManagedSessions
			}
			u, unitErr := s.unit(ctx, v.scope)
			if errors.Is(unitErr, errManagedSessionGone) {
				u = units[n]
				u.active = "inactive"
			} else if unitErr != nil || u.id != units[n].id || u.path != units[n].path || u.cgroup != units[n].cgroup {
				return changed, errManagedSessions
			}
			g, e := s.group(ctx, units[n].cgroup)
			if e != nil || !g.gone && (g.device != groups[n].device || g.inode != groups[n].inode) {
				return changed, errManagedSessions
			}
			if errors.Is(sessionErr, errManagedSessionGone) && sessionScopeComplete(u, g) {
				break
			}
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return changed, errManagedSessions
			case <-timer.C:
			}
		}
	}
	if preserved() != nil {
		return changed, errManagedSessions
	}
	return changed, nil
}

type logindSessionOS struct {
	conn                    *dbus.Conn
	loginOwner, systemOwner string
}

func (s *logindSessionOS) owner(ctx context.Context, name string) (string, error) {
	var owner string
	var uid uint32
	b := s.conn.Object("org.freedesktop.DBus", "/org/freedesktop/DBus")
	if b.CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, name).Store(&owner) != nil || !strings.HasPrefix(owner, ":") || len(owner) > 128 || b.CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", 0, owner).Store(&uid) != nil || uid != 0 {
		return "", errManagedSessions
	}
	return owner, nil
}
func (s *logindSessionOS) pin(ctx context.Context) error {
	var e error
	s.loginOwner, e = s.owner(ctx, "org.freedesktop.login1")
	if e != nil {
		return e
	}
	s.systemOwner, e = s.owner(ctx, "org.freedesktop.systemd1")
	return e
}
func (s *logindSessionOS) owners(ctx context.Context) error {
	a, e := s.owner(ctx, "org.freedesktop.login1")
	if e != nil || a != s.loginOwner {
		return errManagedSessions
	}
	b, e := s.owner(ctx, "org.freedesktop.systemd1")
	if e != nil || b != s.systemOwner {
		return errManagedSessions
	}
	return nil
}
func (s *logindSessionOS) properties(ctx context.Context, owner string, path dbus.ObjectPath, iface string) (map[string]dbus.Variant, error) {
	if !path.IsValid() {
		return nil, errManagedSessions
	}
	var values map[string]dbus.Variant
	e := s.conn.Object(owner, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, iface).Store(&values)
	if e != nil {
		if dbusErrorNamed(e, "org.freedesktop.DBus.Error.UnknownObject") {
			return nil, errManagedSessionGone
		}
		return nil, errManagedSessions
	}
	if len(values) > 512 {
		return nil, errManagedSessions
	}
	return values, nil
}
func dbusErrorNamed(e error, name string) bool {
	var value dbus.Error
	if errors.As(e, &value) {
		return value.Name == name
	}
	var pointer *dbus.Error
	return errors.As(e, &pointer) && pointer.Name == name
}
func (s *logindSessionOS) caller(ctx context.Context, pid uint32) (managedSession, error) {
	var path dbus.ObjectPath
	if s.conn.Object(s.loginOwner, "/org/freedesktop/login1").CallWithContext(ctx, "org.freedesktop.login1.Manager.GetSessionByPID", 0, pid).Store(&path) != nil {
		return managedSession{}, errManagedSessions
	}
	return s.session(ctx, string(path))
}
func (s *logindSessionOS) session(ctx context.Context, path string) (managedSession, error) {
	v, e := s.properties(ctx, s.loginOwner, dbus.ObjectPath(path), "org.freedesktop.login1.Session")
	if e != nil {
		return managedSession{}, e
	}
	return decodeManagedSession(path, v)
}
func decodeManagedSession(path string, p map[string]dbus.Variant) (managedSession, error) {
	get := func(k string) any { return p[k].Value() }
	id, a := get("Id").(string)
	service, b := get("Service").(string)
	scope, c := get("Scope").(string)
	leader, d := get("Leader").(uint32)
	started, e := get("TimestampMonotonic").(uint64)
	remote, f := get("Remote").(bool)
	state, g := get("State").(string)
	user, h := get("User").([]any)
	if !a || !b || !c || !d || !e || !f || !g || !h || len(user) != 2 || !managedSessionID.MatchString(id) || !dbus.ObjectPath(path).IsValid() || !strings.HasPrefix(path, "/org/freedesktop/login1/session/") || len(service) > 64 || len(scope) > 128 || len(state) > 32 {
		return managedSession{}, errManagedSessions
	}
	uid, i := user[0].(uint32)
	userPath, j := user[1].(dbus.ObjectPath)
	if !i || !j || !userPath.IsValid() {
		return managedSession{}, errManagedSessions
	}
	return managedSession{id: id, path: path, scope: scope, service: service, state: state, uid: uid, leader: leader, started: started, remote: remote}, nil
}
func (s *logindSessionOS) list(ctx context.Context) ([]managedSession, error) {
	var rows []struct {
		ID         string
		UID        uint32
		Name, Seat string
		Path       dbus.ObjectPath
	}
	if s.conn.Object(s.loginOwner, "/org/freedesktop/login1").CallWithContext(ctx, "org.freedesktop.login1.Manager.ListSessions", 0).Store(&rows) != nil || len(rows) > 128 {
		return nil, errManagedSessions
	}
	out := make([]managedSession, 0, len(rows))
	for _, row := range rows {
		v, e := s.session(ctx, string(row.Path))
		if e != nil || v.id != row.ID || v.uid != row.UID {
			return nil, errManagedSessions
		}
		out = append(out, v)
	}
	return out, nil
}
func (s *logindSessionOS) unit(ctx context.Context, name string) (managedSessionUnit, error) {
	if name != "ssh.service" && (!strings.HasPrefix(name, "session-") || !strings.HasSuffix(name, ".scope") || !managedSessionID.MatchString(strings.TrimSuffix(strings.TrimPrefix(name, "session-"), ".scope"))) {
		return managedSessionUnit{}, errManagedSessions
	}
	var path dbus.ObjectPath
	e := s.conn.Object(s.systemOwner, "/org/freedesktop/systemd1").CallWithContext(ctx, "org.freedesktop.systemd1.Manager.GetUnit", 0, name).Store(&path)
	if e != nil {
		if dbusErrorNamed(e, "org.freedesktop.systemd1.NoSuchUnit") {
			return managedSessionUnit{}, errManagedSessionGone
		}
		return managedSessionUnit{}, errManagedSessions
	}
	p, e := s.properties(ctx, s.systemOwner, path, "org.freedesktop.systemd1.Unit")
	if e != nil {
		return managedSessionUnit{}, e
	}
	id, a := p["Id"].Value().(string)
	active, b := p["ActiveState"].Value().(string)
	load, c := p["LoadState"].Value().(string)
	iface := "org.freedesktop.systemd1.Scope"
	if name == "ssh.service" {
		iface = "org.freedesktop.systemd1.Service"
	}
	q, e := s.properties(ctx, s.systemOwner, path, iface)
	if e != nil {
		return managedSessionUnit{}, e
	}
	cg, d := q["ControlGroup"].Value().(string)
	if !a || !b || !c || !d || id != name || load != "loaded" || len(active) > 32 || cg == "" || !strings.HasPrefix(cg, "/") || filepath.Clean(cg) != cg || len(cg) > 512 {
		return managedSessionUnit{}, errManagedSessions
	}
	u := managedSessionUnit{id: id, path: string(path), active: active, cgroup: cg}
	if name == "ssh.service" {
		var ok bool
		u.pid, ok = q["MainPID"].Value().(uint32)
		if !ok {
			return u, errManagedSessions
		}
		u.started, ok = q["ExecMainStartTimestampMonotonic"].Value().(uint64)
		if !ok {
			return u, errManagedSessions
		}
	}
	return u, nil
}
func (s *logindSessionOS) group(ctx context.Context, path string) (managedSessionGroup, error) {
	if ctx.Err() != nil || path == "/" || !strings.HasPrefix(path, "/") || filepath.Clean(path) != path || len(path) > 512 {
		return managedSessionGroup{}, errManagedSessions
	}
	r, e := os.OpenRoot("/sys/fs/cgroup")
	if e != nil {
		return managedSessionGroup{}, errManagedSessions
	}
	defer r.Close()
	name := strings.TrimPrefix(path, "/")
	info, e := r.Lstat(name)
	if os.IsNotExist(e) {
		return managedSessionGroup{gone: true}, nil
	}
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return managedSessionGroup{}, errManagedSessions
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return managedSessionGroup{}, errManagedSessions
	}
	f, e := r.Open(name + "/cgroup.events")
	if e != nil {
		return managedSessionGroup{}, errManagedSessions
	}
	defer f.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return managedSessionGroup{}, errManagedSessions
	}
	var raw [257]byte
	n, e := f.Read(raw[:])
	if e != nil || n == 0 || n > 256 {
		return managedSessionGroup{}, errManagedSessions
	}
	populated, seen := false, false
	for _, line := range strings.Split(string(raw[:n]), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			if seen || (fields[1] != "0" && fields[1] != "1") {
				return managedSessionGroup{}, errManagedSessions
			}
			seen = true
			populated = fields[1] == "1"
		}
	}
	after, e := r.Lstat(name)
	if e != nil || !os.SameFile(info, after) || !seen {
		return managedSessionGroup{}, errManagedSessions
	}
	return managedSessionGroup{device: uint64(st.Dev), inode: st.Ino, populated: populated}, nil
}
func (s *logindSessionOS) terminate(ctx context.Context, v managedSession) error {
	return s.conn.Object(s.loginOwner, dbus.ObjectPath(v.path)).CallWithContext(ctx, "org.freedesktop.login1.Session.Terminate", 0).Store()
}
