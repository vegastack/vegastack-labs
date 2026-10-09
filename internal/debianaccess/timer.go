package debianaccess

import (
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"time"
)

const rollbackService = "[Unit]\nDescription=Restore armed VegaStack access configuration\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/vsk-labs access-rollback\nUser=root\nGroup=root\nUMask=0077\n"
const rollbackBootService = "[Unit]\nDescription=Restore interrupted VegaStack access change before network services\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target ssh.service ssh.socket docker.service\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/vsk-labs access-rollback\nUser=root\nGroup=root\nUMask=0077\n[Install]\nWantedBy=sysinit.target\nRequiredBy=ssh.service docker.service\n"

func timerBytes(deadline time.Time) []byte {
	return []byte("[Unit]\nDescription=Ten-minute VegaStack access safety deadline\n[Timer]\nOnActiveSec=600s\nOnCalendar=" + deadline.UTC().Format("2006-01-02 15:04:05") + " UTC\nAccuracySec=1s\nRandomizedDelaySec=0\nPersistent=true\nUnit=vsk-access-rollback.service\n")
}

func RollbackUnitsDigest() string {
	return hostaction.Digest([]string{rollbackService, rollbackBootService, string(timerBytes(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)))})
}
