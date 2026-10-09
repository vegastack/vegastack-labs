//go:build linux

package qualification

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// installConsoleStep copies only the exact typed step and its one operation-
// selected sibling into the disposable guest. Protected slots are exclusive:
// interruption leaves an unusable slot rather than overwriting prior input.
func (d *ownedGuestLifecycle) installConsoleStep(conn net.Conn, in generated.NativeStepRequest) error {
	stem := in.ScenarioID + "-" + strconv.FormatInt(in.Ordinal, 10)
	files := []struct{ suffix, schema string }{{".json", generated.SchemaIDNativeStepRequest}}
	switch in.Operation {
	case "prepare":
		files = append(files, struct{ suffix, schema string }{".prepare.json", generated.SchemaIDNativePreparationRequest})
	case "witness", "select-controller":
		files = append(files, struct{ suffix, schema string }{".witness.json", generated.SchemaIDNativeWitnessRequest})
	case "collect-native":
		files = append(files, struct{ suffix, schema string }{".collect.json", generated.SchemaIDNativeCollectRequest})
	case "execute", "observe":
	default:
		return ErrUnavailable
	}
	for _, f := range files {
		raw, err := ownedFile(filepath.Join(d.scope.value.OutputRoot, stem+f.suffix), uint32(os.Geteuid()), 65536)
		if err != nil || generated.ValidateContractJSON(f.schema, raw, generated.ContractExact) != nil {
			return ErrUnavailable
		}
		if f.suffix == ".json" {
			var installed generated.NativeStepRequest
			if json.Unmarshal(raw, &installed) != nil || hostaction.Digest(installed) != hostaction.Digest(in) {
				return ErrUnavailable
			}
		}
		token := "VSKSLOT" + strings.TrimPrefix(hostaction.BytesDigest(raw), "sha256:")
		encoded := base64.StdEncoding.EncodeToString(raw)
		var lines strings.Builder
		for len(encoded) > 0 {
			n := 76
			if len(encoded) < n {
				n = len(encoded)
			}
			lines.WriteString(encoded[:n])
			lines.WriteByte('\n')
			encoded = encoded[n:]
		}
		path := "/run/vsk-labs-native/" + stem + f.suffix
		// All interpolated path components passed the closed contract and catalog;
		// payload is base64, never shell syntax. /run is the OS-owned runtime root.
		command := fmt.Sprintf("\x15umask 077; test ! -L /run/vsk-labs-native && test \"$(/usr/bin/stat -c '%%u:%%a' /run/vsk-labs-native)\" = 0:700 && (set -C; /usr/bin/base64 -d > '%s.installing' <<'%s'\n%s%s\n) && test \"$(/usr/bin/sha256sum '%s.installing')\" = '%s  %s.installing' && /usr/bin/ln -T '%s.installing' '%s' && /usr/bin/rm '%s.installing' && /usr/bin/printf '\\n%sOK\\n'\n", path, token, lines.String(), token, path, strings.TrimPrefix(hostaction.BytesDigest(raw), "sha256:"), path, path, path, path, token)
		if _, err = io.WriteString(conn, command); err != nil {
			return err
		}
		scanner := bufio.NewScanner(io.LimitReader(conn, 256*1024))
		scanner.Buffer(make([]byte, 1024), 8192)
		found := false
		for scanner.Scan() {
			if strings.TrimSuffix(scanner.Text(), "\r") == token+"OK" {
				found = true
				break
			}
		}
		if !found {
			return ErrUnavailable
		}
	}
	return nil
}
