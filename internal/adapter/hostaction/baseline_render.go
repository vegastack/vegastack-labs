package hostaction

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"time"

	assets "github.com/vegastack/vegastack-labs/ansible"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const baselineRenderPlaybook = "---\n- hosts: localhost\n  connection: local\n  gather_facts: false\n  become: false\n  roles:\n    - debian_baseline_render\n"
const baselineRenderConfig = "[defaults]\ninventory = localhost,\nroles_path = ./roles\nretry_files_enabled = False\nno_target_syslog = True\nlocal_tmp = ./tmp\nremote_tmp = ./tmp\ninterpreter_python = /usr/bin/python3\ncollections_scan_sys_path = False\ncollections_paths = ./collections\n"

func BaselineRendererDigest() string { return DebianRendererDigest() }

// RenderRole is finite local preparation. It has no inventory/host/SSH inputs,
// no become and no configurable plugin paths; it never applies configuration.
func RenderBaselineRole(ctx context.Context, input generated.DebianBaselineInput) (string, error) {
	var output string
	if ctx == nil || ctx.Err() != nil || debianbaseline.ValidateDesiredInput(input) != nil || input.ProfileLock.RoleDigest != BaselineRendererDigest() {
		return output, denied()
	}
	// Reject template syntax anywhere before Ansible's recursive variable engine.
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 32768 || bytes.Contains(raw, []byte("{{")) || bytes.Contains(raw, []byte("{%")) || bytes.Contains(raw, []byte("{#")) {
		return output, denied()
	}

	if !protectedRendererPath("/usr/bin/ansible-playbook") || !protectedRendererPath("/usr/bin/python3") {
		return output, denied()
	}
	binaryFile, err := os.Open("/usr/bin/ansible-playbook")
	if err != nil {
		return output, denied()
	}
	binary, err := io.ReadAll(io.LimitReader(binaryFile, 8<<20+1))
	binaryFile.Close()
	if err != nil || len(binary) > 8<<20 || protocol.BytesDigest(binary) != input.ProfileLock.AnsibleExecutableDigest {
		return output, denied()
	}
	collection, err := InstalledAnsibleCollectionDigest()
	if err != nil || collection != input.ProfileLock.CollectionDigest {
		return output, denied()
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("", "vsk-baseline-render-")
	if err != nil {
		return output, denied()
	}
	defer os.RemoveAll(root)
	for _, dir := range []string{"roles/debian_baseline_render/tasks", "tmp", "collections"} {
		if os.MkdirAll(filepath.Join(root, dir), 0700) != nil {
			return output, denied()
		}
	}
	role, err := assets.BaselineRenderer.ReadFile("roles/debian_baseline_render/tasks/main.yml")
	if err != nil {
		return output, denied()
	}
	files := map[string][]byte{"roles/debian_baseline_render/tasks/main.yml": role, "playbook.yml": []byte(baselineRenderPlaybook), "ansible.cfg": []byte(baselineRenderConfig)}
	vars, err := json.Marshal(map[string]any{"baseline_files": debianbaseline.DesiredFiles(input), "render_destination": filepath.Join(root, "rendered.json")})
	if err != nil {
		return output, denied()
	}
	files["variables.json"] = vars
	for name, data := range files {
		if os.WriteFile(filepath.Join(root, name), data, 0600) != nil {
			return output, denied()
		}
	}
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + root, "LANG=C.UTF-8", "PYTHONNOUSERSITE=1", "ANSIBLE_CONFIG=" + filepath.Join(root, "ansible.cfg"), "ANSIBLE_NOCOLOR=1"}
	// Query the installed interpreter's machine-readable version, not localized
	// CLI prose. The pinned executable and core version must agree with the lock.
	version := exec.CommandContext(bounded, "/usr/bin/python3", "-I", "-c", "import ansible,ansible.release,json; print(json.dumps({'version':ansible.release.__version__,'path':ansible.__file__}))")
	version.Dir = root
	version.Env = env
	var versionOut limitBuffer
	versionOut.limit = 1024
	version.Stdout = &versionOut
	version.Stderr = io.Discard
	if version.Run() != nil {
		return output, denied()
	}
	var observed struct {
		Version string `json:"version"`
		Path    string `json:"path"`
	}
	if json.Unmarshal(versionOut.Bytes(), &observed) != nil || observed.Version != input.ProfileLock.AnsibleVersion || observed.Path != "/usr/lib/python3/dist-packages/ansible/__init__.py" {
		return output, denied()
	}
	command := exec.CommandContext(bounded, "/usr/bin/ansible-playbook", "--inventory", "localhost,", "--connection", "local", "--extra-vars", "@variables.json", "playbook.yml")
	command.Dir = root
	command.Env = env
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if command.Run() != nil || bounded.Err() != nil {
		return output, denied()
	}
	f, err := os.Open(filepath.Join(root, "rendered.json"))
	if err != nil {
		return output, denied()
	}
	rendered, err := io.ReadAll(io.LimitReader(f, 32769))
	f.Close()
	var renderedFiles map[string][]byte
	if err != nil || len(rendered) > 32768 || strictjson.Scan(ctx, rendered, strictjson.Limits{MaxDepth: 16}) != nil || json.Unmarshal(rendered, &renderedFiles) != nil || protocol.Digest(renderedFiles) != debianbaseline.PolicyDigest(input) {
		return "", denied()
	}
	return protocol.Digest(renderedFiles), nil
}
