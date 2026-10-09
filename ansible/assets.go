// Package ansible embeds only the fixed, centrally executed access renderer.
package ansible

import "embed"

//go:embed roles/debian_access_render/tasks/main.yml
var AccessRenderer embed.FS
