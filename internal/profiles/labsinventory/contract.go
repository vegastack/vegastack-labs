// Package labsinventory decodes the versioned VegaStack Labs Sheet1 CSV
// projection into provider-neutral, inert inventory candidates.
package labsinventory

import "time"

const (
	Format                = "labs-sheet1-csv"
	AdapterVersion        = "1.0.0"
	HeaderContractVersion = "1.0.0"
	MaxInputBytes         = 4 << 20
	MaxCSVRecords         = 4097
	MaxFieldBytes         = 1024
)

var headerV1 = [...]string{
	"lifecycle",
	"hardware_serial",
	"reported_hostname",
	"manufacturer",
	"model",
	"cpu_architecture",
	"cpu_model",
	"cpu_physical_cores",
	"cpu_logical_threads",
	"factory_ram_gb",
	"factory_ssd_gb",
	"factory_hdd_gb",
	"current_ram_gb",
	"current_ssd_gb",
	"current_hdd_gb",
}

// Config contains trusted source metadata supplied by the later composition
// layer. Neither value is inferred from a path or filesystem timestamp.
type Config struct {
	SourceRevision string
	CapturedAt     time.Time
}
