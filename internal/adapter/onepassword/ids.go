package onepassword

import (
	"regexp"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// IDs are adapter-private immutable locators, never platform-core fields.
type IDs struct{ VaultID, ItemID, FieldID string }

var exactID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)

func ParseIDs(vaultID, itemID, fieldID string) (IDs, error) {
	for _, id := range []string{vaultID, itemID, fieldID} {
		if !exactID.MatchString(id) {
			return IDs{}, failure.New(generated.ErrorCodeInputInvalid, "onepassword-id", false)
		}
	}
	return IDs{VaultID: vaultID, ItemID: itemID, FieldID: fieldID}, nil
}

func (ids IDs) URI() string { return "op://" + ids.VaultID + "/" + ids.ItemID + "/" + ids.FieldID }
