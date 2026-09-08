package store

func (store *Store) migrationSafeMode(reason string) {
	store.enterSafeMode(reason)
	store.health.RecoveryPending = true
}
