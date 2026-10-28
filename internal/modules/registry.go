package modules

import (
	"jenderalscan/internal/engine"
	"jenderalscan/internal/storage"
)

// RegisterAll registers all 10 PRD scanner modules into the provided Engine.
func RegisterAll(eng *engine.Engine, store *storage.Store) *CVEModule {
	cveMod := NewCVEModule(store)
	eng.RegisterModule(NewHeadersModule())
	eng.RegisterModule(NewTLSModule())
	eng.RegisterModule(NewCookiesModule())
	eng.RegisterModule(NewPathsModule())
	eng.RegisterModule(NewFingerprintModule())
	eng.RegisterModule(cveMod)
	eng.RegisterModule(NewCORSModule())
	eng.RegisterModule(NewDisclosureModule())
	eng.RegisterModule(NewDNSModule())
	eng.RegisterModule(NewPortsModule())
	return cveMod
}
