package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	webMode := flag.Bool("web", false, "Run JenderalScan UI on a local HTTP server instead of native desktop window")
	webAddr := flag.String("addr", "127.0.0.1:8787", "Local address for --web mode")
	dbPath := flag.String("db", "", "Custom SQLite database file path")
	flag.Parse()

	app, err := NewApp(*dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize JenderalScan: %v", err)
	}

	if *webMode {
		mux := http.NewServeMux()
		app.registerAPIRoutes(mux)

		distFS, err := fs.Sub(assets, "frontend/dist")
		if err != nil {
			log.Fatalf("Failed to load embedded frontend assets: %v", err)
		}
		mux.Handle("/", http.FileServer(http.FS(distFS)))

		fmt.Printf("JenderalScan Web GUI running at http://%s\n", *webAddr)
		log.Fatal(http.ListenAndServe(*webAddr, mux))
		return
	}

	err = wails.Run(&options.App{
		Title:     "JenderalScan — Non-Intrusive Web Security Scanner",
		Width:     1280,
		Height:    840,
		MinWidth:  1024,
		MinHeight: 680,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 15, G: 23, B: 42, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind: []interface{}{
			app,
		},
		Mac: &mac.Options{
			TitleBar:             mac.TitleBarDefault(),
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			About: &mac.AboutInfo{
				Title:   "JenderalScan",
				Message: "Desktop Web Vulnerability Surface Scanner (Non-Intrusive)\n© 2026 Mohammad Irham Akbar",
			},
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
	})
	if err != nil {
		log.Fatalf("Error running Wails desktop application: %v", err)
	}
}
