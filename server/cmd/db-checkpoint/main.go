package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/ricardo/frp-panel-platform/server/internal/db"
)

func main() {
	databasePath := flag.String("db", os.Getenv("FRP_SERVER_DB"), "SQLite database path")
	flag.Parse()
	if err := run(*databasePath); err != nil {
		if *databasePath == "" {
			fmt.Fprintln(os.Stderr, "-db or FRP_SERVER_DB is required")
		} else {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		os.Exit(1)
	}
	fmt.Println("SQLite WAL checkpoint completed")
}

func run(databasePath string) error {
	if databasePath == "" {
		return fmt.Errorf("-db or FRP_SERVER_DB is required")
	}
	database, err := db.Open(databasePath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()
	if err := database.Checkpoint(context.Background()); err != nil {
		return fmt.Errorf("checkpoint failed: %w", err)
	}
	return nil
}
