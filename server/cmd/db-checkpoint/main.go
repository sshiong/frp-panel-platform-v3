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
	if *databasePath == "" {
		fmt.Fprintln(os.Stderr, "-db or FRP_SERVER_DB is required")
		os.Exit(2)
	}
	database, err := db.Open(*databasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()
	if err := database.Checkpoint(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "checkpoint failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("SQLite WAL checkpoint completed")
}
