// Command backup-restore installs a validated Server Panel FPPB1 backup.
// Stop the Server Panel first and provide FRP_BACKUP_PASSWORD out of band.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ricardo/frp-panel-platform/server/internal/backup"
)

func main() {
	input := flag.String("input", "", "path to an FPPB1 backup")
	target := flag.String("target", "", "target SQLite database path")
	dataDir := flag.String("data-dir", "", "server data directory for restoring encrypted keys and certificate metadata")
	flag.Parse()
	if *input == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "usage: backup-restore -input backup.fppb -target server.db")
		os.Exit(2)
	}
	password := os.Getenv("FRP_BACKUP_PASSWORD")
	if password == "" {
		fmt.Fprintln(os.Stderr, "FRP_BACKUP_PASSWORD is required and must be supplied out of band")
		os.Exit(2)
	}
	previous, err := restore(*input, password, *target, *dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "restore failed: %v\n", err)
		os.Exit(1)
	}
	if previous == "" {
		fmt.Println("restore completed; no previous database existed")
		return
	}
	fmt.Printf("restore completed; previous database preserved at %s\n", previous)
}

func restore(input, password, target, dataDir string) (string, error) {
	if input == "" || target == "" {
		return "", fmt.Errorf("input and target are required")
	}
	if password == "" {
		return "", fmt.Errorf("FRP_BACKUP_PASSWORD is required")
	}
	return backup.RestoreWithOptions(input, password, target, backup.Options{DataDir: dataDir})
}
