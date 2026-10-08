// Command journal-migrate converts an offline plaintext deployment journal to
// a new encrypted file. Stop the controller before migrating its journal.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
)

const usage = `Usage: journal-migrate -from SOURCE -to DESTINATION

Stop the controller before migration. SOURCE must be a plaintext deployment
journal. DESTINATION must be a distinct file that does not already exist.
The source remains unchanged; configure the controller to use the destination.

Required environment: APP_ENCRYPTION_KEY (base64-encoded 32-byte key).
Optional environment: APP_ENCRYPTION_KEY_ID (default: primary).
`

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("journal-migrate", flag.ContinueOnError)
	// Parse errors can reflect arbitrary argument values. Report a fixed error
	// instead, so a misplaced credential never appears in command diagnostics.
	flags.SetOutput(io.Discard)
	from := flags.String("from", "", "source plaintext journal")
	to := flags.String("to", "", "new encrypted journal")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		fmt.Fprintln(stderr, "invalid migration arguments; use -help for usage")
		return 2
	}
	if strings.TrimSpace(*from) == "" || strings.TrimSpace(*to) == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "-from and -to are required; positional arguments are not accepted")
		return 2
	}
	key, err := secrets.ParseKey(getenv("APP_ENCRYPTION_KEY"))
	if err != nil {
		fmt.Fprintln(stderr, "APP_ENCRYPTION_KEY must be a base64-encoded 32-byte encryption key")
		return 1
	}
	keyID := strings.TrimSpace(getenv("APP_ENCRYPTION_KEY_ID"))
	if keyID == "" {
		keyID = "primary"
	}
	vault, err := secrets.New(keyID, key)
	clear(key)
	if err != nil {
		fmt.Fprintln(stderr, "application encryption configuration is invalid")
		return 1
	}
	if err := deployment.MigratePlainFileJournal(*from, *to, vault); err != nil {
		fmt.Fprintln(stderr, "journal migration failed; verify the plaintext source and a distinct, absent destination")
		return 1
	}
	fmt.Fprintln(stdout, "Journal migration completed. The source remains unchanged.")
	return 0
}
