// Command cnpgen watches what your pods actually talk to and writes a Cilium
// network policy for them. It never blocks anything on its own: every policy
// it writes is deployed in a safe, non-enforcing mode.
package main

import (
	"os"

	"github.com/kwistof/cnpgen/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
