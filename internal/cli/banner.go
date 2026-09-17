package cli

// Version is the current cnpgen version.
const Version = "0.1.4"

const banner = `
  _________  ____  ____  ___  ____
 / ___/ __ \/ __ \/ __ ` + "`" + `/ _ \/ __ \
/ /__/ / / / /_/ / /_/ /  __/ / / /
\___/_/ /_/ .___/\__, /\___/_/ /_/
         /_/    /____/

   Cilium Network Policy Generator
         by kwistof - v` + Version + `

It never blocks anything on its own: policies deploy in safe mode.

`
