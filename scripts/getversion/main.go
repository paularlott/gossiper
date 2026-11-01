// Command getversion prints the version of gossiper, for the release tasks.
package main

import (
	"fmt"

	"github.com/paularlott/gossiper/build"
)

func main() {
	fmt.Println(build.Version)
}
