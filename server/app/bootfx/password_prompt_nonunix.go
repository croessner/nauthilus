//go:build !unix

package bootfx

import "fmt"

func readPasswordPrompt(_ string) ([]byte, error) {
	return nil, fmt.Errorf("password prompt is only supported on unix terminals")
}
