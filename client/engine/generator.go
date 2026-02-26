package engine

import (
	"encoding/csv"
	"fmt"
	"math/rand/v2"
	"os"
)

func GenerateCSV(path string, total int, cidrProb float64, cidrPrefix int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	_ = w.Write([]string{"username", "password", "ip", "expected_ok"})

	var (
		baseNet uint32
		mask    uint32
		hasCIDR bool
	)

	if cidrProb > 0 {
		baseNet, mask, hasCIDR = pickRoutableCIDR(cidrPrefix)
	}

	for i := range total {
		username := fmt.Sprintf("user%d", i)
		password := "password"
		ip := ""

		if hasCIDR && rand.Float64() < cidrProb {
			ip = uint32ToIP(randomHostInCIDR(baseNet, mask))
		} else {
			ip = uint32ToIP(randomRoutableIPv4())
		}

		expected := "true"
		if rand.Float64() < 0.1 {
			expected = "false"
		}

		_ = w.Write([]string{username, password, ip, expected})
	}

	return nil
}

func uint32ToIP(u uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

func randomRoutableIPv4() uint32 {
	for {
		u := rand.Uint32()
		if isRoutableIPv4(u) {
			return u
		}
	}
}

func isRoutableIPv4(u uint32) bool {
	// Simplified check: avoid 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4
	first := byte(u >> 24)
	if first == 0 || first == 127 || first >= 224 {
		return false
	}
	if first == 169 && byte(u>>16) == 254 {
		return false
	}
	return true
}

func pickRoutableCIDR(prefix int) (uint32, uint32, bool) {
	mask := maskFromPrefix(prefix)
	for range 1000 {
		base := rand.Uint32() & mask
		if isRoutableIPv4(base) && isRoutableIPv4(base|(^mask)) {
			return base, mask, true
		}
	}
	return 0, 0, false
}

func maskFromPrefix(prefix int) uint32 {
	if prefix <= 0 {
		return 0
	}
	if prefix >= 32 {
		return 0xFFFFFFFF
	}
	return 0xFFFFFFFF << (32 - prefix)
}

func randomHostInCIDR(baseNet uint32, mask uint32) uint32 {
	hostPart := rand.Uint32() & (^mask)
	return baseNet | hostPart
}
