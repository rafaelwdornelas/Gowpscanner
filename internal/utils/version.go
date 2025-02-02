// internal\utils\version.go
package utils

import (
	"regexp"
	"strconv"
	"strings"
)

// CompararVersao verifica se currentVersion atende o comparator em relação a requiredVersion
func CompararVersao(currentVersion, requiredVersion, comparator string) bool {
	cMaj, cMin, cPatch := parseSemVer(currentVersion)
	rMaj, rMin, rPatch := parseSemVer(requiredVersion)

	switch comparator {
	case "<":
		return compareSemVer(cMaj, cMin, cPatch, rMaj, rMin, rPatch) < 0
	case "<=":
		return compareSemVer(cMaj, cMin, cPatch, rMaj, rMin, rPatch) <= 0
	case ">":
		return compareSemVer(cMaj, cMin, cPatch, rMaj, rMin, rPatch) > 0
	case ">=":
		return compareSemVer(cMaj, cMin, cPatch, rMaj, rMin, rPatch) >= 0
	case "=":
		return compareSemVer(cMaj, cMin, cPatch, rMaj, rMin, rPatch) == 0
	case "all":
		return true
	}
	return false
}

// parseSemVer converte "1.8.5-beta" em três números inteiros.
func parseSemVer(version string) (int, int, int) {
	version = strings.TrimSpace(version)
	version = strings.ReplaceAll(version, "-", ".")
	version = strings.ReplaceAll(version, "_", ".")

	parts := strings.Split(version, ".")
	nums := [3]int{}

	for i := 0; i < 3 && i < len(parts); i++ {
		p := trimNonNumericSuffix(parts[i])
		val, err := strconv.Atoi(p)
		if err != nil {
			val = 0
		}
		nums[i] = val
	}
	return nums[0], nums[1], nums[2]
}

// trimNonNumericSuffix remove sufixos não numéricos (ex: "5-beta" -> "5")
func trimNonNumericSuffix(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// compareSemVer retorna <0 se v1 < v2, 0 se ==, >0 se v1 > v2
func compareSemVer(ma1, mi1, pa1, ma2, mi2, pa2 int) int {
	if ma1 != ma2 {
		return ma1 - ma2
	}
	if mi1 != mi2 {
		return mi1 - mi2
	}
	return pa1 - pa2
}

// FromStableTagOrVersion procura linhas do tipo "Version: X" ou "Stable tag: X"
func FromStableTagOrVersion(body string) string {
	re := regexp.MustCompile(`(?i)\b(?:stable tag|version):\s*([0-9a-zA-Z.\-_]+)`)
	match := re.FindStringSubmatch(body)
	if len(match) == 2 {
		ver := match[1]
		// ignora "trunk"
		if strings.EqualFold(ver, "trunk") {
			return ""
		}
		if strings.ContainsAny(ver, "0123456789") {
			return ver
		}
	}
	return ""
}

// FromChangelogSection tenta encontrar versões no estilo "= 1.2.3 =" etc.
func FromChangelogSection(body string) string {
	re := regexp.MustCompile(`(?m)^=+\s+(?:v(?:ersion)?\s*)?([0-9a-zA-Z.\-_]+)[^=]*=+\s*$`)
	matches := re.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return ""
	}

	var highestVersion string
	var highestVal float64

	for _, m := range matches {
		if len(m) == 2 {
			vStr := m[1]
			if !strings.ContainsAny(vStr, "0123456789") {
				continue
			}
			vf, err := versaoParaFloat(vStr)
			if err != nil {
				continue
			}
			if vf > highestVal {
				highestVal = vf
				highestVersion = vStr
			}
		}
	}
	return highestVersion
}

// versaoParaFloat converte "1.2.3" em algo como 1.23 (parcialmente confiável)
func versaoParaFloat(v string) (float64, error) {
	v = strings.TrimSpace(v)
	v = strings.ReplaceAll(v, "-", ".")
	v = strings.ReplaceAll(v, "_", ".")
	parts := strings.SplitN(v, ".", 3)
	join := strings.Join(parts, ".")
	return strconv.ParseFloat(join, 64)
}
