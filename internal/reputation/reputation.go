package reputation

import "strings"

// TrustedScopes maps organization scopes to their known affiliations.
// Packages under these scopes receive reduced risk scores due to established trust.
var TrustedScopes = map[string]string{
	"@angular":      "Google Angular Team",
	"@ngrx":         "NgRx Team",
	"@babel":        "Babel Core Team",
	"@types":        "DefinitelyTyped",
	"@typescript":   "Microsoft TypeScript Team",
	"@microsoft":    "Microsoft",
	"@azure":        "Microsoft Azure",
	"@google-cloud": "Google Cloud",
	"@aws-sdk":      "Amazon Web Services",
	"@firebase":     "Google Firebase",
	"@nestjs":       "NestJS Team",
	"@vue":          "Vue.js Team",
	"@nuxt":         "Nuxt Team",
	"@svelte":       "Svelte Team",
	"@prisma":       "Prisma Team",
	"@graphql":      "GraphQL Foundation",
	"@apollo":       "Apollo GraphQL",
	"@emotion":      "Emotion CSS Team",
	"@mui":          "Material-UI Team",
	"@chakra-ui":    "Chakra UI Team",
	"@radix-ui":     "Radix UI Team",
	"@testing":      "Testing Library Team",
	"@storybook":    "Storybook Team",
	"@eslint":       "ESLint Team",
	"@tailwindcss":  "Tailwind Labs",
	"@vercel":       "Vercel",
	"@remix-run":    "Remix Team",
	"@next":         "Vercel Next.js",
	"@reduxjs":      "Redux Team",
	"@tanstack":     "TanStack",
	"@trpc":         "tRPC Team",
	"@playwright":   "Microsoft Playwright",
	"@vitest":       "Vitest Team",
}

// DownloadTier represents the popularity tier of a package based on weekly downloads.
type DownloadTier string

const (
	TierMassive  DownloadTier = "massive"  // 10M+ weekly downloads
	TierPopular  DownloadTier = "popular"  // 1M+ weekly downloads
	TierModerate DownloadTier = "moderate" // 100K+ weekly downloads
	TierLow      DownloadTier = "low"      // 10K+ weekly downloads
	TierMinimal  DownloadTier = "minimal"  // <10K weekly downloads
)

// GetDownloadTier returns the popularity tier based on weekly download count.
func GetDownloadTier(downloads int) DownloadTier {
	switch {
	case downloads >= 10_000_000:
		return TierMassive
	case downloads >= 1_000_000:
		return TierPopular
	case downloads >= 100_000:
		return TierModerate
	case downloads >= 10_000:
		return TierLow
	default:
		return TierMinimal
	}
}

// IsTrustedScope checks if a package name belongs to a trusted scope.
// Returns whether it's trusted and the organization name if so.
func IsTrustedScope(name string) (bool, string) {
	if !strings.HasPrefix(name, "@") {
		return false, ""
	}

	// Extract the scope (e.g., "@angular" from "@angular/core")
	parts := strings.SplitN(name, "/", 2)
	if len(parts) < 1 {
		return false, ""
	}

	scope := parts[0]
	if org, ok := TrustedScopes[scope]; ok {
		return true, org
	}

	return false, ""
}

// Info holds reputation information for a package, including its popularity and trust signals.
type Info struct {
	// WeeklyDownloads is the number of downloads in the last 7 days.
	WeeklyDownloads int `json:"weekly_downloads"`
	// DownloadTier is a classification of the package's popularity (e.g., massive, popular).
	DownloadTier DownloadTier `json:"download_tier"`
	// IsTrustedScope indicates if the package name starts with a well-known, trusted scope.
	IsTrustedScope bool `json:"is_trusted_scope"`
	// TrustedScopeOrg is the name of the organization associated with the trusted scope.
	TrustedScopeOrg string `json:"trusted_scope_org,omitempty"`
	// ReputationScore is a calculated value (0-100) representing the overall trust in the package.
	ReputationScore int `json:"reputation_score"`
}

// Build constructs reputation information for a package.
func Build(name string, downloads int) Info {
	isTrusted, org := IsTrustedScope(name)
	tier := GetDownloadTier(downloads)

	return Info{
		WeeklyDownloads: downloads,
		DownloadTier:    tier,
		IsTrustedScope:  isTrusted,
		TrustedScopeOrg: org,
		ReputationScore: CalculateReputationScore(name, downloads),
	}
}

// CalculateReputationScore computes a 0-100 score based on trust signals.
// Higher score = better reputation = lower risk adjustment.
func CalculateReputationScore(name string, downloads int) int {
	score := 50 // Start at neutral

	// Trust signals increase score
	if isTrusted, _ := IsTrustedScope(name); isTrusted {
		score += 30
	}

	// Download tier affects score
	switch GetDownloadTier(downloads) {
	case TierMassive:
		score += 20
	case TierPopular:
		score += 15
	case TierModerate:
		score += 10
	case TierLow:
		score += 5
	case TierMinimal:
		// No bonus for minimal downloads
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// GetRiskAdjustment returns the risk score adjustment based on reputation.
// Returns a negative number (risk reduction) for well-reputed packages.
func GetRiskAdjustment(info Info) int {
	adjustment := 0

	// Trusted scope: significant reduction
	if info.IsTrustedScope {
		adjustment -= 15
	}

	// Download tier adjustments
	switch info.DownloadTier {
	case TierMassive:
		adjustment -= 10
	case TierPopular:
		adjustment -= 5
	case TierMinimal:
		// Minimal downloads with many findings could be suspicious
		// but we don't add penalty here - that's handled by findings
	}

	return adjustment
}

// FormatDownloads returns a human-readable download count.
func FormatDownloads(downloads int) string {
	switch {
	case downloads >= 1_000_000_000:
		return formatWithUnit(downloads, 1_000_000_000, "B")
	case downloads >= 1_000_000:
		return formatWithUnit(downloads, 1_000_000, "M")
	case downloads >= 1_000:
		return formatWithUnit(downloads, 1_000, "K")
	default:
		return formatInt(downloads)
	}
}

func formatWithUnit(n, unit int, suffix string) string {
	value := float64(n) / float64(unit)
	if value >= 10 {
		return formatInt(int(value)) + suffix
	}
	// Show one decimal for values < 10
	return strings.TrimRight(strings.TrimRight(
		formatFloat(value, 1), "0"), ".") + suffix
}

func formatInt(n int) string {
	if n < 1000 {
		return intToString(n)
	}

	// Add commas for thousands
	str := intToString(n)
	result := make([]byte, 0, len(str)+(len(str)-1)/3)

	for i, c := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}

	return string(result)
}

func formatFloat(f float64, decimals int) string {
	// Simple float formatting without importing strconv
	intPart := int(f)
	decPart := int((f - float64(intPart)) * 10)
	if decPart < 0 {
		decPart = -decPart
	}
	return intToString(intPart) + "." + intToString(decPart)
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}

	negative := n < 0
	if negative {
		n = -n
	}

	digits := make([]byte, 0, 20)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}

	// Reverse
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}

	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}
