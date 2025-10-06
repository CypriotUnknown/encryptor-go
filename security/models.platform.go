package security

import "fmt"

type Platform string

const (
	errorPlatform   Platform = ""
	PlatformBrowser Platform = "browser"
	PlatformApp     Platform = "app"
)

var platforms map[string]Platform = map[string]Platform{
	string(PlatformBrowser): PlatformBrowser,
	string(PlatformApp):     PlatformApp,
}

func ExtractPlatformFromString(s string) (Platform, error) {
	if platform, exists := platforms[s]; exists {
		return platform, nil
	}

	return errorPlatform, fmt.Errorf("platform does not exist")
}
