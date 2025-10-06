package security

type Platform string

const (
	PlatformBrowser Platform = "browser"
	PlatformApp     Platform = "app"
)

var platforms map[string]Platform = map[string]Platform{
	string(PlatformBrowser): PlatformBrowser,
	string(PlatformApp):     PlatformApp,
}

func ExtractPlatformFromString(s string) *Platform {
	if platform, exists := platforms[s]; exists {
		return &platform
	}

	return nil
}
