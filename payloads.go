package gocaptcha

type RecaptchaV2Payload struct {
	// EndpointUrl is the endpoint that has Recaptcha Protection
	EndpointUrl string

	// EndpointKey is the Recaptcha Key
	// Can be found on the Endpoint URL page
	EndpointKey string

	// IsInvisibleCaptcha Enable if endpoint has invisible Recaptcha V2
	IsInvisibleCaptcha bool
}

type RecaptchaV3Payload struct {
	// EndpointUrl is the endpoint that has Recaptcha Protection
	EndpointUrl string

	// EndpointKey is the Recaptcha Key
	// Can be found on the Endpoint URL page
	EndpointKey string

	// Action is the action name of the recaptcha, you can find it in source code of site
	Action string

	// IsEnterprise should be set if V3 Enterprise is used
	IsEnterprise bool

	// MinScore defaults to 0.3, accepted values are 0.3, 0.6, 0.9
	MinScore float32

	// Used for proxy captcha tasks (Needed)
	Proxy string
}

type TurnstilePayload struct {
	// EndpointUrl is the endpoint that has turnstile Protection
	EndpointUrl string

	// EndpointKey is the cf Key
	EndpointKey string
}

type WafPayload struct {
	// EndpointUrl is the endpoint that has waf Protection
	EndpointUrl string
}

type ImageCaptchaPayload struct {
	// Base64String is the base64 representation of the image
	Base64String string

	// CaseSensitive should be set to true if captcha is case-sensitive
	CaseSensitive bool

	// InstructionsForSolver should be set if the human solver needs additional information
	// about how to solve the captcha
	InstructionsForSolver string
}

type HCaptchaPayload struct {
	// EndpointUrl is the endpoint that has Recaptcha Protection
	EndpointUrl string

	// EndpointKey is the HCaptcha Key
	// Can be found on the Endpoint URL page
	EndpointKey string
}

type AntiCloudflarePayload struct {
	// WebsiteURL is the URL of the page protected by Cloudflare
	WebsiteURL string

	// Proxy is required for AntiCloudflare tasks (format: http://user:pass@ip:port)
	Proxy string
}
