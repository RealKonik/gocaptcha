package gocaptcha

import (
	"context"
	"testing"
)

func TestNewCaptchaSolver(t *testing.T) {
	ctx := context.Background()

	cs := NewCaptchaSolver(NewCustomAntiCaptcha("https://api.capmonster.cloud", "key"))

	resp, err := cs.SolveRecaptchaV2(ctx, &RecaptchaV2Payload{
		EndpointUrl: "https://www.google.com/recaptcha/api2/demo",
		EndpointKey: "6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-",
	})
	if err != nil {
		t.Error(err)
	}

	t.Log(resp.Solution()) // gets the answer or recaptcha token etc
}

func TestNewCaptchaSolverTurnstile(t *testing.T) {
	ctx := context.Background()

	cs := NewCaptchaSolver(NewCustomAntiCaptcha("https://api.capmonster.cloud", "d230c188d73d35a2f3c353202c6b67f9"))

	resp, err := cs.SolveTurnstile(ctx, &TurnstilePayload{
		EndpointUrl: "https://zachbryanpresale.com",
		EndpointKey: "0x4AAAAAABkpv4xb6MdfcZRJ",
	})
	if err != nil {
		t.Error(err)
	}

	t.Log(resp.Solution()) // gets the answer or recaptcha token etc
}
