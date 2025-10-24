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

	cs := NewCaptchaSolver(NewCustomAntiCaptcha("https://api.anti-captcha.com", "6a0ec931a8e86b6a8bf5ac22c785f938"))

	resp, err := cs.SolveTurnstile(ctx, &TurnstilePayload{
		EndpointUrl: "https://www.popmart.com/au/store-apppointment-event/your-reservationInfo",
		EndpointKey: "0x4AAAAAABjS33Y7wk11lsWy",
	})
	if err != nil {
		t.Error(err)
	}

	t.Log(resp.Solution()) // gets the answer or recaptcha token etc
}
