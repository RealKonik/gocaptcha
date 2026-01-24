package gocaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/RealKonik/gocaptcha/internal"
)

type AntiCaptcha struct {
	baseUrl string
	apiKey  string
}

func NewAntiCaptcha(apiKey string) *AntiCaptcha {
	return &AntiCaptcha{
		apiKey:  apiKey,
		baseUrl: "https://api.anti-captcha.com",
	}
}

func NewCapMonsterCloud(apiKey string) *AntiCaptcha {
	return &AntiCaptcha{
		apiKey:  apiKey,
		baseUrl: "https://api.capmonster.cloud",
	}
}

func NewCapSolver(apiKey string) *AntiCaptcha {
	return &AntiCaptcha{
		apiKey:  apiKey,
		baseUrl: "https://api.capsolver.com",
	}
}

// NewCustomAntiCaptcha can be used to change the baseUrl, some providers such as CapMonster, XEVil and CapSolver
// have the exact same API as AntiCaptcha, thus allowing you to use these providers with ease.
func NewCustomAntiCaptcha(baseUrl, apiKey string) *AntiCaptcha {
	return &AntiCaptcha{
		baseUrl: baseUrl,
		apiKey:  apiKey,
	}
}

func (a *AntiCaptcha) SolveImageCaptcha(
	ctx context.Context,
	settings *Settings,
	payload *ImageCaptchaPayload,
) (ICaptchaResponse, error) {
	task := map[string]any{
		"type": "ImageToTextTask",
		"body": payload.Base64String,
		"case": payload.CaseSensitive,
	}

	// Add module if specified (e.g., "queueit" for Queue-IT specialized recognition)
	if payload.Module != "" {
		task["module"] = payload.Module
	}

	// CapSolver returns ImageToTextTask results synchronously
	if a.baseUrl == "https://api.capsolver.com" {
		result, err := a.solveTaskSync(ctx, settings, task)
		if err != nil {
			return nil, err
		}
		result.reportBad = a.report("/reportIncorrectImageCaptcha", result.taskId, settings)
		return result, nil
	}

	result, err := a.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	result.reportBad = a.report("/reportIncorrectImageCaptcha", result.taskId, settings)
	return result, nil
}

func (a *AntiCaptcha) SolveRecaptchaV2(
	ctx context.Context,
	settings *Settings,
	payload *RecaptchaV2Payload,
) (ICaptchaResponse, error) {
	task := map[string]any{
		"type":        "NoCaptchaTaskProxyless",
		"websiteURL":  payload.EndpointUrl,
		"websiteKey":  payload.EndpointKey,
		"isInvisible": payload.IsInvisibleCaptcha}

	result, err := a.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	result.reportBad = a.report("/reportIncorrectRecaptcha", result.taskId, settings)
	result.reportGood = a.report("/reportCorrectRecaptcha", result.taskId, settings)
	return result, nil
}

func (a *AntiCaptcha) SolveRecaptchaV3Proxyless(
	ctx context.Context,
	settings *Settings,
	payload *RecaptchaV3Payload,
) (ICaptchaResponse, error) {
	var captchaType string
	if payload.IsEnterprise {
		switch a.baseUrl {
		case "https://api.capmonster.cloud":
			return nil, fmt.Errorf("CapMonsterdoes not support ReCaptchaV3 Enterprise tasks")
		case "https://api.capsolver.com":
			captchaType = "ReCaptchaV3EnterpriseTaskProxyLess"
		case "https://api.anti-captcha.com":
			captchaType = "RecaptchaV3TaskProxyless"
		}
	} else {
		captchaType = "RecaptchaV3TaskProxyless"
	}
	fmt.Println(captchaType)
	task := map[string]any{
		"type":         captchaType,
		"websiteURL":   payload.EndpointUrl,
		"websiteKey":   payload.EndpointKey,
		"minScore":     payload.MinScore,
		"pageAction":   payload.Action,
		"isEnterprise": payload.IsEnterprise,
	}

	result, err := a.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	result.reportBad = a.report("/reportIncorrectRecaptcha", result.taskId, settings)
	result.reportGood = a.report("/reportCorrectRecaptcha", result.taskId, settings)
	return result, nil
}

func (a *AntiCaptcha) SolveRecaptchaV3Proxy(
	ctx context.Context,
	settings *Settings,
	payload *RecaptchaV3Payload,
) (ICaptchaResponse, error) {
	if payload.Proxy == "" {
		return nil, errors.New("proxy is required for SolveRecaptchaV3Proxy")
	}
	var captchaType string
	if payload.IsEnterprise {
		switch a.baseUrl {
		case "https://api.capmonster.cloud":
			return nil, fmt.Errorf("CapMonsterdoes not support ReCaptchaV3 Enterprise tasks")
		case "https://api.capsolver.com":
			captchaType = "ReCaptchaV3EnterpriseTask"
		case "https://api.anti-captcha.com":
			return nil, fmt.Errorf("Anti-Captcha does not support ReCaptchaV3 Enterprise tasks with proxy")
		}
	} else {
		captchaType = "RecaptchaV3Task"
	}
	task := map[string]any{
		"type":         captchaType,
		"websiteURL":   payload.EndpointUrl,
		"websiteKey":   payload.EndpointKey,
		"minScore":     payload.MinScore,
		"proxy":        payload.Proxy,
		"pageAction":   payload.Action,
		"isEnterprise": payload.IsEnterprise,
	}

	result, err := a.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	result.reportBad = a.report("/reportIncorrectRecaptcha", result.taskId, settings)
	result.reportGood = a.report("/reportCorrectRecaptcha", result.taskId, settings)
	return result, nil
}

func (a *AntiCaptcha) SolveHCaptcha(
	ctx context.Context,
	settings *Settings,
	payload *HCaptchaPayload,
) (ICaptchaResponse, error) {
	task := map[string]any{
		"type":       "HCaptchaTaskProxyless",
		"websiteURL": payload.EndpointUrl,
		"websiteKey": payload.EndpointKey,
	}

	result, err := a.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (a *AntiCaptcha) SolveTurnstile(
	ctx context.Context,
	settings *Settings,
	payload *TurnstilePayload,
) (ICaptchaResponse, error) {
	var captchaType string
	switch a.baseUrl {
	case "https://api.capsolver.com":
		captchaType = "AntiTurnstileTaskProxyLess"
	case "https://api.capmonster.cloud":
		captchaType = "TurnstileTask"
	case "https://api.anti-captcha.com":
		captchaType = "TurnstileTaskProxyless"
	}
	task := map[string]any{
		"type":       captchaType,
		"websiteURL": payload.EndpointUrl,
		"websiteKey": payload.EndpointKey,
	}

	result, err := a.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (a *AntiCaptcha) SolveWaf(
	ctx context.Context,
	settings *Settings,
	payload *WafPayload,
) (ICaptchaResponse, error) {

	task := map[string]any{
		"type":       "AntiAwsWafTaskProxyLess",
		"websiteURL": payload.EndpointUrl,
	}

	result, err := a.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// solveTaskSync handles CapSolver's synchronous response for ImageToTextTask
// CapSolver returns the solution directly in createTask response instead of requiring polling
func (a *AntiCaptcha) solveTaskSync(
	ctx context.Context,
	settings *Settings,
	task map[string]any,
) (*CaptchaResponse, error) {
	type syncResponse struct {
		ErrorID          int    `json:"errorId"`
		ErrorDescription string `json:"errorDescription"`
		TaskID           string `json:"taskId"`
		Status           string `json:"status"`
		Solution         struct {
			Text string `json:"text"`
		} `json:"solution"`
	}

	jsonValue, err := json.Marshal(map[string]any{"clientKey": a.apiKey, "task": task})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseUrl+"/createTask", bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")

	resp, err := settings.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result syncResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	if result.ErrorID != 0 {
		return nil, errors.New(result.ErrorDescription)
	}

	// CapSolver returns solution directly for ImageToTextTask
	if result.Status == "ready" && result.Solution.Text != "" {
		return &CaptchaResponse{solution: result.Solution.Text, taskId: result.TaskID}, nil
	}

	// Fallback to polling if taskId returned but no immediate solution
	if result.TaskID != "" {
		return a.pollTask(ctx, settings, result.TaskID)
	}

	return nil, errors.New("no solution returned")
}

// pollTask polls for task result (used as fallback for sync tasks)
func (a *AntiCaptcha) pollTask(
	ctx context.Context,
	settings *Settings,
	taskId string,
) (*CaptchaResponse, error) {
	if err := internal.SleepWithContext(ctx, settings.initialWaitTime); err != nil {
		return nil, err
	}

	for i := 0; i < settings.maxRetries; i++ {
		answer, err := a.getTaskResult(ctx, settings, taskId)
		if err != nil {
			return nil, err
		}

		if answer != "" {
			return &CaptchaResponse{solution: answer, taskId: taskId}, nil
		}

		if err := internal.SleepWithContext(ctx, settings.pollInterval); err != nil {
			return nil, err
		}
	}

	return nil, errors.New("max tries exceeded")
}

func (a *AntiCaptcha) solveTask(
	ctx context.Context,
	settings *Settings,
	task map[string]any,
) (*CaptchaResponse, error) {
	taskId, err := a.createTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	if err := internal.SleepWithContext(ctx, settings.initialWaitTime); err != nil {
		return nil, err
	}

	for i := 0; i < settings.maxRetries; i++ {
		answer, err := a.getTaskResult(ctx, settings, taskId)
		if err != nil {
			return nil, err
		}

		if answer != "" {
			return &CaptchaResponse{solution: answer, taskId: taskId}, nil
		}

		if err := internal.SleepWithContext(ctx, settings.pollInterval); err != nil {
			return nil, err
		}
	}

	return nil, errors.New("max tries exceeded")
}

func (a *AntiCaptcha) createTask(
	ctx context.Context,
	settings *Settings,
	task map[string]any,
) (string, error) {
	type antiCaptchaCreateResponse struct {
		ErrorID          int    `json:"errorId"`
		ErrorDescription string `json:"errorDescription"`
		TaskID           any    `json:"taskId"`
	}

	jsonValue, err := json.Marshal(map[string]any{"clientKey": a.apiKey, "task": task})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.baseUrl+"/createTask",
		bytes.NewBuffer(jsonValue),
	)
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")

	resp, err := settings.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var responseAsJSON antiCaptchaCreateResponse
	if err := json.Unmarshal(respBody, &responseAsJSON); err != nil {
		return "", err
	}

	if responseAsJSON.ErrorID != 0 {
		return "", errors.New(responseAsJSON.ErrorDescription)
	}
	switch responseAsJSON.TaskID.(type) {
	case string:
		// taskId is a string with CapSolver
		return responseAsJSON.TaskID.(string), nil
	case float64:
		// taskId is a float64 with AntiCaptcha
		return strconv.FormatFloat(responseAsJSON.TaskID.(float64), 'f', 0, 64), nil
	}

	// if you encounter this error with a custom provider, please open an issue
	return "", errors.New("unexpected taskId type, expecting string or float64")
}

func (a *AntiCaptcha) getTaskResult(
	ctx context.Context,
	settings *Settings,
	taskId string,
) (string, error) {
	type antiCapSolution struct {
		RecaptchaResponse string `json:"gRecaptchaResponse"`
		Text              string `json:"text"`
		Token             string `json:"token"`
		Cookie            string `json:"cookie"`
	}

	type resultResponse struct {
		Status           string          `json:"status"`
		ErrorID          int             `json:"errorId"`
		ErrorDescription string          `json:"errorDescription"`
		Solution         antiCapSolution `json:"solution"`
	}

	resultData := map[string]string{"clientKey": a.apiKey, "taskId": taskId}
	jsonValue, err := json.Marshal(resultData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.baseUrl+"/getTaskResult",
		bytes.NewBuffer(jsonValue),
	)
	if err != nil {
		return "", err
	}

	resp, err := settings.client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var respJson resultResponse
	if err := json.Unmarshal(respBody, &respJson); err != nil {
		return "", err
	}

	if respJson.ErrorID != 0 {
		return "", errors.New(respJson.ErrorDescription)
	}

	if respJson.Status != "ready" {
		return "", nil
	}

	if respJson.Solution.Text != "" {
		return respJson.Solution.Text, nil
	}

	if respJson.Solution.Token != "" {
		return respJson.Solution.Token, nil
	}
	if respJson.Solution.RecaptchaResponse != "" {
		return respJson.Solution.RecaptchaResponse, nil
	}
	if respJson.Solution.Cookie != "" {
		return respJson.Solution.Cookie, nil
	}

	return "", nil
}

func (a *AntiCaptcha) report(
	path, taskId string,
	settings *Settings,
) func(ctx context.Context) error {
	type response struct {
		ErrorID          int64  `json:"errorId"`
		ErrorCode        string `json:"errorCode"`
		ErrorDescription string `json:"errorDescription"`
	}

	return func(ctx context.Context) error {
		payload := map[string]string{
			"clientKey": a.apiKey,
			"taskId":    taskId,
		}
		rawPayload, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			a.baseUrl+path,
			bytes.NewBuffer(rawPayload),
		)
		if err != nil {
			return err
		}

		resp, err := settings.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var respJson response
		if err := json.Unmarshal(respBody, &respJson); err != nil {
			return err
		}

		if respJson.ErrorID != 0 {
			return fmt.Errorf("%v: %v", respJson.ErrorCode, respJson.ErrorDescription)
		}

		return nil
	}
}

var _ IProvider = (*AntiCaptcha)(nil)
