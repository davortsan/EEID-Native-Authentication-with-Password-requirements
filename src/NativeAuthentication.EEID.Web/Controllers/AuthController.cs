using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using NativeAuthentication.EEID.Web.Models.Auth;
using NativeAuthentication.EEID.Web.Options;
using NativeAuthentication.EEID.Web.Services;

namespace NativeAuthentication.EEID.Web.Controllers;

public sealed class AuthController : Controller
{
    private const string SignUpStateKey = "signup-state";
    private const string ResetPasswordStateKey = "reset-password-state";
    private const string MfaStateKey = "mfa-state";
    private const string TokensStateKey = "tokens-state";

    private readonly NativeAuthenticationClient _nativeAuthenticationClient;
    private readonly MicrosoftGraphUserLifecycleClient _microsoftGraphUserLifecycleClient;
    private readonly MicrosoftGraphUserLifecycleOptions _microsoftGraphUserLifecycleOptions;

    public AuthController(
        NativeAuthenticationClient nativeAuthenticationClient,
        MicrosoftGraphUserLifecycleClient microsoftGraphUserLifecycleClient,
        IOptions<MicrosoftGraphUserLifecycleOptions> microsoftGraphUserLifecycleOptions)
    {
        _nativeAuthenticationClient = nativeAuthenticationClient;
        _microsoftGraphUserLifecycleClient = microsoftGraphUserLifecycleClient;
        _microsoftGraphUserLifecycleOptions = microsoftGraphUserLifecycleOptions.Value;
    }

    [HttpGet]
    public IActionResult SignIn()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction(nameof(Profile));
        }

        return View(new SignInViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SignIn(SignInViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var lockoutState = await _microsoftGraphUserLifecycleClient.GetSignInLockoutStateAsync(model.Email, cancellationToken);
        if (lockoutState.IsLocked)
        {
            ModelState.AddModelError(string.Empty, BuildSignInLockoutMessage(lockoutState));
            return View(model);
        }

        var result = await _nativeAuthenticationClient.SignInAsync(model.Email, model.Password, cancellationToken);
        var mfaAction = await TryHandleMfaRequirementAsync(model.Email, result, cancellationToken);
        if (mfaAction is not null)
        {
            await _microsoftGraphUserLifecycleClient.TryResetFailedSignInStateAsync(model.Email, cancellationToken);
            return mfaAction;
        }

        if (!result.IsSuccess || result.Payload?.IdToken is null)
        {
            var failedAttemptState = await _microsoftGraphUserLifecycleClient.RegisterFailedSignInAttemptAsync(model.Email, cancellationToken);
            ModelState.AddModelError(
                string.Empty,
                failedAttemptState.IsLocked
                    ? BuildSignInLockoutMessage(failedAttemptState)
                    : result.Message ?? "No fue posible iniciar sesión.");
            return View(model);
        }

        await _microsoftGraphUserLifecycleClient.TryResetFailedSignInStateAsync(model.Email, cancellationToken);

        var signInPrincipal = _nativeAuthenticationClient.CreatePrincipal(result.Payload);
        var passwordPolicyResult = await _microsoftGraphUserLifecycleClient.CheckPasswordAgeAsync(signInPrincipal, model.Email, cancellationToken);
        if (!passwordPolicyResult.IsSuccess)
        {
            ModelState.AddModelError(string.Empty, passwordPolicyResult.FailureMessage ?? "No fue posible validar la antiguedad de la contraseña.");
            return View(model);
        }

        if (passwordPolicyResult.IsExpired)
        {
            TempData["StatusMessage"] = "Tu contraseña ha caducado. Debes restablecerla antes de iniciar sesión.";
            return RedirectToAction(nameof(ForgotPassword), new { email = model.Email });
        }

        await SignInAsync(result.Payload, passwordPolicyResult.ExpiresAtUtc ?? DateTimeOffset.UtcNow);
        TempData["StatusMessage"] = "Sesión iniciada correctamente.";
        return RedirectToAction(nameof(Profile));
    }

    [HttpGet]
    public IActionResult VerifyMfaOtp()
    {
        var state = HttpContext.Session.GetJson<MfaFlowState>(MfaStateKey);
        if (state is null)
        {
            return RedirectToAction(nameof(SignIn));
        }

        return View(new VerifyOtpViewModel
        {
            TargetLabel = state.TargetLabel,
            FlowDescription = state.Mode == MfaFlowMode.Registration
                ? "Tu tenant exige registrar un método MFA antes de completar el inicio de sesión."
                : "Completa el segundo factor MFA para terminar el inicio de sesión.",
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyMfaOtp(VerifyOtpViewModel model, CancellationToken cancellationToken)
    {
        var state = HttpContext.Session.GetJson<MfaFlowState>(MfaStateKey);
        if (state is null)
        {
            return RedirectToAction(nameof(SignIn));
        }

        model.TargetLabel = state.TargetLabel;
        model.FlowDescription = state.Mode == MfaFlowMode.Registration
            ? "Tu tenant exige registrar un método MFA antes de completar el inicio de sesión."
            : "Completa el segundo factor MFA para terminar el inicio de sesión.";

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        NativeAuthenticationResult result;
        if (state.Mode == MfaFlowMode.Registration)
        {
            var registrationResult = await _nativeAuthenticationClient.ContinueRegistrationWithOtpAsync(state.ContinuationToken, model.Code, cancellationToken);
            if (!registrationResult.IsSuccess || string.IsNullOrWhiteSpace(registrationResult.Payload?.ContinuationToken))
            {
                ModelState.AddModelError(string.Empty, registrationResult.Message ?? "No fue posible verificar el código MFA.");
                return View(model);
            }

            result = await _nativeAuthenticationClient.CompleteContinuationAsync(registrationResult.Payload.ContinuationToken, cancellationToken);
        }
        else
        {
            result = await _nativeAuthenticationClient.CompleteMfaAsync(state.ContinuationToken, model.Code, cancellationToken);
        }

        if (!result.IsSuccess || result.Payload?.IdToken is null)
        {
            ModelState.AddModelError(string.Empty, result.Message ?? "No fue posible completar MFA.");
            return View(model);
        }

        var signInPrincipal = _nativeAuthenticationClient.CreatePrincipal(result.Payload);
        var passwordPolicyResult = await _microsoftGraphUserLifecycleClient.CheckPasswordAgeAsync(signInPrincipal, state.Email, cancellationToken);
        if (!passwordPolicyResult.IsSuccess)
        {
            ModelState.AddModelError(string.Empty, passwordPolicyResult.FailureMessage ?? "No fue posible validar la antiguedad de la contraseña.");
            return View(model);
        }

        if (passwordPolicyResult.IsExpired)
        {
            TempData["StatusMessage"] = "Tu contraseña ha caducado. Debes restablecerla antes de iniciar sesión.";
            return RedirectToAction(nameof(ForgotPassword), new { email = state.Email });
        }

        await SignInAsync(result.Payload, passwordPolicyResult.ExpiresAtUtc ?? DateTimeOffset.UtcNow);
        HttpContext.Session.Remove(MfaStateKey);
        TempData["StatusMessage"] = "Inicio de sesión completado con MFA.";
        return RedirectToAction(nameof(Profile));
    }

    [HttpGet]
    public IActionResult SignUp()
    {
        return View(new SignUpViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SignUp(SignUpViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (!ValidatePasswordPolicy(model.Password, nameof(model.Password)))
        {
            return View(model);
        }

        var startResult = await _nativeAuthenticationClient.StartSignUpAsync(model.Email, model.Password, model.DisplayName, cancellationToken);
        if (!startResult.IsSuccess || startResult.Payload?.ContinuationToken is null)
        {
            ModelState.AddModelError(string.Empty, startResult.Message ?? "No fue posible iniciar el registro.");
            return View(model);
        }

        var challengeResult = await _nativeAuthenticationClient.ChallengeSignUpAsync(startResult.Payload.ContinuationToken, cancellationToken);
        if (!challengeResult.IsSuccess || challengeResult.Payload?.ContinuationToken is null)
        {
            ModelState.AddModelError(string.Empty, challengeResult.Message ?? "No fue posible enviar el código OTP.");
            return View(model);
        }

        HttpContext.Session.SetJson(SignUpStateKey, new SignUpFlowState
        {
            Email = model.Email,
            Password = model.Password,
            ContinuationToken = challengeResult.Payload.ContinuationToken,
            DisplayName = model.DisplayName,
        });

        TempData["StatusMessage"] = $"Se envió un código a {challengeResult.Payload.ChallengeTargetLabel ?? model.Email}.";
        return RedirectToAction(nameof(VerifySignUpOtp));
    }

    [HttpGet]
    public IActionResult VerifySignUpOtp()
    {
        if (HttpContext.Session.GetJson<SignUpFlowState>(SignUpStateKey) is null)
        {
            return RedirectToAction(nameof(SignUp));
        }

        return View(new VerifyOtpViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifySignUpOtp(VerifyOtpViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var state = HttpContext.Session.GetJson<SignUpFlowState>(SignUpStateKey);
        if (state is null)
        {
            return RedirectToAction(nameof(SignUp));
        }

        var otpResult = await _nativeAuthenticationClient.ContinueSignUpWithOtpAsync(state.ContinuationToken, model.Code, cancellationToken);
        if ((!otpResult.IsSuccess && !IsAttributesRequired(otpResult)) || otpResult.Payload is null)
        {
            ModelState.AddModelError(string.Empty, otpResult.Message ?? "El código OTP no es válido.");
            return View(model);
        }

        var completionResult = await CompleteSignUpFlowAsync(state, otpResult.Payload, cancellationToken);
        if (completionResult.NextAction == SignUpNextAction.RequiredAttributes)
        {
            return RedirectToAction(nameof(SignUpRequiredAttributes));
        }

        if (!completionResult.IsSuccess || completionResult.Payload?.IdToken is null)
        {
            ModelState.AddModelError(string.Empty, completionResult.Message ?? "No fue posible completar el registro.");
            return View(model);
        }

        var passwordSetAtUtc = DateTimeOffset.UtcNow;
        var signInPrincipal = _nativeAuthenticationClient.CreatePrincipal(completionResult.Payload);
        await _microsoftGraphUserLifecycleClient.TrySetLastPasswordSetAsync(signInPrincipal, state.Email, passwordSetAtUtc, cancellationToken);
        await SignInAsync(completionResult.Payload, _microsoftGraphUserLifecycleClient.CalculatePasswordExpiry(passwordSetAtUtc));
        HttpContext.Session.Remove(SignUpStateKey);
        TempData["StatusMessage"] = "Cuenta creada e inicio de sesión completado.";
        return RedirectToAction(nameof(Profile));
    }

    [HttpGet]
    public IActionResult SignUpRequiredAttributes()
    {
        var state = HttpContext.Session.GetJson<SignUpFlowState>(SignUpStateKey);
        if (state?.RequiredAttributes is null || state.RequiredAttributes.Count == 0)
        {
            return RedirectToAction(nameof(SignUp));
        }

        return View(new RequiredAttributesViewModel
        {
            Title = "Atributos requeridos",
            Attributes = state.RequiredAttributes.Select(attribute => new RequiredAttributeInputViewModel
            {
                Name = attribute.Name,
                Type = attribute.Type,
                Required = attribute.Required,
            }).ToList(),
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SignUpRequiredAttributes(RequiredAttributesViewModel model, CancellationToken cancellationToken)
    {
        var state = HttpContext.Session.GetJson<SignUpFlowState>(SignUpStateKey);
        if (state is null)
        {
            return RedirectToAction(nameof(SignUp));
        }

        foreach (var attribute in model.Attributes.Where(attribute => attribute.Required && string.IsNullOrWhiteSpace(attribute.Value)))
        {
            ModelState.AddModelError(string.Empty, $"El atributo '{attribute.Name}' es obligatorio.");
        }

        if (!ModelState.IsValid)
        {
            model.Title = "Atributos requeridos";
            return View(model);
        }

        var attributesResult = await _nativeAuthenticationClient.SubmitAttributesAsync(
            state.ContinuationToken,
            model.Attributes.ToDictionary(attribute => attribute.Name, attribute => attribute.Value),
            cancellationToken);

        if (!attributesResult.IsSuccess || attributesResult.Payload is null)
        {
            ModelState.AddModelError(string.Empty, attributesResult.Message ?? "No fue posible enviar los atributos requeridos.");
            model.Title = "Atributos requeridos";
            return View(model);
        }

        var tokenResult = await _nativeAuthenticationClient.CompleteContinuationAsync(attributesResult.Payload.ContinuationToken!, cancellationToken);
        var mfaAction = await TryHandleMfaRequirementAsync(state.Email, tokenResult, cancellationToken);
        if (mfaAction is not null)
        {
            return mfaAction;
        }

        if (!tokenResult.IsSuccess || tokenResult.Payload?.IdToken is null)
        {
            ModelState.AddModelError(string.Empty, tokenResult.Message ?? "No fue posible finalizar el alta del usuario.");
            model.Title = "Atributos requeridos";
            return View(model);
        }

        var passwordSetAtUtc = DateTimeOffset.UtcNow;
        var signInPrincipal = _nativeAuthenticationClient.CreatePrincipal(tokenResult.Payload);
        await _microsoftGraphUserLifecycleClient.TrySetLastPasswordSetAsync(signInPrincipal, state.Email, passwordSetAtUtc, cancellationToken);
        await SignInAsync(tokenResult.Payload, _microsoftGraphUserLifecycleClient.CalculatePasswordExpiry(passwordSetAtUtc));
        HttpContext.Session.Remove(SignUpStateKey);
        TempData["StatusMessage"] = "Cuenta creada e inicio de sesión completado.";
        return RedirectToAction(nameof(Profile));
    }

    [HttpGet]
    public IActionResult ForgotPassword(string? email = null)
    {
        return View(new ForgotPasswordViewModel
        {
            Email = email ?? string.Empty,
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var startResult = await _nativeAuthenticationClient.StartPasswordResetAsync(model.Email, cancellationToken);
        if (!startResult.IsSuccess || startResult.Payload?.ContinuationToken is null)
        {
            ModelState.AddModelError(string.Empty, startResult.Message ?? "No fue posible iniciar el reseteo de contraseña.");
            return View(model);
        }

        var challengeResult = await _nativeAuthenticationClient.ChallengePasswordResetAsync(startResult.Payload.ContinuationToken, cancellationToken);
        if (!challengeResult.IsSuccess || challengeResult.Payload?.ContinuationToken is null)
        {
            ModelState.AddModelError(string.Empty, challengeResult.Message ?? "No fue posible enviar el código OTP de reseteo.");
            return View(model);
        }

        HttpContext.Session.SetJson(ResetPasswordStateKey, new ResetPasswordFlowState
        {
            Email = model.Email,
            ContinuationToken = challengeResult.Payload.ContinuationToken,
        });

        TempData["StatusMessage"] = $"Se envió un código a {challengeResult.Payload.ChallengeTargetLabel ?? model.Email}.";
        return RedirectToAction(nameof(VerifyResetCode));
    }

    [HttpGet]
    public IActionResult VerifyResetCode()
    {
        if (HttpContext.Session.GetJson<ResetPasswordFlowState>(ResetPasswordStateKey) is null)
        {
            return RedirectToAction(nameof(ForgotPassword));
        }

        return View(new VerifyOtpViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyResetCode(VerifyOtpViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var state = HttpContext.Session.GetJson<ResetPasswordFlowState>(ResetPasswordStateKey);
        if (state is null)
        {
            return RedirectToAction(nameof(ForgotPassword));
        }

        var result = await _nativeAuthenticationClient.ContinuePasswordResetWithOtpAsync(state.ContinuationToken, model.Code, cancellationToken);
        if (!result.IsSuccess || result.Payload?.ContinuationToken is null)
        {
            ModelState.AddModelError(string.Empty, result.Message ?? "El código OTP no es válido.");
            return View(model);
        }

        state.ContinuationToken = result.Payload.ContinuationToken;
        HttpContext.Session.SetJson(ResetPasswordStateKey, state);
        return RedirectToAction(nameof(ResetPassword));
    }

    [HttpGet]
    public IActionResult ResetPassword()
    {
        if (HttpContext.Session.GetJson<ResetPasswordFlowState>(ResetPasswordStateKey) is null)
        {
            return RedirectToAction(nameof(ForgotPassword));
        }

        return View(new ResetPasswordViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (!ValidatePasswordPolicy(model.NewPassword, nameof(model.NewPassword)))
        {
            return View(model);
        }

        var state = HttpContext.Session.GetJson<ResetPasswordFlowState>(ResetPasswordStateKey);
        if (state is null)
        {
            return RedirectToAction(nameof(ForgotPassword));
        }

        var submitResult = await _nativeAuthenticationClient.SubmitNewPasswordAsync(state.ContinuationToken, model.NewPassword, cancellationToken);
        if (!submitResult.IsSuccess || submitResult.Payload?.ContinuationToken is null)
        {
            ModelState.AddModelError(string.Empty, submitResult.Message ?? "No fue posible actualizar la contraseña.");
            return View(model);
        }

        state.ContinuationToken = submitResult.Payload.ContinuationToken;
        HttpContext.Session.SetJson(ResetPasswordStateKey, state);
        return RedirectToAction(nameof(ResetPasswordStatus));
    }

    [HttpGet]
    public async Task<IActionResult> ResetPasswordStatus(CancellationToken cancellationToken)
    {
        var state = HttpContext.Session.GetJson<ResetPasswordFlowState>(ResetPasswordStateKey);
        if (state is null)
        {
            return RedirectToAction(nameof(ForgotPassword));
        }

        var result = await _nativeAuthenticationClient.PollPasswordResetAsync(state.ContinuationToken, cancellationToken);
        if (!result.IsSuccess || result.Payload is null)
        {
            ViewBag.Status = "failed";
            ViewBag.Message = result.Message ?? "No fue posible consultar el estado del reseteo.";
            return View();
        }

        ViewBag.Status = result.Payload.Status ?? "unknown";
        ViewBag.Message = result.Payload.Status switch
        {
            "succeeded" => "La contraseña se actualizó correctamente.",
            "in_progress" => "Microsoft Entra todavía está aplicando el cambio. Vuelve a cargar esta página en unos segundos.",
            "not_started" => "El cambio todavía no comenzó a procesarse. Vuelve a cargar esta página en unos segundos.",
            _ => "Estado no reconocido del reseteo de contraseña.",
        };

        if (string.Equals(result.Payload.Status, "succeeded", StringComparison.OrdinalIgnoreCase))
        {
            var passwordSetAtUtc = DateTimeOffset.UtcNow;
            await _microsoftGraphUserLifecycleClient.TrySetLastPasswordSetAsync(state.Email, passwordSetAtUtc, cancellationToken);

            if (!string.IsNullOrWhiteSpace(result.Payload.ContinuationToken))
            {
                var tokenResult = await _nativeAuthenticationClient.CompleteContinuationAsync(result.Payload.ContinuationToken, cancellationToken);
                if (tokenResult.IsSuccess && tokenResult.Payload?.IdToken is not null)
                {
                    await SignInAsync(tokenResult.Payload, _microsoftGraphUserLifecycleClient.CalculatePasswordExpiry(passwordSetAtUtc));
                    HttpContext.Session.Remove(ResetPasswordStateKey);
                    TempData["StatusMessage"] = "Contraseña actualizada e inicio de sesión completado.";
                    return RedirectToAction(nameof(Profile));
                }
            }

            HttpContext.Session.Remove(ResetPasswordStateKey);
        }

        return View();
    }

    [HttpGet]
    public IActionResult Profile()
    {
        if (User.Identity?.IsAuthenticated != true)
        {
            return RedirectToAction(nameof(SignIn));
        }

        var tokens = HttpContext.Session.GetJson<TokenSessionState>(TokensStateKey);
        return View(new SignedInUserViewModel
        {
            DisplayName = User.FindFirstValue(ClaimTypes.Name) ?? User.FindFirstValue("name"),
            Email = User.FindFirstValue(ClaimTypes.Email) ?? User.FindFirstValue("preferred_username"),
            AccessTokenExpiresAt = tokens?.AccessTokenExpiresAt,
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SignOutUser()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        HttpContext.Session.Remove(TokensStateKey);
        TempData["StatusMessage"] = "Sesión cerrada.";
        return RedirectToAction(nameof(SignIn));
    }

    private async Task SignInAsync(NativeAuthenticationPayload payload, DateTimeOffset passwordExpiresAtUtc)
    {
        var principal = _nativeAuthenticationClient.CreatePrincipal(payload);
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = true,
                AllowRefresh = false,
                ExpiresUtc = passwordExpiresAtUtc,
            });

        HttpContext.Session.SetJson(TokensStateKey, new TokenSessionState
        {
            AccessToken = payload.AccessToken,
            RefreshToken = payload.RefreshToken,
            IdToken = payload.IdToken,
            AccessTokenExpiresAt = payload.ExpiresIn is int expiresIn
                ? DateTimeOffset.UtcNow.AddSeconds(expiresIn)
                : null,
        });
    }

    private async Task<IActionResult?> TryHandleMfaRequirementAsync(string email, NativeAuthenticationResult result, CancellationToken cancellationToken)
    {
        if (result.IsSuccess || string.IsNullOrWhiteSpace(result.Payload?.ContinuationToken))
        {
            return null;
        }

        if (IsRegistrationRequired(result))
        {
            var registrationMethods = await _nativeAuthenticationClient.GetRegistrationMethodsAsync(result.Payload.ContinuationToken, cancellationToken);
            if (!registrationMethods.IsSuccess || registrationMethods.Payload is null)
            {
                return null;
            }

            var method = registrationMethods.Payload.Methods.FirstOrDefault(candidate =>
                string.Equals(candidate.ChallengeType, "oob", StringComparison.OrdinalIgnoreCase)
                && string.Equals(candidate.ChallengeChannel, "email", StringComparison.OrdinalIgnoreCase));

            if (method is null)
            {
                TempData["StatusMessage"] = "El tenant exige MFA, pero esta demo sólo implementa registro MFA por email.";
                return RedirectToAction(nameof(SignIn));
            }

            var target = method.LoginHint ?? email;
            var challenge = await _nativeAuthenticationClient.ChallengeRegistrationMethodAsync(
                registrationMethods.Payload.ContinuationToken ?? result.Payload.ContinuationToken,
                method.ChallengeType,
                method.ChallengeChannel ?? "email",
                target,
                cancellationToken);

            if (!challenge.IsSuccess || challenge.Payload is null || string.IsNullOrWhiteSpace(challenge.Payload.ContinuationToken))
            {
                TempData["StatusMessage"] = challenge.Message ?? "No fue posible iniciar el registro MFA.";
                return RedirectToAction(nameof(SignIn));
            }

            if (string.Equals(challenge.Payload.ChallengeType, "preverified", StringComparison.OrdinalIgnoreCase))
            {
                var preverified = await _nativeAuthenticationClient.ContinuePreverifiedRegistrationAsync(challenge.Payload.ContinuationToken, cancellationToken);
                if (!preverified.IsSuccess || string.IsNullOrWhiteSpace(preverified.Payload?.ContinuationToken))
                {
                    TempData["StatusMessage"] = preverified.Message ?? "No fue posible completar el preregistro MFA.";
                    return RedirectToAction(nameof(SignIn));
                }

                var tokenResult = await _nativeAuthenticationClient.CompleteContinuationAsync(preverified.Payload.ContinuationToken, cancellationToken);
                if (!tokenResult.IsSuccess || tokenResult.Payload?.IdToken is null)
                {
                    TempData["StatusMessage"] = tokenResult.Message ?? "No fue posible completar el inicio de sesión tras el preregistro MFA.";
                    return RedirectToAction(nameof(SignIn));
                }

                var signInPrincipal = _nativeAuthenticationClient.CreatePrincipal(tokenResult.Payload);
                var passwordPolicyResult = await _microsoftGraphUserLifecycleClient.CheckPasswordAgeAsync(signInPrincipal, email, cancellationToken);
                if (!passwordPolicyResult.IsSuccess)
                {
                    TempData["StatusMessage"] = passwordPolicyResult.FailureMessage ?? "No fue posible validar la antiguedad de la contraseña.";
                    return RedirectToAction(nameof(SignIn));
                }

                if (passwordPolicyResult.IsExpired)
                {
                    TempData["StatusMessage"] = "Tu contraseña ha caducado. Debes restablecerla antes de iniciar sesión.";
                    return RedirectToAction(nameof(ForgotPassword), new { email });
                }

                await SignInAsync(tokenResult.Payload, passwordPolicyResult.ExpiresAtUtc ?? DateTimeOffset.UtcNow);
                TempData["StatusMessage"] = "Método MFA registrado e inicio de sesión completado.";
                return RedirectToAction(nameof(Profile));
            }

            HttpContext.Session.SetJson(MfaStateKey, new MfaFlowState
            {
                Mode = MfaFlowMode.Registration,
                Email = email,
                ContinuationToken = challenge.Payload.ContinuationToken,
                TargetLabel = challenge.Payload.ChallengeTarget ?? challenge.Payload.ChallengeTargetLabel ?? target,
            });

            TempData["StatusMessage"] = $"Se envió un código MFA a {challenge.Payload.ChallengeTarget ?? challenge.Payload.ChallengeTargetLabel ?? target}.";
            return RedirectToAction(nameof(VerifyMfaOtp));
        }

        if (IsMfaRequired(result))
        {
            var methods = await _nativeAuthenticationClient.GetRegisteredStrongAuthenticationMethodsAsync(result.Payload.ContinuationToken, cancellationToken);
            if (!methods.IsSuccess || methods.Payload is null)
            {
                return null;
            }

            var method = methods.Payload.Methods.FirstOrDefault(candidate =>
                string.Equals(candidate.ChallengeType, "oob", StringComparison.OrdinalIgnoreCase)
                && string.Equals(candidate.ChallengeChannel, "email", StringComparison.OrdinalIgnoreCase));

            if (method is null)
            {
                TempData["StatusMessage"] = "El tenant exige MFA, pero esta demo sólo implementa desafío MFA por email.";
                return RedirectToAction(nameof(SignIn));
            }

            var challenge = await _nativeAuthenticationClient.ChallengeStrongAuthenticationMethodAsync(
                methods.Payload.ContinuationToken ?? result.Payload.ContinuationToken,
                method.Id,
                cancellationToken);

            if (!challenge.IsSuccess || challenge.Payload is null || string.IsNullOrWhiteSpace(challenge.Payload.ContinuationToken))
            {
                TempData["StatusMessage"] = challenge.Message ?? "No fue posible iniciar el desafío MFA.";
                return RedirectToAction(nameof(SignIn));
            }

            HttpContext.Session.SetJson(MfaStateKey, new MfaFlowState
            {
                Mode = MfaFlowMode.Challenge,
                Email = email,
                ContinuationToken = challenge.Payload.ContinuationToken,
                TargetLabel = challenge.Payload.ChallengeTargetLabel ?? method.LoginHint ?? email,
            });

            TempData["StatusMessage"] = $"Se envió un código MFA a {challenge.Payload.ChallengeTargetLabel ?? method.LoginHint ?? email}.";
            return RedirectToAction(nameof(VerifyMfaOtp));
        }

        return null;
    }

    private static bool IsRegistrationRequired(NativeAuthenticationResult result)
    {
        return string.Equals(result.Payload?.Suberror, "registration_required", StringComparison.OrdinalIgnoreCase)
            || (result.Message?.Contains("enroll in multi-factor authentication", StringComparison.OrdinalIgnoreCase) ?? false)
            || (result.Message?.Contains("AADSTS50072", StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private static bool IsAttributesRequired(NativeAuthenticationResult result)
    {
        return string.Equals(result.Payload?.Error, "attributes_required", StringComparison.OrdinalIgnoreCase)
            || result.Payload?.RequiredAttributes.Count > 0;
    }

    private static bool IsMfaRequired(NativeAuthenticationResult result)
    {
        return string.Equals(result.Payload?.Suberror, "mfa_required", StringComparison.OrdinalIgnoreCase)
            || (result.Message?.Contains("MFA is required", StringComparison.OrdinalIgnoreCase) ?? false)
            || (result.Message?.Contains("multi-factor authentication", StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private bool ValidatePasswordPolicy(string password, string modelPropertyName)
    {
        if (password.Length < _microsoftGraphUserLifecycleOptions.PasswordMinLength)
        {
            ModelState.AddModelError(modelPropertyName, $"La contraseña debe tener al menos {_microsoftGraphUserLifecycleOptions.PasswordMinLength} caracteres.");
            return false;
        }

        if (!password.Any(char.IsUpper))
        {
            ModelState.AddModelError(modelPropertyName, "La contraseña debe contener al menos una letra mayúscula.");
            return false;
        }

        if (!password.Any(char.IsLower))
        {
            ModelState.AddModelError(modelPropertyName, "La contraseña debe contener al menos una letra minúscula.");
            return false;
        }

        if (!password.Any(char.IsDigit))
        {
            ModelState.AddModelError(modelPropertyName, "La contraseña debe contener al menos un dígito.");
            return false;
        }

        if (!password.Any(character => !char.IsLetterOrDigit(character)))
        {
            ModelState.AddModelError(modelPropertyName, "La contraseña debe contener al menos un carácter especial.");
            return false;
        }

        return true;
    }

    private static string BuildSignInLockoutMessage(SignInLockoutStateResult lockoutState)
    {
        var lockedUntilUtc = lockoutState.LockedUntilUtc ?? DateTimeOffset.UtcNow;
        var remainingSeconds = Math.Max(1, (int)Math.Ceiling((lockedUntilUtc - DateTimeOffset.UtcNow).TotalSeconds));
        return $"Tu cuenta está bloqueada temporalmente por demasiados intentos fallidos. Vuelve a intentarlo en {remainingSeconds} segundos.";
    }

    private async Task<SignUpCompletionResult> CompleteSignUpFlowAsync(SignUpFlowState state, NativeAuthenticationPayload payload, CancellationToken cancellationToken)
    {
        var currentPayload = payload;

        if (string.Equals(currentPayload.ChallengeType, "password", StringComparison.OrdinalIgnoreCase))
        {
            var passwordResult = await _nativeAuthenticationClient.SubmitSignUpPasswordAsync(currentPayload.ContinuationToken!, state.Password, cancellationToken);
            if ((!passwordResult.IsSuccess && !IsAttributesRequired(passwordResult)) || passwordResult.Payload is null)
            {
                return SignUpCompletionResult.FromFailure(passwordResult.Message, passwordResult.Payload);
            }

            currentPayload = passwordResult.Payload;
        }

        if (currentPayload.RequiredAttributes.Count > 0)
        {
            state.ContinuationToken = currentPayload.ContinuationToken!;
            state.RequiredAttributes = currentPayload.RequiredAttributes;
            HttpContext.Session.SetJson(SignUpStateKey, state);
            return SignUpCompletionResult.RequiresAttributes(currentPayload);
        }

        if (string.IsNullOrWhiteSpace(currentPayload.ContinuationToken))
        {
            return SignUpCompletionResult.FromFailure("La respuesta no incluyó continuation_token para finalizar el registro.", currentPayload);
        }

        var tokenResult = await _nativeAuthenticationClient.CompleteContinuationAsync(currentPayload.ContinuationToken, cancellationToken);
        return tokenResult.IsSuccess && tokenResult.Payload is not null
            ? SignUpCompletionResult.FromSuccess(tokenResult.Payload)
            : SignUpCompletionResult.FromFailure(tokenResult.Message, tokenResult.Payload);
    }

    private sealed class SignUpFlowState
    {
        public string Email { get; init; } = string.Empty;

        public string Password { get; init; } = string.Empty;

        public string ContinuationToken { get; set; } = string.Empty;

        public string? DisplayName { get; init; }

        public List<RequiredAttributeDefinition> RequiredAttributes { get; set; } = new();
    }

    private sealed class ResetPasswordFlowState
    {
        public string Email { get; init; } = string.Empty;

        public string ContinuationToken { get; set; } = string.Empty;
    }

    private sealed class MfaFlowState
    {
        public MfaFlowMode Mode { get; init; }

        public string Email { get; init; } = string.Empty;

        public string ContinuationToken { get; set; } = string.Empty;

        public string? TargetLabel { get; init; }
    }

    private enum MfaFlowMode
    {
        Registration,
        Challenge,
    }

    private sealed class TokenSessionState
    {
        public string? AccessToken { get; init; }

        public string? RefreshToken { get; init; }

        public string? IdToken { get; init; }

        public DateTimeOffset? AccessTokenExpiresAt { get; init; }
    }

    private sealed class SignUpCompletionResult
    {
        private SignUpCompletionResult(bool isSuccess, string? message, NativeAuthenticationPayload? payload, SignUpNextAction nextAction)
        {
            IsSuccess = isSuccess;
            Message = message;
            Payload = payload;
            NextAction = nextAction;
        }

        public bool IsSuccess { get; }

        public string? Message { get; }

        public NativeAuthenticationPayload? Payload { get; }

        public SignUpNextAction NextAction { get; }

        public static SignUpCompletionResult FromSuccess(NativeAuthenticationPayload payload)
            => new(true, null, payload, SignUpNextAction.Complete);

        public static SignUpCompletionResult FromFailure(string? message, NativeAuthenticationPayload? payload)
            => new(false, message, payload, SignUpNextAction.Complete);

        public static SignUpCompletionResult RequiresAttributes(NativeAuthenticationPayload payload)
            => new(false, null, payload, SignUpNextAction.RequiredAttributes);
    }

    private enum SignUpNextAction
    {
        Complete,
        RequiredAttributes,
    }
}