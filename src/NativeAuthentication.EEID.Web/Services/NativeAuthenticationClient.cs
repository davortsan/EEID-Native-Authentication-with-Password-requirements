using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using NativeAuthentication.EEID.Web.Options;

namespace NativeAuthentication.EEID.Web.Services;

public sealed class NativeAuthenticationClient
{
    private readonly HttpClient _httpClient;
    private readonly NativeAuthenticationOptions _options;

    public NativeAuthenticationClient(HttpClient httpClient, IOptions<NativeAuthenticationOptions> options)
    {
        _httpClient = httpClient;
        _options = options.Value;
    }

    public async Task<NativeAuthenticationResult> SignInAsync(string email, string password, CancellationToken cancellationToken)
    {
        var initiate = await SendAsync(
            "oauth2/v2.0/initiate",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["username"] = email,
                ["challenge_type"] = _options.SignInChallengeType,
                ["capabilities"] = _options.Capabilities,
            },
            cancellationToken);

        if (!initiate.IsSuccess)
        {
            return initiate;
        }

        var challenge = await SendAsync(
            "oauth2/v2.0/challenge",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = initiate.Payload!.ContinuationToken,
                ["challenge_type"] = _options.SignInChallengeType,
            },
            cancellationToken);

        if (!challenge.IsSuccess)
        {
            return challenge;
        }

        if (!string.Equals(challenge.Payload!.ChallengeType, "password", StringComparison.OrdinalIgnoreCase))
        {
            return NativeAuthenticationResult.Fail(
                $"La aplicación recibió el challenge '{challenge.Payload.ChallengeType ?? "unknown"}'. Este proyecto base espera email + password para el inicio de sesión.",
                challenge.Payload);
        }

        return await SendAsync(
            "oauth2/v2.0/token",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = challenge.Payload.ContinuationToken,
                ["grant_type"] = "password",
                ["password"] = password,
                ["scope"] = _options.Scopes,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> StartSignUpAsync(string email, string password, string? displayName, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string?>
        {
            ["client_id"] = _options.ClientId,
            ["username"] = email,
            ["password"] = password,
            ["challenge_type"] = _options.SignUpChallengeType,
            ["capabilities"] = _options.Capabilities,
        };

        if (!string.IsNullOrWhiteSpace(displayName))
        {
            form["attributes"] = JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["displayName"] = displayName,
            });
        }

        return SendAsync("signup/v1.0/start", form, cancellationToken);
    }

    public Task<NativeAuthenticationResult> ChallengeSignUpAsync(string continuationToken, CancellationToken cancellationToken)
    {
        return SendAsync(
            "signup/v1.0/challenge",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["challenge_type"] = _options.SignUpChallengeType,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> ContinueSignUpWithOtpAsync(string continuationToken, string code, CancellationToken cancellationToken)
    {
        return SendAsync(
            "signup/v1.0/continue",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["grant_type"] = "oob",
                ["oob"] = code,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> SubmitSignUpPasswordAsync(string continuationToken, string password, CancellationToken cancellationToken)
    {
        return SendAsync(
            "signup/v1.0/continue",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["grant_type"] = "password",
                ["password"] = password,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> SubmitAttributesAsync(string continuationToken, IReadOnlyDictionary<string, string> attributes, CancellationToken cancellationToken)
    {
        return SendAsync(
            "signup/v1.0/continue",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["grant_type"] = "attributes",
                ["attributes"] = JsonSerializer.Serialize(attributes),
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> CompleteContinuationAsync(string continuationToken, CancellationToken cancellationToken)
    {
        return SendAsync(
            "oauth2/v2.0/token",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["grant_type"] = "continuation_token",
                ["scope"] = _options.Scopes,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> StartPasswordResetAsync(string email, CancellationToken cancellationToken)
    {
        return SendAsync(
            "resetpassword/v1.0/start",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["username"] = email,
                ["challenge_type"] = _options.ResetPasswordChallengeType,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> ChallengePasswordResetAsync(string continuationToken, CancellationToken cancellationToken)
    {
        return SendAsync(
            "resetpassword/v1.0/challenge",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["challenge_type"] = _options.ResetPasswordChallengeType,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> ContinuePasswordResetWithOtpAsync(string continuationToken, string code, CancellationToken cancellationToken)
    {
        return SendAsync(
            "resetpassword/v1.0/continue",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["grant_type"] = "oob",
                ["oob"] = code,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> SubmitNewPasswordAsync(string continuationToken, string newPassword, CancellationToken cancellationToken)
    {
        return SendAsync(
            "resetpassword/v1.0/submit",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["new_password"] = newPassword,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> PollPasswordResetAsync(string continuationToken, CancellationToken cancellationToken)
    {
        return SendAsync(
            "resetpassword/v1.0/poll_completion",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> GetRegisteredStrongAuthenticationMethodsAsync(string continuationToken, CancellationToken cancellationToken)
    {
        return SendAsync(
            "oauth2/v2.0/introspect",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> ChallengeStrongAuthenticationMethodAsync(string continuationToken, string methodId, CancellationToken cancellationToken)
    {
        return SendAsync(
            "oauth2/v2.0/challenge",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["id"] = methodId,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> CompleteMfaAsync(string continuationToken, string code, CancellationToken cancellationToken)
    {
        return SendAsync(
            "oauth2/v2.0/token",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["grant_type"] = "mfa_oob",
                ["oob"] = code,
                ["scope"] = _options.Scopes,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> GetRegistrationMethodsAsync(string continuationToken, CancellationToken cancellationToken)
    {
        return SendAsync(
            "register/v1.0/introspect",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> ChallengeRegistrationMethodAsync(string continuationToken, string challengeType, string challengeChannel, string challengeTarget, CancellationToken cancellationToken)
    {
        return SendAsync(
            "register/v1.0/challenge",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["challenge_type"] = challengeType,
                ["challenge_channel"] = challengeChannel,
                ["challenge_target"] = challengeTarget,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> ContinueRegistrationWithOtpAsync(string continuationToken, string code, CancellationToken cancellationToken)
    {
        return SendAsync(
            "register/v1.0/continue",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["grant_type"] = "oob",
                ["oob"] = code,
            },
            cancellationToken);
    }

    public Task<NativeAuthenticationResult> ContinuePreverifiedRegistrationAsync(string continuationToken, CancellationToken cancellationToken)
    {
        return SendAsync(
            "register/v1.0/continue",
            new Dictionary<string, string?>
            {
                ["client_id"] = _options.ClientId,
                ["continuation_token"] = continuationToken,
                ["grant_type"] = "continuation_token",
            },
            cancellationToken);
    }

    public ClaimsPrincipal CreatePrincipal(NativeAuthenticationPayload payload)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(payload.IdToken);
        var claims = token.Claims.ToList();

        if (!claims.Any(claim => claim.Type == ClaimTypes.Name))
        {
            var displayName = claims.FirstOrDefault(claim => claim.Type == "name")?.Value
                ?? claims.FirstOrDefault(claim => claim.Type == "preferred_username")?.Value;

            if (!string.IsNullOrWhiteSpace(displayName))
            {
                claims.Add(new Claim(ClaimTypes.Name, displayName));
            }
        }

        if (!claims.Any(claim => claim.Type == ClaimTypes.Email))
        {
            var email = claims.FirstOrDefault(claim => claim.Type == "email")?.Value
                ?? claims.FirstOrDefault(claim => claim.Type == "preferred_username")?.Value;

            if (!string.IsNullOrWhiteSpace(email))
            {
                claims.Add(new Claim(ClaimTypes.Email, email));
            }
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, "NativeAuthentication"));
    }

    private async Task<NativeAuthenticationResult> SendAsync(string relativePath, IReadOnlyDictionary<string, string?> values, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsync(
            $"{_options.AuthorityBaseUrl}/{relativePath}",
            new FormUrlEncodedContent(values.Where(pair => !string.IsNullOrWhiteSpace(pair.Value))!
                .ToDictionary(pair => pair.Key, pair => pair.Value!)),
            cancellationToken);

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        var payload = string.IsNullOrWhiteSpace(content)
            ? new NativeAuthenticationPayload()
            : JsonSerializer.Deserialize<NativeAuthenticationPayload>(content, JsonOptions()) ?? new NativeAuthenticationPayload();

        if (response.IsSuccessStatusCode)
        {
            if (string.Equals(payload.ChallengeType, "redirect", StringComparison.OrdinalIgnoreCase))
            {
                return NativeAuthenticationResult.Fail(
                    payload.RedirectReason ?? "Microsoft Entra requiere fallback a autenticación basada en navegador para este paso.",
                    payload,
                    response.StatusCode);
            }

            return NativeAuthenticationResult.Success(payload, response.StatusCode);
        }

        var message = payload.ErrorDescription
            ?? payload.Error
            ?? $"La llamada a '{relativePath}' devolvió {(int)response.StatusCode}.";

        if (!string.IsNullOrWhiteSpace(payload.TraceId) || !string.IsNullOrWhiteSpace(payload.CorrelationId))
        {
            message = $"{message} Endpoint: {relativePath}. Trace ID: {payload.TraceId ?? "n/a"}. Correlation ID: {payload.CorrelationId ?? "n/a"}.";
        }

        return NativeAuthenticationResult.Fail(message, payload, response.StatusCode);
    }

    private static JsonSerializerOptions JsonOptions()
    {
        return new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = true,
        };
    }
}

public sealed class NativeAuthenticationResult
{
    private NativeAuthenticationResult(bool isSuccess, string? message, NativeAuthenticationPayload? payload, HttpStatusCode? statusCode)
    {
        IsSuccess = isSuccess;
        Message = message;
        Payload = payload;
        StatusCode = statusCode;
    }

    public bool IsSuccess { get; }

    public string? Message { get; }

    public NativeAuthenticationPayload? Payload { get; }

    public HttpStatusCode? StatusCode { get; }

    public static NativeAuthenticationResult Success(NativeAuthenticationPayload payload, HttpStatusCode? statusCode = null)
        => new(true, null, payload, statusCode);

    public static NativeAuthenticationResult Fail(string message, NativeAuthenticationPayload? payload = null, HttpStatusCode? statusCode = null)
        => new(false, message, payload, statusCode);
}

public sealed class NativeAuthenticationPayload
{
    [JsonPropertyName("continuation_token")]
    public string? ContinuationToken { get; init; }

    [JsonPropertyName("challenge_type")]
    public string? ChallengeType { get; init; }

    [JsonPropertyName("binding_method")]
    public string? BindingMethod { get; init; }

    [JsonPropertyName("challenge_channel")]
    public string? ChallengeChannel { get; init; }

    [JsonPropertyName("challenge_target_label")]
    public string? ChallengeTargetLabel { get; init; }

    [JsonPropertyName("code_length")]
    public int? CodeLength { get; init; }

    [JsonPropertyName("challenge_target")]
    public string? ChallengeTarget { get; init; }

    [JsonPropertyName("access_token")]
    public string? AccessToken { get; init; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }

    [JsonPropertyName("id_token")]
    public string? IdToken { get; init; }

    [JsonPropertyName("expires_in")]
    public int? ExpiresIn { get; init; }

    public string? Scope { get; init; }

    public string? Error { get; init; }

    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; init; }

    [JsonPropertyName("trace_id")]
    public string? TraceId { get; init; }

    [JsonPropertyName("correlation_id")]
    public string? CorrelationId { get; init; }

    public string? Suberror { get; init; }

    [JsonPropertyName("redirect_reason")]
    public string? RedirectReason { get; init; }

    public string? Status { get; init; }

    [JsonPropertyName("poll_interval")]
    public int? PollInterval { get; init; }

    [JsonPropertyName("required_attributes")]
    public List<RequiredAttributeDefinition> RequiredAttributes { get; init; } = new();

    [JsonPropertyName("methods")]
    public List<StrongAuthenticationMethodDefinition> Methods { get; init; } = new();
}

public sealed class RequiredAttributeDefinition
{
    public string Name { get; init; } = string.Empty;

    public string Type { get; init; } = "string";

    public bool Required { get; init; }
}

public sealed class StrongAuthenticationMethodDefinition
{
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("challenge_type")]
    public string ChallengeType { get; init; } = string.Empty;

    [JsonPropertyName("challenge_channel")]
    public string? ChallengeChannel { get; init; }

    [JsonPropertyName("login_hint")]
    public string? LoginHint { get; init; }
}