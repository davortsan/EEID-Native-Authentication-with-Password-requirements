using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using NativeAuthentication.EEID.Web.Options;

namespace NativeAuthentication.EEID.Web.Services;

public sealed class MicrosoftGraphUserLifecycleClient
{
    private const string GraphScope = "https://graph.microsoft.com/.default";

    private readonly HttpClient _httpClient;
    private readonly NativeAuthenticationOptions _nativeAuthenticationOptions;
    private readonly MicrosoftGraphUserLifecycleOptions _options;
    private readonly ILogger<MicrosoftGraphUserLifecycleClient> _logger;

    public MicrosoftGraphUserLifecycleClient(
        HttpClient httpClient,
        IOptions<NativeAuthenticationOptions> nativeAuthenticationOptions,
        IOptions<MicrosoftGraphUserLifecycleOptions> options,
        ILogger<MicrosoftGraphUserLifecycleClient> logger)
    {
        _httpClient = httpClient;
        _nativeAuthenticationOptions = nativeAuthenticationOptions.Value;
        _options = options.Value;
        _logger = logger;
    }

    public DateTimeOffset CalculatePasswordExpiry(DateTimeOffset lastPasswordSetUtc)
        => lastPasswordSetUtc.AddDays(_options.PasswordMaxAgeDays);

    public async Task<SignInLockoutStateResult> GetSignInLockoutStateAsync(string fallbackEmail, CancellationToken cancellationToken)
    {
        if (!IsSignInLockoutEnabled())
        {
            return SignInLockoutStateResult.Disabled();
        }

        var userContext = await ResolveGraphUserContextAsync(fallbackEmail, cancellationToken);
        if (userContext is null)
        {
            return SignInLockoutStateResult.Unavailable(_options.MaxFailedSignInAttempts);
        }

        using var document = await GetUserDocumentAsync(
            userContext.UserId,
            userContext.AccessToken,
            GetSignInLockoutSelectProperties(),
            cancellationToken);

        if (document is null)
        {
            return SignInLockoutStateResult.Unavailable(_options.MaxFailedSignInAttempts);
        }

        return CreateSignInLockoutState(document.RootElement);
    }

    public async Task<SignInLockoutStateResult> RegisterFailedSignInAttemptAsync(string fallbackEmail, CancellationToken cancellationToken)
    {
        if (!IsSignInLockoutEnabled())
        {
            return SignInLockoutStateResult.Disabled();
        }

        var userContext = await ResolveGraphUserContextAsync(fallbackEmail, cancellationToken);
        if (userContext is null)
        {
            return SignInLockoutStateResult.Unavailable(_options.MaxFailedSignInAttempts);
        }

        using var document = await GetUserDocumentAsync(
            userContext.UserId,
            userContext.AccessToken,
            GetSignInLockoutSelectProperties(),
            cancellationToken);

        if (document is null)
        {
            return SignInLockoutStateResult.Unavailable(_options.MaxFailedSignInAttempts);
        }

        var currentState = CreateSignInLockoutState(document.RootElement);
        var nowUtc = DateTimeOffset.UtcNow;
        var nextFailedAttempts = currentState.LockedUntilUtc.HasValue && currentState.LockedUntilUtc.Value <= nowUtc
            ? 1
            : currentState.FailedAttempts + 1;

        var nextLockoutEndUtc = nextFailedAttempts >= _options.MaxFailedSignInAttempts
            ? nowUtc.AddSeconds(_options.LockoutDurationSeconds)
            : (DateTimeOffset?)null;

        var updated = await SetUserAttributesAsync(
            userContext.UserId,
            userContext.AccessToken,
            new Dictionary<string, object?>
            {
                [GetFailedSignInCountExtensionName()] = nextFailedAttempts.ToString(CultureInfo.InvariantCulture),
                [GetLockoutEndUtcExtensionName()] = nextLockoutEndUtc?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            },
            cancellationToken);

        return updated
            ? SignInLockoutStateResult.Success(nextFailedAttempts, _options.MaxFailedSignInAttempts, nextLockoutEndUtc)
            : SignInLockoutStateResult.Unavailable(_options.MaxFailedSignInAttempts);
    }

    public async Task<bool> TryResetFailedSignInStateAsync(string fallbackEmail, CancellationToken cancellationToken)
    {
        if (!IsSignInLockoutEnabled())
        {
            return false;
        }

        var userContext = await ResolveGraphUserContextAsync(fallbackEmail, cancellationToken);
        if (userContext is null)
        {
            return false;
        }

        return await SetUserAttributesAsync(
            userContext.UserId,
            userContext.AccessToken,
            new Dictionary<string, object?>
            {
                [GetFailedSignInCountExtensionName()] = "0",
                [GetLockoutEndUtcExtensionName()] = null,
            },
            cancellationToken);
    }

    public async Task<PasswordAgeCheckResult> CheckPasswordAgeAsync(ClaimsPrincipal principal, string fallbackEmail, CancellationToken cancellationToken)
    {
        if (!IsConfigured())
        {
            return PasswordAgeCheckResult.Fail(
                "Configura Microsoft Graph para validar la antiguedad de la contraseña. Falta MicrosoftGraphUserLifecycle:ClientSecret o la identidad de tenant/app.");
        }

        var accessToken = await AcquireAccessTokenAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return PasswordAgeCheckResult.Fail("No fue posible obtener un token de aplicación para Microsoft Graph.");
        }

        var userId = await ResolveGraphUserIdAsync(principal, fallbackEmail, accessToken, cancellationToken);
        if (string.IsNullOrWhiteSpace(userId))
        {
            return PasswordAgeCheckResult.Fail("No fue posible resolver el usuario en Microsoft Graph para validar la fecha del ultimo cambio de contraseña.");
        }

        var extensionName = _options.LastPasswordSetExtensionName?.Trim();
        var selectProperties = new List<string>();
        if (_options.UseBuiltInLastPasswordChangeDateTime)
        {
            selectProperties.Add("lastPasswordChangeDateTime");
        }

        if (!string.IsNullOrWhiteSpace(extensionName))
        {
            selectProperties.Add(extensionName);
        }

        if (selectProperties.Count == 0)
        {
            return PasswordAgeCheckResult.Fail(
                "No hay ninguna propiedad configurada para determinar la fecha del ultimo cambio de contraseña.");
        }

        using var document = await GetUserDocumentAsync(userId, accessToken, selectProperties, cancellationToken);
        if (document is null)
        {
            return PasswordAgeCheckResult.Fail("No fue posible leer la fecha del ultimo cambio de contraseña en Microsoft Graph.");
        }

        var root = document.RootElement;

        DateTimeOffset? lastPasswordSetUtc = null;
        if (!string.IsNullOrWhiteSpace(extensionName)
            && root.TryGetProperty(extensionName, out var extensionValue)
            && extensionValue.ValueKind == JsonValueKind.String
            && DateTimeOffset.TryParse(extensionValue.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var customTimestamp))
        {
            lastPasswordSetUtc = customTimestamp.ToUniversalTime();
        }

        if (lastPasswordSetUtc is null
            && _options.UseBuiltInLastPasswordChangeDateTime
            && root.TryGetProperty("lastPasswordChangeDateTime", out var lastPasswordChangeValue)
            && lastPasswordChangeValue.ValueKind == JsonValueKind.String
            && DateTimeOffset.TryParse(lastPasswordChangeValue.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var builtInTimestamp))
        {
            lastPasswordSetUtc = builtInTimestamp.ToUniversalTime();
        }

        if (lastPasswordSetUtc is null)
        {
            if (!string.IsNullOrWhiteSpace(extensionName))
            {
                var bootstrappedAtUtc = DateTimeOffset.UtcNow;
                var updated = await SetLastPasswordSetAsync(userId, extensionName, accessToken, bootstrappedAtUtc, cancellationToken);
                if (updated)
                {
                    _logger.LogInformation(
                        "Bootstrapped LastPasswordSet for Graph user {GraphUserId} because neither lastPasswordChangeDateTime nor the custom attribute was available.",
                        userId);

                    var bootstrappedExpiresAtUtc = CalculatePasswordExpiry(bootstrappedAtUtc);
                    return PasswordAgeCheckResult.Success(bootstrappedAtUtc, bootstrappedExpiresAtUtc, false);
                }
            }

            return PasswordAgeCheckResult.Fail(
                "Microsoft Graph no devolvió ninguna fecha valida para el ultimo cambio de contraseña del usuario y no fue posible inicializar el atributo custom LastPasswordSet.");
        }

        var expiresAtUtc = CalculatePasswordExpiry(lastPasswordSetUtc.Value);
        return PasswordAgeCheckResult.Success(lastPasswordSetUtc.Value, expiresAtUtc, DateTimeOffset.UtcNow >= expiresAtUtc);
    }

    public async Task<bool> TrySetLastPasswordSetAsync(ClaimsPrincipal principal, string fallbackEmail, DateTimeOffset timestampUtc, CancellationToken cancellationToken)
    {
        if (!IsConfigured())
        {
            _logger.LogWarning("Graph user lifecycle is not configured. Skipping LastPasswordSet update for {FallbackEmail}.", fallbackEmail);
            return false;
        }

        var extensionName = _options.LastPasswordSetExtensionName?.Trim();
        if (string.IsNullOrWhiteSpace(extensionName))
        {
            _logger.LogInformation("No LastPasswordSet extension configured. Skipping custom attribute update for {FallbackEmail}.", fallbackEmail);
            return false;
        }

        var accessToken = await AcquireAccessTokenAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return false;
        }

        var userId = await ResolveGraphUserIdAsync(principal, fallbackEmail, accessToken, cancellationToken);
        if (string.IsNullOrWhiteSpace(userId))
        {
            _logger.LogWarning("Could not resolve Graph user id to update LastPasswordSet for {FallbackEmail}.", fallbackEmail);
            return false;
        }

        return await SetLastPasswordSetAsync(userId, extensionName, accessToken, timestampUtc, cancellationToken);
    }

    public Task<bool> TrySetLastPasswordSetAsync(string fallbackEmail, DateTimeOffset timestampUtc, CancellationToken cancellationToken)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        return TrySetLastPasswordSetAsync(principal, fallbackEmail, timestampUtc, cancellationToken);
    }

    public Task<bool> TrySetLastSuccessSignInAsync(ClaimsPrincipal principal, string fallbackEmail, DateTimeOffset timestampUtc, CancellationToken cancellationToken)
        => TrySetCustomTimestampAsync(
            principal,
            fallbackEmail,
            timestampUtc,
            _options.LastSuccessSignInExtensionName,
            "LastSuccessSignIn",
            cancellationToken);

    public Task<bool> TrySetLastSuccessSignInAsync(string fallbackEmail, DateTimeOffset timestampUtc, CancellationToken cancellationToken)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        return TrySetLastSuccessSignInAsync(principal, fallbackEmail, timestampUtc, cancellationToken);
    }

    public Task<bool> TrySetLastFailedSignInAsync(string fallbackEmail, DateTimeOffset timestampUtc, CancellationToken cancellationToken)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        return TrySetCustomTimestampAsync(
            principal,
            fallbackEmail,
            timestampUtc,
            _options.LastFailedSignInExtensionName,
            "LastFailedSignIn",
            cancellationToken);
    }

    private async Task<bool> TrySetCustomTimestampAsync(
        ClaimsPrincipal principal,
        string fallbackEmail,
        DateTimeOffset timestampUtc,
        string? extensionName,
        string attributeLabel,
        CancellationToken cancellationToken)
    {
        if (!IsConfigured())
        {
            _logger.LogWarning("Graph user lifecycle is not configured. Skipping {AttributeLabel} update for {FallbackEmail}.", attributeLabel, fallbackEmail);
            return false;
        }

        var trimmedExtensionName = extensionName?.Trim();
        if (string.IsNullOrWhiteSpace(trimmedExtensionName))
        {
            _logger.LogInformation("No {AttributeLabel} extension configured. Skipping custom attribute update for {FallbackEmail}.", attributeLabel, fallbackEmail);
            return false;
        }

        var accessToken = await AcquireAccessTokenAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return false;
        }

        var userId = await ResolveGraphUserIdAsync(principal, fallbackEmail, accessToken, cancellationToken);
        if (string.IsNullOrWhiteSpace(userId))
        {
            _logger.LogWarning("Could not resolve Graph user id to update {AttributeLabel} for {FallbackEmail}.", attributeLabel, fallbackEmail);
            return false;
        }

        return await SetTimestampAttributeAsync(userId, trimmedExtensionName, accessToken, timestampUtc, cancellationToken);
    }

    private async Task<bool> SetLastPasswordSetAsync(string userId, string extensionName, string accessToken, DateTimeOffset timestampUtc, CancellationToken cancellationToken)
    {
        return await SetTimestampAttributeAsync(userId, extensionName, accessToken, timestampUtc, cancellationToken);
    }

    private async Task<bool> SetTimestampAttributeAsync(string userId, string extensionName, string accessToken, DateTimeOffset timestampUtc, CancellationToken cancellationToken)
    {
        return await SetUserAttributesAsync(
            userId,
            accessToken,
            new Dictionary<string, object?>
            {
                [extensionName] = timestampUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            },
            cancellationToken);
    }

    private async Task<bool> SetUserAttributesAsync(string userId, string accessToken, IReadOnlyDictionary<string, object?> attributes, CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Serialize(attributes);

        using var request = new HttpRequestMessage(
            HttpMethod.Patch,
            $"https://graph.microsoft.com/v1.0/users/{Uri.EscapeDataString(userId)}")
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json"),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        if (response.IsSuccessStatusCode)
        {
            return true;
        }

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        _logger.LogWarning("Graph PATCH user failed for {GraphUserId}. Status={StatusCode}. Body={Body}", userId, response.StatusCode, content);
        return false;
    }

    private async Task<GraphUserContext?> ResolveGraphUserContextAsync(string fallbackEmail, CancellationToken cancellationToken)
    {
        if (!IsConfigured())
        {
            _logger.LogWarning("Graph user lifecycle is not configured. Skipping Graph-backed user state for {FallbackEmail}.", fallbackEmail);
            return null;
        }

        var accessToken = await AcquireAccessTokenAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return null;
        }

        var userId = await ResolveGraphUserIdAsync(new ClaimsPrincipal(new ClaimsIdentity()), fallbackEmail, accessToken, cancellationToken);
        if (string.IsNullOrWhiteSpace(userId))
        {
            _logger.LogWarning("Could not resolve Graph user id for {FallbackEmail}.", fallbackEmail);
            return null;
        }

        return new GraphUserContext(userId, accessToken);
    }

    private async Task<JsonDocument?> GetUserDocumentAsync(string userId, string accessToken, IReadOnlyCollection<string> selectProperties, CancellationToken cancellationToken)
    {
        var requestUri = $"https://graph.microsoft.com/v1.0/users/{Uri.EscapeDataString(userId)}?$select={Uri.EscapeDataString(string.Join(',', selectProperties))}";
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("Graph GET user failed for {GraphUserId}. Status={StatusCode}. Body={Body}", userId, response.StatusCode, content);
            return null;
        }

        return JsonDocument.Parse(content);
    }

    private SignInLockoutStateResult CreateSignInLockoutState(JsonElement root)
    {
        var failedAttempts = TryReadIntValue(root, GetFailedSignInCountExtensionName(), out var parsedFailedAttempts)
            ? Math.Max(0, parsedFailedAttempts)
            : 0;

        var lockedUntilUtc = TryReadDateTimeOffsetValue(root, GetLockoutEndUtcExtensionName(), out var parsedLockedUntilUtc)
            ? parsedLockedUntilUtc.ToUniversalTime()
            : (DateTimeOffset?)null;

        return SignInLockoutStateResult.Success(failedAttempts, _options.MaxFailedSignInAttempts, lockedUntilUtc);
    }

    private IReadOnlyCollection<string> GetSignInLockoutSelectProperties()
        => new[] { GetFailedSignInCountExtensionName(), GetLockoutEndUtcExtensionName() };

    private string GetFailedSignInCountExtensionName()
        => _options.FailedSignInCountExtensionName!.Trim();

    private string GetLockoutEndUtcExtensionName()
        => _options.LockoutEndUtcExtensionName!.Trim();

    private bool IsSignInLockoutEnabled()
    {
        return _options.MaxFailedSignInAttempts > 0
            && _options.LockoutDurationSeconds > 0
            && !string.IsNullOrWhiteSpace(_options.FailedSignInCountExtensionName)
            && !string.IsNullOrWhiteSpace(_options.LockoutEndUtcExtensionName);
    }

    private static bool TryReadIntValue(JsonElement root, string propertyName, out int value)
    {
        value = 0;

        if (!root.TryGetProperty(propertyName, out var property))
        {
            return false;
        }

        if (property.ValueKind == JsonValueKind.Number)
        {
            return property.TryGetInt32(out value);
        }

        return property.ValueKind == JsonValueKind.String
            && int.TryParse(property.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryReadDateTimeOffsetValue(JsonElement root, string propertyName, out DateTimeOffset value)
    {
        value = default;

        return root.TryGetProperty(propertyName, out var property)
            && property.ValueKind == JsonValueKind.String
            && DateTimeOffset.TryParse(property.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out value);
    }

    private async Task<string?> ResolveGraphUserIdAsync(ClaimsPrincipal principal, string fallbackEmail, string accessToken, CancellationToken cancellationToken)
    {
        var objectId = principal.FindFirstValue("oid")
            ?? principal.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier");

        if (!string.IsNullOrWhiteSpace(objectId))
        {
            return objectId;
        }

        var signInIdentifier = principal.FindFirstValue(ClaimTypes.Email)
            ?? principal.FindFirstValue("email")
            ?? principal.FindFirstValue("preferred_username")
            ?? fallbackEmail;

        if (string.IsNullOrWhiteSpace(signInIdentifier))
        {
            _logger.LogWarning("Graph user resolution failed because no oid or sign-in identifier was available.");
            return null;
        }

        var escapedIdentifier = EscapeODataString(signInIdentifier);
        var filter = $"mail eq '{escapedIdentifier}' or userPrincipalName eq '{escapedIdentifier}'";
        var requestUri = $"https://graph.microsoft.com/v1.0/users?$filter={Uri.EscapeDataString(filter)}&$select=id,mail,userPrincipalName";
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("Graph user lookup failed for {SignInIdentifier}. Status={StatusCode}. Body={Body}", signInIdentifier, response.StatusCode, content);
            return null;
        }

        using var document = JsonDocument.Parse(content);
        if (TryGetFirstUserId(document.RootElement, out var directUserId))
        {
            return directUserId;
        }

        return await ResolveGraphUserIdByScanningUsersAsync(signInIdentifier, accessToken, cancellationToken);
    }

    private async Task<string?> ResolveGraphUserIdByScanningUsersAsync(string signInIdentifier, string accessToken, CancellationToken cancellationToken)
    {
        var requestUri = "https://graph.microsoft.com/v1.0/users?$select=id,mail,userPrincipalName,identities";

        while (!string.IsNullOrWhiteSpace(requestUri))
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            using var response = await _httpClient.SendAsync(request, cancellationToken);
            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Graph user scan failed for {SignInIdentifier}. Status={StatusCode}. Body={Body}", signInIdentifier, response.StatusCode, content);
                return null;
            }

            using var document = JsonDocument.Parse(content);
            if (document.RootElement.TryGetProperty("value", out var value)
                && value.ValueKind == JsonValueKind.Array)
            {
                foreach (var candidate in value.EnumerateArray())
                {
                    if (UserMatchesIdentifier(candidate, signInIdentifier)
                        && candidate.TryGetProperty("id", out var idElement))
                    {
                        return idElement.GetString();
                    }
                }
            }

            requestUri = document.RootElement.TryGetProperty("@odata.nextLink", out var nextLink)
                ? nextLink.GetString()
                : null;
        }

        _logger.LogWarning("Graph user lookup returned no results for {SignInIdentifier}.", signInIdentifier);
        return null;
    }

    private static bool TryGetFirstUserId(JsonElement root, out string? userId)
    {
        userId = null;

        if (!root.TryGetProperty("value", out var value)
            || value.ValueKind != JsonValueKind.Array
            || value.GetArrayLength() == 0)
        {
            return false;
        }

        var first = value[0];
        if (!first.TryGetProperty("id", out var idElement))
        {
            return false;
        }

        userId = idElement.GetString();
        return !string.IsNullOrWhiteSpace(userId);
    }

    private static bool UserMatchesIdentifier(JsonElement user, string signInIdentifier)
    {
        if (PropertyEquals(user, "mail", signInIdentifier) || PropertyEquals(user, "userPrincipalName", signInIdentifier))
        {
            return true;
        }

        if (!user.TryGetProperty("identities", out var identities) || identities.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var identity in identities.EnumerateArray())
        {
            if (!identity.TryGetProperty("issuerAssignedId", out var issuerAssignedId)
                || issuerAssignedId.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            if (string.Equals(issuerAssignedId.GetString(), signInIdentifier, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool PropertyEquals(JsonElement element, string propertyName, string expected)
    {
        return element.TryGetProperty(propertyName, out var property)
            && property.ValueKind == JsonValueKind.String
            && string.Equals(property.GetString(), expected, StringComparison.OrdinalIgnoreCase);
    }

    private static string EscapeODataString(string value)
        => value.Replace("'", "''", StringComparison.Ordinal);

    private bool IsConfigured()
    {
        return !string.IsNullOrWhiteSpace(ResolveTenant())
            && !string.IsNullOrWhiteSpace(ResolveClientId())
            && !string.IsNullOrWhiteSpace(_options.ClientSecret);
    }

    private string ResolveTenant()
        => _options.TenantIdOrDomain?.Trim() ?? _nativeAuthenticationOptions.TenantDomain;

    private string ResolveClientId()
        => _options.ClientId?.Trim() ?? _nativeAuthenticationOptions.ClientId;

    private async Task<string?> AcquireAccessTokenAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"https://login.microsoftonline.com/{ResolveTenant()}/oauth2/v2.0/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = ResolveClientId(),
                ["client_secret"] = _options.ClientSecret!,
                ["scope"] = GraphScope,
                ["grant_type"] = "client_credentials",
            }),
        };

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("Graph token acquisition failed. Status={StatusCode}. Body={Body}", response.StatusCode, content);
            return null;
        }

        using var document = JsonDocument.Parse(content);
        return document.RootElement.TryGetProperty("access_token", out var accessToken)
            ? accessToken.GetString()
            : null;
    }
}

internal sealed class GraphUserContext
{
    public GraphUserContext(string userId, string accessToken)
    {
        UserId = userId;
        AccessToken = accessToken;
    }

    public string UserId { get; }

    public string AccessToken { get; }
}

public sealed class PasswordAgeCheckResult
{
    private PasswordAgeCheckResult(bool isSuccess, string? failureMessage, DateTimeOffset? lastPasswordSetUtc, DateTimeOffset? expiresAtUtc, bool isExpired)
    {
        IsSuccess = isSuccess;
        FailureMessage = failureMessage;
        LastPasswordSetUtc = lastPasswordSetUtc;
        ExpiresAtUtc = expiresAtUtc;
        IsExpired = isExpired;
    }

    public bool IsSuccess { get; }

    public string? FailureMessage { get; }

    public DateTimeOffset? LastPasswordSetUtc { get; }

    public DateTimeOffset? ExpiresAtUtc { get; }

    public bool IsExpired { get; }

    public static PasswordAgeCheckResult Success(DateTimeOffset lastPasswordSetUtc, DateTimeOffset expiresAtUtc, bool isExpired)
        => new(true, null, lastPasswordSetUtc, expiresAtUtc, isExpired);

    public static PasswordAgeCheckResult Fail(string failureMessage)
        => new(false, failureMessage, null, null, false);
}

public sealed class SignInLockoutStateResult
{
    private SignInLockoutStateResult(bool isEnabled, bool isAvailable, int failedAttempts, int maxFailedAttempts, DateTimeOffset? lockedUntilUtc)
    {
        IsEnabled = isEnabled;
        IsAvailable = isAvailable;
        FailedAttempts = failedAttempts;
        MaxFailedAttempts = maxFailedAttempts;
        LockedUntilUtc = lockedUntilUtc;
    }

    public bool IsEnabled { get; }

    public bool IsAvailable { get; }

    public int FailedAttempts { get; }

    public int MaxFailedAttempts { get; }

    public DateTimeOffset? LockedUntilUtc { get; }

    public bool IsLocked => LockedUntilUtc.HasValue && LockedUntilUtc.Value > DateTimeOffset.UtcNow;

    public static SignInLockoutStateResult Disabled()
        => new(false, true, 0, 0, null);

    public static SignInLockoutStateResult Unavailable(int maxFailedAttempts)
        => new(true, false, 0, maxFailedAttempts, null);

    public static SignInLockoutStateResult Success(int failedAttempts, int maxFailedAttempts, DateTimeOffset? lockedUntilUtc)
        => new(true, true, failedAttempts, maxFailedAttempts, lockedUntilUtc);
}