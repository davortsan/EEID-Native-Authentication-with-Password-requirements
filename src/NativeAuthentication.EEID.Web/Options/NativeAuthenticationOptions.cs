using System.ComponentModel.DataAnnotations;

namespace NativeAuthentication.EEID.Web.Options;

public sealed class NativeAuthenticationOptions
{
    public const string SectionName = "NativeAuthentication";

    [Required]
    public string TenantSubdomain { get; init; } = string.Empty;

    [Required]
    public string TenantDomain { get; init; } = string.Empty;

    [Required]
    public string ClientId { get; init; } = string.Empty;

    [Required]
    public string Scopes { get; init; } = "openid profile offline_access";

    [Required]
    public string SignInChallengeType { get; init; } = "password redirect";

    [Required]
    public string SignUpChallengeType { get; init; } = "oob password redirect";

    [Required]
    public string ResetPasswordChallengeType { get; init; } = "oob redirect";

    public string Capabilities { get; init; } = "registration_required mfa_required";

    public string AuthorityBaseUrl => $"https://{TenantSubdomain}.ciamlogin.com/{TenantDomain}";
}