using System.ComponentModel.DataAnnotations;

namespace NativeAuthentication.EEID.Web.Options;

public sealed class MicrosoftGraphUserLifecycleOptions
{
    public const string SectionName = "MicrosoftGraphUserLifecycle";

    public string? TenantIdOrDomain { get; init; }

    public string? ClientId { get; init; }

    public string? ClientSecret { get; init; }

    public string? LastPasswordSetExtensionName { get; init; } = "extension_d697ea7bfcb54949bd86b3f886d023e7_LastPasswordSet";

    public string? LastSuccessSignInExtensionName { get; init; } = "extension_d697ea7bfcb54949bd86b3f886d023e7_LastSuccessSignIn";

    public string? LastFailedSignInExtensionName { get; init; } = "extension_d697ea7bfcb54949bd86b3f886d023e7_LastFailedSignIn";

    public string? FailedSignInCountExtensionName { get; init; } = "extension_d697ea7bfcb54949bd86b3f886d023e7_FailedCount";

    public string? LockoutEndUtcExtensionName { get; init; } = "extension_d697ea7bfcb54949bd86b3f886d023e7_LockoutUntil";

    [RangeAttribute(1, int.MaxValue)]
    public int PasswordMinLength { get; init; } = 15;

    public int PasswordMaxAgeDays { get; init; } = 90;

    public int MaxFailedSignInAttempts { get; init; } = 5;

    public int LockoutDurationSeconds { get; init; } = 30;

    public bool UseBuiltInLastPasswordChangeDateTime { get; init; } = true;
}