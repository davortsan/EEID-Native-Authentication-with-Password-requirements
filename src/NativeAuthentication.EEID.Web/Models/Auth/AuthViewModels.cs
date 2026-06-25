using System.ComponentModel.DataAnnotations;

namespace NativeAuthentication.EEID.Web.Models.Auth;

public sealed class SignInViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;
}

public sealed class SignUpViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    [Compare(nameof(Password))]
    public string ConfirmPassword { get; set; } = string.Empty;

    [Display(Name = "Display name")]
    public string? DisplayName { get; set; }
}

public sealed class VerifyOtpViewModel
{
    [Required]
    [Display(Name = "One-time passcode")]
    public string Code { get; set; } = string.Empty;

    public string? TargetLabel { get; set; }

    public string? FlowDescription { get; set; }
}

public sealed class RequiredAttributesViewModel
{
    public string Title { get; set; } = string.Empty;

    public List<RequiredAttributeInputViewModel> Attributes { get; set; } = new();
}

public sealed class RequiredAttributeInputViewModel
{
    [Required]
    public string Name { get; set; } = string.Empty;

    public string Type { get; set; } = "string";

    public bool Required { get; set; }

    [Required]
    public string Value { get; set; } = string.Empty;
}

public sealed class ForgotPasswordViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}

public sealed class ResetPasswordViewModel
{
    [Required]
    [DataType(DataType.Password)]
    public string NewPassword { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    [Compare(nameof(NewPassword))]
    public string ConfirmPassword { get; set; } = string.Empty;
}

public sealed class SignedInUserViewModel
{
    public string? DisplayName { get; init; }

    public string? Email { get; init; }

    public DateTimeOffset? AccessTokenExpiresAt { get; init; }
}