# NativeAuthentication.EEID

ASP.NET Core MVC application on .NET 9 to integrate Microsoft Entra External ID with Native Authentication from the server.

## Why this architecture

The Native Authentication APIs indicated by Microsoft do not support CORS. For that reason, this project does not call those endpoints from browser JavaScript; the Web App performs the HTTP calls from the server using `HttpClient`.

## What it includes

- Sign-in with `email + password`
- Sign-up with `email + password` and OTP verification
- Support for required attributes returned by Entra during sign-up
- Self-service password reset (SSPR)
- Password expiration enforcement with Microsoft Graph
- Temporary account lockout after consecutive failed sign-in attempts
- Configurable minimum password length and password complexity enforcement for sign-up and password reset
- Local ASP.NET Core session cookie after obtaining `id_token` and `access_token`

## Structure

- `src/NativeAuthentication.EEID.Web`: Web App MVC
- `src/NativeAuthentication.EEID.Web/Services/NativeAuthenticationClient.cs`: Native Authentication HTTP client
- `src/NativeAuthentication.EEID.Web/Controllers/AuthController.cs`: MVC authentication flows

## Required configuration in Entra External ID

Before running the app, configure the following in your external tenant:

1. Register an application.
2. Enable `public client` and `native authentication` for the registered app.
3. Grant admin consent where applicable.
4. Create and associate the sign-up/sign-in user flow.
5. If you use `email + password`, enable that method in the tenant.
6. If you use SSPR, enable self-service password reset for customer users.
7. If the flow will require MFA or strong method enrollment, keep the capabilities `registration_required mfa_required`.
8. If you want password expiration and sign-in lockout policies, create the required custom user attributes in External ID and make sure their programmable names match the values configured in `MicrosoftGraphUserLifecycle`.
9. The app registration used for `MicrosoftGraphUserLifecycle` must have Microsoft Graph application permission `User.ReadWrite.All` so the app can read and update the custom user attributes used by the repository.
10. If Microsoft Entra Password Protection is enabled in the tenant, configure its lockout-related thresholds with sufficiently high values so they don't interfere with the failed-attempt policy enforced by this application.

## Local configuration

Fill in the `NativeAuthentication` section in `appsettings.json`, or preferably in User Secrets:

```json
{
  "NativeAuthentication": {
    "TenantSubdomain": "contoso",
    "TenantDomain": "contoso.onmicrosoft.com",
    "ClientId": "00000000-0000-0000-0000-000000000000",
    "Scopes": "openid profile offline_access",
    "SignInChallengeType": "password redirect",
    "SignUpChallengeType": "oob password redirect",
    "ResetPasswordChallengeType": "oob redirect",
    "Capabilities": "registration_required mfa_required"
  }
}
```

To enforce password expiration, temporary sign-in lockout, and the configurable minimum password length, configure `MicrosoftGraphUserLifecycle` with an app secret or certificate-backed equivalent. This project reads the built-in `lastPasswordChangeDateTime` property when available, falls back to the custom attribute `extension_d697ea7bfcb54949bd86b3f886d023e7_LastPasswordSet`, and stores lockout state in custom user attributes.

```json
{
  "MicrosoftGraphUserLifecycle": {
    "TenantIdOrDomain": "contoso.onmicrosoft.com",
    "ClientId": "00000000-0000-0000-0000-000000000000",
    "ClientSecret": "<app-secret>",
    "LastPasswordSetExtensionName": "extension_d697ea7bfcb54949bd86b3f886d023e7_LastPasswordSet",
    "FailedSignInCountExtensionName": "extension_d697ea7bfcb54949bd86b3f886d023e7_FailedCount",
    "LockoutEndUtcExtensionName": "extension_d697ea7bfcb54949bd86b3f886d023e7_LockoutUntil",
    "PasswordMinLength": 15,
    "PasswordMaxAgeDays": 90,
    "MaxFailedSignInAttempts": 5,
    "LockoutDurationSeconds": 30,
    "UseBuiltInLastPasswordChangeDateTime": true
  }
}
```

The custom attribute can be updated in Microsoft Graph with a standard user `PATCH`:

```http
PATCH https://graph.microsoft.com/v1.0/users/user@contoso.com
Content-Type: application/json

{
  "extension_d697ea7bfcb54949bd86b3f886d023e7_LastPasswordSet": "2026-06-25T10:30:00.0000000Z"
}
```

And retrieved with `$select`:

```http
GET https://graph.microsoft.com/v1.0/users/user@contoso.com?$select=lastPasswordChangeDateTime,extension_d697ea7bfcb54949bd86b3f886d023e7_LastPasswordSet
```

To enable temporary account lockout after consecutive failed sign-in attempts, create the custom user attributes referenced by `FailedSignInCountExtensionName` and `LockoutEndUtcExtensionName`. The app stores the consecutive failed-attempt counter and the UTC timestamp until which the account remains blocked. By default, the account is locked after 5 consecutive failed attempts for 30 seconds, and all related values are configurable.

The current configuration expects these lockout attributes to be String-typed custom user attributes:

- `extension_d697ea7bfcb54949bd86b3f886d023e7_FailedCount`
- `extension_d697ea7bfcb54949bd86b3f886d023e7_LockoutUntil`

`PasswordMinLength` is also configured under `MicrosoftGraphUserLifecycle` and is enforced by the MVC app during sign-up and password reset before the request is sent to Entra.

For both new-user registration and password reset, the app currently requires passwords to satisfy all of the following rules:

- At least `PasswordMinLength` characters.
- At least one uppercase letter.
- At least one lowercase letter.
- At least one digit.
- At least one special character.

## Run

```powershell
dotnet run --project src/NativeAuthentication.EEID.Web/NativeAuthentication.EEID.Web.csproj
```

## Important notes

- The base project is prepared for the main `email + password + SSPR` flow.
- If Entra responds with `challenge_type=redirect`, the app currently shows the reason and does not yet implement the full web fallback.
- Custom attributes must be sent using their programmable name, for example `extension_<appIdWithoutHyphens>_<name>`.
- For custom user attributes, the programmable name and its casing must match exactly what External ID exposes in Graph.
- A custom user attribute can exist in the tenant and still not appear in a `GET /users?...$select=...` response until it has a value for that user.
- The Graph app registration used by this project needs application permission `User.ReadWrite.All` to manage the custom user attributes referenced in `MicrosoftGraphUserLifecycle`.
- If Password Protection lockout settings are stricter than the app-level failed-attempt policy, Entra can block the account before the repository's own `FailedCount` and `LockoutUntil` logic reaches its configured threshold.