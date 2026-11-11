# IAM OIDC Provider vs. Identity Center Trusted Token Issuer

Two AWS objects use the same Entra ID issuer URL (`https://login.microsoftonline.com/<tenant-id>/v2.0`). They look like duplicates, but they are separate resources that do different jobs. The PEP's Plane A uses **both**, one after the other.

| | IAM → Identity providers (OIDC provider) | IAM Identity Center → Settings → Trusted token issuer |
|---|---|---|
| **Service** | AWS STS / IAM | IAM Identity Center (`sso-oauth`) |
| **What it does** | Lets an Entra JWT assume an IAM role through `sts:AssumeRoleWithWebIdentity` | Lets Identity Center accept an Entra JWT in `sso-oauth:CreateTokenWithIAM` and map it to an Identity Center user |
| **Gives you** | Temporary AWS credentials. These are a role, not a user identity | An Identity Center token carrying the user's identity context. This is what Trusted Identity Propagation (TIP) needs |
| **Trust check** | The token's `aud` must be one of the provider's **Audiences** | Issuer URL plus attribute mapping (for example `email` → Identity Center user email). The issuer is applied to a customer-managed Identity Center application that has the JWT-bearer grant, and that grant lists the accepted audiences (**Aud claim**) |
| **ARN shape** | `arn:aws:iam::<account>:oidc-provider/login.microsoftonline.com/<tenant-id>/v2.0` | `arn:aws:sso::<account>:trustedTokenIssuer/<instance-id>/tti-<id>` |

## How the PEP uses them

1. **Plane A, step 1:** The PEP calls `AssumeRoleWithWebIdentity` with the Entra JWT to assume the OIDC bootstrap role (`OIDC_ROLE_ARN`). This needs the **IAM OIDC provider**. The role's trust policy has `Principal: {"Federated": "<OidcProviderArn>"}` and a `<issuer-host>:aud` condition.
2. **Plane A, step 2:** With the OIDC role credentials, the PEP calls `CreateTokenWithIAM` using the same JWT. This needs the **trusted token issuer**. `CreateTokenWithIAM` is SigV4-signed, so step 1 is how the PEP gets the IAM credentials to sign it. The OIDC role is allowed `sso-oauth:CreateTokenWithIAM` and nothing else.
3. **Plane B:** The PEP base role (the Fargate task role) assumes the identity-enhanced carrier role (`TIP_ROLE_ARN`) with `SetContext`. `ProvidedContexts` carries the Identity Center assertion. The PEP then queries Athena and Lake Formation as that user.

```
Entra JWT --AssumeRoleWithWebIdentity--> OIDC role          (needs IAM OIDC provider)
          --CreateTokenWithIAM---------> identity context   (needs trusted token issuer + IdC app grant)
PEP base role --AssumeRole + SetContext--> carrier role --> Lake Formation / Athena
```

If you delete the IAM OIDC provider, step 1 fails and `/sessions/init` breaks. You could drop it only if the PEP signed `CreateTokenWithIAM` with some other credentials, such as its task role. The current design does not do that. See [pep-base-identity.md](./pep-base-identity.md) for the role design.

## The `aud` claim must be accepted in two places

The Entra token's `aud` has to match in both of these places:

1. **IAM OIDC provider → Audiences:** one of the listed client IDs. The OIDC role's trust policy `aud` condition must also include it.
2. **Identity Center application → trusted token issuer → Aud claim** (`AuthorizedAudiences` in the API).

On the trusted token issuer itself (IAM Identity Center → Settings → Authentication → Trusted token issuers), the console shows only the issuer URL and attribute mapping. **It does not show `aud`.** The audience is set per application:

- **Console:** IAM Identity Center → **Applications** → **Customer managed** → *your app* → **Trusted applications for identity propagation** / **Authentication** → **Trusted token issuers**. Each issuer listed there shows its **Aud claim**. Click **Edit** to change it.
- **CLI:**

  ```powershell
  aws sso-admin get-application-grant `
    --application-arn <idc-application-arn> `
    --grant-type "urn:ietf:params:oauth:grant-type:jwt-bearer" `
    --region <idc-region>
  ```

  ```json
  "JwtBearer": {
    "AuthorizedTokenIssuers": [{
      "TrustedTokenIssuerArn": "arn:aws:sso::<account>:trustedTokenIssuer/<instance-id>/tti-<id>",
      "AuthorizedAudiences": ["<client-id or api://...>"]
    }]
  }
  ```

With MSAL PKCE and a custom API scope, `aud` is usually the API app's client ID or `api://...`, not the SPA's client ID. If the Entra scope or app registration changes and the token's `aud` changes, update **both** places.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `AssumeRoleWithWebIdentity` fails with `InvalidIdentityToken` | No IAM OIDC provider for the token's issuer, or the issuer URL doesn't match exactly (`/v2.0` vs. v1 `sts.windows.net/<tenant>/`) |
| `AssumeRoleWithWebIdentity` fails with `AccessDenied` | The token's `aud` isn't in the OIDC role's trust-policy `aud` condition or the provider's Audiences |
| `CreateTokenWithIAM` fails with `invalid_grant` | The `aud` isn't in the application's `AuthorizedAudiences`, the issuer isn't attached to the application, or the attribute mapping doesn't resolve to an Identity Center user |
| `CreateTokenWithIAM` fails with `AccessDenied` | The OIDC role is missing `sso-oauth:CreateTokenWithIAM` |
