# Google, Apple and Entra sign-in

The optional identity broker provides one provider chooser for coordinator enrollment and the private management console. Configure Google, Apple, Entra, or a subset. The existing direct-Entra profile and disposable token lab retain their existing behavior. Provider authentication uses the system browser, including from the Mac and iPhone clients; client secrets and Apple signing keys stay on the coordinator host.

This is an additional four-container deployment profile. The profile itself does not create provider applications, complete a provider's approval process, establish a live login, or qualify a signed Apple VPN installation. `covee setup` registers Microsoft sign-in itself and guides you through Google and Apple ([CLI](cli.md)); this page describes the profile underneath and how to run it by hand. Provider account policies and quotas still apply; the broker adds no limit on the number of users.

## Register the upstream providers

The examples use `covee.example.com`; use your network's stable public hostname instead. The broker issuer is `https://covee.example.com/identity`; it has no public administration UI. The private console remains `https://localhost:8444` through the existing SSH forwarding arrangement. Upstream provider callbacks go to the public broker; its downstream clients return only to their exact configured coordinator or private-console callback.

| Provider | Application type | Exact upstream callback |
| --- | --- | --- |
| Google | OAuth client of type Web application | `https://covee.example.com/identity/callback/google` |
| Apple | Services ID associated with a primary App ID enabled for Sign in with Apple | `https://covee.example.com/identity/callback/apple` |
| Entra, when enabled | One confidential, tenant-specific web application for the broker | `https://covee.example.com/identity/callback/entra` |

Covee needs its own application registration with each provider it uses: a Gmail or Apple Account identifies the person signing in, not the application. Networks of one organization can share a Google client, with a redirect URI for each. Access to the domain, for example in Route 53, supplies neither provider's credentials. Providers can be enabled independently; for example, start with Google or Entra while an Apple registration is completed. Sign-in also needs reachable, trusted HTTPS at the exact callback above and explicit access grants after authentication.

For Google, select a Google Cloud project, configure the consent/branding settings and the exact authorized redirect URI, and create a Web application OAuth client. Keep its client ID and private client secret on the coordinator. The broker requests only `openid profile email`, with no Gmail or mailbox access scopes; it uses the verified immutable `sub` claim for authorization, not an email address, hosted-domain hint, or profile name. Google documents [OAuth client setup](https://support.google.com/cloud/answer/15549257), [OpenID Connect registration and token claims](https://developers.google.com/identity/openid-connect/openid-connect), and its [OAuth application policies](https://developers.google.com/identity/protocols/oauth2/policies). Basic OpenID/profile/email-only sign-in has an exception to the general testing-mode user-list and seven-day authorization restrictions; see [Google's audience configuration rules](https://support.google.com/cloud/answer/15549945).

For Apple, register the public domain and exact return URL under a Services ID linked to a primary Sign in with Apple App ID. Apple requires a domain-based HTTPS return URL; `localhost` and IP-address callbacks are unsupported. Create the associated Sign in with Apple private key and retain its `.p8` file, ten-character key ID and ten-character team ID. The broker signs a short-lived ES256 client-secret JWT for each token exchange; do not paste a long-lived precomputed JWT into the deployment configuration. See [Apple's web setup](https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/) and [environment/key configuration](https://developer.apple.com/documentation/signinwithapple/configuring-your-environment-for-sign-in-with-apple).

This key must be enabled for Sign in with Apple and associated with the correct primary App ID. Native app code-signing certificates/private keys and App Store Connect API keys serve different purposes; a `.p8` filename alone does not establish login-key eligibility. Reuse a local key only after verifying its service and app association in the developer account. See [Sign in with Apple key setup](https://developer.apple.com/help/account/capabilities/create-a-sign-in-with-apple-private-key) and [App Store Connect API access](https://developer.apple.com/help/app-store-connect/get-started/app-store-connect-api/).

The Apple callback uses `form_post` with a browser-binding cookie suitable for a cross-site HTTPS POST. Browser-supplied name/email payloads do not authorize access. Apple may supply initial profile data only on the first authorization; this implementation does not need it and never links accounts by email. See [Apple's authorization request documentation](https://developer.apple.com/documentation/signinwithapplerestapi/request-an-authorization-to-the-sign-in-with-apple-server).

For brokered Entra, create one registration for the upstream broker, require assignment, define exact user app roles `Covee.Admin` and `Covee.Reader`, and assign console users appropriately. Configure group claims and explicit enrollment group object UUIDs in this provider's `allowed_group_ids`. Console roles and enrollment groups remain independent. A token with group overage instead of the required group list is denied enrollment; the broker does not query Graph. Sending only groups assigned to the application avoids overage, but once the registration defines app roles Entra will not give a group plain default access, so give the enrollment group a sign-in-only role such as `Covee.User`, which the broker ignores. Assigning that group `Covee.Reader` instead would give every device user console access. See [app roles](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps), [ID-token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference), and [assignment restrictions](https://learn.microsoft.com/en-us/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users).

## Prepare and start a new broker runtime

Copy [deployment.social.example.json](../deploy/deployment.social.example.json) outside the destination runtime. Remove providers you do not intend to enable. Replace all placeholder IDs, hosts and absolute private source-file paths. All credentials must be private regular files readable by the dedicated non-root service account. Leave `grants` empty initially, or include only independently verified provider subjects.

The top-level `identity` profile is mutually exclusive with the direct-Entra `oidc` and `allowed_group_ids` fields. Preparation requires a new directory. It creates separate random coordinator/console client secrets, an RSA 3072 signing key, a private broker TLS certificate, copied provider credentials, and a strict provider/client/grant configuration. It records container credential paths rather than operator source paths in portable metadata.

```sh
python3 scripts/deploy.py prepare --config /srv/covee/deployment.social.json --directory /srv/covee/social-runtime
python3 scripts/deploy.py validate --directory /srv/covee/social-runtime
python3 scripts/deploy.py build --with-identity
python3 scripts/deploy.py up --directory /srv/covee/social-runtime
```

This profile requires Docker Compose 2.24.4 or later for `!override` port replacement. Inside the private Docker network, the public control hostname resolves to the gateway, which listens on container TCP 443. A container-local `net.ipv4.ip_unprivileged_port_start=443` setting allows its existing non-root user to bind that port with all capabilities dropped. It does not change the host sysctl. The existing direct-Entra profile still uses container TCP 8443.

During startup, the gateway exposes only the broker identity routes while Headscale verifies discovery and the operator script checks the persisted network policy. Coordinator and administration routes remain denied during this phase. The script then recreates the ordinary gateway configuration. Identity-provider discovery or policy failure prevents completion. Provider credentials and the broker signing key are included in the existing encrypted backup/restore contract; retain the same off-host recovery controls.

## Approve Google and Apple accounts

Successful provider authentication alone grants no access. An unapproved Google or Apple account receives an access-denied page displaying the verified provider and exact subject. Obtain that pair from the intended person through a trusted channel, verify that it belongs to the intended account, and explicitly grant the required capabilities. An email address, Apple relay address, or matching profile name cannot replace the subject. Providers remain separate even when their email addresses match.

Put the complete desired grants array in a private JSON file outside the runtime. Enrollment and console access are independent; a console Reader cannot mutate settings. For example:

```json
[
  {"provider": "google", "subject": "REPLACE_WITH_VERIFIED_GOOGLE_SUB", "role": "Covee.Admin", "enroll": true},
  {"provider": "apple", "subject": "REPLACE_WITH_VERIFIED_APPLE_SUB", "role": "Covee.Reader", "enroll": false}
]
```

Apply the complete list using the selected runtime's operation lock:

```sh
python3 scripts/deploy.py update-identity-grants --config /srv/covee/social-grants.json --directory /srv/covee/social-runtime
```

This validates and replaces the broker/metadata grant lists and recreates only that broker service. An empty list removes all Google/Apple grants. Restarting the broker invalidates its pending login flows, authorization codes and access tokens. Already-issued signed ID tokens and management sessions can remain valid until their expiry, capped by the broker's five-minute ID-token lifetime. Removing enrollment permission does not remove an enrolled node. Revoke affected nodes and access policy through administration when immediate network revocation is required.

Keep the broker signing key and upstream provider registration stable during recovery: issuer plus verified upstream subject determine the broker account identity. Changing a provider client registration, Apple's primary-app grouping, or the issuer can change subjects. There is no automatic account linking or migration. Moving an existing direct-Entra coordinator to the broker also changes the issuer and Entra pairwise subject; plan an explicit device/user migration in a separate runtime instead of editing a live installation in place.

## How people appear

The broker passes each person's email address and name to the coordinator and the console, which show them in device lists and on Tailscale clients instead of an account ID. They only label the person: access, roles and the account itself still come from the issuer and subject alone, so two accounts with one address stay two people. Google's and Apple's addresses are passed only when the provider marks them verified; Apple sends no name in its token, so its address doubles as the name. Entra's address is the `email` claim, present for guests, or otherwise the sign-in name (`preferred_username`) when it is an email address; the broker does not request Entra's `email` scope, which would ask every member to consent again. Covee accounts use the address and name their invite set. Access rules that Covee writes, such as a gateway entry for chosen people, name the account rather than the address, so a changed or shared address never changes whom a rule covers. The coordinator updates a person's address and name at each sign-in, so people who signed in before this behavior appear by account ID until their next sign-in.

## Remaining production acceptance

The local tests validate signed tokens, redirects, browser bindings, role/enrollment decisions and deployment contracts. The four-container runtime smoke also checks real Headscale/console discovery against the broker, identity-only startup, persisted default deny, public/private route isolation and container hardening. It fetches real public Google discovery metadata with disposable placeholder client credentials; it does not log into a provider account. Run it after building the optional image:

```sh
python3 scripts/social_check.py
```

The smoke publishes no host ports, uses a separate project and cleans up its containers. Live Google consent, live Apple sign-in, live Entra assignment behavior, public DNS/TLS/ingress, and signed Mac/iPhone browser-to-VPN flows require separate acceptance with the intended registrations and accounts. The Apple callback currently requires the exact `Origin: https://appleid.apple.com`; browser privacy modes that replace this with `null` are rejected and need explicit live qualification.

This broker does not implement refresh tokens, provider logout, continuous access evaluation, Graph/SCIM reconciliation, or provider-driven account/session notifications. Apple access and refresh tokens are not persisted; Apple grant revocation and account-deletion lifecycle support remain outstanding. Before distributing an app that requires that lifecycle, implement and qualify the requirements in [Apple's account-deletion and token-revocation guidance](https://developer.apple.com/documentation/technotes/tn3194-handling-account-deletions-and-revoking-tokens-for-sign-in-with-apple) and [revocation API](https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens). Console logout ends the local session, not the user's upstream provider session. Provider signing-key rotation/revocation and secret expiry require operator monitoring and replacement.
