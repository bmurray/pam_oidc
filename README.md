# pam\_oidc

> **This is a maintained fork of [salesforce/pam_oidc](https://github.com/salesforce/pam_oidc),
> which Salesforce archived in 2025.** It is not affiliated with or endorsed by
> Salesforce. The original work is copyright 2021 Salesforce.com, Inc., under the
> BSD 3-Clause License ([LICENSE.txt](LICENSE.txt)); this fork's changes are
> released under the same license.

**pam_oidc** authenticates users with an OpenID Connect (OIDC) token: the token
is presented as the password and verified locally against the issuer's published
signing keys (JWKS). There is no interactive login flow, which makes it suited to
machine identities such as Kubernetes ServiceAccount tokens.

Linux-PAM extensions are used, so currently the module only supports Linux. Contributions to support other operating systems are welcomed.

## What changed in this fork

- **Maintained JWT libraries.** Verification moved off the abandoned
  `pardot/oidc` library and the deprecated `gopkg.in/square/go-jose.v2` onto
  [`coreos/go-oidc` v3](https://github.com/coreos/go-oidc) and `go-jose` v4:
  discovery with issuer matching, cached JWKS, and signature, issuer, audience
  and expiry checks. Options and user templates are unchanged.
- **Current Go.** Built with Go 1.27 and current dependencies, using modern
  Go idioms throughout.
- **Logs to stderr as well as syslog**, since containers usually have no syslog
  daemon. Successful logins are logged by username. Tokens are never logged.
- **Tests rewritten** around an in-process issuer, covering wrong audience or
  issuer, expiry, an unpublished signing key, non-JWT input, a discovery document
  that names a different issuer, and Kubernetes ServiceAccount subject mapping.
- **Init-container image** ([`Dockerfile.module`](Dockerfile.module)) delivers
  the module to stock service images (MariaDB, PostgreSQL) at deploy time, so
  you don't maintain custom database images (see [Containers](#containers)).
- **Debian/Ubuntu packages.** Tagged releases ship a `.deb` (`libpam-oidc`,
  installed to `/usr/lib/x86_64-linux-gnu/security`) alongside the RPM
  (`pam_oidc`, `/usr/lib64/security`). Build locally with `make deb` or `make rpm`.
- **PostgreSQL support**, with an integration test (see [PostgreSQL](#postgresql)).
- The Go module path is now `github.com/bmurray/pam_oidc`.

Another independent fork, [MatthiasValvekens/pam_oidc](https://github.com/MatthiasValvekens/pam_oidc),
takes a different route: it vendors and maintains `pardot/oidc` itself and adds
on-disk caching of signing keys.

## Installing

Tagged [releases](https://github.com/bmurray/pam_oidc/releases) provide, with a
`SHA256SUMS` file:

- `libpam-oidc_<version>_amd64.deb` for Debian and Ubuntu (installs to
  `/usr/lib/x86_64-linux-gnu/security`)
- `pam_oidc-<version>-1.x86_64.rpm` for RHEL and Fedora (installs to
  `/usr/lib64/security`)
- `pam_oidc-<version>-linux-amd64-gnu.so`, the bare module, for container
  images or any other layout: copy it into your PAM module directory as
  `pam_oidc.so`, or reference it by absolute path in the PAM config.

The module is self-contained (the Go runtime and all Go dependencies are built
in). At runtime it needs:

- **A supported glibc distribution**: currently supported releases of Debian
  (12, 13) and Ubuntu (22.04, 24.04, 26.04), and RHEL 9 or newer. Builds target
  glibc 2.34, below the oldest of these. Releases that have reached end of life
  are not supported. CI loads the module through a real PAM stack on each of
  these releases.
- **Linux-PAM** (`libpam.so.0`). The module must be a shared object loaded by
  PAM, so it can't be fully static.
- **A CA bundle** at a standard path (for example
  `/etc/ssl/certs/ca-certificates.crt` or `/etc/pki/tls/certs/ca-bundle.crt`) to
  verify the issuer's HTTPS certificate. Minimal container images often lack one.
- **Network access** to the issuer's discovery document and JWKS at login time.

**musl (Alpine) is not supported.** musl's loader refuses to `dlopen` Go
`c-shared` libraries, because the Go runtime uses the initial-exec TLS model,
and PAM always loads modules with `dlopen`.
Running a static build through `pam_exec.so expose_authtok` is not a
workaround either: `pam_exec` copies the password into a 512-byte buffer and
silently truncates it, and OIDC tokens are usually longer (a Kubernetes
ServiceAccount token is typically around 850 bytes). Use a glibc-based image.

## Containers

Rather than building custom database images, deliver the module with an init
container and keep the stock image. The `Dockerfile.module` image copies
`pam_oidc.so` and a CA bundle into a shared `emptyDir`; the PAM config then
references the module by absolute path:

```yaml
initContainers:
  - name: pam-oidc
    image: ghcr.io/bmurray/pam_oidc:<version>   # copies into /opt/pam-oidc
    volumeMounts:
      - { name: pam-oidc, mountPath: /opt/pam-oidc }
containers:
  - name: db
    image: postgres:18          # or mariadb:12.3, unmodified
    volumeMounts:
      - { name: pam-oidc, mountPath: /opt/pam-oidc, readOnly: true }
      # Only if the image has no CA bundle (the official MariaDB and
      # PostgreSQL images don't):
      - { name: pam-oidc, mountPath: /etc/ssl/certs/ca-certificates.crt,
          subPath: ca-certificates.crt, readOnly: true }
volumes:
  - { name: pam-oidc, emptyDir: {} }
```

```
auth required /opt/pam-oidc/pam_oidc.so issuer=https://oidc.example.com aud=postgres ...
```

The database and the module then upgrade independently.

## Example Usage

In `/etc/pam.d/service`:

```
auth required pam_oidc.so <options>
```

Example for Google:

```
auth required pam_oidc.so issuer=https://accounts.google.com aud=12345-v12345.apps.googleusercontent.com
```

### Options

#### issuer

Required.

The issuer URL. The OpenID configuration should be available at _issuer_/.well-known/openid-configuration

#### aud

Required.

The audience value to expect. Tokens signed by the issuer but for a different audience will be rejected. This prevents tokens issued for a different purpose from being used for authentication.

#### user\_template

Default: `{{.Subject}}`

A Go [text/template](http://pkg.go.dev/text/template) that, when rendered with the JWT/OIDC claims, provides the expected username.

For example, `{{.Subject}}` would mean that users are expected to authenticate with the JWT `sub` claim as their username.

The `trimPrefix` and `trimSuffix` functions are available. For example `{{.Subject | trimSuffix "@example.com"}}` would mean a user whose token subject is `jdoe@example.com` would authenticate as `jdoe`.

#### groups\_claim\_key

Default: `groups`

The name of the key within the token claims that specifies which groups a user is a member of.

If the token uses a key other than `groups` (e.g., `{"roles":["a", "b", "c"]}`), specifies `groups_claim_key=roles`.

#### authorized\_groups

Default: (no value)

If specified, a comma-separated list of groups required for authentication to pass. A user must be a member of _at least_ one of the groups in the list, if specified.

#### require\_acr

Default: (no value)

If specified, the required value of the `acr` claim in the token for authentication to pass.

#### require\_acrs

Default: (no value)

If specified, a comma-separated list of acrs one of which must match the `acr` claim in the token for authentication to pass.

#### http\_proxy

Default: (no value)

If specified, an HTTP proxy used to connect to the issuer to discover OpenID Connect parameters.

## Kubernetes ServiceAccount tokens with MariaDB

Workloads can log in to MariaDB as `<namespace>:<serviceaccount>`, using their
ServiceAccount token as the password, provided the cluster's ServiceAccount
issuer publishes its discovery document and JWKS at an HTTPS URL the server can
reach.

`/etc/pam.d/mariadb-oidc` (the brackets let the argument contain spaces;
`pam_permit` is needed because MariaDB also runs the PAM account phase):

```
auth required pam_oidc.so issuer=https://oidc.example.com aud=mariadb [user_template={{.Subject | trimPrefix "system:serviceaccount:"}}]
account required pam_permit.so
```

Server configuration. The token is a bearer credential sent as a cleartext
password, so require TLS:

```ini
[mariadbd]
plugin_load_add = auth_pam
pam_use_cleartext_plugin = ON
require_secure_transport = ON
```

Accounts:

```sql
CREATE USER 'apps:billing'@'%' IDENTIFIED VIA pam USING 'mariadb-oidc';
GRANT ALL ON billing.* TO 'apps:billing'@'%';
```

Clients mount a projected token with a dedicated audience, so a database token
can't be replayed against the Kubernetes API, and re-read it on every connect
because the kubelet rotates it:

```yaml
volumes:
  - name: mariadb-token
    projected:
      sources:
        - serviceAccountToken:
            audience: mariadb
            expirationSeconds: 600
            path: token
```

With the [init-container image](#containers), write the module's absolute
path, `/opt/pam-oidc/pam_oidc.so`, instead of `pam_oidc.so`.

MariaDB's `auth_pam` runs PAM in a separate helper process (`auth_pam_tool`), so
the Go runtime never runs inside `mariadbd`. Its stderr is the server's, so
`pam_oidc:` messages appear in the server log.

## PostgreSQL

PostgreSQL authenticates through PAM natively (`pam` in `pg_hba.conf`), so the
same module and the same PAM service config work. Unlike MariaDB, PostgreSQL
runs PAM inside each connection's backend process, so the module and the Go
runtime load in-process there. The integration test
([`hack/postgres-test.sh`](hack/postgres-test.sh), run in CI via
[`Dockerfile.pgtest`](Dockerfile.pgtest)) checks that backend features relying
on PostgreSQL's own signal handling keep working in a token-authenticated
session: latch waits, `statement_timeout`, cancellation from another session,
parallel query, and `LISTEN`/`NOTIFY`.

`pg_hba.conf`. The token is sent as a cleartext password, so accept TCP only
over TLS and reject the rest:

```
hostssl all all 0.0.0.0/0 pam pamservice=postgres-oidc
host    all all 0.0.0.0/0 reject
```

`/etc/pam.d/postgres-oidc` takes the same form as the MariaDB example above,
with its own audience (for example `aud=postgres`), so a token minted for one
database can't be replayed against the other.

Roles need no password:

```sql
CREATE ROLE "apps:billing" LOGIN;
CREATE DATABASE billing OWNER "apps:billing";
```

Clients pass the token as the password, for example with libpq:
`PGPASSWORD="$(cat /var/run/secrets/postgres/token)" psql "host=... user=apps:billing sslmode=verify-full"`.

## Development

Unit tests cover token verification and need no PAM headers:

```
CGO_ENABLED=0 go test ./...
```

The full build compiles the module against Linux-PAM, runs the tests, and then
loads the module through a real PAM stack (`hack/smoke-test.sh`). It runs in
Docker, so the host needs no PAM development headers:

```
docker build -f Dockerfile.release --output dist .   # writes dist/pam_oidc-linux-amd64-gnu.so
docker build -f Dockerfile.module -t pam-oidc-module .  # init-container image
```

`make deb` and `make rpm` build packages from a compiled `pam_oidc.so` (they
need [nfpm](https://nfpm.goreleaser.com/)).
