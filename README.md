# OSSign CLI
An easy to use CLI code signing tool based on [Relic](https://github.com/sassoftware/relic)

## Roadmap
- Basic signing
  - [x] Powershell Script
  - [x] PE/COFF
  - [X] MSI
  - [ ] JAR
  - [ ] APK
  - [ ] DMG
- Interfaces
  - [x] Local Certificate
  - [x] Azure Key Vault
  - [x] Azure Trusted Signing
  - [x] OSSign Server (keyless, OIDC trusted-publishing style)
- Compatibility
  - [x] Windows
  - [x] Linux
  - [x] MacOS
  - [ ] JS/WASM

## Installation
### APT Repository
You can use the APT repository to install and update the OSSign CLI on Debian-based systems.

```bash
sudo curl https://vcs.fi/api/packages/OSSign/debian/repository.key -o /etc/apt/keyrings/forgejo-OSSign.asc
echo "deb [signed-by=/etc/apt/keyrings/forgejo-OSSign.asc] https://vcs.fi/api/packages/OSSign/debian stable main" | sudo tee /etc/apt/sources.list.d/forgejo.list
sudo apt update
sudo apt install ossign
```

### Releases
You can download precompiled binaries from the [releases page](https://github.com/sassoftware/ossign/releases/latest/).

### Build from source
You can build OSSign from source using Go. Make sure you have Go 1.25.0+ installed and set up.

```bash
git clone https://github.com/ossign/ossign.git
cd ossign
go build -o ossign ./cmd/ossign
```

## Usage
You can use the OSSign CLI to sign files using various methods. Below are some examples.

For more configuration examples, see below.

### Configuration
The configuration can be provided via a json or yaml file. If no `OSSIGN_CONFIG`/`OSSIGN_CONFIG_BASE64` environment variable and no `--config` flag is given, the CLI uses `~/.ossign/config.yaml`, then `~/ossign/config.yaml` (`%USERPROFILE%` on Windows), and finally falls back to `/etc/ossign/config.yaml` on Linux/MacOS or `%PROGRAMDATA%\ossign\config.yaml` on Windows.

```yaml
# Currently "azure" (Azure Key Vault), "azureTrusted" (Azure Artifact Signing), "ossignServer" (OSSign Server, keyless) or "certificate" (Local Certificate) are supported
tokenType: azure

# Which type of signature. Can also be provided on the command line with the -t flag
# signatureType: pecoff

# Configuration for Azure Key Vault
azure:
    vaultUrl: https://my-certs.vault.azure.net/
    tenantId: my-tenant-id
    clientId: my-client-id
    clientSecret: my-client-secret
    certificateName: my-cert-name
    certificateVersion: version-id

# Use a local certificate, PEM-encoded as a string
certificate:
  certificate: |
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJALa7r+3bXG4uMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
    ...
    -----END CERTIFICATE-----
  privateKey: |
    -----BEGIN PRIVATE KEY-----
    .....
    -----END PRIVATE KEY-----

# Configuration for Azure Artifact Signing (formerly Trusted Signing)
azureTrusted:
    tenantId: my-tenant-id
    clientId: my-client-id
    clientSecret: my-client-secret
    region: region, e.g. "neu"
    account: Account name
    profile: Profile name

# Configuration for an OSSign Server (no secrets, access is granted server-side
# based on the CI job's OIDC identity: repository, branch/tag, environment, ...)
ossignServer:
    url: https://sign.example.com
    key: my-key-name

# Optional timestamp server URL, default is http://timestamp.globalsign.com/tsa/advanced
timestampUrl: http://timestamp.globalsign.com/tsa/advanced

# Optional Microsoft Authenticode timestamp server URL, default is http://timestamp.microsoft.com/tsa
msTimestampUrl: http://timestamp.microsoft.com/tsa

# Input file. Can also be provided on the command line
# inputFile: myFile.exe

# Output file. If not provided, the input file is signed in place.
# outputFile: myFile-signed.exe
```


### Github Actions
You can use the ossign action like this:

```yaml
- uses: ossign/ossign-action@v1
  with:
    # Optional. The latest release is found without a token; pass one only if
    # you want the authenticated GitHub API to be used instead.
    # token: ${{ secrets.GITHUB_TOKEN }}

    # Only install the OSSign CLI, don't sign anything
    # The command can then be run with "ossign" in a later step
    installOnly: false

    # The configuration to use
    config: |
      tokenType: azure
      azure:
        ...................
      timestampUrl: http://timestamp.globalsign.com/tsa/advanced
    
    # Sign a single file
    inputFile: path/to/file.exe

    # Sign multiple files using a glob pattern
    inputFiles: path/to/*.exe

    # Type of signature. Can be "pecoff", "msi", "jar", "apk" or "dmg"
    signatureType: pecoff
```

For trusted signing together with OSSign Server (TBA), use the following configuration. Please note that trusted signing needs `id-token: write` permission to be able to issue a token for use in the signing process.

```yaml
- uses: ossign/ossign-action@v1
  with:
    # Optional. The latest release is found without a token; pass one only if
    # you want the authenticated GitHub API to be used instead.
    # token: ${{ secrets.GITHUB_TOKEN }}

    # Only install the OSSign CLI, don't sign anything
    # The command can then be run with "ossign" in a later step
    installOnly: false

    # Enable trusted signing
    trustedSigning: true

    # Set the key to use in the trusted signing server
    trustedSigningKey: test-certificate
    
    # Sign a single file
    inputFile: path/to/file.exe

    # Sign multiple files using a glob pattern
    inputFiles: path/to/*.exe

    # Type of signature. Can be "pecoff", "msi", "jar", "apk" or "dmg"
    signatureType: pecoff
```

You can also install the configuration along with installOnly, and then just use the ossign CLI in a later step without providing the configuration again. This is especially useful for workflows with for example tauri, electron-builder or goreleaser which sign multiple times during their build process.

Do note that the later step still requires `id-token: write` permission to be able to issue a token for use in the signing process, since that is done at the time of signing.

```yaml
- uses: ossign/ossign-action@v1
  with:
    # Optional. The latest release is found without a token; pass one only if
    # you want the authenticated GitHub API to be used instead.
    # token: ${{ secrets.GITHUB_TOKEN }}

    # Only install the OSSign CLI, don't sign anything
    installOnly: true

    # Enable trusted signing (along with installOnly will install the config file for later use)
    trustedSigning: true

    # Set the key to use in the trusted signing server
    trustedSigningKey: test-certificate

- name: Sign my file
  run: |
    ossign -t pecoff path/to/file.exe
```



### Verifying a signed file

```bash
ossign verify myFile-signed.exe
ossign verify --cert expected.pem myFile-signed.exe
ossign verify --detached review-report.json.p7s review-report.json   # OSSign Server review report
```

Checks the embedded signature of PE/COFF, MSI, CAB, APPX/MSIX and PowerShell
files, prints the signer and timestamp, and exits with 1 on a broken
signature, 2 when the file was signed with an OSSign Server test-mode
certificate, and 3 when the signer does not match `--cert`.

## Configuration Examples
### Using Azure Key Vault (json)
```yaml
# Currently "azure" (Azure Key Vault), "azureTrusted" (Azure Artifact Signing), "ossignServer" (OSSign Server, keyless) or "certificate" (Local Certificate) are supported
tokenType: azure

# Which type of signature. Can also be provided on the command line with the -t flag
# signatureType: pecoff

# Configuration for Azure Key Vault
azure:
    vaultUrl: https://my-certs.vault.azure.net/
    tenantId: my-tenant-id
    clientId: my-client-id
    clientSecret: my-client-secret
    certificateName: my-cert-name
    certificateVersion: version-id

# Optional timestamp server URL, default is http://timestamp.globalsign.com/tsa/advanced
timestampUrl: http://timestamp.globalsign.com/tsa/advanced

# Optional Microsoft Authenticode timestamp server URL, default is http://timestamp.microsoft.com/tsa
msTimestampUrl: http://timestamp.microsoft.com/tsa

# Input file. Can also be provided on the command line
# inputFile: myFile.exe

# Output file. If not provided, the input file is signed in place.
# outputFile: myFile-signed.exe
```

**Command-line:**
```bash
ossign -c config.yaml -t pecoff -i myFile.exe -o myFile-signed.exe
```

### Using Local Certificate (yaml)
```yaml
# Currently "azure" (Azure Key Vault), "azureTrusted" (Azure Artifact Signing), "ossignServer" (OSSign Server, keyless) or "certificate" (Local Certificate) are supported
tokenType: certificate

# Which type of signature. Can also be provided on the command line with the -t flag
# signatureType: pecoff

# Use a local certificate, PEM-encoded as a string
certificate:
  certificate: |
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJALa7r+3bXG4uMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
    ...
    -----END CERTIFICATE-----
  privateKey: |
    -----BEGIN PRIVATE KEY-----
    .....
    -----END PRIVATE KEY-----

# Optional timestamp server URL, default is http://timestamp.globalsign.com/tsa/advanced
timestampUrl: http://timestamp.globalsign.com/tsa/advanced

# Optional Microsoft Authenticode timestamp server URL, default is http://timestamp.microsoft.com/tsa
msTimestampUrl: http://timestamp.microsoft.com/tsa
```
**Command-line:**
```bash
ossign -c config.yaml -t powershell -i myFile.ps1 -o myFile-signed.ps1
```

### Using Azure Artifact Signing (formerly Trusted Signing) (json)

The app registration used for Azure Artifact Signing must have the "Artifact Signing Certificate Profile Signer" role assigned in the Azure portal.

```yaml
{

    "tokenType": "azureTrusted",
    "azureTrusted": {
        "tenantId": "my-tenant-id",
        "clientId": "my-client-id",
        "clientSecret": "my-client-secret",
        "region": "neu",
        "account": "my-account",
        "profile": "my-profile"
    },
    "certificate": {
        "certificate": "",
        "privateKey": ""
    },
    "timestampUrl": "http://timestamp.globalsign.com/tsa/advanced",
    "msTimestampUrl": "http://timestamp.microsoft.com/tsa"
}

### Using an OSSign Server (keyless, no secrets)

An OSSign Server holds the signing keys and decides, per key, which CI identities
may use them. The decision is based on the OIDC token the CI provider issues to
the job, in the same way as "trusted publishing" on PyPI or npm. The repository
needs no secrets at all; a GitHub Actions job only needs `permissions: id-token: write`.

```yaml
tokenType: ossignServer
ossignServer:
  url: https://sign.example.com
  key: release-windows
  # Optional: audience, provider (auto|github|gitlab|env|static), idTokenEnv, idToken, metadata
```

**Command-line:**
```bash
ossign -c config.yaml -t pecoff -o myFile-signed.exe myFile.exe
```

See [docs/ossign-server.md](docs/ossign-server.md) for the full configuration,
the policy model and GitLab usage, [docs/ossign-server-api.yaml](docs/ossign-server-api.yaml)
for the server API definition (OpenAPI 3.1), and
[examples/workflows/sign-with-ossign-server.yml](examples/workflows/sign-with-ossign-server.yml)
for a complete GitHub Actions workflow.
