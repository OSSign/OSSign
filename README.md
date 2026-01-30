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
- Compatibility
  - [x] Windows
  - [x] Linux
  - [x] MacOS
  - [ ] JS/WASM

## Installation
### APT Repository
You can use the APT repository to install and update the OSSign CLI on Debian-based systems.

```bash
sudo curl https://pkg.ossign.org/debian/repository.key -o /etc/apt/keyrings/gitea-ossign.asc
echo "deb [signed-by=/etc/apt/keyrings/gitea-ossign.asc] https://pkg.ossign.org/debian all main" | sudo tee /etc/apt/sources.list.d/ossign.list
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
The configuration can be provided via a json or yaml file. As a default, the CLI will look for a file named `config.yaml` in ~/.ossign/ or /etc/ossign on Linux/MacOS, and %PROGRAMDATA%\ossign\config.yaml or %USERPROFILE%\.ossign\config.yaml on Windows.

```yaml
# Currently "azure" (Azure Key Vault), "azureTrusted" (Azure Artifact Signing) or "certificate" (Local Certificate) are supported
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

# Optional timestamp server URL, default is http://timestamp.globalsign.com/tsa/advanced
timestampUrl: http://timestamp.globalsign.com/tsa/advanced

# Optional Microsoft Authenticode timestamp server URL, default is http://timestamp.microsoft.com/tsa
msTimestampUrl: http://timestamp.microsoft.com/tsa

# Input file. Can also be provided on the command line
# inputFile: myFile.exe

# Output file. If not provided, the signed file will be saved as [fileName]-signed.[fileExtension]
# outputFile: myFile-signed.exe
```


### Github Actions
You can use the ossign action like this:

```yaml
- uses: ossign/ossign-action@v1
  with:
    # Github Token (read-only)
    token: ${{ secrets.GITHUB_TOKEN }}

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



## Configuration Examples
### Using Azure Key Vault (json)
```yaml
# Currently "azure" (Azure Key Vault), "azureTrusted" (Azure Artifact Signing) or "certificate" (Local Certificate) are supported
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

# Output file. If not provided, the signed file will be saved as [fileName]-signed.[fileExtension]
# outputFile: myFile-signed.exe
```

**Command-line:**
```bash
ossign -c config.yaml -t pecoff -i myFile.exe -o myFile-signed.exe
```

### Using Local Certificate (yaml)
```yaml
# Currently "azure" (Azure Key Vault), "azureTrusted" (Azure Artifact Signing) or "certificate" (Local Certificate) are supported
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