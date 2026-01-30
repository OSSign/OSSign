// JavaScript Example
const ossign = require('../dist/index');
const fs = require('fs/promises');
const path = require('path');
const { exec } = require('child_process');

const psFile = path.join(__dirname, 'example-js.ps1');
const psFile2 = path.join(__dirname, 'example-js-2.ps1');
const configFile = path.join(__dirname, 'ossign-config-js.json');

async function runExamples() {
  console.log('=== OSSign-JS JavaScript Tests ===\\n');

  // Create dummy powershell files
  await fs.writeFile(psFile, 'Write-Host "Hello, OSSign!"');
  await fs.writeFile(psFile2, 'Write-Host "Hello, OSSign 2!"');

  // Create OSSIGN configuration file for testing
  const config = `{
    "tokenType": "certificate",
    "certificate": {
      "certificate": "-----BEGIN CERTIFICATE-----\\nMIICEjCCAXugAwIBAgIUchRukHCbf3cZq37F8CJ0NE+82EowDQYJKoZIhvcNAQEL\\nBQAwGzEZMBcGA1UEAwwQVGVzdCBDZXJ0aWZpY2F0ZTAeFw0yNjAxMjgyMzI0NTla\\nFw0zNjAxMjYyMzI0NTlaMBsxGTAXBgNVBAMMEFRlc3QgQ2VydGlmaWNhdGUwgZ8w\\nDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAL2c6EfIfA8Ui3WpuMqWcMJ0GleJp3OX\\nkdTHbdmH7fiSi8QuNwPlcy14zbj6UebsHwegR+7QlHCmJG9WjP0YYLx1N4khnMj7\\nZ/qI+3iEmk9afjG+L2Ihb4/tmifYQloBIBBOBc7h1kuEzXnmpRfsZp6Qiil4SNmn\\njtsSFhrZGLI3AgMBAAGjUzBRMB0GA1UdDgQWBBRtz3rXq9czSkGkDfQap8kGplQb\\nijAfBgNVHSMEGDAWgBRtz3rXq9czSkGkDfQap8kGplQbijAPBgNVHRMBAf8EBTAD\\nAQH/MA0GCSqGSIb3DQEBCwUAA4GBALc5XQVoHKb4j7cUzUkxqS4PZZNEqlzZ+g5D\\n/BdKXrovKpkd5wG1Y8ci5NXj5V2tA9pHm+SLAGXJWdPUdu3irtLFzZXMcr9nQPwG\\nTBmPja9tBq1fVTya8RRZA5KZ65N1g5lasCksnbyPldgU1M/V5yORwdK0siZM4Fjs\\nJEfB6p+a\\n-----END CERTIFICATE-----\\n",
      "privateKey": "-----BEGIN PRIVATE KEY-----\\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL2c6EfIfA8Ui3Wp\\nuMqWcMJ0GleJp3OXkdTHbdmH7fiSi8QuNwPlcy14zbj6UebsHwegR+7QlHCmJG9W\\njP0YYLx1N4khnMj7Z/qI+3iEmk9afjG+L2Ihb4/tmifYQloBIBBOBc7h1kuEzXnm\\npRfsZp6Qiil4SNmnjtsSFhrZGLI3AgMBAAECgYARln9ZQTh4saAp/t88M24sK1bS\\nLduRdkq5oPIIjno9Z2J9hQfnXZ4sZps2gEmekOJj87MYbNKIDHEuvql/RIaca5TD\\nNpAigNCGnCDcT8BV3cuaqa9LK7IDFnswIEMn1q4ADJnM3QyKShau9myJewH8Tz4Q\\nHzhxlvDNtKFwX0WveQJBAOnsH+yuBbN/KWp3RJJWn966Pju4taOohr1oLvKaE2Ii\\nZxH4+92AKXaFiNJwrTk/Gq4qV/nXhe4Ar7VlDRr5A9UCQQDPgjUkc8AVHvSM1J5h\\nVEBtmI5tnq+8Avh9tk4nwviCh6HMKhKc2Y0JUBv8mdO0Zel9y3EWUUmk0dEDXZZT\\nHT/bAkAmFL+ZuzbIYuIuJ95s6Fc8Xht1g3tmei/9M7G44uZW6nzXCy6Nf6jAV7rP\\nb3JzyFcilVgfHzv5Y/k20Y2Rn4pFAkAaPF43s6LPiNBmleNIbvyOXsFzPqL9ZGrC\\nijAres0sw7VDOPaNejwIt2Yyc8h+gHwa+YPczH5BJn4ErOp6q7INAkEAxfcU5KIE\\nS0EtN6raGsZqfjbiNzGTeVVpcipurc1Hpbe3hoT59RokTNGc/WXXbEpyzyQvJLLR\\nk3b5/iMJr7pZiQ==\\n-----END PRIVATE KEY-----\\n"
    },
    "timestampUrl": "http://timestamp.globalsign.com/tsa/advanced",
    "msTimestampUrl": "http://timestamp.microsoft.com/tsa"
  }`;

  await fs.writeFile(configFile, config);

  console.log(ossign.SignSync(psFile, psFile, "powershell", configFile));

  const content = await fs.readFile(psFile, 'utf8');
  console.log('\\nSigned PowerShell file content:\\n', content);

  if (content.includes('SIG # Begin signature block')) {
    console.log('✓ PowerShell file signed successfully');
  } else {
    console.error('✗ PowerShell file signing failed');
  }

  const signFunc = ossign.GetSignerFunction("powershell", configFile);
  console.log('\\nUsing signer function to sign another file:');
  console.log(signFunc(psFile2));

  const content2 = await fs.readFile(psFile2, 'utf8');
  console.log('\\nSigned PowerShell file 2 content:\\n', content2);

  if (content2.includes('SIG # Begin signature block')) {
    console.log('✓ PowerShell file 2 signed successfully');
  } else {
    console.error('✗ PowerShell file 2 signing failed');
  }

  console.log('\\n=== End of OSSign-JS JavaScript Tests ===');
}

// Run examples
runExamples().catch(console.error).finally(() => {
  fs.unlink(psFile);
  fs.unlink(psFile2);
  fs.unlink(configFile);
});