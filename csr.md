ambicert csr --stdout config.yaml
    -----BEGIN CERTIFICATE REQUEST-----
    -----END CERTIFICATE REQUEST-----
    -----BEGIN PRIVATE KEY-----
    -----END PRIVATE KEY-----

ambicert csr --output-csr file.csr --output-key file.key config.yaml

config.yaml
```yaml
metadata:
  outputCert: ...
  outputKey: ...
csr: # -> csr.CSRConfig
  subject:
    ...
```
