# TODO

## Goals:

* Fully support running the CA in Azure KeyVault, without external tooling (like Step)
* The tool should enable automation of all the steps needed to manage mTLS certificates in an internal environment. Including:
  * Azure Pipelines
  * GitHub Actions
  * Manual scripting

## Scenarios:
Document usage in the following scenarios:

* mTLS for APIs in Azure
* mTLS setup for Event Grid MQTT
* mTLS setup for API Management / App Gateway

## Current status
The core library has most of the required functionality:
* Create a CA cert
* Sign certificate requests
* Issue Intermediate and leaf certs
* Handle EC and RSA keys
* Test harnass to verify KV interactions

## Work breakdown
* Clear out unused code, restructure to make it more intuitive
* Add CLI project
  * Create CA cert
  * Issue Intermediate cert
  * Issue leaf cert
  * Renew leaf cert
  * Download cert (optionally with key, as that is needed for some scenarios)
  * Revoke cert
  * Specify key parameters (key size, key type)
  * Specify cert parameters (subject, validity, SAN)
  * Support PKCS12 format (.pfx)
  * Support PKCS8 / PEM format (.pem, .crt and ,key)
  * Support DER format (.der, .crt and .key)

* Add auto-renewal worker for containerized deployment

* Handle certificate chain
* Provide instructions and bicep for deploying KeyVault(s) and other resources needed for the CA

## Future work
* Certificate revocation endpoint
* Add auto-renewal worker for Azure Function deployment
* 
# Research notes

## Refactor SignCSR to sign cert payloads in Azure KeyVault
The first version of this project relied on Step to sign the CSR. This is not ideal, because out of the box Step works 
with private keys on the local machine. Signing certs in KV is much more secure.
 
*Can we do this with StepCLI?*

Possibly using https://github.com/smallstep/step-kms-plugin

Get the kms plugin here: https://github.com/smallstep/step-kms-plugin/releases
Install it in %HOME%\.step\plugins\ and/or add the binary to the path.

It's a standalone app that can operate on KeyVault directly.

Create a key for the root cert. The key will not be exporable from KeyVault.
```pwsh
step kms create 'azurekms:vault=mvv-kv-ca;name=step-key'
```

Create a root cert with the key:
```pswh
step certificate create --profile root-ca --kms 'azurekms:vault=mvv-kv-ca' --key 'azurekms:vault=mvv-kv-ca;name=step-key' 'KMS Root' root_ca.crt
```

Create a key for the intermediate cert:
```pwsh
step kms create --kms 'azurekms:vault=mvv-kv-ca;name=step-intermediate-key'
```

Create an intermediate cert with the key:
```pwsh
step certificate create --profile intermediate-ca --kms 'azurekms:vault=mvv-kv-ca' --key 'azurekms:vault=mvv-kv-ca;name=step-intermediate-key' 'KMS Intermediate' --ca root_ca.crt --ca-key 'azurekms:vault=mvv-kv-ca;name=step-key' intermediate_ca.crt
```

https://github.com/smallstep/step-kms-plugin#signing-certificates-with-step

## Refactor PS scripts to not have any keys locally, at all
Not even for CA cert Setup

## Build functions / jobs to automate cert renewal

Dot on the horizon:

## Use mTLS to secure the APIs
