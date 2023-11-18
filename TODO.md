# TODO

## Finalize code
* Clear out unused code
* Build certificate chain

## Refactor SignCSR to sign cert payloads in Azure KeyVault
* Can we do this with StepCLI?
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
