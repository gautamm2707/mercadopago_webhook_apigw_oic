# OCI API Gateway + OCI Function for Mercado Pago Webhooks to OIC

This project provides an OCI Function that securely receives Mercado Pago webhook notifications through OCI API Gateway, validates the Mercado Pago signature, generates an OCI Identity Domain access token, and invokes an Oracle Integration Cloud REST endpoint.

## Architecture

```text
Mercado Pago
    |
    v
OCI API Gateway
    |
    v
OCI Function
    |
    v
OCI Vault + OCI Identity Domain
    |
    v
Oracle Integration Cloud
```

## What This Function Does

1. Receives the webhook request from OCI API Gateway.
2. Reads `x-signature` and `x-request-id` from Mercado Pago.
3. Reads `data.id` from the request query string.
4. Retrieves the Mercado Pago webhook secret from OCI Vault.
5. Validates the Mercado Pago HMAC-SHA256 signature.
6. Retrieves the OIC OAuth client secret from OCI Vault.
7. Generates an OCI Identity Domain access token scoped for OIC.
8. Caches config, secrets, and access tokens.
9. Invokes the configured OIC REST endpoint with a bearer token.
10. Returns the OIC response to API Gateway.

## Mercado Pago Signature Validation

Mercado Pago sends:

```text
x-signature: ts=<timestamp>,v1=<signature>
x-request-id: <request-id>
```

The webhook URL must include:

```text
data.id=<notification-data-id>
```

Example:

```text
https://<api-gateway-url>/mercadopago/webhook?data.id=999999999
```

The function builds this manifest:

```text
id:<data.id>;request-id:<x-request-id>;ts:<ts>;
```

Then calculates:

```text
HMAC-SHA256(manifest, mercadopago_webhook_secret)
```

The calculated hex digest is compared with `v1` from `x-signature`.

## Required Function Configuration

```text
MERCADOPAGO_SECRET=ocid1.vaultsecret...
OIC_ENDPOINT=https://<oic-host>/ic/api/integration/v2/flows/rest/<integration-endpoint>
OIC_HTTP_METHOD=POST
```

Identity Domain / OIC OAuth config:

```text
idcs_app_client_id=<identity-domain-client-id>
idcs_client_secret_ocid=<oci-vault-secret-ocid>
idcs_token_endpoint=https://<identity-domain>.identity.oraclecloud.com/oauth2/v1/token
idcs_oauth_scope=https://<oic-host>:443urn:opc:resource:consumer::all
```

Supported alternate config names:

```text
CLIENT_ID
CLIENT_SECRET_OCID
TOKEN_URL
OIC_SCOPE
TOKEN_GRANT_TYPE
```

## Optional Cache Configuration

```text
CONFIG_CACHE_TTL_SECONDS=300
SECRET_CACHE_TTL_SECONDS=300
TOKEN_EXPIRY_SKEW_SECONDS=300
MERCADOPAGO_TS_TOLERANCE_SECONDS=300
```

Set `MERCADOPAGO_TS_TOLERANCE_SECONDS=0` to disable timestamp freshness validation.

## IAM Policy

The function must be allowed to read secrets from OCI Vault.

Example:

```text
Allow dynamic-group <function-dynamic-group> to read secret-bundles in compartment <compartment-name>
```

## API Gateway Route

Example route:

```text
Path: /mercadopago/webhook
Method: POST
Backend: Oracle Functions
Function: <function-name>
```

Mercado Pago webhook URL:

```text
https://<api-gateway-deployment-url>/mercadopago/webhook?data.id=<id>
```

## Example Request

```bash
curl -X POST \
  'https://<api-gateway-url>/mercadopago/webhook?data.id=999999999' \
  -H 'Content-Type: application/json' \
  -H 'x-request-id: 123456789' \
  -H 'x-signature: ts=1710000000,v1=<calculated-signature>' \
  -d '{"type":"payment","data":{"id":"999999999"}}'
```

## requirements.txt

```text
fdk
oci
requests
```

## Deployment

Using Fn CLI:

```bash
fn init --runtime python mercadopago-webhook
```

Replace the generated `func.py` with this project code.

Deploy:

```bash
fn -v deploy --app <function-app-name>
```

Using Docker and OCI CLI:

```bash
docker build --platform linux/amd64 \
  -t <region-key>.ocir.io/<namespace>/<repo>/mercadopago-webhook:0.0.1 .
```

```bash
docker push <region-key>.ocir.io/<namespace>/<repo>/mercadopago-webhook:0.0.1
```

```bash
oci fn function update \
  --function-id <function-ocid> \
  --image <region-key>.ocir.io/<namespace>/<repo>/mercadopago-webhook:0.0.1 \
  --wait-for-state ACTIVE
```

## Security Notes

- Do not hardcode Mercado Pago secrets.
- Store webhook secrets in OCI Vault.
- Store Identity Domain client secrets in OCI Vault.
- Validate the Mercado Pago signature before calling OIC.
- Do not log secrets, bearer tokens, or authorization headers.
- Use POST for webhook payload forwarding.
- Restrict Vault access using least-privilege IAM policies.

## Response Behavior

| Scenario | Response |
|---|---|
| Missing `MERCADOPAGO_SECRET` | `401` |
| Missing `x-signature` | `401` |
| Missing `x-request-id` | `401` |
| Missing `data.id` query parameter | `401` |
| Invalid signature | `401` |
| Expired timestamp | `401` |
| OIC timeout | `504` |
| OIC success | Returns OIC response |

## Summary

This OCI Function provides a secure webhook bridge between Mercado Pago and Oracle Integration Cloud.

Mercado Pago sends a standard webhook to OCI API Gateway. The function validates the webhook signature, generates an OIC bearer token using OCI Identity Domain, and forwards the request to OIC securely.
