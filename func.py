import io
import json
import logging
import base64
import hashlib
import hmac
import time
from urllib.parse import parse_qs, urlparse
from typing import Any, Dict, Optional, Tuple

import oci
import requests
from fdk import response


LOGGER = logging.getLogger()

CONFIG: Dict[str, str] = {}
CONFIG_CACHE_EXPIRES_AT = 0.0

SECRET_CACHE: Dict[str, Tuple[str, float]] = {}
TOKEN_CACHE: Dict[str, Dict[str, Any]] = {}

DEFAULT_TOKEN_URL = "https://idcs-ff3532e3a9ba4###########.identity.oraclecloud.com/oauth2/v1/token"
DEFAULT_OIC_SCOPE = "https://01DB8CF84FDB4C##############.integration.us-ashburn-1.ocp.oraclecloud.com:443urn:opc:resource:consumer::all"
DEFAULT_OIC_ENDPOINT = "https://<oic-host>/ic/api/integration/v1/flows/rest/<endpoint>"
DEFAULT_TOKEN_GRANT_TYPE = "client_credentials"

DEFAULT_CONFIG_CACHE_TTL_SECONDS = 300
DEFAULT_SECRET_CACHE_TTL_SECONDS = 300
DEFAULT_TOKEN_EXPIRY_SKEW_SECONDS = 300
DEFAULT_MERCADOPAGO_TS_TOLERANCE_SECONDS = 300


def initContext(config: Dict[str, str]) -> None:
    global CONFIG
    CONFIG = {str(k): str(v).strip() for k, v in (config or {}).items() if v is not None}


def initContextCached(ctx: Any) -> None:
    global CONFIG_CACHE_EXPIRES_AT

    now = time.time()
    current_config = dict(ctx.Config() or {})
    ttl = int(current_config.get("CONFIG_CACHE_TTL_SECONDS", DEFAULT_CONFIG_CACHE_TTL_SECONDS))

    if CONFIG and now < CONFIG_CACHE_EXPIRES_AT:
        return

    initContext(current_config)
    CONFIG_CACHE_EXPIRES_AT = now + ttl


def _json_response(ctx: Any, status_code: int, payload: Dict[str, Any]) -> response.Response:
    return response.Response(
        ctx,
        response_data=json.dumps(payload),
        status_code=status_code,
        headers={"Content-Type": "application/json"},
    )


def _normalize_header_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        return str(value[-1]).strip()
    return str(value).strip()


def _get_header(headers: Dict[str, Any], name: str) -> Optional[str]:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return _normalize_header_value(value)
    return None


def _get_config(key: str, default: str, *aliases: str) -> str:
    for config_key in (key, *aliases):
        value = CONFIG.get(config_key)
        if value:
            return str(value).strip()
    return default


def _get_required_config(key: str, *aliases: str) -> str:
    value = _get_config(key, "", *aliases)
    if not value:
        accepted_keys = ", ".join((key, *aliases))
        raise ValueError(f"Missing required function config. Expected one of: {accepted_keys}")
    return value


def getSecret(ocid: str) -> str:
    ocid = str(ocid).strip()
    now = time.time()
    ttl = int(_get_config("SECRET_CACHE_TTL_SECONDS", str(DEFAULT_SECRET_CACHE_TTL_SECONDS)))

    cached = SECRET_CACHE.get(ocid)
    if cached and now < cached[1]:
        return cached[0]

    signer = oci.auth.signers.get_resource_principals_signer()
    client = oci.secrets.SecretsClient({}, signer=signer)
    secret_bundle = client.get_secret_bundle(ocid).data
    secret_content = secret_bundle.secret_bundle_content.content.encode("utf-8")
    secret_value = base64.b64decode(secret_content).decode("utf-8").strip()

    SECRET_CACHE[ocid] = (secret_value, now + ttl)
    return secret_value


def _build_basic_auth_header(client_id: str, client_secret: str) -> str:
    encoded = f"{client_id}:{client_secret}"
    baseencoded = base64.urlsafe_b64encode(encoded.encode("UTF-8")).decode("ascii")
    return f"Basic {baseencoded}"


def _parse_signature_header(x_signature: str) -> Dict[str, str]:
    values = {}

    for part in x_signature.split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        values[key.strip()] = value.strip()

    return values


def _get_request_url(ctx: Any, request_headers: Dict[str, Any]) -> str:
    for attr_name in ("RequestURL", "RequestUrl", "URL", "Url"):
        attr = getattr(ctx, attr_name, None)
        if callable(attr):
            value = attr()
            if value:
                return str(value)

    for header_name in (
        "Fn-Http-Request-Url",
        "X-Forwarded-Uri",
        "X-Original-Uri",
        "X-Request-Uri",
    ):
        value = _get_header(request_headers, header_name)
        if value:
            return value

    return ""


def _get_query_param(ctx: Any, request_headers: Dict[str, Any], param_name: str) -> Optional[str]:
    request_url = _get_request_url(ctx, request_headers)
    if request_url:
        parsed = urlparse(request_url)
        query_values = parse_qs(parsed.query, keep_blank_values=True)
        values = query_values.get(param_name)
        if values:
            return values[-1].strip()

        # Some gateways pass only the URI path/query in forwarded headers.
        if "?" in request_url and not parsed.query:
            query = request_url.split("?", 1)[1]
            query_values = parse_qs(query, keep_blank_values=True)
            values = query_values.get(param_name)
            if values:
                return values[-1].strip()

    for header_name in ("Fn-Http-Query-String", "X-Forwarded-Query-String"):
        query = _get_header(request_headers, header_name)
        if query:
            query_values = parse_qs(query, keep_blank_values=True)
            values = query_values.get(param_name)
            if values:
                return values[-1].strip()

    return None


def _validate_timestamp(ts: str) -> None:
    tolerance = int(
        _get_config(
            "MERCADOPAGO_TS_TOLERANCE_SECONDS",
            str(DEFAULT_MERCADOPAGO_TS_TOLERANCE_SECONDS),
        )
    )

    if tolerance <= 0:
        return

    try:
        ts_value = int(ts)
        # Mercado Pago examples use seconds. If milliseconds are received, normalize.
        if ts_value > 10_000_000_000:
            ts_value = ts_value // 1000
    except ValueError:
        raise PermissionError("Invalid Mercado Pago timestamp")

    now = int(time.time())
    if abs(now - ts_value) > tolerance:
        raise PermissionError("Expired Mercado Pago signature timestamp")


def _validate_mercadopago_webhook(request_headers: Dict[str, Any], ctx: Any) -> None:
    secret_ocid = _get_config(
        "MERCADOPAGO_SECRET",
        "",
        "MERCADOPAGO_SECRET_OCID",
        "mercadopago_secret_ocid",
    )

    if not secret_ocid:
        raise PermissionError("MERCADOPAGO_SECRET is not configured")

    x_signature = _get_header(request_headers, "x-signature")
    x_request_id = _get_header(request_headers, "x-request-id")

    if not x_signature:
        raise PermissionError("Missing Mercado Pago x-signature header")
    if not x_request_id:
        raise PermissionError("Missing Mercado Pago x-request-id header")

    signature_values = _parse_signature_header(x_signature)
    ts = signature_values.get("ts")
    received_hash = signature_values.get("v1")

    if not ts or not received_hash:
        raise PermissionError("Invalid Mercado Pago x-signature header format")

    _validate_timestamp(ts)

    data_id = _get_query_param(ctx, request_headers, "data.id")
    if not data_id:
        raise PermissionError("Missing Mercado Pago data.id query parameter")

    if data_id.isalnum():
        data_id = data_id.lower()

    manifest = f"id:{data_id};request-id:{x_request_id};ts:{ts};"
    secret = getSecret(secret_ocid)

    calculated_hash = hmac.new(
        secret.encode("utf-8"),
        manifest.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        raise PermissionError("Invalid Mercado Pago signature")


def _get_request_method(ctx: Any, request_headers: Dict[str, Any]) -> str:
    method_func = getattr(ctx, "Method", None)
    if callable(method_func):
        method = method_func()
        if method:
            return str(method).upper()

    for header_name in (
        "Fn-Http-Method",
        "X-Forwarded-Method",
        "X-Original-Method",
        "X-Http-Method-Override",
    ):
        header_value = _get_header(request_headers, header_name)
        if header_value:
            return header_value.upper()

    return "POST"


def _get_jwt_assertion() -> Optional[str]:
    jwt_assertion = CONFIG.get("JWT_ASSERTION")
    if jwt_assertion:
        return str(jwt_assertion).strip()

    jwt_assertion_secret_ocid = CONFIG.get("JWT_ASSERTION_SECRET_OCID")
    if jwt_assertion_secret_ocid:
        return getSecret(str(jwt_assertion_secret_ocid))

    return None


def _decode_jwt_exp(access_token: str) -> Optional[int]:
    try:
        parts = access_token.split(".")
        if len(parts) < 2:
            return None

        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload.encode("utf-8"))
        claims = json.loads(decoded.decode("utf-8"))
        exp = claims.get("exp")

        if exp:
            return int(exp)
    except Exception:
        LOGGER.warning("Unable to decode JWT exp claim")

    return None


def _token_cache_key(
    token_url: str,
    scope: str,
    grant_type: str,
    client_id: str,
    jwt_assertion: Optional[str],
) -> str:
    raw_key = "|".join(
        [
            token_url,
            scope,
            grant_type,
            client_id,
            hashlib.sha256((jwt_assertion or "").encode("utf-8")).hexdigest(),
        ]
    )
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _get_identity_domain_token(
    token_url: str,
    scope: str,
    basic_auth_header: str,
    grant_type: str,
    client_id: str,
) -> str:
    jwt_assertion = None
    token_payload = {
        "grant_type": grant_type,
        "scope": scope,
    }

    if grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer":
        jwt_assertion = _get_jwt_assertion()
        if not jwt_assertion:
            raise ValueError(
                "JWT bearer grant requires JWT_ASSERTION or JWT_ASSERTION_SECRET_OCID function config"
            )
        token_payload["assertion"] = jwt_assertion

    cache_key = _token_cache_key(token_url, scope, grant_type, client_id, jwt_assertion)
    skew = int(_get_config("TOKEN_EXPIRY_SKEW_SECONDS", str(DEFAULT_TOKEN_EXPIRY_SKEW_SECONDS)))
    now = int(time.time())

    cached_token = TOKEN_CACHE.get(cache_key)
    if cached_token and now < int(cached_token["expires_at"]) - skew:
        return str(cached_token["access_token"])

    token_headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Authorization": basic_auth_header,
        "Accept": "*/*",
    }

    token_response = requests.post(
        token_url,
        headers=token_headers,
        data=token_payload,
        timeout=10,
    )

    if token_response.status_code != 200:
        raise RuntimeError(
            f"Token endpoint failed with status {token_response.status_code}: {token_response.text}"
        )

    token_body = token_response.json()
    access_token = token_body.get("access_token")

    if not access_token:
        raise RuntimeError("Token endpoint response did not include access_token")

    expires_at = _decode_jwt_exp(access_token)

    if not expires_at:
        expires_in = int(token_body.get("expires_in", 3600))
        expires_at = now + expires_in

    TOKEN_CACHE[cache_key] = {
        "access_token": access_token,
        "expires_at": expires_at,
    }

    return access_token


def _build_oic_headers(request_headers: Dict[str, Any], access_token: str) -> Dict[str, str]:
    oic_headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    for header_name in (
        "x-signature",
        "x-request-id",
    ):
        header_value = _get_header(request_headers, header_name)
        if header_value:
            oic_headers[header_name] = header_value

    return oic_headers


def handler(ctx, data: io.BytesIO = None):
    try:
        initContextCached(ctx)
        LOGGER.info("handler: started Mercado Pago webhook function execution")

        request_headers = ctx.Headers() or {}
        raw_body = data.getvalue() if data else b""

        _validate_mercadopago_webhook(request_headers, ctx)

        token_url = _get_config("TOKEN_URL", DEFAULT_TOKEN_URL, "idcs_token_endpoint")
        oic_scope = _get_config("OIC_SCOPE", DEFAULT_OIC_SCOPE, "idcs_oauth_scope")
        oic_endpoint = _get_config("OIC_ENDPOINT", DEFAULT_OIC_ENDPOINT, "OIC_Endpoint", "oic_endpoint")
        grant_type = _get_config("TOKEN_GRANT_TYPE", DEFAULT_TOKEN_GRANT_TYPE, "idcs_token_grant_type")

        incoming_method = _get_request_method(ctx, request_headers)
        oic_http_method = _get_config("OIC_HTTP_METHOD", incoming_method, "oic_http_method").upper()

        client_id = _get_required_config("CLIENT_ID", "idcs_app_client_id")
        client_secret_ocid = _get_required_config("CLIENT_SECRET_OCID", "idcs_client_secret_ocid")
        client_secret = getSecret(client_secret_ocid)

        basic_auth_header = _build_basic_auth_header(client_id, client_secret)

        access_token = _get_identity_domain_token(
            token_url=token_url,
            scope=oic_scope,
            basic_auth_header=basic_auth_header,
            grant_type=grant_type,
            client_id=client_id,
        )

        oic_headers = _build_oic_headers(request_headers, access_token)

        if oic_http_method == "GET":
            oic_response = requests.get(
                oic_endpoint,
                headers=oic_headers,
                timeout=30,
            )
        elif oic_http_method == "POST":
            content_type = _get_header(request_headers, "Content-Type") or "application/json"
            oic_headers["Content-Type"] = content_type
            oic_response = requests.post(
                oic_endpoint,
                headers=oic_headers,
                data=raw_body,
                timeout=30,
            )
        else:
            return _json_response(
                ctx,
                500,
                {"error": f"Unsupported OIC_HTTP_METHOD: {oic_http_method}"},
            )

        return response.Response(
            ctx,
            response_data=oic_response.text,
            status_code=oic_response.status_code,
            headers={
                "Content-Type": _normalize_header_value(
                    oic_response.headers.get("Content-Type")
                ) or "application/json"
            },
        )

    except requests.Timeout:
        LOGGER.exception("Timeout while calling downstream service")
        return _json_response(ctx, 504, {"error": "Timeout while calling downstream service"})
    except PermissionError as ex:
        return _json_response(ctx, 401, {"error": str(ex)})
    except Exception as ex:
        LOGGER.exception("Exception occurred")
        return _json_response(ctx, 500, {"error": str(ex)})
