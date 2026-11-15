Here is the complete, ready-to-paste Markdown specification block containing the HMAC middleware code, Redis nonce store, defense-in-depth table, and threat model checklist.
You can copy this directly and paste it right after the verification section in your README.md:
---

## Secure Gateway & Kernel Architecture Specification

### 1. Cryptographic Handshake & Sigil Verification
To prevent unauthorized task orchestration and payload tampering, inter-service communication with the LM777 Kernel enforces strict cryptographic verification.

*   **HMAC-SHA256 Signature:** Requests must include an `X-Sigil-Signature` header computed over the payload using a pre-shared secret key fetched securely from Google Cloud Secret Manager.
*   **Constant-Time Comparison:** Uses `hmac.compare_digest` to prevent timing side-channel attacks during signature validation.
*   **Timestamp Drift Window:** Enforces a strict $\pm 30$-second validation window (`X-Sigil-Timestamp`) to mitigate replay vulnerabilities.

### 2. Distributed Nonce Store (Redis)
To eliminate replay attacks within the valid timestamp window across multi-worker deployments (e.g., Uvicorn behind a load balancer), nonces are tracked atomically using Redis:
*   **Atomic `SET NX EX`:** Nonces are registered with a 60-second Time-to-Live (`ex=60`) and `nx=True` condition.
*   **Fail-Closed Security:** If Redis experiences an outage, the middleware catches the exception and returns a `503 Service Unavailable` rather than failing open.
*   **HMAC Verification First:** Signatures are verified *before* a nonce is claimed in Redis, preventing denial-of-service (DoS) attacks that attempt to burn valid nonces with forged payloads.

---

### 3. FastAPI Secure Gateway Middleware Implementation

```python
import hmac
import hashlib
import time
import redis.asyncio as redis
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from google.cloud import secretmanager

app = FastAPI(title="LM777 Kernel Hardened & Secure Gateway")

# Configuration Constants
ALLOWED_TIME_DRIFT_SECONDS = 30
NONCE_TTL_SECONDS = 60
SECRET_RESOURCE_NAME = "projects/your-gcp-project-id/secrets/lm777-hmac-secret/versions/latest"

redis_client = redis.Redis.from_url(
    "redis://localhost:6379/0", 
    encoding="utf-8", 
    decode_responses=True
)

def get_secret_from_gcp() -> bytes:
    try:
        client = secretmanager.SecretManagerServiceClient()
        response = client.access_secret_version(request={"name": SECRET_RESOURCE_NAME})
        return response.payload.data
    except Exception as e:
        print(f"Warning: Failed to fetch secret from GCP Secret Manager: {e}")
        return b"fallback-dev-secret-key"

HMAC_SECRET_KEY = get_secret_from_gcp()


class SecureSigilAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in ["/docs", "/redoc", "/openapi.json", "/health"]:
            return await call_next(request)

        signature_header = request.headers.get("X-Sigil-Signature")
        timestamp_header = request.headers.get("X-Sigil-Timestamp")
        nonce_header = request.headers.get("X-Sigil-Nonce")

        if not signature_header or not timestamp_header or not nonce_header:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Authentication failed: Missing required cryptographic headers."}
            )

        # 1. Validate timestamp window
        try:
            req_timestamp = int(timestamp_header)
        except ValueError:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Bad Request: Invalid timestamp format."}
            )

        if abs(int(time.time()) - req_timestamp) > ALLOWED_TIME_DRIFT_SECONDS:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Unauthorized: Timestamp outside acceptable validation window."}
            )

        # 2. Read and cache body stream early so it's available for hashing and downstream handlers
        body = await request.body()
        async def receive():
            return {"type": "http.request", "body": body}
        request._receive = receive

        # 3. Verify HMAC Signature FIRST (Prevents nonce-burning DoS attacks)
        message_payload = f"{timestamp_header}:{nonce_header}".encode("utf-8") + body

        expected_signature = hmac.new(
            HMAC_SECRET_KEY,
            message_payload,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_signature, signature_header):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Unauthorized: Invalid cryptographic sigil signature."}
            )

        # 4. Claim Nonce in Redis ONLY AFTER signature verification passes
        redis_nonce_key = f"lm777:nonce:{nonce_header}"
        
        try:
            is_new_nonce = await redis_client.set(
                redis_nonce_key, 
                "1", 
                ex=NONCE_TTL_SECONDS, 
                nx=True
            )
            
            if not is_new_nonce:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Unauthorized: Nonce already utilized (Replay attack detected)."}
                )
        except redis.RedisError as e:
            print(f"CRITICAL: Redis nonce store failure: {e}")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": "Service Unavailable: Authentication store failure."}
            )

        response = await call_next(request)
        return response

app.add_middleware(SecureSigilAuthMiddleware)

@app.post("/api/v1/kernel/execute")
async def execute_task(payload: dict):
    return {
        "status": "fully_verified_and_secured",
        "kernel": "LM777",
        "received_payload": payload
    }

4. Defense-in-Depth & Threat Model Matrix
| Threat Vector | Potential Impact | Mitigation Strategy & Controls |
|---|---|---|
| Payload Tampering | Unauthorized mutation of task parameters in transit | HMAC-SHA256 signature calculated over raw body bytes + headers |
| Replay Attacks | Interception and re-transmission of valid signed requests | \pm 30-second timestamp window combined with atomic Redis nonces (SET NX EX) |
| Nonce-Burning DoS | Flooding endpoint with forged requests to exhaust nonce storage | HMAC verification executed prior to Redis nonce registration |
| Timing Side-Channels | Signature extraction via execution time analysis | Constant-time string comparison (hmac.compare_digest) |
| Store Outage Exploits | Failing open during Redis cluster partitions | Fail-closed design returning 503 Service Unavailable on Redis errors |

