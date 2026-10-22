"""Local-only telemetry endpoints with strict browser-origin and session-token checks."""
from ipaddress import ip_address
import secrets
from fastapi import APIRouter, HTTPException, Request
from backend.capture_worker import CaptureController, CaptureSetupError

router = APIRouter(prefix="/api/capture", tags=["live capture telemetry"])
controller = CaptureController()
csrf_token = secrets.token_urlsafe(32)
ALLOWED_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}


def _local_request(request):
    host = (request.url.hostname or "").lower()
    client = request.client.host if request.client else ""
    try: local_host = host == "localhost" or ip_address(host).is_loopback
    except ValueError: local_host = False
    try: local_client = ip_address(client.split("%", 1)[0]).is_loopback
    except ValueError: local_client = client.lower() == "localhost"
    if not local_host or not local_client: raise HTTPException(403, "Local access only")


def _guard(request, token=False):
    _local_request(request)
    origin = request.headers.get("origin")
    if origin not in ALLOWED_ORIGINS: raise HTTPException(403, "Browser origin is not allowed")
    if token:
        supplied = request.headers.get("x-capture-token", "")
        if not controller.token or not secrets.compare_digest(supplied, controller.token):
            raise HTTPException(403, "Invalid capture session token")


def validate_start_body(body):
    if not isinstance(body, dict) or set(body) != {"interface"} or not isinstance(body["interface"], str):
        raise HTTPException(422, "Provide only a valid interface identifier")
    return body["interface"]


@router.get("/interfaces")
def get_interfaces(request: Request):
    _guard(request)
    try:
        return {"interfaces": controller.interface_provider()}
    except CaptureSetupError as exc:
        raise HTTPException(503, str(exc)) from None


@router.get("/csrf")
def get_csrf(request: Request):
    _guard(request)
    return {"token": csrf_token}


@router.get("/session")
def get_capture_session(request: Request):
    _guard(request)
    if not secrets.compare_digest(request.headers.get("x-capture-token", ""), csrf_token):
        raise HTTPException(403, "Invalid request token")
    state = controller.status()["state"]
    return {"token": controller.token if state in ("running", "error") else None}


@router.get("/status")
def get_status(request: Request):
    _guard(request)
    status = controller.status()
    status.pop("token", None)
    return status


@router.get("/telemetry")
def get_telemetry(request: Request):
    _guard(request, token=True)
    return controller.snapshot()


@router.get("/flows")
def get_flows(request: Request):
    _guard(request, token=True)
    # Serialize the running check with stop/restart so a snapshot cannot
    # cross a session boundary after authorization has been checked.
    with controller.lifecycle_lock:
        status = controller.status()
        if status["state"] != "running" or status["error"]:
            raise HTTPException(409, "Capture session is not running")
        return controller.flow_snapshot()


@router.post("/start")
async def start_capture(request: Request):
    _guard(request)
    if not secrets.compare_digest(request.headers.get("x-capture-token", ""), csrf_token):
        raise HTTPException(403, "Invalid request token")
    try: body = await request.json()
    except Exception: raise HTTPException(400, "Expected JSON body")
    interface = validate_start_body(body)
    try: return controller.start(interface)
    except CaptureSetupError as exc: raise HTTPException(503, str(exc))
    except ValueError as exc: raise HTTPException(409, str(exc))
    except RuntimeError as exc: raise HTTPException(503, str(exc))


@router.post("/stop")
def stop_capture(request: Request):
    _guard(request, token=True)
    try: return controller.stop()
    except ValueError as exc: raise HTTPException(409, str(exc))

