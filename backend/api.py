"""REST API for Network Spoofer."""

import asyncio
from contextlib import asynccontextmanager
from typing import Optional
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app import NetworkSpoofer, DeviceState


class TargetRequest(BaseModel):
    ip: str


class LimitRequest(BaseModel):
    limit_kbps: int


class DeviceResponse(BaseModel):
    ip: str
    mac: str
    hostname: Optional[str] = None
    is_gateway: bool = False


class SpooferStatusResponse(BaseModel):
    running: bool
    target_count: int
    targets: list[str]


class StatsResponse(BaseModel):
    ip: str
    mac: str
    hostname: Optional[str] = None
    status: str
    bandwidth_limit_kbps: Optional[int] = None
    download_rate_mbps: float
    upload_rate_mbps: float
    total_download_mb: float
    total_upload_mb: float


spoofer: Optional[NetworkSpoofer] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize spoofer on startup, cleanup on shutdown."""
    global spoofer
    
    print("[*] Starting API server...")
    spoofer = NetworkSpoofer()
    
    try:
        spoofer.initialize()
    except Exception as e:
        print(f"[!] Failed to initialize: {e}")
        print("    Make sure you're connected to a network")
        
    yield  # App runs here
    
    # Cleanup on shutdown
    print("[*] Shutting down API server...")
    if spoofer and spoofer.is_running():
        spoofer.stop()


app = FastAPI(
    title="Network Spoofer API",
    description="Network monitoring and control tool",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


connected_clients: list[WebSocket] = []


async def broadcast_stats():
    """Send stats to all connected WebSocket clients."""
    if not spoofer or not spoofer.is_running():
        return
        
    states = spoofer.get_device_states()
    data = [asdict(state) for state in states]
    
    for client in connected_clients:
        try:
            await client.send_json({"type": "stats", "data": data})
        except:
            pass


async def stats_broadcaster():
    """Periodically broadcast stats to WebSocket clients."""
    while True:
        await broadcast_stats()
        await asyncio.sleep(1)


@app.on_event("startup")
async def start_broadcaster():
    asyncio.create_task(stats_broadcaster())


# API Endpoints

@app.get("/api/network/info")
async def get_network_info():
    """Get current network information."""
    if not spoofer or not spoofer.network_info:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    return spoofer.get_network_info_dict()


@app.get("/api/network/scan")
async def scan_network() -> list[DeviceResponse]:
    """Scan network for devices using ARP."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    devices = spoofer.scan_network()
    
    return [
        DeviceResponse(
            ip=d.ip,
            mac=d.mac,
            hostname=d.hostname,
            is_gateway=d.is_gateway
        )
        for d in devices
    ]


@app.get("/api/devices")
async def get_devices() -> list[DeviceResponse]:
    """Get list of discovered devices from last scan."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    return [
        DeviceResponse(
            ip=d.ip,
            mac=d.mac,
            hostname=d.hostname,
            is_gateway=d.is_gateway
        )
        for d in spoofer.devices
    ]


@app.post("/api/targets")
async def add_target(request: TargetRequest):
    """Add a device as a target for monitoring."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    success = spoofer.add_target(request.ip)
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to add target. Make sure device was scanned.")
        
    return {"status": "success", "message": f"Added target {request.ip}"}


@app.delete("/api/targets/{ip}")
async def remove_target(ip: str):
    """Remove a device from targets."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    spoofer.remove_target(ip)
    
    return {"status": "success", "message": f"Removed target {ip}"}


@app.post("/api/spoofer/start")
async def start_spoofing():
    """Start ARP spoofing for all targets."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    success = spoofer.start()
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to start. Add targets first.")
        
    return {"status": "success", "message": "Spoofing started"}


@app.post("/api/spoofer/stop")
async def stop_spoofing():
    """Stop spoofing and restore ARP tables."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    spoofer.stop()
    
    return {"status": "success", "message": "Spoofing stopped"}


@app.get("/api/spoofer/status")
async def get_spoofer_status() -> SpooferStatusResponse:
    """Get the current status of the spoofer."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    targets = list(spoofer.spoofer.targets.keys())
    
    return SpooferStatusResponse(
        running=spoofer.is_running(),
        target_count=len(targets),
        targets=targets
    )


@app.post("/api/device/{ip}/block")
async def block_device(ip: str):
    """Block a device's internet access."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    success = spoofer.block_device(ip)
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to block device")
        
    return {"status": "success", "message": f"Blocked {ip}"}


@app.post("/api/device/{ip}/unblock")
async def unblock_device(ip: str):
    """Unblock a previously blocked device."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    success = spoofer.unblock_device(ip)
    
    return {"status": "success", "message": f"Unblocked {ip}"}


@app.post("/api/device/{ip}/limit")
async def limit_device(ip: str, request: LimitRequest):
    """Limit a device's bandwidth (Kbps)."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    success = spoofer.limit_device(ip, request.limit_kbps)
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to limit device")
        
    return {"status": "success", "message": f"Limited {ip} to {request.limit_kbps} Kbps"}


@app.post("/api/device/{ip}/unlimit")
async def unlimit_device(ip: str):
    """Remove bandwidth limit from a device."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    success = spoofer.remove_limit(ip)
    
    return {"status": "success", "message": f"Removed limit from {ip}"}


@app.get("/api/stats")
async def get_stats() -> list[StatsResponse]:
    """Get bandwidth statistics for all monitored devices."""
    if not spoofer:
        raise HTTPException(status_code=503, detail="Spoofer not initialized")
        
    states = spoofer.get_device_states()
    
    return [
        StatsResponse(
            ip=s.ip,
            mac=s.mac,
            hostname=s.hostname,
            status=s.status,
            bandwidth_limit_kbps=s.bandwidth_limit_kbps,
            download_rate_mbps=round(s.download_rate_mbps, 2),
            upload_rate_mbps=round(s.upload_rate_mbps, 2),
            total_download_mb=round(s.total_download_mb, 2),
            total_upload_mb=round(s.total_upload_mb, 2)
        )
        for s in states
    ]


# WebSocket

@app.websocket("/ws/stats")
async def websocket_stats(websocket: WebSocket):
    """WebSocket endpoint for real-time statistics."""
    await websocket.accept()
    connected_clients.append(websocket)
    
    try:
        while True:
            # Keep connection alive, wait for client messages
            data = await websocket.receive_text()
            # Could handle commands from client here
            
    except WebSocketDisconnect:
        connected_clients.remove(websocket)


# Entry Point

if __name__ == "__main__":
    import uvicorn
    
    print("Network Spoofer API Server")
    print("Run with sudo for full functionality")
    print("Docs: http://localhost:8000/docs")
    
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=False)
