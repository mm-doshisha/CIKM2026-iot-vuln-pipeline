"""LLM server lifecycle management for llama-server."""

import json
import logging
import os
import subprocess
import time
from urllib.request import urlopen

try:
    import fcntl
except ImportError:
    class _NoopFcntl:
        LOCK_EX = 1
        LOCK_UN = 2

        @staticmethod
        def flock(*_args, **_kwargs):
            return None

    fcntl = _NoopFcntl()

logger = logging.getLogger("llm_server")

LLM_PORT = int(os.environ.get("LLM_PORT", "8080"))
LLM_HEALTH_URL = f"http://127.0.0.1:{LLM_PORT}/health"

# Server start command — set via env var or auto_retry.sh manages it
LLM_SERVER_CMD = os.environ.get("LLM_SERVER_CMD", "")


def is_healthy() -> bool:
    try:
        with urlopen(LLM_HEALTH_URL, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("status") == "ok"
    except Exception:
        return False


_RESTART_LOCK_PATH = "/tmp/llama_server_restart.lock"


def restart_server(wait_timeout: int = 120) -> bool:
    lock_fd = open(_RESTART_LOCK_PATH, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if is_healthy():
            logger.info("llama-server already recovered by another worker")
            return True
        return _restart_server_locked(wait_timeout)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


def _restart_server_locked(wait_timeout: int) -> bool:
    logger.info("Restarting llama-server...")

    subprocess.run(["pkill", "-9", "-f", "llama-server"],
                   capture_output=True, timeout=10)

    # Kill anything holding our port (prevents bind failures on restart)
    try:
        result = subprocess.run(
            ["lsof", "-t", "-i", f":{LLM_PORT}"],
            capture_output=True, text=True, timeout=5)
        for pid in result.stdout.strip().split("\n"):
            if pid.strip():
                subprocess.run(["kill", "-9", pid.strip()],
                               capture_output=True, timeout=5)
    except Exception:
        pass
    time.sleep(2)

    # Wait for GPU memory to be fully released
    for attempt in range(10):
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-compute-apps=pid", "--format=csv,noheader"],
                capture_output=True, text=True, timeout=10)
            pids = [p.strip() for p in result.stdout.strip().split("\n") if p.strip()]
            if not pids:
                break
            for pid in pids:
                subprocess.run(["kill", "-9", pid], capture_output=True, timeout=5)
            time.sleep(2)
        except Exception:
            break
    else:
        logger.warning("GPU processes still alive after cleanup retries")

    cmd = LLM_SERVER_CMD
    if not cmd:
        cmd = _find_server_cmd()
    if not cmd:
        logger.error("No LLM_SERVER_CMD set and cannot auto-detect")
        return False

    env = os.environ.copy()
    ld_path = env.get("LD_LIBRARY_PATH", "")
    # Optional extra CUDA lib dirs (colon-separated) for the llama.cpp server.
    cuda_extra = os.environ.get("LLAMA_CUDA_LIB_DIRS", "")
    for cuda_path in [p for p in cuda_extra.split(":") if p]:
        if cuda_path not in ld_path:
            ld_path = f"{cuda_path}:{ld_path}"
    env["LD_LIBRARY_PATH"] = ld_path

    log_path = os.environ.get("LLAMA_SERVER_LOG", "llama_server.log")
    with open(log_path, "w") as log_fh:
        subprocess.Popen(cmd, shell=True, stdout=log_fh, stderr=log_fh, env=env)

    for i in range(wait_timeout):
        if is_healthy():
            logger.info("llama-server ready (%ds)", i + 1)
            return True
        time.sleep(1)

    logger.error("llama-server failed to start within %ds", wait_timeout)
    return False


def ensure_healthy() -> bool:
    if is_healthy():
        return True
    logger.warning("llama-server unhealthy, attempting restart...")
    return restart_server()


def _find_server_cmd() -> str:
    # Configure via env vars (defaults assume a local ./models and ./llama.cpp layout).
    model_path = os.environ.get(
        "LLAMA_MODEL_PATH", "./models/Qwen3-8B-BF16/Qwen3-8B-BF16.gguf")
    server_bin = os.environ.get(
        "LLAMA_SERVER_BIN", "./llama.cpp/build/bin/llama-server")
    if os.path.exists(server_bin) and os.path.exists(model_path):
        return (f"nohup {server_bin} "
                f"--model {model_path} "
                f"--host 0.0.0.0 --port {LLM_PORT} "
                f"--parallel 4 --ctx-size 16384 "
                f"--reasoning off --cache-ram 0 --ctx-checkpoints 0 "
                f"--n-gpu-layers 999")
    return ""
