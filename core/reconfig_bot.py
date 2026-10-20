"""Panel-controllable reconfigure bot and service for VX-LB.

Provides:
- Panel & CLI controllable state: IDLE, RUNNING, PAUSED, COMPLETED, ROLLED_BACK, ERROR.
- Step-by-step reconfig trigger with checkpoint snapshot.
- Safe pause and resume mid-operation.
- Safe rollback restoring checkpoint state.
- Structured persistent audit logging.
- External notification configuration is stored, but delivery is not implemented.
  Calls report that no notification was sent.
"""
import copy
import json
import logging
import time
import uuid
from typing import Dict, List, Optional, Tuple, Any

from core.storage import atomic_update, load_data

logger = logging.getLogger("vxlb.reconfig_bot")

BOT_STATE_IDLE = "IDLE"
BOT_STATE_RUNNING = "RUNNING"
BOT_STATE_PAUSED = "PAUSED"
BOT_STATE_COMPLETED = "COMPLETED"
BOT_STATE_ROLLED_BACK = "ROLLED_BACK"
BOT_STATE_ERROR = "ERROR"

class ReconfigBot:
    """Manages controllable reconfigurations with audit logs, pause, and rollback."""

    @staticmethod
    def get_status() -> dict:
        data = load_data()
        bot_state = data.get("reconfig_bot", {})
        return {
            "state": bot_state.get("state", BOT_STATE_IDLE),
            "paused": bot_state.get("paused", False),
            "current_operation": bot_state.get("current_operation"),
            "current_step": bot_state.get("current_step", 0),
            "total_steps": bot_state.get("total_steps", 0),
            "last_action": bot_state.get("last_action", "none"),
            "last_updated": bot_state.get("last_updated"),
            "notifications_enabled": bot_state.get("notifications_enabled", False),
            "has_checkpoint": bool(bot_state.get("checkpoint")),
        }

    @staticmethod
    def configure_notifications(
        enabled: bool,
        webhook_url: Optional[str] = None,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None
    ) -> dict:
        """Configures external notifications with explicit opt-in."""
        result = {}
        def _update(data: dict):
            nonlocal result
            bot_state = data.setdefault("reconfig_bot", {})
            bot_state["notifications_enabled"] = bool(enabled)
            bot_state["webhook_url"] = str(webhook_url or "")
            bot_state["bot_token"] = str(bot_token or "")
            bot_state["chat_id"] = str(chat_id or "")
            bot_state["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            result = {
                "notifications_enabled": bot_state["notifications_enabled"],
                "has_webhook": bool(bot_state["webhook_url"]),
                "has_bot_token": bool(bot_state["bot_token"])
            }
        atomic_update(_update)
        ReconfigBot._record_audit_log("CONFIGURE_NOTIFICATIONS", "system", "notification_settings", {
            "enabled": enabled,
            "has_webhook": bool(webhook_url),
            "has_bot_token": bool(bot_token)
        })
        return result

    @staticmethod
    def notify(event: str, message: str, payload: Optional[dict] = None) -> dict:
        """Report notification availability without claiming unimplemented delivery."""
        data = load_data()
        bot_state = data.get("reconfig_bot", {})
        if not bot_state.get("notifications_enabled", False):
            return {
                "sent": False,
                "reason": "اعلان خارجی به دلیل عدم پیکربندی صریح (Opt-in) غیرفعال است."
            }

        webhook = bot_state.get("webhook_url")
        token = bot_state.get("bot_token")
        if not webhook and not token:
            return {
                "sent": False,
                "reason": "اعلان خارجی فعال است اما وب‌هوک یا توکن ربات مقداردهی نشده است."
            }

        return {
            "sent": False,
            "reason": "ارسال اعلان خارجی هنوز پیاده‌سازی نشده است.",
            "channel": "webhook" if webhook else "telegram",
            "event": event,
            "message": message,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    @staticmethod
    def trigger_reconfig(
        target_name: str,
        target_type: str,
        new_config: dict,
        steps: Optional[List[dict]] = None
    ) -> dict:
        """Triggers a staged reconfigure workflow with checkpoint and pause support."""
        data = load_data()
        bot_state = data.get("reconfig_bot", {})
        if bot_state.get("state") == BOT_STATE_RUNNING and not bot_state.get("paused"):
            raise RuntimeError("عملیات reconfigure دیگری در حال اجراست.")

        # Capture snapshot for rollback
        if target_type == "link":
            target_data = data.get("custom_links", {}).get(target_name)
        elif target_type == "pool":
            target_data = data.get("pools", {}).get(target_name)
        else:
            raise ValueError(f"Unknown target_type '{target_type}'")

        if not target_data:
            raise ValueError(f"{target_type} '{target_name}' یافت نشد.")

        checkpoint_id = f"cp-{uuid.uuid4().hex[:8]}"
        planned_steps = steps or [
            {"name": "validate_prerequisites", "status": "pending"},
            {"name": "apply_parameters", "status": "pending"},
            {"name": "verify_health", "status": "pending"},
            {"name": "commit_changes", "status": "pending"}
        ]

        def _update(data: dict):
            bot = data.setdefault("reconfig_bot", {})
            bot["state"] = BOT_STATE_RUNNING
            bot["paused"] = False
            bot["current_operation"] = {
                "operation_id": f"op-{uuid.uuid4().hex[:8]}",
                "target_name": target_name,
                "target_type": target_type,
                "new_config": new_config,
                "steps": planned_steps
            }
            bot["current_step"] = 0
            bot["total_steps"] = len(planned_steps)
            bot["checkpoint"] = {
                "checkpoint_id": checkpoint_id,
                "target_type": target_type,
                "target_name": target_name,
                "snapshot": copy.deepcopy(target_data),
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            bot["last_action"] = "reconfig_started"
            bot["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")

        atomic_update(_update)
        ReconfigBot._record_audit_log(
            "TRIGGER_RECONFIG", "panel", f"{target_type}:{target_name}",
            {"checkpoint_id": checkpoint_id, "steps_count": len(planned_steps)}
        )
        return {
            "status": "started",
            "checkpoint_id": checkpoint_id,
            "target": f"{target_type}:{target_name}",
            "steps": planned_steps
        }

    @staticmethod
    def pause() -> dict:
        """Pauses any active reconfig workflow safely."""
        paused = False
        def _update(data: dict):
            nonlocal paused
            bot = data.setdefault("reconfig_bot", {})
            if bot.get("state") == BOT_STATE_RUNNING:
                bot["state"] = BOT_STATE_PAUSED
                bot["paused"] = True
                bot["last_action"] = "paused_by_user"
                bot["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
                paused = True
            elif bot.get("state") == BOT_STATE_IDLE:
                bot["paused"] = True
                paused = True
        atomic_update(_update)
        ReconfigBot._record_audit_log("PAUSE_RECONFIG", "user", "reconfig_bot", {"paused": paused})
        return {"success": True, "paused": True, "state": BOT_STATE_PAUSED if paused else BOT_STATE_IDLE}

    @staticmethod
    def resume() -> dict:
        """Resumes a paused reconfig workflow."""
        resumed = False
        def _update(data: dict):
            nonlocal resumed
            bot = data.setdefault("reconfig_bot", {})
            if bot.get("state") == BOT_STATE_PAUSED or bot.get("paused"):
                bot["state"] = BOT_STATE_RUNNING if bot.get("current_operation") else BOT_STATE_IDLE
                bot["paused"] = False
                bot["last_action"] = "resumed_by_user"
                bot["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
                resumed = True
        atomic_update(_update)
        ReconfigBot._record_audit_log("RESUME_RECONFIG", "user", "reconfig_bot", {"resumed": resumed})
        return {"success": True, "resumed": resumed, "state": BOT_STATE_RUNNING if resumed else BOT_STATE_IDLE}

    @staticmethod
    def rollback() -> dict:
        """Rolls back the target resource to its pre-reconfig checkpoint state."""
        rolled_back = False
        restored_target = ""

        def _update(data: dict):
            nonlocal rolled_back, restored_target
            bot = data.setdefault("reconfig_bot", {})
            cp = bot.get("checkpoint")
            if not cp:
                raise RuntimeError("هیچ نقطه بازگشتی (checkpoint) برای rollback یافت نشد.")

            t_type = cp.get("target_type")
            t_name = cp.get("target_name")
            snapshot = cp.get("snapshot")
            restored_target = f"{t_type}:{t_name}"

            if t_type == "link":
                data.setdefault("custom_links", {})[t_name] = copy.deepcopy(snapshot)
            elif t_type == "pool":
                data.setdefault("pools", {})[t_name] = copy.deepcopy(snapshot)

            bot["state"] = BOT_STATE_ROLLED_BACK
            bot["paused"] = False
            bot["current_operation"] = None
            bot["last_action"] = f"rolled_back_to_{cp.get('checkpoint_id')}"
            bot["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            rolled_back = True

        atomic_update(_update)
        ReconfigBot._record_audit_log("ROLLBACK_RECONFIG", "user", restored_target, {"status": "restored"})
        return {
            "success": rolled_back,
            "status": "rolled_back",
            "restored_target": restored_target
        }

    @staticmethod
    def _record_audit_log(action: str, actor: str, target: str, details: dict):
        """Appends a persistent audit log entry."""
        entry = {
            "log_id": f"audit-{uuid.uuid4().hex[:8]}",
            "action": action,
            "actor": actor,
            "target": target,
            "details": details,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        def _update(data: dict):
            logs = data.setdefault("reconfig_audit_logs", [])
            logs.append(entry)
            # Keep last 500 audit logs
            if len(logs) > 500:
                data["reconfig_audit_logs"] = logs[-500:]
        atomic_update(_update)

    @staticmethod
    def get_audit_logs(limit: int = 50) -> List[dict]:
        """Returns the most recent audit log records."""
        data = load_data()
        logs = data.get("reconfig_audit_logs", [])
        return logs[-max(1, limit):]
