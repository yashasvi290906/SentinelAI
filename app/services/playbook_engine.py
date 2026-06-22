import asyncio
import json
import uuid
import re
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Callable, Awaitable
from enum import Enum

from pydantic import BaseModel, Field, validator
from database import db

logger = logging.getLogger(__name__)


class StepType(str, Enum):
    ACTION = "action"
    CONDITION = "condition"
    APPROVAL_GATE = "approval_gate"
    ENRICHMENT = "enrichment"
    NOTIFICATION = "notification"
    CONTAINMENT = "containment"
    PARALLEL = "parallel"
    SCRIPT = "script"


class ConditionBranch(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    label: str
    condition: Dict[str, Any] = {}
    next_steps: List[str] = []


class ApprovalConfig(BaseModel):
    required_approvers: int = 1
    approvers: List[str] = []
    timeout_seconds: int = 3600
    auto_approve_on_timeout: bool = False
    message: str = ""


class ErrorHandling(BaseModel):
    retry_count: int = 3
    retry_delay_seconds: int = 5
    on_max_retries: str = "fail"


class StepConfig(BaseModel):
    action_type: Optional[str] = None
    parameters: Dict[str, Any] = {}
    script_code: Optional[str] = None
    timeout_seconds: int = 300
    parallel_steps: List[str] = []


class PlaybookStep(BaseModel):
    id: str
    type: StepType
    name: str
    description: str = ""
    config: StepConfig = Field(default_factory=StepConfig)
    conditions: List[ConditionBranch] = []
    approval: Optional[ApprovalConfig] = None
    on_success: Optional[str] = None
    on_failure: Optional[str] = None
    next: Optional[str] = None


class TriggerConfig(BaseModel):
    type: str = "manual"
    filters: Dict[str, Any] = {}


class Playbook(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    version: str = "1.0.0"
    author: str = "SentinelAI"
    tags: List[str] = []
    severity_threshold: str = "medium"
    mitre_tactics: List[str] = []
    trigger: TriggerConfig = Field(default_factory=TriggerConfig)
    steps: List[PlaybookStep] = []
    error_handling: ErrorHandling = Field(default_factory=ErrorHandling)
    enabled: bool = True


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING_APPROVAL = "waiting_approval"


class PlaybookRunner:
    def __init__(self):
        self._step_handlers: Dict[StepType, Callable] = {
            StepType.ACTION: self._run_action,
            StepType.CONDITION: self._evaluate_condition,
            StepType.APPROVAL_GATE: self._wait_for_approval,
            StepType.ENRICHMENT: self._run_action,
            StepType.NOTIFICATION: self._run_action,
            StepType.CONTAINMENT: self._run_action,
            StepType.PARALLEL: self._run_parallel,
            StepType.SCRIPT: self._run_script,
        }

    async def execute(self, playbook: Playbook, trigger_data: Dict[str, Any]) -> str:
        execution_id = str(uuid.uuid4())
        context = {
            "execution_id": execution_id,
            "playbook_id": playbook.id,
            "playbook_name": playbook.name,
            "trigger_data": trigger_data,
            "variables": {},
            "step_outputs": {},
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": ExecutionStatus.RUNNING.value,
            "current_step": None,
            "error_log": [],
        }

        await db.execute(
            """INSERT INTO playbook_executions
               (id, playbook_id, playbook_name, trigger_data, status, context, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (execution_id, playbook.id, playbook.name, json.dumps(trigger_data),
             ExecutionStatus.RUNNING.value, json.dumps(context),
             datetime.now(timezone.utc).isoformat()),
        )

        logger.info(f"Starting playbook execution {execution_id} for playbook {playbook.name}")

        step_map = {s.id: s for s in playbook.steps}
        first_step = playbook.steps[0] if playbook.steps else None

        if not first_step:
            context["status"] = ExecutionStatus.COMPLETED.value
            await self._update_execution(execution_id, context)
            return execution_id

        try:
            await self._execute_dag(playbook, first_step.id, step_map, context)
        except Exception as e:
            logger.error(f"Playbook execution {execution_id} failed: {e}")
            context["status"] = ExecutionStatus.FAILED.value
            context["error_log"].append({
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "step": context.get("current_step"),
            })

        context["completed_at"] = datetime.now(timezone.utc).isoformat()
        await self._update_execution(execution_id, context)
        logger.info(f"Playbook execution {execution_id} finished with status {context['status']}")
        return execution_id

    async def _execute_dag(self, playbook: Playbook, step_id: str, step_map: Dict[str, PlaybookStep], context: Dict[str, Any]):
        visited = set()
        queue = [step_id]

        while queue:
            current_id = queue.pop(0)
            if current_id in visited or current_id not in step_map:
                continue

            visited.add(current_id)
            step = step_map[current_id]
            context["current_step"] = current_id

            result = await self._execute_step(step, context)

            await self._log_action(context["execution_id"], step.id, step.name, step.type.value, result)

            if result.get("status") == "failed" and not result.get("continue_on_failure"):
                context["status"] = ExecutionStatus.FAILED.value
                raise RuntimeError(f"Step {step.id} ({step.name}) failed: {result.get('error', 'Unknown error')}")

            if step.type == StepType.CONDITION:
                selected_branch = result.get("selected_branch")
                if selected_branch and selected_branch in step_map:
                    queue.append(selected_branch)
            else:
                next_step = result.get("next_step") or step.next
                if next_step and next_step in step_map:
                    queue.append(next_step)

        if context["status"] == ExecutionStatus.RUNNING.value:
            context["status"] = ExecutionStatus.COMPLETED.value

    async def _execute_step(self, step: PlaybookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        handler = self._step_handlers.get(step.type)
        if not handler:
            return {"status": "failed", "error": f"No handler for step type {step.type}"}

        max_retries = context.get("retry_count", 3)
        retry_delay = context.get("retry_delay", 5)

        for attempt in range(max_retries + 1):
            try:
                result = await handler(step, context)
                if attempt > 0:
                    logger.info(f"Step {step.id} succeeded on attempt {attempt + 1}")
                return result
            except Exception as e:
                if attempt < max_retries:
                    logger.warning(f"Step {step.id} attempt {attempt + 1} failed: {e}, retrying in {retry_delay}s")
                    await asyncio.sleep(retry_delay)
                else:
                    logger.error(f"Step {step.id} failed after {max_retries + 1} attempts: {e}")
                    return {"status": "failed", "error": str(e)}

        return {"status": "failed", "error": "Max retries exceeded"}

    async def _run_action(self, step: PlaybookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        action_type = step.config.action_type
        if not action_type:
            return {"status": "failed", "error": "No action_type specified"}

        resolved_params = self._resolve_templates(step.config.parameters, context)
        action_func = action_registry.get_action(action_type)

        if not action_func:
            return {"status": "failed", "error": f"Unknown action: {action_type}"}

        try:
            result = await asyncio.wait_for(
                action_func(**resolved_params),
                timeout=step.config.timeout_seconds,
            )
            context["step_outputs"][step.id] = result
            return {"status": "completed", "result": result, "next_step": step.on_success or step.next}
        except asyncio.TimeoutError:
            return {"status": "failed", "error": f"Action {action_type} timed out after {step.config.timeout_seconds}s"}
        except Exception as e:
            logger.error(f"Action {action_type} failed: {e}")
            return {"status": "failed", "error": str(e), "next_step": step.on_failure}

    async def _evaluate_condition(self, step: PlaybookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        for branch in step.conditions:
            condition = branch.condition
            if not condition:
                continue

            field_ref = condition.get("field", "")
            operator = condition.get("operator", "equals")
            expected = condition.get("expected", "")

            actual = self._resolve_template_value(field_ref, context)

            if self._compare(actual, operator, expected):
                next_steps = branch.next_steps or [branch.id]
                return {
                    "status": "completed",
                    "selected_branch": next_steps[0] if next_steps else None,
                    "branch_label": branch.label,
                    "next_step": next_steps[0] if next_steps else step.next,
                }

        return {"status": "completed", "selected_branch": None, "next_step": step.next}

    async def _wait_for_approval(self, step: PlaybookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        approval_config = step.approval
        if not approval_config:
            return {"status": "failed", "error": "No approval config"}

        resolved_message = self._resolve_template_value(approval_config.message, context) if approval_config.message else step.description

        approval_id = str(uuid.uuid4())
        approval_record = {
            "id": approval_id,
            "step_id": step.id,
            "execution_id": context["execution_id"],
            "message": resolved_message,
            "required_approvers": approval_config.required_approvers,
            "approvers": approval_config.approvers,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "timeout_seconds": approval_config.timeout_seconds,
        }

        context["step_outputs"][step.id] = {"approval_id": approval_id, "status": "pending"}
        context["status"] = ExecutionStatus.PAUSED.value

        await self._update_execution(context["execution_id"], context)
        await self._log_action(context["execution_id"], step.id, step.name, "approval_gate",
                               {"approval_id": approval_id, "status": "waiting"})

        logger.info(f"Waiting for approval on step {step.id}, approval_id: {approval_id}")

        if approval_config.auto_approve_on_timeout:
            try:
                await asyncio.wait_for(
                    self._wait_for_approval_completion(approval_id),
                    timeout=approval_config.timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.info(f"Approval {approval_id} timed out, auto-approving")
                context["status"] = ExecutionStatus.RUNNING.value
                return {"status": "completed", "approval_granted": True, "auto_approved": True, "next_step": step.on_success or step.next}

        context["status"] = ExecutionStatus.RUNNING.value
        return {"status": "completed", "approval_granted": True, "next_step": step.on_success or step.next}

    async def _wait_for_approval_completion(self, approval_id: str):
        while True:
            result = await db.fetch_one(
                "SELECT status FROM playbook_action_log WHERE id = ?", (approval_id,)
            )
            if result and result["status"] in ("approved", "rejected"):
                return result["status"]
            await asyncio.sleep(2)

    async def _run_parallel(self, step: PlaybookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        parallel_step_ids = step.config.parallel_steps
        if not parallel_step_ids:
            return {"status": "completed", "result": {}, "next_step": step.next}

        tasks = []
        for ps_id in parallel_step_ids:
            tasks.append(self._execute_parallel_step(ps_id, context))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        parallel_results = {}
        all_succeeded = True
        for i, result in enumerate(results):
            ps_id = parallel_step_ids[i]
            if isinstance(result, Exception):
                parallel_results[ps_id] = {"status": "failed", "error": str(result)}
                all_succeeded = False
            else:
                parallel_results[ps_id] = result
                if result.get("status") == "failed":
                    all_succeeded = False

        context["step_outputs"][step.id] = parallel_results

        return {
            "status": "completed" if all_succeeded else "failed",
            "result": parallel_results,
            "next_step": step.on_success if all_succeeded else step.on_failure,
        }

    async def _execute_parallel_step(self, step_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "completed", "parallel_step": step_id, "output": {}}

    async def _run_script(self, step: PlaybookStep, context: Dict[str, Any]) -> Dict[str, Any]:
        script_code = step.config.script_code
        if not script_code:
            return {"status": "failed", "error": "No script code"}

        resolved_params = self._resolve_templates(step.config.parameters, context)

        try:
            script_globals = {
                "context": context,
                "params": resolved_params,
                "asyncio": asyncio,
                "json": json,
                "uuid": uuid,
                "datetime": datetime,
                "re": re,
                "hashlib": hashlib,
                "logger": logger,
            }
            script_globals["result"] = {}

            exec(compile(script_code, f"<script:{step.id}>", "exec"), script_globals)
            output = script_globals.get("result", {})
            context["step_outputs"][step.id] = output
            return {"status": "completed", "result": output, "next_step": step.on_success or step.next}
        except Exception as e:
            logger.error(f"Script execution failed for step {step.id}: {e}")
            return {"status": "failed", "error": str(e), "next_step": step.on_failure}

    def _resolve_templates(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        resolved = {}
        for key, value in params.items():
            resolved[key] = self._resolve_template_value(value, context)
        return resolved

    def _resolve_template_value(self, value: Any, context: Dict[str, Any]) -> Any:
        if isinstance(value, str):
            pattern = re.compile(r"\$trigger\.([a-zA-Z0-9_.]+)")
            matches = pattern.findall(value)
            resolved = value
            for match in matches:
                trigger_val = self._get_nested_value(context.get("trigger_data", {}), match)
                resolved = resolved.replace(f"$trigger.{match}", str(trigger_val) if trigger_val is not None else "")

            step_pattern = re.compile(r"\$step-([a-zA-Z0-9_]+)\.output\.([a-zA-Z0-9_.]+)")
            step_matches = step_pattern.findall(resolved)
            for step_id, field_path in step_matches:
                step_output = context.get("step_outputs", {}).get(step_id, {})
                field_val = self._get_nested_value(step_output, field_path)
                resolved = resolved.replace(f"$step-{step_id}.output.{field_path}", str(field_val) if field_val is not None else "")

            var_pattern = re.compile(r"\$var\.([a-zA-Z0-9_]+)")
            var_matches = var_pattern.findall(resolved)
            for var_name in var_matches:
                var_val = context.get("variables", {}).get(var_name)
                resolved = resolved.replace(f"$var.{var_name}", str(var_val) if var_val is not None else "")

            return resolved
        elif isinstance(value, dict):
            return {k: self._resolve_template_value(v, context) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._resolve_template_value(item, context) for item in value]
        return value

    def _resolve_template_value_plain(self, value: Any, context: Dict[str, Any]) -> Any:
        if isinstance(value, str) and value.startswith("$trigger."):
            field = value[len("$trigger."):]
            return self._get_nested_value(context.get("trigger_data", {}), field)
        return value

    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        keys = path.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current

    def _compare(self, actual: Any, operator: str, expected: Any) -> bool:
        if actual is None:
            return False

        try:
            if operator == "equals":
                return str(actual) == str(expected)
            elif operator == "not_equals":
                return str(actual) != str(expected)
            elif operator == "greater_than":
                return float(actual) > float(expected)
            elif operator == "less_than":
                return float(actual) < float(expected)
            elif operator == "greater_than_or_equals":
                return float(actual) >= float(expected)
            elif operator == "less_than_or_equals":
                return float(actual) <= float(expected)
            elif operator == "contains":
                return str(expected) in str(actual)
            elif operator == "not_contains":
                return str(expected) not in str(actual)
            elif operator == "in":
                if isinstance(expected, str):
                    expected_list = [x.strip() for x in expected.split(",")]
                elif isinstance(expected, list):
                    expected_list = expected
                else:
                    expected_list = [expected]
                return str(actual) in [str(x) for x in expected_list]
            elif operator == "regex":
                return bool(re.search(str(expected), str(actual)))
            elif operator == "starts_with":
                return str(actual).startswith(str(expected))
            elif operator == "ends_with":
                return str(actual).endswith(str(expected))
            elif operator == "is_empty":
                return not actual or (isinstance(actual, (str, list, dict)) and len(actual) == 0)
            elif operator == "is_not_empty":
                return bool(actual) and len(actual) > 0 if isinstance(actual, (str, list, dict)) else bool(actual)
            elif operator == "and":
                if isinstance(expected, list):
                    return all(self._compare(actual, "equals", exp) for exp in expected)
                return False
            elif operator == "or":
                if isinstance(expected, list):
                    return any(self._compare(actual, "equals", exp) for exp in expected)
                return False
            else:
                logger.warning(f"Unknown comparison operator: {operator}")
                return False
        except (ValueError, TypeError) as e:
            logger.error(f"Comparison failed: {actual} {operator} {expected}: {e}")
            return False

    async def _update_execution(self, execution_id: str, context: Dict[str, Any]):
        try:
            await db.execute(
                """UPDATE playbook_executions
                   SET status = ?, context = ?, updated_at = ?
                   WHERE id = ?""",
                (context["status"], json.dumps(context),
                 datetime.now(timezone.utc).isoformat(), execution_id),
            )
        except Exception as e:
            logger.error(f"Failed to update execution {execution_id}: {e}")

    async def _log_action(self, execution_id: str, step_id: str, step_name: str, action_type: str, result: Dict[str, Any]):
        try:
            log_id = str(uuid.uuid4())
            await db.execute(
                """INSERT INTO playbook_action_log
                   (id, execution_id, step_id, step_name, action_type, result, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (log_id, execution_id, step_id, step_name, action_type,
                 json.dumps(result), datetime.now(timezone.utc).isoformat()),
            )
        except Exception as e:
            logger.error(f"Failed to log action for step {step_id}: {e}")


class ActionRegistry:
    def __init__(self):
        self._actions: Dict[str, Callable[..., Awaitable[Dict[str, Any]]]] = {}
        self._register_builtin_actions()

    def register(self, name: str, func: Callable[..., Awaitable[Dict[str, Any]]]):
        self._actions[name] = func

    def get_action(self, name: str) -> Optional[Callable[..., Awaitable[Dict[str, Any]]]]:
        return self._actions.get(name)

    def list_actions(self) -> List[str]:
        return list(self._actions.keys())

    def _register_builtin_actions(self):
        self.register("firewall.block_ip", self._firewall_block_ip)
        self.register("firewall.block_domain", self._firewall_block_domain)
        self.register("active_directory.disable_account", self._ad_disable_account)
        self.register("active_directory.force_password_reset", self._ad_force_password_reset)
        self.register("notification.email", self._notification_email)
        self.register("notification.slack", self._notification_slack)
        self.register("notification.pagerduty", self._notification_pagerduty)
        self.register("ticket.create", self._ticket_create)
        self.register("ticket.update", self._ticket_update)
        self.register("enrichment.virustotal", self._enrichment_virustotal)
        self.register("enrichment.abuseipdb", self._enrichment_abuseipdb)
        self.register("enrichment.geoip", self._enrichment_geoip)
        self.register("forensics.hash", self._forensics_hash)
        self.register("siem.create_alert", self._siem_create_alert)

    async def _firewall_block_ip(self, ip_address: str, duration: str = "24h", reason: str = "", **kwargs) -> Dict[str, Any]:
        rule_id = str(uuid.uuid4())[:12]
        logger.info(f"Firewall: Blocking IP {ip_address} for {duration}. Rule ID: {rule_id}")
        await db.execute(
            """INSERT INTO playbook_action_log (id, execution_id, step_id, step_name, action_type, result, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (rule_id, kwargs.get("execution_id", ""), "firewall", "firewall.block_ip",
             json.dumps({"ip": ip_address, "duration": duration, "reason": reason, "rule_id": rule_id}),
             datetime.now(timezone.utc).isoformat()),
        )
        return {"success": True, "rule_id": rule_id, "ip": ip_address, "duration": duration, "message": f"IP {ip_address} blocked for {duration}"}

    async def _firewall_block_domain(self, domain: str, duration: str = "24h", reason: str = "", **kwargs) -> Dict[str, Any]:
        rule_id = str(uuid.uuid4())[:12]
        logger.info(f"Firewall: Blocking domain {domain} for {duration}. Rule ID: {rule_id}")
        return {"success": True, "rule_id": rule_id, "domain": domain, "duration": duration, "message": f"Domain {domain} blocked for {duration}"}

    async def _ad_disable_account(self, username: str, reason: str = "", **kwargs) -> Dict[str, Any]:
        logger.info(f"AD: Disabling account {username}. Reason: {reason}")
        return {"success": True, "username": username, "action": "disabled", "message": f"Account {username} disabled"}

    async def _ad_force_password_reset(self, username: str, **kwargs) -> Dict[str, Any]:
        logger.info(f"AD: Forcing password reset for {username}")
        return {"success": True, "username": username, "action": "password_reset", "message": f"Password reset forced for {username}"}

    async def _notification_email(self, to: str, subject: str, body: str, cc: str = "", **kwargs) -> Dict[str, Any]:
        logger.info(f"Email notification sent to {to}: {subject}")
        return {"success": True, "to": to, "subject": subject, "message": f"Email sent to {to}"}

    async def _notification_slack(self, channel: str, message: str, webhook_url: str = "", **kwargs) -> Dict[str, Any]:
        logger.info(f"Slack notification sent to {channel}: {message[:50]}...")
        return {"success": True, "channel": channel, "message": f"Slack message sent to {channel}"}

    async def _notification_pagerduty(self, service_key: str, description: str, severity: str = "critical", **kwargs) -> Dict[str, Any]:
        incident_id = str(uuid.uuid4())[:8]
        logger.info(f"PagerDuty incident {incident_id} created: {description}")
        return {"success": True, "incident_id": incident_id, "severity": severity, "message": f"PagerDuty incident {incident_id} created"}

    async def _ticket_create(self, title: str, description: str, priority: str = "medium", assignee: str = "", **kwargs) -> Dict[str, Any]:
        ticket_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        logger.info(f"Ticket created: {ticket_id} - {title}")
        return {"success": True, "ticket_id": ticket_id, "title": title, "priority": priority, "message": f"Ticket {ticket_id} created"}

    async def _ticket_update(self, ticket_id: str, status: str = "", comment: str = "", **kwargs) -> Dict[str, Any]:
        logger.info(f"Ticket {ticket_id} updated: status={status}")
        return {"success": True, "ticket_id": ticket_id, "status": status, "message": f"Ticket {ticket_id} updated"}

    async def _enrichment_virustotal(self, ioc: str, ioc_type: str = "ip", **kwargs) -> Dict[str, Any]:
        logger.info(f"VirusTotal enrichment for {ioc_type}: {ioc}")
        return {
            "success": True, "ioc": ioc, "ioc_type": ioc_type,
            "detection_ratio": "0/90", "reputation": "clean",
            "categories": [], "tags": [],
            "message": f"VirusTotal analysis complete for {ioc}",
        }

    async def _enrichment_abuseipdb(self, ip_address: str, **kwargs) -> Dict[str, Any]:
        logger.info(f"AbuseIPDB lookup for {ip_address}")
        return {
            "success": True, "ip": ip_address,
            "abuse_confidence_score": 0, "total_reports": 0,
            "country_code": "US", "isp": "Unknown",
            "message": f"AbuseIPDB lookup complete for {ip_address}",
        }

    async def _enrichment_geoip(self, ip_address: str, **kwargs) -> Dict[str, Any]:
        logger.info(f"GeoIP lookup for {ip_address}")
        return {
            "success": True, "ip": ip_address,
            "country": "United States", "country_code": "US",
            "city": "Unknown", "latitude": 0.0, "longitude": 0.0,
            "message": f"GeoIP lookup complete for {ip_address}",
        }

    async def _forensics_hash(self, file_path: str = "", file_content: str = "", algorithm: str = "sha256", **kwargs) -> Dict[str, Any]:
        if file_content:
            hash_value = hashlib.new(algorithm)
            hash_value.update(file_content.encode("utf-8"))
            digest = hash_value.hexdigest()
        else:
            digest = hashlib.sha256(file_path.encode("utf-8")).hexdigest()

        logger.info(f"Forensics hash ({algorithm}): {digest}")
        return {"success": True, "algorithm": algorithm, "hash": digest, "file_path": file_path, "message": f"Hash computed: {digest[:16]}..."}

    async def _siem_create_alert(self, title: str, severity: str = "medium", description: str = "", source: str = "SentinelAI", **kwargs) -> Dict[str, Any]:
        alert_id = str(uuid.uuid4())[:12]
        logger.info(f"SIEM alert created: {alert_id} - {title}")
        return {"success": True, "alert_id": alert_id, "title": title, "severity": severity, "source": source, "message": f"SIEM alert {alert_id} created"}


PREBUILT_PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "id": "pb-critical-threat-auto-contain",
        "name": "Critical Threat Auto-Contain",
        "description": "Automatically contain critical severity threats by blocking malicious IPs, disabling compromised accounts, and creating incident tickets.",
        "version": "1.0.0",
        "author": "SentinelAI",
        "tags": ["critical", "auto-contain", "incident-response"],
        "severity_threshold": "critical",
        "mitre_tactics": ["TA0001", "TA0002", "TA0005"],
        "trigger": {"type": "alert", "filters": {"severity": "critical"}},
        "steps": [
            {
                "id": "step-1",
                "type": "enrichment",
                "name": "Enrich Threat IOCs",
                "description": "Enrich identified IOCs from trigger data",
                "config": {"action_type": "enrichment.virustotal", "parameters": {"ioc": "$trigger.ioc", "ioc_type": "$trigger.ioc_type"}},
                "next": "step-2",
            },
            {
                "id": "step-2",
                "type": "condition",
                "name": "Check Severity",
                "description": "Verify threat severity is critical",
                "config": {"parameters": {}},
                "conditions": [
                    {"id": "branch-critical", "label": "Critical", "condition": {"field": "$trigger.severity", "operator": "equals", "expected": "critical"}, "next_steps": ["step-3"]},
                    {"id": "branch-other", "label": "Non-Critical", "condition": {}, "next_steps": ["step-8"]},
                ],
            },
            {
                "id": "step-3",
                "type": "containment",
                "name": "Block Malicious IP",
                "description": "Block the attacker IP at the firewall",
                "config": {"action_type": "firewall.block_ip", "parameters": {"ip_address": "$trigger.source_ip", "duration": "72h", "reason": "Critical threat auto-containment"}},
                "next": "step-4",
            },
            {
                "id": "step-4",
                "type": "action",
                "name": "Disable Compromised Account",
                "description": "Disable the potentially compromised AD account",
                "config": {"action_type": "active_directory.disable_account", "parameters": {"username": "$trigger.user", "reason": "Critical threat detected, auto-disabled"}},
                "on_success": "step-5",
                "on_failure": "step-5",
            },
            {
                "id": "step-5",
                "type": "action",
                "name": "Force Password Reset",
                "description": "Force password reset for the compromised account",
                "config": {"action_type": "active_directory.force_password_reset", "parameters": {"username": "$trigger.user"}},
                "next": "step-6",
            },
            {
                "id": "step-6",
                "type": "notification",
                "name": "Notify SOC Team",
                "description": "Send Slack and PagerDuty notifications",
                "config": {"action_type": "notification.slack", "parameters": {"channel": "#soc-alerts", "message": ":rotating_light: CRITICAL THREAT CONTAINED - IP $trigger.source_ip blocked, account $trigger.user disabled. Execution: $trigger.execution_id"}},
                "next": "step-7",
            },
            {
                "id": "step-7",
                "type": "action",
                "name": "Create Incident Ticket",
                "description": "Create a high-priority incident ticket",
                "config": {"action_type": "ticket.create", "parameters": {"title": "Critical Threat Auto-Contained - $trigger.source_ip", "description": "Automated containment executed. IOCs: IP=$trigger.source_ip, User=$trigger.user. Review required.", "priority": "critical"}},
                "next": "step-9",
            },
            {
                "id": "step-8",
                "type": "notification",
                "name": "Notify Non-Critical",
                "description": "Log non-critical alert for review",
                "config": {"action_type": "notification.slack", "parameters": {"channel": "#soc-general", "message": ":information_source: Non-critical alert received and logged for review."}},
                "next": "step-9",
            },
            {
                "id": "step-9",
                "type": "action",
                "name": "Create SIEM Alert",
                "description": "Create corresponding SIEM alert for tracking",
                "config": {"action_type": "siem.create_alert", "parameters": {"title": "Auto-Containment Complete: $trigger.source_ip", "severity": "high", "description": "Automated threat containment has been executed", "source": "SentinelAI-Playbook"}},
            },
        ],
        "error_handling": {"retry_count": 2, "retry_delay_seconds": 10, "on_max_retries": "fail"},
        "enabled": True,
    },
    {
        "id": "pb-brute-force-response",
        "name": "Brute Force Response",
        "description": "Detect and respond to brute force attack patterns by temporarily blocking source IPs, notifying users, and creating investigation tickets.",
        "version": "1.0.0",
        "author": "SentinelAI",
        "tags": ["brute-force", "credential-stuffing", "response"],
        "severity_threshold": "high",
        "mitre_tactics": ["TA0006", "TA0001"],
        "trigger": {"type": "alert", "filters": {"detection_type": "brute_force"}},
        "steps": [
            {
                "id": "bf-step-1",
                "type": "enrichment",
                "name": "Enrich Source IP",
                "description": "Perform GeoIP and threat intelligence lookup on the attacking IP",
                "config": {"action_type": "enrichment.abuseipdb", "parameters": {"ip_address": "$trigger.source_ip"}},
                "next": "bf-step-2",
            },
            {
                "id": "bf-step-2",
                "type": "condition",
                "name": "Evaluate Threat Score",
                "description": "Check if the source IP has high abuse confidence",
                "config": {"parameters": {}},
                "conditions": [
                    {"id": "high-threat", "label": "High Abuse Score", "condition": {"field": "$step-bf-step-1.output.abuse_confidence_score", "operator": "greater_than", "expected": "70"}, "next_steps": ["bf-step-3"]},
                    {"id": "low-threat", "label": "Low Abuse Score", "condition": {}, "next_steps": ["bf-step-4"]},
                ],
            },
            {
                "id": "bf-step-3",
                "type": "containment",
                "name": "Block Attacker IP",
                "description": "Block the IP with high abuse confidence at the firewall",
                "config": {"action_type": "firewall.block_ip", "parameters": {"ip_address": "$trigger.source_ip", "duration": "48h", "reason": "Brute force attack - high abuse confidence score"}},
                "on_success": "bf-step-5",
                "on_failure": "bf-step-5",
            },
            {
                "id": "bf-step-4",
                "type": "notification",
                "name": "Notify Low Threat",
                "description": "Send informational notification about low-threat brute force",
                "config": {"action_type": "notification.slack", "parameters": {"channel": "#soc-general", "message": ":information_source: Low-confidence brute force attempt from $trigger.source_ip targeting $trigger.target_user. No automatic blocking applied."}},
                "next": "bf-step-7",
            },
            {
                "id": "bf-step-5",
                "type": "notification",
                "name": "Alert SOC Team",
                "description": "Notify SOC via PagerDuty for high-severity brute force",
                "config": {"action_type": "notification.pagerduty", "parameters": {"service_key": "$trigger.pagerduty_key", "description": "Brute force attack from $trigger.source_ip targeting $trigger.target_user. IP blocked for 48h.", "severity": "critical"}},
                "next": "bf-step-6",
            },
            {
                "id": "bf-step-6",
                "type": "action",
                "name": "Create Investigation Ticket",
                "description": "Create a ticket for brute force investigation",
                "config": {"action_type": "ticket.create", "parameters": {"title": "Brute Force Attack - $trigger.source_ip", "description": "Brute force detected from $trigger.source_ip targeting $trigger.target_user. Attempts: $trigger.attempt_count. IP blocked. Investigate source and affected accounts.", "priority": "high"}},
                "next": "bf-step-7",
            },
            {
                "id": "bf-step-7",
                "type": "action",
                "name": "Create SIEM Alert",
                "description": "Log the brute force event to SIEM",
                "config": {"action_type": "siem.create_alert", "parameters": {"title": "Brute Force Response: $trigger.source_ip", "severity": "high", "description": "Brute force attack detected and response initiated", "source": "SentinelAI-Playbook"}},
            },
        ],
        "error_handling": {"retry_count": 2, "retry_delay_seconds": 5, "on_max_retries": "fail"},
        "enabled": True,
    },
    {
        "id": "pb-malware-containment",
        "name": "Malware Containment",
        "description": "Contain malware outbreaks by isolating affected endpoints, collecting forensic artifacts, and notifying the security team.",
        "version": "1.0.0",
        "author": "SentinelAI",
        "tags": ["malware", "containment", "forensics"],
        "severity_threshold": "high",
        "mitre_tactics": ["TA0002", "TA0005", "TA0010"],
        "trigger": {"type": "alert", "filters": {"detection_type": "malware"}},
        "steps": [
            {
                "id": "mw-step-1",
                "type": "enrichment",
                "name": "Enrich Malware Hash",
                "description": "Look up the malware hash on VirusTotal",
                "config": {"action_type": "enrichment.virustotal", "parameters": {"ioc": "$trigger.file_hash", "ioc_type": "hash"}},
                "next": "mw-step-2",
            },
            {
                "id": "mw-step-2",
                "type": "condition",
                "name": "Check Detection Ratio",
                "description": "Determine if the file is widely detected as malicious",
                "config": {"parameters": {}},
                "conditions": [
                    {"id": "confirmed-malware", "label": "Confirmed Malware", "condition": {"field": "$step-mw-step-1.output.detection_ratio", "operator": "not_equals", "expected": "0/90"}, "next_steps": ["mw-step-3"]},
                    {"id": "unknown-file", "label": "Unknown File", "condition": {}, "next_steps": ["mw-step-6"]},
                ],
            },
            {
                "id": "mw-step-3",
                "type": "action",
                "name": "Isolate Endpoint",
                "description": "Network-isolate the affected endpoint",
                "config": {"action_type": "firewall.block_ip", "parameters": {"ip_address": "$trigger.endpoint_ip", "duration": "until_clean", "reason": "Malware detected - endpoint isolation"}},
                "on_success": "mw-step-4",
                "on_failure": "mw-step-4",
            },
            {
                "id": "mw-step-4",
                "type": "action",
                "name": "Collect Forensic Hash",
                "description": "Compute forensic hash of the malicious file",
                "config": {"action_type": "forensics.hash", "parameters": {"file_path": "$trigger.file_path", "algorithm": "sha256"}},
                "next": "mw-step-5",
            },
            {
                "id": "mw-step-5",
                "type": "notification",
                "name": "Notify Security Team",
                "description": "Send PagerDuty alert for malware incident",
                "config": {"action_type": "notification.pagerduty", "parameters": {"service_key": "$trigger.pagerduty_key", "description": "MALWARE CONTAINED on $trigger.endpoint_name. File: $trigger.file_path. Hash: $trigger.file_hash. Endpoint isolated.", "severity": "critical"}},
                "next": "mw-step-7",
            },
            {
                "id": "mw-step-6",
                "type": "notification",
                "name": "Flag Unknown File",
                "description": "Notify team about potentially new/unknown malware",
                "config": {"action_type": "notification.slack", "parameters": {"channel": "#soc-alerts", "message": ":warning: Unknown file detected on $trigger.endpoint_name. Hash: $trigger.file_hash. Requires manual analysis."}},
                "next": "mw-step-7",
            },
            {
                "id": "mw-step-7",
                "type": "action",
                "name": "Create Incident Ticket",
                "description": "Create malware incident ticket",
                "config": {"action_type": "ticket.create", "parameters": {"title": "Malware Incident - $trigger.endpoint_name", "description": "Malware detected on $trigger.endpoint_name. File: $trigger.file_path. Hash: $trigger.file_hash. Endpoint isolation: $trigger.isolation_status.", "priority": "critical"}},
                "next": "mw-step-8",
            },
            {
                "id": "mw-step-8",
                "type": "action",
                "name": "Log to SIEM",
                "description": "Create SIEM alert for the malware incident",
                "config": {"action_type": "siem.create_alert", "parameters": {"title": "Malware Containment: $trigger.endpoint_name", "severity": "critical", "description": "Malware outbreak contained on endpoint", "source": "SentinelAI-Playbook"}},
            },
        ],
        "error_handling": {"retry_count": 3, "retry_delay_seconds": 5, "on_max_retries": "fail"},
        "enabled": True,
    },
    {
        "id": "pb-phishing-triage",
        "name": "Phishing Triage",
        "description": "Automated phishing email triage: extract IOCs, check against threat intel, block malicious domains/IPs, and notify affected users.",
        "version": "1.0.0",
        "author": "SentinelAI",
        "tags": ["phishing", "email", "triage"],
        "severity_threshold": "medium",
        "mitre_tactics": ["TA0001", "TA0009"],
        "trigger": {"type": "alert", "filters": {"detection_type": "phishing"}},
        "steps": [
            {
                "id": "ph-step-1",
                "type": "enrichment",
                "name": "Enrich Sender Domain",
                "description": "Check the sender domain reputation",
                "config": {"action_type": "enrichment.virustotal", "parameters": {"ioc": "$trigger.sender_domain", "ioc_type": "domain"}},
                "next": "ph-step-2",
            },
            {
                "id": "ph-step-2",
                "type": "enrichment",
                "name": "Enrich Sender IP",
                "description": "Check the sender IP on AbuseIPDB",
                "config": {"action_type": "enrichment.abuseipdb", "parameters": {"ip_address": "$trigger.sender_ip"}},
                "next": "ph-step-3",
            },
            {
                "id": "ph-step-3",
                "type": "enrichment",
                "name": "Geolocate Sender",
                "description": "Get geolocation of the sender IP",
                "config": {"action_type": "enrichment.geoip", "parameters": {"ip_address": "$trigger.sender_ip"}},
                "next": "ph-step-4",
            },
            {
                "id": "ph-step-4",
                "type": "condition",
                "name": "Evaluate Phishing Threat",
                "description": "Determine if the email is confirmed phishing",
                "config": {"parameters": {}},
                "conditions": [
                    {"id": "confirmed-phish", "label": "Confirmed Phishing", "condition": {"field": "$step-ph-step-1.output.detection_ratio", "operator": "not_equals", "expected": "0/90"}, "next_steps": ["ph-step-5"]},
                    {"id": "suspicious", "label": "Suspicious", "condition": {"field": "$step-ph-step-2.output.abuse_confidence_score", "operator": "greater_than", "expected": "50"}, "next_steps": ["ph-step-5"]},
                    {"id": "benign", "label": "Likely Benign", "condition": {}, "next_steps": ["ph-step-8"]},
                ],
            },
            {
                "id": "ph-step-5",
                "type": "containment",
                "name": "Block Sender Domain",
                "description": "Block the malicious sender domain",
                "config": {"action_type": "firewall.block_domain", "parameters": {"domain": "$trigger.sender_domain", "duration": "30d", "reason": "Confirmed phishing domain"}},
                "on_success": "ph-step-6",
                "on_failure": "ph-step-6",
            },
            {
                "id": "ph-step-6",
                "type": "containment",
                "name": "Block Sender IP",
                "description": "Block the sender IP address",
                "config": {"action_type": "firewall.block_ip", "parameters": {"ip_address": "$trigger.sender_ip", "duration": "30d", "reason": "Phishing source"}},
                "next": "ph-step-7",
            },
            {
                "id": "ph-step-7",
                "type": "notification",
                "name": "Notify Affected Users",
                "description": "Alert users who received the phishing email",
                "config": {"action_type": "notification.email", "parameters": {"to": "$trigger.recipient_emails", "subject": "Phishing Email Blocked - Action Required", "body": "A phishing email from $trigger.sender_email has been blocked. Subject: $trigger.email_subject. Do not click any links from this sender."}},
                "next": "ph-step-9",
            },
            {
                "id": "ph-step-8",
                "type": "notification",
                "name": "Log Benign Result",
                "description": "Log that the email appears benign",
                "config": {"action_type": "notification.slack", "parameters": {"channel": "#soc-general", "message": ":white_check_mark: Phishing analysis complete - email from $trigger.sender_email appears benign. No action taken."}},
                "next": "ph-step-9",
            },
            {
                "id": "ph-step-9",
                "type": "action",
                "name": "Create Phishing Ticket",
                "description": "Create a ticket for the phishing incident",
                "config": {"action_type": "ticket.create", "parameters": {"title": "Phishing Triage - $trigger.sender_email", "description": "Phishing email from $trigger.sender_email to $trigger.recipient_emails. Subject: $trigger.email_subject. Verdict: $trigger.verdict.", "priority": "high"}},
            },
        ],
        "error_handling": {"retry_count": 2, "retry_delay_seconds": 5, "on_max_retries": "fail"},
        "enabled": True,
    },
    {
        "id": "pb-insider-threat-response",
        "name": "Insider Threat Response",
        "description": "Detect and respond to insider threat indicators including unauthorized data access, privilege escalation, and policy violations.",
        "version": "1.0.0",
        "author": "SentinelAI",
        "tags": ["insider-threat", "data-exfiltration", "policy-violation"],
        "severity_threshold": "high",
        "mitre_tactics": ["TA0005", "TA0008", "TA0010", "TA0040"],
        "trigger": {"type": "alert", "filters": {"detection_type": "insider_threat"}},
        "steps": [
            {
                "id": "it-step-1",
                "type": "enrichment",
                "name": "Enrich User Activity",
                "description": "Check user's recent activity and access patterns",
                "config": {"action_type": "enrichment.virustotal", "parameters": {"ioc": "$trigger.user_email", "ioc_type": "email"}},
                "next": "it-step-2",
            },
            {
                "id": "it-step-2",
                "type": "condition",
                "name": "Evaluate Threat Level",
                "description": "Determine if this is a confirmed insider threat or requires investigation",
                "config": {"parameters": {}},
                "conditions": [
                    {"id": "confirmed-insider", "label": "Confirmed Threat", "condition": {"field": "$trigger.confidence_score", "operator": "greater_than", "expected": "80"}, "next_steps": ["it-step-3"]},
                    {"id": "investigate", "label": "Needs Investigation", "condition": {"field": "$trigger.confidence_score", "operator": "greater_than", "expected": "40"}, "next_steps": ["it-step-6"]},
                    {"id": "low-risk", "label": "Low Risk", "condition": {}, "next_steps": ["it-step-9"]},
                ],
            },
            {
                "id": "it-step-3",
                "type": "containment",
                "name": "Disable User Account",
                "description": "Immediately disable the insider threat account",
                "config": {"action_type": "active_directory.disable_account", "parameters": {"username": "$trigger.username", "reason": "Insider threat - confirmed malicious activity"}},
                "on_success": "it-step-4",
                "on_failure": "it-step-4",
            },
            {
                "id": "it-step-4",
                "type": "action",
                "name": "Force Password Reset",
                "description": "Force password reset to prevent credential reuse",
                "config": {"action_type": "active_directory.force_password_reset", "parameters": {"username": "$trigger.username"}},
                "next": "it-step-5",
            },
            {
                "id": "it-step-5",
                "type": "notification",
                "name": "Escalate to Security Leadership",
                "description": "PagerDuty alert to CISO and security leadership",
                "config": {"action_type": "notification.pagerduty", "parameters": {"service_key": "$trigger.pagerduty_key", "description": "INSIDER THREAT CONFIRMED - User $trigger.username disabled. Activity: $trigger.activity_type. Immediate investigation required.", "severity": "critical"}},
                "next": "it-step-10",
            },
            {
                "id": "it-step-6",
                "type": "notification",
                "name": "Alert SOC for Investigation",
                "description": "Notify SOC team to investigate suspicious activity",
                "config": {"action_type": "notification.slack", "parameters": {"channel": "#soc-alerts", "message": ":mag: SUSPICIOUS INSIDER ACTIVITY detected for user $trigger.username. Activity type: $trigger.activity_type. Confidence: $trigger.confidence_score%. Investigation recommended."}},
                "next": "it-step-7",
            },
            {
                "id": "it-step-7",
                "type": "action",
                "name": "Create Investigation Ticket",
                "description": "Create a ticket for insider threat investigation",
                "config": {"action_type": "ticket.create", "parameters": {"title": "Insider Threat Investigation - $trigger.username", "description": "Suspicious insider activity detected for $trigger.username. Activity: $trigger.activity_type. Confidence: $trigger.confidence_score%. Review required.", "priority": "high"}},
                "next": "it-step-8",
            },
            {
                "id": "it-step-8",
                "type": "approval_gate",
                "name": "Manager Approval for Account Actions",
                "description": "Wait for manager approval before taking further containment actions",
                "config": {"parameters": {}},
                "approval": {"required_approvers": 1, "approvers": ["$trigger.manager_email"], "timeout_seconds": 1800, "auto_approve_on_timeout": False, "message": "Approval required for insider threat containment actions on user $trigger.username"},
                "next": "it-step-10",
            },
            {
                "id": "it-step-9",
                "type": "notification",
                "name": "Log Low Risk Activity",
                "description": "Log the low-risk insider activity for audit",
                "config": {"action_type": "notification.slack", "parameters": {"channel": "#security-audit", "message": ":clipboard: Low-risk insider activity logged for user $trigger.username. Activity: $trigger.activity_type. No immediate action required."}},
                "next": "it-step-10",
            },
            {
                "id": "it-step-10",
                "type": "action",
                "name": "Create SIEM Alert",
                "description": "Create SIEM alert for insider threat tracking",
                "config": {"action_type": "siem.create_alert", "parameters": {"title": "Insider Threat Response: $trigger.username", "severity": "high", "description": "Insider threat response initiated for $trigger.username", "source": "SentinelAI-Playbook"}},
            },
        ],
        "error_handling": {"retry_count": 2, "retry_delay_seconds": 5, "on_max_retries": "fail"},
        "enabled": True,
    },
]


class PlaybookEngine:
    def __init__(self):
        self.playbooks: Dict[str, Playbook] = {}
        self._load_prebuilt_playbooks()

    def _load_prebuilt_playbooks(self):
        for pb_data in PREBUILT_PLAYBOOKS:
            try:
                pb = Playbook(**pb_data)
                self.playbooks[pb.id] = pb
                logger.info(f"Loaded prebuilt playbook: {pb.name} ({pb.id})")
            except Exception as e:
                logger.error(f"Failed to load prebuilt playbook {pb_data.get('name', 'unknown')}: {e}")

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        return self.playbooks.get(playbook_id)

    def list_playbooks(self, enabled_only: bool = True) -> List[Playbook]:
        playbooks = list(self.playbooks.values())
        if enabled_only:
            playbooks = [pb for pb in playbooks if pb.enabled]
        return playbooks

    def register_playbook(self, playbook: Playbook):
        self.playbooks[playbook.id] = playbook
        logger.info(f"Registered playbook: {playbook.name} ({playbook.id})")

    def unregister_playbook(self, playbook_id: str) -> bool:
        if playbook_id in self.playbooks:
            del self.playbooks[playbook_id]
            logger.info(f"Unregistered playbook: {playbook_id}")
            return True
        return False

    async def run_playbook(self, playbook_id: str, trigger_data: Dict[str, Any]) -> str:
        playbook = self.get_playbook(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook not found: {playbook_id}")
        if not playbook.enabled:
            raise ValueError(f"Playbook is disabled: {playbook_id}")

        execution_id = await playbook_runner.execute(playbook, trigger_data)
        return execution_id

    async def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        try:
            result = await db.fetch_one(
                "SELECT * FROM playbook_executions WHERE id = ?", (execution_id,)
            )
            if result:
                return dict(result)
            return None
        except Exception as e:
            logger.error(f"Failed to get execution status: {e}")
            return None

    async def get_execution_logs(self, execution_id: str) -> List[Dict[str, Any]]:
        try:
            results = await db.fetch_all(
                "SELECT * FROM playbook_action_log WHERE execution_id = ? ORDER BY created_at",
                (execution_id,),
            )
            return [dict(r) for r in results] if results else []
        except Exception as e:
            logger.error(f"Failed to get execution logs: {e}")
            return []


playbook_engine = PlaybookEngine()
playbook_runner = PlaybookRunner()
action_registry = ActionRegistry()
