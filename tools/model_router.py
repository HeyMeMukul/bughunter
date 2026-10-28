#!/usr/bin/env python3
"""
model_router.py — Token-Optimized Model Routing
Routes tasks to the right model (Lead vs Worker) based on complexity scoring.
Lead = Muse Spark 1.3 Contributor high thinking (strategy),
Worker = Muse Spark 1.3 Contributor default thinking (execution),
Fallback = DeepSeek V4.1 Flash (429/5xx/capacity).
"""

import json
import sys
import argparse
from typing import Dict, Any


class ModelRouter:
    """Routes framework tasks to optimal model based on complexity."""

    LEAD_MODEL = "opencode-go/muse-spark-1.3-contributor"
    LEAD_VARIANT = "high"
    WORKER_MODEL = "opencode-go/muse-spark-1.3-contributor"
    WORKER_VARIANT = "default"
    FALLBACK_MODEL = "opencode-go/deepseek-v4.1-flash"

    # Task complexity scores — higher = needs Lead
    COMPLEXITY_SCORES = {
        # Strategic tasks (Lead)
        "chain_synthesis": 10,
        "report_writing": 9,
        "hypothesis_prioritization": 8,
        "phase_transition": 7,
        "startup_context": 7,
        "pivoting_decision": 7,
        "quality_gate_analysis": 6,
        "program_profiling": 6,
        "recon_analysis": 5,

        # Tactical tasks (Worker)
        "recon_execution": 3,
        "spider_execution": 2,
        "mapping_execution": 4,
        "testing_execution": 4,
        "validation_execution": 3,
        "nuclei_runner": 2,
        "oob_setup": 2,
        "sqlmap_runner": 1,
        "secret_scanning": 1,
        "parameter_discovery": 2,
        "path_fuzzing": 1,
        "waf_detection": 2,
        "cookie_extraction": 1,
    }

    # Token cost estimates per task type
    TOKEN_COSTS = {
        "chain_synthesis": 15000,
        "report_writing": 5000,
        "hypothesis_prioritization": 4000,
        "phase_transition": 3000,
        "startup_context": 16000,
        "pivoting_decision": 5000,
        "quality_gate_analysis": 3000,
        "program_profiling": 6000,
        "recon_analysis": 1500,
        "recon_execution": 1000,
        "spider_execution": 2000,
        "mapping_execution": 2500,
        "testing_execution": 3000,
        "validation_execution": 2000,
        "nuclei_runner": 500,
        "oob_setup": 1000,
        "sqlmap_runner": 1500,
        "secret_scanning": 500,
        "parameter_discovery": 500,
        "path_fuzzing": 500,
        "waf_detection": 500,
        "cookie_extraction": 200,
    }

    PRO_THRESHOLD = 5  # Tasks with complexity >= 5 go to Lead

    def route(self, task_type: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Route a task to the appropriate model."""
        complexity = self.COMPLEXITY_SCORES.get(task_type, 5)
        token_cost = self.TOKEN_COSTS.get(task_type, 1000)

        # Adjust complexity based on context
        if context:
            if context.get("num_endpoints", 0) > 10:
                complexity += 1
            if context.get("num_hypotheses", 0) > 20:
                complexity += 1
            if context.get("is_novel", False):
                complexity += 1
            if context.get("requires_chaining", False):
                complexity += 2
            if context.get("first_engagement", False):
                complexity += 1

        if complexity >= self.PRO_THRESHOLD:
            model = "lead"
            model_id = self.LEAD_MODEL
            variant = self.LEAD_VARIANT
            reason = "Lead (Muse Spark 1.3 high): strategic reasoning required"
        else:
            model = "worker"
            model_id = self.WORKER_MODEL
            variant = self.WORKER_VARIANT
            reason = "Worker (Muse Spark 1.3 default): tactical execution sufficient"

        return {
            "task_type": task_type,
            "complexity": complexity,
            "estimated_tokens": token_cost,
            "recommended_model": model,
            "recommended_model_id": model_id,
            "recommended_variant": variant,
            "lead_variant": self.LEAD_VARIANT,
            "worker_variant": self.WORKER_VARIANT,
            "fallback_model_id": self.FALLBACK_MODEL,
            "reason": reason,
        }

    def estimate_session_tokens(self, tasks: list) -> Dict[str, Any]:
        """Estimate total token usage for a session plan."""
        total = 0
        breakdown = []

        for task in tasks:
            task_type = task.get("type", "unknown")
            cost = self.TOKEN_COSTS.get(task_type, 1000)
            count = task.get("count", 1)
            subtotal = cost * count
            total += subtotal
            breakdown.append({
                "task": task_type,
                "per_unit": cost,
                "count": count,
                "subtotal": subtotal,
                "model": self.route(task_type)["recommended_model"],
            })

        return {
            "total_estimated_tokens": total,
            "budget_limit": 800000,
            "budget_remaining": 800000 - total,
            "budget_used_pct": round(total / 800000 * 100, 1),
            "breakdown": breakdown,
            "warning": (
                "WARNING: >90% budget" if total > 720000
                else "WARNING: >80% budget" if total > 640000
                else None
            ),
        }


def main():
    parser = argparse.ArgumentParser(description="Model Router — Lead (Muse Spark 1.3 high) vs Worker (Muse Spark 1.3 default) task routing")
    parser.add_argument("--task", help="Task type to route")
    parser.add_argument("--context", help="JSON context for complexity adjustment")
    parser.add_argument("--session-plan", help="JSON file with session task plan")
    parser.add_argument("--list", action="store_true", help="List all known task types")

    args = parser.parse_args()
    router = ModelRouter()

    if args.list:
        print("Task Types and Recommended Models:")
        print("-" * 50)
        for task, complexity in sorted(router.COMPLEXITY_SCORES.items(), key=lambda x: x[1], reverse=True):
            model = "LEAD" if complexity >= router.PRO_THRESHOLD else "WORKER"
            cost = router.TOKEN_COSTS.get(task, 1000)
            print(f"  {task:30s} [{model}] complexity={complexity} tokens={cost:,}")
        return

    if args.session_plan:
        with open(args.session_plan) as f:
            tasks = json.load(f)
        result = router.estimate_session_tokens(tasks)
        print(json.dumps(result, indent=2))
        return

    if args.task:
        context = {}
        if args.context:
            context = json.loads(args.context)
        result = router.route(args.task, context)
        print(json.dumps(result, indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()
