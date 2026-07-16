"""Lazy singleton dependencies shared across FastAPI requests."""

from functools import lru_cache


@lru_cache
def get_orchestrator():
    from pipeline.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator()
    orchestrator.model.warmup()
    return orchestrator


@lru_cache
def get_feedback_store():
    from ml_engine.tier5.feedback import FeedbackStore

    return FeedbackStore()


@lru_cache
def get_drift_monitor():
    from ml_engine.tier5.drift import DriftMonitor

    return DriftMonitor()


@lru_cache
def get_webhook_store():
    from ml_engine.tier5.webhooks import WebhookStore

    return WebhookStore()


@lru_cache
def get_webhook_dispatcher():
    from ml_engine.tier5.webhooks import WebhookDispatcher

    return WebhookDispatcher(get_webhook_store())
