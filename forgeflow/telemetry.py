import os
from threading import Lock

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_configured = False
_lock = Lock()


def configure_telemetry() -> None:
    """Configure OTLP tracing once per process."""
    global _configured
    with _lock:
        if _configured:
            return

        service_name = os.getenv("OTEL_SERVICE_NAME", "forgeflow-agent")
        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        if endpoint:
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        HTTPXClientInstrumentor().instrument()
        _configured = True
