try:
	from .adk_agent import golden_hour_agent  # noqa: F401
except Exception:
	golden_hour_agent = None  # type: ignore
