try:
	from .adk_agent import build_golden_hour_agent, golden_hour_agent  # noqa: F401
except Exception:
	golden_hour_agent = None  # type: ignore
	build_golden_hour_agent = None  # type: ignore
