try:
	from .adk_agent import osint_agent  # noqa: F401
except Exception:
	osint_agent = None  # type: ignore
