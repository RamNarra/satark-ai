try:
	from .adk_agent import apk_analyzer_agent  # noqa: F401
except Exception:
	apk_analyzer_agent = None  # type: ignore
