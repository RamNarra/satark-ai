try:
	from .adk_agent import scam_detector_agent  # noqa: F401
except Exception:
	scam_detector_agent = None  # type: ignore

