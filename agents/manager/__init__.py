try:
	from .adk_manager import run_pipeline  # noqa: F401
except Exception:
	# Keep package importable even if ADK deps aren't present.
	run_pipeline = None  # type: ignore

