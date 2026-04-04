try:
	from .adk_agent import audio_analyzer_agent  # noqa: F401
except Exception:
	# ADK agent is optional; keep package importable even if deps/creds missing.
	audio_analyzer_agent = None  # type: ignore
