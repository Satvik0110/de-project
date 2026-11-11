"""Stream processor config. Every value can be overridden with an environment variable."""
import os

from ingest.config import KAFKA_BOOTSTRAP, TOPIC_DLQ, TOPIC_RAW  # noqa: F401  (re-exported)

TOPIC_ALERTS = os.getenv("TOPIC_ALERTS", "security.alerts")
TOPIC_AGGREGATES = os.getenv("TOPIC_AGGREGATES", "security.aggregates")
TOPIC_METRICS = os.getenv("TOPIC_METRICS", "security.pipeline.metrics")

# The real processor's consumer group. Distinct from the test consumer's group so
# the two never move each other's offsets.
GROUP_ID = os.getenv("PROCESSOR_GROUP", "stream-processor-v1")

# --- event-time windowing (Lab 3 section 3) ---------------------------------
# Sliding windows of WINDOW_S seconds, a new one starting every SLIDE_S seconds.
WINDOW_S = int(os.getenv("WINDOW_S", "60"))
SLIDE_S = int(os.getenv("SLIDE_S", "10"))
# "Assume no event is more than ten seconds late": the watermark trails the newest
# event_time seen by this much, and a window is emitted once the watermark passes its end.
LATENESS_S = float(os.getenv("LATENESS_S", "10"))
# When the topic goes quiet, nothing pushes the watermark forward and the last
# windows would never close. After this many idle seconds, the watermark follows
# the wall clock instead.
IDLE_ADVANCE_S = float(os.getenv("IDLE_ADVANCE_S", "5"))
# An event_time this far in the future means a broken source clock. Accepting it
# would drag the watermark forward and make every honest event look late.
MAX_FUTURE_S = float(os.getenv("MAX_FUTURE_S", "60"))

# --- housekeeping -------------------------------------------------------------
COMMIT_INTERVAL_S = float(os.getenv("COMMIT_INTERVAL_S", "2"))
METRICS_INTERVAL_S = float(os.getenv("METRICS_INTERVAL_S", "10"))
# Event ids kept on each alert, so an analyst can trace it back to raw events.
SAMPLE_IDS_PER_ALERT = int(os.getenv("SAMPLE_IDS_PER_ALERT", "10"))
