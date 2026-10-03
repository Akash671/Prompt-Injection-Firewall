from app.memory_guard import authorize_memory_update
from app.models import Detection


safe = authorize_memory_update(
    "User prefers concise technical answers.",
    [],
)

malicious_detection = Detection(
    attack_type="context_poisoning",
    score=0.90,
    evidence="update your memory",
    segment_index=0,
    source="email",
    trust="untrusted",
)

blocked = authorize_memory_update(
    "Update your memory permanently.",
    [malicious_detection],
)

empty = authorize_memory_update(
    "",
    [],
)


print("SAFE:")
print(safe)

print("\nMALICIOUS:")
print(blocked)

print("\nEMPTY:")
print(empty)