"""Safe reads from a fixed, synthetic file set used by the local demo."""

from pathlib import PurePosixPath

DEMO_FILES = {
    "public/readme.txt": "Public demo file. This content is synthetic.",
    "private/internal_note.txt": (
        "SYNTHETIC PRIVATE NOTE: this is demonstration-only content."
    ),
}


def read_public_demo_file(requested_path: str) -> str | None:
    """Read only files beneath the synthetic public directory."""
    normalized = requested_path.replace("\\", "/")
    if normalized.startswith("/"):
        return None

    relative_path = PurePosixPath(normalized)
    if ".." in relative_path.parts:
        return None

    if relative_path.parts and relative_path.parts[0] == "public":
        key = relative_path.as_posix()
    else:
        key = PurePosixPath("public", relative_path).as_posix()

    if not key.startswith("public/"):
        return None

    return DEMO_FILES.get(key)
