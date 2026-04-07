import importlib.metadata

try:
    __version__ = importlib.metadata.version("promptfuzz")
except importlib.metadata.PackageNotFoundError:
    __version__ = "unknown"
