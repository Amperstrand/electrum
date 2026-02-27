import functools
import inspect
import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import cast

from electrum.logging import get_logger

# Fully log the first N calls to each function; after that only log slow calls.
_INITIAL_FULL_LOG: int = 3
# Calls slower than this (seconds) are always logged, even after the initial window.
# Card I/O / network typically >100 ms; fast getters / loop helpers are <1 ms.
_SLOW_THRESHOLD_S: float = 0.05


def _safe_repr(obj: object, max_len: int = 200) -> str:
    try:
        rendered = repr(obj)
    except Exception:
        rendered = f"<repr failed: {type(obj).__name__}>"
    if len(rendered) > max_len:
        truncated = len(rendered) - max_len
        return f"{rendered[:max_len]}...[truncated {truncated} chars]"
    return rendered


def _should_skip(name: str, obj: object) -> bool:
    # Skip dunder methods AND single-underscore private/internal methods
    if name.startswith("_"):
        return True
    if isinstance(obj, property):
        return True
    if getattr(obj, "__isabstractmethod__", False):
        return True
    if inspect.isgeneratorfunction(obj):
        return True
    if not callable(obj):
        return True
    return False


def _format_param(name: str, value: object) -> str:
    if name == "self":
        return type(value).__name__
    # For objects with the default memory-address repr, show just the class name
    try:
        raw = repr(value)
    except Exception:
        return type(value).__name__
    if raw.startswith("<") and " object at 0x" in raw:
        return type(value).__name__
    if isinstance(value, bytes):
        hex_str = value.hex()
        preview = hex_str[:64]
        if len(hex_str) > 64:
            preview = f"{preview}..."
        return f"bytes({len(value)}): {preview}"
    if isinstance(value, str):
        if len(value) > 200:
            truncated = len(value) - 200
            return f"{value[:200]}...[truncated {truncated} chars]"
        return value
    return _safe_repr(value)


def _format_args(func: Callable[..., object], args: tuple[object, ...], kwargs: Mapping[str, object]) -> str:
    try:
        signature = inspect.signature(func)
        bound = signature.bind_partial(*args, **kwargs)
        entries: list[str] = []
        for param_name in bound.arguments:
            value_obj = cast(object, bound.arguments[param_name])
            rendered = _format_param(param_name, value_obj)
            type_name = type(value_obj).__name__
            # Omit the redundant (TypeName) suffix when the rendered value already conveys it
            if rendered == type_name or param_name == "self":
                entries.append(f"{param_name}={rendered}")
            else:
                entries.append(f"{param_name}={rendered}({type_name})")
        return ", ".join(entries)
    except Exception:
        items: list[str] = []
        for index, value in enumerate(args):
            rendered = _format_param(f"arg{index}", value)
            items.append(f"arg{index}={rendered}({type(value).__name__})")
        for key, value in kwargs.items():
            rendered = _format_param(key, value)
            items.append(f"{key}={rendered}({type(value).__name__})")
        return ", ".join(items)


def _make_sync_wrapper(func: Callable[..., object], func_name: str, logger: logging.Logger) -> Callable[..., object]:
    call_count = 0

    @functools.wraps(func)
    def wrapped(*args: object, **kwargs: object) -> object:
        nonlocal call_count
        call_count += 1
        is_initial = call_count <= _INITIAL_FULL_LOG

        if is_initial:
            params = _format_args(func, args, kwargs)
            logger.debug(f"ENTER {func_name}({params})")

        started_at = time.monotonic()
        try:
            result = func(*args, **kwargs)
        except Exception as exc:
            elapsed = time.monotonic() - started_at
            logger.debug(
                f"EXCEPTION {func_name} → {type(exc).__name__}: {_safe_repr(exc)} [{elapsed:.4f}s]"
            )
            raise
        elapsed = time.monotonic() - started_at

        if is_initial:
            logger.debug(
                f"EXIT  {func_name} → {_safe_repr(result)}({type(result).__name__}) [{elapsed:.4f}s]"
            )
        elif elapsed >= _SLOW_THRESHOLD_S:
            # Log slow calls even outside the initial window (card I/O, network, etc.)
            params = _format_args(func, args, kwargs)
            logger.debug(f"ENTER {func_name}({params}) [call #{call_count}]")
            logger.debug(
                f"EXIT  {func_name} → {_safe_repr(result)}({type(result).__name__}) [{elapsed:.4f}s]"
            )

        return result

    setattr(wrapped, "_satochip_entry_logged", True)
    return wrapped


def _make_async_wrapper(
    func: Callable[..., Awaitable[object]], func_name: str, logger: logging.Logger
) -> Callable[..., Awaitable[object]]:
    call_count = 0

    @functools.wraps(func)
    async def wrapped(*args: object, **kwargs: object) -> object:
        nonlocal call_count
        call_count += 1
        is_initial = call_count <= _INITIAL_FULL_LOG

        if is_initial:
            params = _format_args(func, args, kwargs)
            logger.debug(f"ENTER {func_name}({params})")

        started_at = time.monotonic()
        try:
            result = await func(*args, **kwargs)
        except Exception as exc:
            elapsed = time.monotonic() - started_at
            logger.debug(
                f"EXCEPTION {func_name} → {type(exc).__name__}: {_safe_repr(exc)} [{elapsed:.4f}s]"
            )
            raise
        elapsed = time.monotonic() - started_at

        if is_initial:
            logger.debug(
                f"EXIT  {func_name} → {_safe_repr(result)}({type(result).__name__}) [{elapsed:.4f}s]"
            )
        elif elapsed >= _SLOW_THRESHOLD_S:
            params = _format_args(func, args, kwargs)
            logger.debug(f"ENTER {func_name}({params}) [call #{call_count}]")
            logger.debug(
                f"EXIT  {func_name} → {_safe_repr(result)}({type(result).__name__}) [{elapsed:.4f}s]"
            )

        return result

    setattr(wrapped, "_satochip_entry_logged", True)
    return wrapped


def _wrap_function(func: Callable[..., object], func_name: str, logger: logging.Logger) -> Callable[..., object]:
    if inspect.iscoroutinefunction(func):
        async_func = cast(Callable[..., Awaitable[object]], func)
        return cast(Callable[..., object], _make_async_wrapper(async_func, func_name, logger))
    return _make_sync_wrapper(func, func_name, logger)


def _wrap_class_methods(cls: type, logger: logging.Logger) -> int:
    wrapped_count = 0
    class_dict = cast(dict[str, object], dict(cls.__dict__))
    for attr_name, attr_value in class_dict.items():
        if isinstance(attr_value, staticmethod):
            func = attr_value.__func__
            if _should_skip(attr_name, func):
                continue
            if getattr(func, "_satochip_entry_logged", False):
                continue
            wrapped = _wrap_function(func, f"{cls.__qualname__}.{func.__name__}", logger)
            setattr(cls, attr_name, staticmethod(wrapped))
            wrapped_count += 1
            continue

        if isinstance(attr_value, classmethod):
            func = cast(Callable[..., object], attr_value.__func__)
            if _should_skip(attr_name, func):
                continue
            if getattr(func, "_satochip_entry_logged", False):
                continue
            wrapped = _wrap_function(func, f"{cls.__qualname__}.{func.__name__}", logger)
            setattr(cls, attr_name, classmethod(wrapped))
            wrapped_count += 1
            continue

        if _should_skip(attr_name, attr_value):
            continue

        if inspect.isfunction(attr_value):
            if getattr(attr_value, "_satochip_entry_logged", False):
                continue
            wrapped = _wrap_function(attr_value, f"{cls.__qualname__}.{attr_value.__name__}", logger)
            setattr(cls, attr_name, wrapped)
            wrapped_count += 1

    return wrapped_count


def instrument_module_function_entries(logger, module_globals: dict[str, object], module_name: str) -> None:  # pyright: ignore[reportMissingParameterType, reportUnknownParameterType]
    active_logger: logging.Logger
    if isinstance(logger, logging.Logger):
        active_logger = logger
    else:
        active_logger = cast(logging.Logger, get_logger(__name__))
    instrumented_count = 0

    for name, value in list(module_globals.items()):
        if inspect.isfunction(value):
            if _should_skip(name, value):
                continue
            if value.__module__ not in {module_name, "__main__"}:
                continue
            if getattr(value, "_satochip_entry_logged", False):
                continue
            module_globals[name] = _wrap_function(value, value.__qualname__, active_logger)
            instrumented_count += 1
            continue

        if inspect.isclass(value):
            if value.__module__ not in {module_name, "__main__"}:
                continue
            instrumented_count += _wrap_class_methods(value, active_logger)

    active_logger.debug(f"Instrumented {instrumented_count} functions in {module_name}")
