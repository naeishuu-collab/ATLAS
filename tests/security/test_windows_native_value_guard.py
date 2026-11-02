"""Synthetic UIA guards; no live application or desktop is accessed."""

import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from openjarvis.windows.identity import IdentityError
from openjarvis.windows.native import NativeBackend


def backend(style):
    native = object.__new__(NativeBackend)
    native._owner = threading.get_ident()
    native._closed = False
    native.user = SimpleNamespace(GetWindowLongPtrW=Mock(return_value=style))
    native._module = SimpleNamespace(IUIAutomationValuePattern=object())
    return native


def element():
    return SimpleNamespace(
        CurrentIsPassword=False,
        CurrentNativeWindowHandle=123,
        GetCurrentPattern=Mock(),
    )


def test_win32_password_style_denied_even_when_uia_flag_is_false():
    native = backend(0x20)
    target = element()
    assert native.value_capability(target) is False
    with pytest.raises(IdentityError, match="Password"):
        native.value(target)
    target.GetCurrentPattern.assert_not_called()


def test_native_style_failure_does_not_read_value():
    native = backend(0)
    target = element()
    with patch("ctypes.get_last_error", return_value=5):
        with pytest.raises(IdentityError, match="style"):
            native.value(target)
        with pytest.raises(IdentityError, match="style"):
            native.value_capability(target)
    target.GetCurrentPattern.assert_not_called()
