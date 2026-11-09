"""Single entry point the iOS app calls from Swift.

Swift cannot call Python objects directly, so everything goes through call(method, args_json):
the arguments are a JSON array, the result is always a JSON string.

  call("init", '[{"app_dir": "...", "download_dir": "...", "passphrase": "", "burner": false, ...}]')
  call("state", "[]")
  call("poll", "[500]")            # blocks up to 500 ms (releases the GIL while waiting)

Module level functions of android_bridge (themes, identity_state, moat_*, ...) are reachable by
the same name; everything else is forwarded to the Bridge object created by "init".
Errors never raise into C: they come back as {"error": "message"}.
"""
import json
import sys
import threading
import traceback

import android_bridge as ab

_bridge = None
_lock = threading.Lock()

_MODULE_FUNCS = {
    "identity_state", "check_passphrase", "themes", "cover_profiles", "shape_labels",
    "shape_estimate", "moat_captcha", "moat_solve", "moat_builtin", "sound_wav_b64",
}
_BRIDGE_METHODS = {
    "state", "configure", "queue", "start_direct", "start_tor_external", "connect", "set_closed",
    "allow", "set_psk", "send_text", "send_file", "name_peer", "pause_transfers", "resume_transfers",
    "cancel_transfers", "poll", "answer_confirm", "shutdown",
    # voice calls, push to talk, volume and sound settings
    "set_mic_permission", "call_peer", "call_accept", "call_reject", "call_hangup", "call_mute", "call_duck",
    "call_ptt", "call_info", "audio_prefs", "set_audio_prefs", "audio_in_b64", "audio_out_b64",
}


def _wrap(value):
    # bridge methods already return JSON text or plain strings; wrap everything uniformly
    return json.dumps({"ok": value})


def call(method, args_json="[]"):
    global _bridge
    try:
        args = json.loads(args_json) if args_json else []
        if method == "init":
            kw = args[0] if args else {}
            with _lock:
                if _bridge is not None:
                    try:
                        _bridge.shutdown()
                    except Exception:
                        pass
                _bridge = ab.Bridge(
                    kw["app_dir"], kw["download_dir"], None, None,
                    kw.get("passphrase") or None, bool(kw.get("burner", False)),
                    bool(kw.get("scrub", True)), bool(kw.get("amnesia", False)),
                )
            return _wrap(True)
        if method in _MODULE_FUNCS:
            return _wrap(getattr(ab, method)(*args))
        if method == "drop":
            with _lock:
                b, _bridge = _bridge, None
            if b is not None:
                b.shutdown()
            return _wrap(True)
        if method in _BRIDGE_METHODS:
            b = _bridge
            if b is None:
                return json.dumps({"error": "not started"})
            return _wrap(getattr(b, method)(*args))
        return json.dumps({"error": "unknown method " + method})
    except Exception as e:  # noqa: BLE001 - must never raise into C
        traceback.print_exc(file=sys.stderr)
        return json.dumps({"error": "%s: %s" % (type(e).__name__, e)})
