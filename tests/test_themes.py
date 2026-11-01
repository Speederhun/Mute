"""Theme sanity (colours readable, roles distinct) and, when Tk is available, a live switch of every widget.
Run: python tests/test_themes.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import mute as m


def ok(cond, msg):
    assert cond, msg
    print("PASS", msg)


ok(len(m.THEMES) >= 8 and {"hacker", "miami", "light"} <= set(m.THEMES), "at least 8 themes incl. hacker, miami, light")
for n, t in m.THEMES.items():
    ok(len({t[k] for k in m.THEME_ROLES}) == len(m.THEME_ROLES), f"{n}: every colour role is distinct (needed for live switching)")
    ok(all(len(t[k]) == 7 and t[k] == t[k].lower() for k in m.THEME_ROLES) and len(t["pal"]) == 8, f"{n}: colours well-formed")
    for a, b, lim in (("fg", "bg", 4.5), ("fg", "chat", 4.5), ("fg", "ent", 4.5), ("fg", "btn", 4.5),
                      ("dim", "bg", 3.0), ("dim", "chat", 3.0), ("acc", "chat", 4.5), ("red", "chat", 4.5)):
        r = m.contrast_ratio(t[a], t[b])
        ok(r >= lim, f"{n}: {a} on {b} readable (contrast {r:.1f} >= {lim})")
    ok(all(m.contrast_ratio(p, t["chat"]) >= 4.0 for p in t["pal"]), f"{n}: peer colours readable on the chat background")

m.APP_DIR = tempfile.mkdtemp(prefix="mute_theme_")
ok(m.load_theme() == "hacker", "default theme is hacker")
open(m.theme_file(), "w").write("miami")
ok(m.load_theme() == "miami", "saved theme is loaded")
open(m.theme_file(), "w").write("../../etc/passwd")
ok(m.load_theme() == "hacker", "unknown / hostile theme name falls back to hacker")

if sys.platform == "darwin" and os.environ.get("CI"):
    print("SKIP live switch (macOS CI runners have no usable GUI session)")
    print("all theme tests passed")
    sys.exit(0)
try:
    import tkinter as tk
    root = tk.Tk()
    root.destroy()
except Exception:
    print("SKIP live switch (no Tk / display)")
    print("all theme tests passed")
    sys.exit(0)

# live switch through the real GUI
import threading
from tkinter import messagebox
messagebox.askyesnocancel = lambda *a, **k: True
orig = tk.Tk.mainloop
result = {}


def walk(w):
    yield w
    for c in w.winfo_children():
        yield from walk(c)


def patched(self, n=0):
    def go():
        try:
            btn = [w for w in walk(self) if isinstance(w, tk.Button) and w.cget("text") == "Options..."][0]
            btn.invoke(); self.update()
            top = [w for w in self.winfo_children() if isinstance(w, tk.Toplevel)][0]
            menus = [w for w in walk(top) if isinstance(w, tk.Menubutton)]
            theme_menu = [w for w in menus if self.getvar(str(w.cget("textvariable"))) in m.THEMES][0]
            menu = self.nametowidget(theme_menu.cget("menu"))
            labels = [menu.entrycget(i, "label") for i in range(menu.index("end") + 1)]
            seen = {}
            for name in ("miami", "light", "amber", "hacker"):
                menu.invoke(labels.index(name)); self.update()
                t = m.THEMES[name]
                chat = [w for w in walk(self) if isinstance(w, tk.Text) and str(w.winfo_class()) == "Text"][0]
                leftovers = []
                for w in walk(self):
                    for opt in m.THEME_OPTS:
                        try:
                            v = str(w.cget(opt)).lower()
                        except tk.TclError:
                            continue
                        for other, ot in m.THEMES.items():
                            if other != name and v in [ot[k] for k in m.THEME_ROLES] and v not in [t[k] for k in m.THEME_ROLES]:
                                leftovers.append((str(w), opt, v))
                seen[name] = (self.cget("bg") == t["bg"], chat.cget("bg") == t["chat"], not leftovers,
                              str(chat.tag_cget("sys", "foreground")).lower() == t["dim"], leftovers[:3])
            result["seen"] = seen
        except Exception as e:
            import traceback; traceback.print_exc()
            result["err"] = e
        self.destroy()
    self.after(500, go)
    return orig(self)


tk.Tk.mainloop = patched
args = m.build_parser().parse_args(["--amnesia"])
m.main(args)
ok("err" not in result, "live theme switch ran without errors")
for name, (rootok, chatok, clean, tagok, left) in result["seen"].items():
    ok(rootok and chatok and clean and tagok, f"switching to {name} recolours window, chat, tags and open dialogs (leftovers: {left})")
print("all theme tests passed")
