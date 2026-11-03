#!/usr/bin/env python3
"""LunaSurfer 0.3.33 - Qt 6 / QtWebEngine browser."""
import json
import pathlib
import sys
import urllib.parse
import os
import subprocess
import time
from html.parser import HTMLParser
from html import escape

# Keep QtWebEngine's own helper selection. Forcing a system helper can mix
# Qt installations and leave the browser surface blank on some Debian systems.
# Widevine is passed only when the local CDM exists.
WIDEVINE_CDM = pathlib.Path("/opt/WidevineCdm/gmp-widevinecdm/latest/libwidevinecdm.so")
if WIDEVINE_CDM.is_file():
    existing_flags = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "").strip()
    widevine_flag = f"--widevine-path={WIDEVINE_CDM}"
    if widevine_flag not in existing_flags:
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (existing_flags + " " + widevine_flag).strip()

from PySide6.QtCore import QUrl, QSize, Qt, QTimer, QEvent
from PySide6.QtGui import QAction, QKeySequence, QIcon
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QToolBar, QLineEdit, QToolButton,
    QVBoxLayout, QWidget, QMenu, QFileDialog, QMessageBox, QDialog,
    QFormLayout, QPushButton, QHBoxLayout, QLabel, QCheckBox, QComboBox, QStyle, QInputDialog, QListWidget, QListWidgetItem, QTreeWidget, QTreeWidgetItem, QHeaderView, QProgressBar, QSizePolicy, QScrollArea
)
from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage, QWebEngineSettings, QWebEngineUrlRequestInterceptor
from PySide6.QtWebEngineWidgets import QWebEngineView

APP_NAME = "LunaSurfer"
_VERSION_FILE = pathlib.Path(__file__).resolve().with_name("VERSION")
try:
    APP_VERSION = _VERSION_FILE.read_text(encoding="utf-8").strip() or "0.3.33"
except OSError:
    APP_VERSION = "0.3.33"
CONFIG_DIR = pathlib.Path.home() / ".config" / "lunasurfer"
DATA_DIR = pathlib.Path.home() / ".local" / "share" / "lunasurfer"
CONFIG_FILE = CONFIG_DIR / "settings.json"
BOOKMARKS_FILE = DATA_DIR / "bookmarks.json"
HISTORY_FILE = DATA_DIR / "history.json"
SESSION_FILE = DATA_DIR / "session.json"
DOWNLOADS_FILE = DATA_DIR / "downloads.json"
DOWNLOAD_DIR = pathlib.Path.home() / "Downloads"

def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


class StoredDownload:
    """Read-only completed download restored from the persistent history."""
    def __init__(self, record):
        self._received = int(record.get("received", 0) or 0)
        self._total = int(record.get("total", self._received) or self._received)
    def isFinished(self): return True
    def receivedBytes(self): return self._received
    def totalBytes(self): return self._total
    def cancel(self): return None


class ChromiumBookmarksParser(HTMLParser):
    """Read Chromium/Netscape bookmark HTML while preserving folder structure."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items = []
        self._stack = [self.items]
        self._href = None
        self._text = []
        self._folder_text = []
        self._in_h3 = False
        self._pending_folder = None
        self._last_start = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        self._last_start = tag
        if tag == "h3":
            self._in_h3 = True; self._folder_text = []
        elif tag == "a":
            self._href = dict(attrs).get("href", "").strip(); self._text = []
        elif tag == "dl" and self._pending_folder is not None:
            folder = self._pending_folder
            self._pending_folder = None
            self._stack.append(folder["children"])

    def handle_data(self, data):
        if self._in_h3: self._folder_text.append(data)
        if self._href is not None: self._text.append(data)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "h3" and self._in_h3:
            title = "".join(self._folder_text).strip() or "Ordner"
            folder = {"type": "folder", "title": title, "children": []}
            self._stack[-1].append(folder)
            self._pending_folder = folder
            self._in_h3 = False
        elif tag == "a" and self._href is not None:
            title = "".join(self._text).strip() or self._href
            if self._href.startswith(("http://", "https://", "file://")):
                self._stack[-1].append({"title": title, "url": self._href})
            self._href = None; self._text = []
        elif tag == "dl":
            if len(self._stack) > 1: self._stack.pop()

class AddressLineEdit(QLineEdit):
    """Address field with a language-aware context menu.

    Qt's built-in QLineEdit menu follows the Qt platform translation and may
    remain English even when LunaSurfer itself is switched to German.  This
    menu is owned by LunaSurfer so it always follows the selected language.
    """
    def __init__(self, window):
        super().__init__()
        self.window_ref = window

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        de = self.window_ref.settings_data.get("language", "de") != "en"
        labels = (
            ("Rückgängig", "Wiederholen", "Ausschneiden", "Kopieren", "Einfügen", "Löschen", "Alles auswählen")
            if de else
            ("Undo", "Redo", "Cut", "Copy", "Paste", "Delete", "Select All")
        )
        actions = [
            menu.addAction(labels[0], self.undo),
            menu.addAction(labels[1], self.redo),
        ]
        menu.addSeparator()
        actions.extend([
            menu.addAction(labels[2], self.cut),
            menu.addAction(labels[3], self.copy),
            menu.addAction(labels[4], self.paste),
            menu.addAction(labels[5], lambda: self.insert("")),
        ])
        menu.addSeparator()
        actions.append(menu.addAction(labels[6], self.selectAll))
        has_selection = bool(self.hasSelectedText())
        actions[0].setEnabled(self.isUndoAvailable())
        actions[1].setEnabled(self.isRedoAvailable())
        actions[2].setEnabled(has_selection and not self.isReadOnly())
        actions[3].setEnabled(has_selection)
        actions[4].setEnabled(not self.isReadOnly())
        actions[5].setEnabled(has_selection and not self.isReadOnly())
        menu.exec(event.globalPos())
        event.accept()


class PrivacyInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, window):
        super().__init__()
        self.window_ref = window

    def interceptRequest(self, info):
        if self.window_ref.settings_data.get("send_dnt", False):
            info.setHttpHeader(b"DNT", b"1")
        if not self.window_ref.settings_data.get("adblock_enabled", True):
            return
        url = info.requestUrl().toString().lower()
        host = info.requestUrl().host().lower()
        whitelist = [str(x).lower() for x in self.window_ref.settings_data.get("adblock_whitelist", [])]
        if any(host == x or host.endswith("." + x) for x in whitelist):
            return
        standard = ["doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.", "adsystem.com", "taboola.com", "outbrain.com", "scorecardresearch.com"]
        strong = standard + ["adnxs.com", "adsrvr.org", "amazon-adsystem.com", "criteo.com", "criteo.net", "demdex.net", "rubiconproject.com", "openx.net", "pubmatic.com", "casalemedia.com", "mathtag.com", "smartadserver.com", "advertising.com", "2mdn.net", "moatads.com", "quantserve.com", "bluekai.com", "chartbeat.com", "hotjar.com", "mouseflow.com", "mixpanel.com", "segment.io"]
        very_strong = strong + ["google-analytics.com", "googletagmanager.com", "analytics.google.com", "facebook.net", "connect.facebook.net", "bat.bing.com", "clarity.ms", "branch.io", "app-measurement.com", "newrelic.com", "nr-data.net", "sentry.io"]
        # Super strong adds a broader set of common advertising, attribution and telemetry endpoints.
        # It can occasionally affect login, embedded media or site statistics; the whitelist remains available.
        super_strong = very_strong + [
            "googletagservices.com", "googlesyndication.com", "doubleclick.net", "2mdn.net",
            "adform.net", "adnxs.net", "adsafeprotected.com", "advertising.com", "advertserve.com",
            "bidswitch.net", "contextweb.com", "lijit.com", "media.net", "mgid.com", "revcontent.com",
            "sharethrough.com", "smaato.net", "spotxchange.com", "teads.tv", "tradedoubler.com",
            "yieldmo.com", "yieldlab.net", "zedo.com", "serving-sys.com", "eyeota.net",
            "exelator.com", "krxd.net", "rlcdn.com", "turn.com", "turner.com",
            "omtrdc.net", "2o7.net", "demdex.net", "everesttech.net", "agkn.com",
            "segment.com", "segment.io", "amplitude.com", "amplitudeapp.com", "heap.io",
            "fullstory.com", "luckyorange.com", "inspectlet.com", "crazyegg.com", "smartlook.com",
            "optimizely.com", "vwo.com", "visualwebsiteoptimizer.com", "contentsquare.net",
            "ads-twitter.com", "analytics.twitter.com", "snap.licdn.com", "px.ads.linkedin.com",
            "ads.yahoo.com", "gemini.yahoo.com", "yahoo.com/analytics"
        ]
        # Mega strong is deliberately intended for maximum privacy/ad-test use.
        # Keep host rules and URL/path rules separate: a hostname comparison cannot
        # reliably match entries such as "facebook.com/tr".
        mega_strong = super_strong + [
            "adobedtm.com", "demdex.com", "marketo.net", "pardot.com", "hubspot.com",
            "hs-analytics.net", "hsadspixel.net", "bizible.com", "drift.com", "intercom.io",
            "pendo.io", "appcues.com", "launchdarkly.com", "split.io", "statsig.com",
            "logrocket.io", "datadoghq.com", "browser-intake-datadoghq.com", "bugsnag.com",
            "rollbar.com", "raygun.io", "mousestats.com", "clicktale.net", "sessioncam.com",
            "glassboxdigital.com", "matomo.cloud", "piwik.pro", "kissmetrics.io", "woopra.com",
            "chartbeat.net", "parsely.com", "conviva.com", "nielsen.com", "adsymptotic.com",
            "adkernel.com", "adroll.com", "adition.com", "adsnative.com", "adzerk.net",
            "moatpixel.com", "doubleverify.com", "integralads.com", "casalegslb.com",
            "indexexchange.com", "bluekai.net", "liveintent.com", "lotame.com", "permutive.com",
            "zeotap.com", "tealiumiq.com", "tealium.com", "tagcommander.com", "ensighten.com",
            "fingerprintjs.com", "fingerprint.com", "iovation.com", "threatmetrix.com",
            # Frequently used advertising, attribution and tracker hosts.
            "1rx.io", "33across.com", "360yield.com", "acuityads.com", "adblade.com",
            "adbutler.com", "adcolony.com", "adgear.com", "adhaven.com", "adition.com",
            "admarvel.com", "adnxs.net", "adnxs.com", "adpushup.com", "adskeeper.com",
            "adswizz.com", "adtech.de", "adtechus.com", "advertising.com", "advertserve.com",
            "agkn.com", "appsflyer.com", "atdmt.com", "beacon.kr", "beeswax.io",
            "branch.io", "btloader.com", "cedexis.com", "clicky.com", "criteo.net",
            "demdex.net", "dpm.demdex.net", "everesttech.net", "eyeota.net", "flashtalking.com",
            "gemius.pl", "getclicky.com", "impactradius.com", "imrworldwide.com",
            "inmobi.com", "krxd.net", "liadm.com", "mathtag.com", "media6degrees.com",
            "nexac.com", "omnitagjs.com", "openx.net", "optimizely.com", "quantserve.com",
            "rfihub.com", "scorecardresearch.com", "serving-sys.com", "sharethis.com",
            "simpli.fi", "sitescout.com", "skimresources.com", "stickyadstv.com", "tapad.com",
            "teads.tv", "tribalfusion.com", "undertone.com", "weborama.com", "yieldlab.net",
            "zemanta.com", "analytics.tiktok.com", "analytics.twitter.com", "snap.licdn.com"
        ]
        mega_url_patterns = [
            "facebook.com/tr", "/collect?", "/collect/", "/analytics", "/analytics/",
            "/tracking", "/tracking/", "/tracker", "/tracker/", "/telemetry", "/telemetry/",
            "/beacon", "/beacon/", "/pixel", "/pixel/", "/pageview", "/page-view",
            "/event?", "/events?", "/conversion", "/conversions", "/remarketing",
            "/adservice", "/adserver", "/ads/", "/ads?", "/advert/", "/advertising/",
            "utm_source=", "utm_medium=", "gclid=", "fbclid="
        ]
        strength = self.window_ref.settings_data.get("adblock_strength", "standard")
        builtins = (standard if strength == "standard" else
                    strong if strength == "strong" else
                    very_strong if strength == "very_strong" else
                    super_strong if strength == "super_strong" else mega_strong)
        custom = [str(x).lower() for x in self.window_ref.settings_data.get("adblock_custom_blocklist", [])]
        # Match domains precisely (including subdomains), while custom entries may
        # still be URL patterns. This avoids accidental partial hostname matches.
        domain_match = any(host == token or host.endswith("." + token) for token in builtins if "/" not in token)
        pattern_match = any(token in url for token in custom)
        mega_pattern_match = strength == "mega_strong" and any(token in url for token in mega_url_patterns)
        if domain_match or pattern_match or mega_pattern_match:
            info.block(True)


class BrowserView(QWebEngineView):
    def __init__(self, window):
        super().__init__()
        self.window_ref = window
        self.titleChanged.connect(self.on_title)
        self.urlChanged.connect(self.on_url)
        self.loadProgress.connect(lambda p: window.statusBar().showMessage(f"Laden … {p}%"))
        self.loadFinished.connect(self.on_load_finished)
        self.renderProcessTerminated.connect(self.on_render_process_terminated)
        # The page is replaced with a profile-specific QWebEnginePage in add_tab().
        # Configure fullscreen support there, otherwise the signal remains connected
        # to this temporary default page and video fullscreen never reaches the window.

    def configure_web_page(self):
        page = self.page()
        settings = page.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        # Allow websites to copy text after an explicit user action.  Many modern
        # pages use navigator.clipboard.writeText() for their own Copy buttons.
        clipboard_attr = getattr(QWebEngineSettings.WebAttribute, "JavascriptCanAccessClipboard", None)
        if clipboard_attr is not None:
            settings.setAttribute(clipboard_attr, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)
        page.fullScreenRequested.connect(self.handle_fullscreen)

    def contextMenuEvent(self, event):
        """Show QtWebEngine's full context menu with German labels."""
        menu = self.createStandardContextMenu()
        if self.window_ref.settings_data.get("language", "de") == "en":
            menu.exec(event.globalPos())
            event.accept()
            return
        translations = {
            "back": self.tr("Zurück", "Back"), "forward": self.tr("Vorwärts", "Forward"), "reload": self.tr("Neu laden", "Reload"),
            "save page": "Seite speichern unter…", "view page source": "Seitenquelltext anzeigen",
            "undo": "Rückgängig", "redo": "Wiederholen", "cut": "Ausschneiden",
            "copy": "Kopieren", "paste": "Einfügen", "delete": "Löschen",
            "select all": "Alles auswählen", "open link in new tab": "Link in neuem Tab öffnen",
            "open link in new window": "Link in neuem Fenster öffnen",
            "copy link address": "Link-Adresse kopieren", "save link": "Link speichern unter…",
            "open image in new tab": "Bild in neuem Tab öffnen", "copy image": "Bild kopieren",
            "copy image address": "Bild-Adresse kopieren", "save image": "Bild speichern unter…",
            "open audio in new tab": "Audio in neuem Tab öffnen",
            "open video in new tab": "Video in neuem Tab öffnen",
            "play": "Wiedergabe", "pause": "Pause", "mute": "Stummschalten",
            "unmute": "Ton einschalten", "loop": "Wiederholen", "show controls": "Steuerelemente anzeigen",
            "save video": "Video speichern unter…", "copy video address": "Video-Adresse kopieren",
            "save audio": "Audio speichern unter…", "copy audio address": "Audio-Adresse kopieren",
            "inspect": "Untersuchen", "spellcheck": "Rechtschreibprüfung",
            "writing direction": "Schreibrichtung", "left to right": "Von links nach rechts",
            "right to left": "Von rechts nach links", "translate": "Übersetzen"
        }
        def translate_menu(target):
            for action in target.actions():
                if action.menu():
                    translate_menu(action.menu())
                    label = action.text().replace("&", "").strip().lower()
                    if label in translations:
                        action.setText(translations[label])
                else:
                    original = action.text()
                    label = original.replace("&", "").strip().lower()
                    if label in translations:
                        action.setText(translations[label])
        translate_menu(menu)
        menu.exec(event.globalPos())
        event.accept()

    def createWindow(self, window_type):
        if self.window_ref.settings_data.get("block_popups", True):
            self.window_ref.statusBar().showMessage("Pop-up wurde blockiert.", 4000)
            return None
        self.window_ref.add_tab("about:blank", switch=True)
        return self.window_ref.current_view()

    def on_title(self, title):
        self.window_ref.update_tab_title(self, title)

    def on_url(self, url):
        if self.window_ref.current_view() is self:
            self.window_ref.address.setText(url.toString())

    def on_load_finished(self, ok):
        url = self.url().toString()
        # GitHub's traffic graphs contain a few light SVG panels.  With the
        # dark browser chrome on this QtWebEngine build their SVG labels can be
        # rendered too lightly.  Correct only those graph labels, not GitHub's
        # normal page colours.
        if ok and "github.com" in url and "/graphs/traffic" in url:
            self.page().runJavaScript("""
                (() => {
                    const style = document.createElement('style');
                    style.id = 'lunasurfer-github-traffic-contrast';
                    style.textContent = `svg text { fill: #57606a !important; color: #57606a !important; }
                                         svg [fill="white"] + text { fill: #24292f !important; }`;
                    if (!document.getElementById(style.id)) document.head.appendChild(style);
                })();
            """)
        if ok:
            if url.startswith(("http://", "https://")):
                history = read_json(HISTORY_FILE, [])
                history = [x for x in history if x.get("url") != url]
                history.insert(0, {"title": self.title() or url, "url": url})
                write_json(HISTORY_FILE, history[:1500])
            self.window_ref.statusBar().showMessage("Seite geladen", 2500)
        else:
            self.window_ref.statusBar().showMessage("Seite konnte nicht geladen werden – Adresse und Netzwerk prüfen", 8000)
        self.window_ref.update_navigation()
        # Re-apply after the page and its own CSS have finished loading.
        # This prevents the selected browser font size from reverting to medium.
        self.window_ref.enforce_font_size(self)

    def on_render_process_terminated(self, status, exit_code):
        self.window_ref.statusBar().showMessage(
            f"WebEngine-Prozess beendet (Status {status}, Code {exit_code}). Seite neu laden.", 10000
        )

    def keyPressEvent(self, event):
        # QtWebEngine can consume Escape internally, so handle it before the
        # event reaches Chromium. This gives LunaSurfer a reliable way back
        # from HTML/video fullscreen.
        if event.key() == Qt.Key.Key_Escape and self.window_ref._web_fullscreen:
            self.window_ref.leave_web_fullscreen()
            event.accept()
            return
        super().keyPressEvent(event)

    def handle_fullscreen(self, request):
        # Accept the Chromium/HTML fullscreen request immediately.  The native
        # window change is queued for the next event-loop turn: changing a
        # QMainWindow while QtWebEngine is dispatching this signal can otherwise
        # leave the page enlarged but keep the browser chrome visible.
        turn_on = bool(request.toggleOn())
        request.accept()
        if turn_on:
            QTimer.singleShot(0, self.window_ref.enter_web_fullscreen)
        else:
            QTimer.singleShot(0, self.window_ref.leave_web_fullscreen)

class LunaSurfer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(1250, 820)
        self._web_fullscreen = False
        self._was_maximized_before_fullscreen = False
        self._fullscreen_chrome = []
        self.settings_data = read_json(CONFIG_FILE, {
            "home": "https://duckduckgo.com",
            "search": "https://duckduckgo.com/?q={}",
            "dark": True,
            "theme": "dark",
            "browser_design": "dark",
            "show_bookmarks_bar": True,
            "restore_session": False,
            "startup_mode": "home",
            "search_engine": "DuckDuckGo",
            "block_popups": True,
            "permission_camera": "ask", "permission_microphone": "ask",
            "permission_location": "ask", "permission_notifications": "ask",
            "download_dir": str(DOWNLOAD_DIR),
            "default_zoom": 100,
            "clear_history_on_exit": False,
            "clear_cache_on_exit": False,
            "clear_cookies_on_exit": False,
            "ask_download_location": False,
            "send_dnt": False,
            "confirm_close_multiple_tabs": True,
            "remember_window_size": True,
            "window_geometry": None,
            "font_size": "Mittel",
            "language": "de",
            "default_browser": False,
            "adblock_enabled": True,
            "adblock_whitelist": [],
            "adblock_custom_blocklist": [],
            "adblock_strength": "standard"
        })
        if self.settings_data.get("remember_window_size", True):
            geometry = self.settings_data.get("window_geometry")
            if isinstance(geometry, (list, tuple)) and len(geometry) == 4:
                try:
                    self.setGeometry(*[int(v) for v in geometry])
                except (TypeError, ValueError):
                    pass
        self.profile = QWebEngineProfile("LunaSurfer", self)
        self.profile.setPersistentStoragePath(str(DATA_DIR / "webengine"))
        self.profile.setCachePath(str(pathlib.Path.home() / ".cache" / "lunasurfer" / "webengine"))
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)
        self.download_items = []
        self.load_download_history()
        self.privacy_interceptor = PrivacyInterceptor(self)
        self.profile.setUrlRequestInterceptor(self.privacy_interceptor)
        self.profile.downloadRequested.connect(self.on_download)
        self.download_dir = pathlib.Path(self.settings_data.get("download_dir", str(DOWNLOAD_DIR))).expanduser()

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setMovable(True)
        self.tabs.setTabsClosable(True)
        self.tabs.tabBar().setExpanding(False)
        self.tabs.tabBar().setUsesScrollButtons(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.on_tab_changed)
        # The + button belongs directly after the last open tab, not at the
        # far right edge of the window.  This keeps the tab strip compact.
        self.new_tab_button = QToolButton(self.tabs.tabBar())
        self.new_tab_button.setText("+")
        self.new_tab_button.setToolTip("Neuer Tab / New tab")
        self.new_tab_button.setFixedSize(38, 30)
        self.new_tab_button.setStyleSheet("font-size: 21px; font-weight: bold; color: #ffffff; background: #1769aa; border: 1px solid #5fa8e8; border-radius: 5px; margin: 1px;")
        self.new_tab_button.clicked.connect(lambda: self.add_tab(self.settings_data.get("home", "https://duckduckgo.com")))
        self.tabs.tabBar().installEventFilter(self)
        self.setCentralWidget(self.tabs)
        QTimer.singleShot(0, self.update_new_tab_button_position)

        self.navigation_bar = QToolBar("Navigation")
        bar = self.navigation_bar
        bar.setMovable(False)
        bar.setIconSize(QSize(28, 28))
        bar.setMinimumHeight(54)
        self.addToolBar(bar)

        style = QApplication.style()
        self.back_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_ArrowBack), "", self); self.back_action.setToolTip(self.tr("Zurück", "Back"))
        self.back_action.triggered.connect(lambda: self.current_view() and self.current_view().back())
        bar.addAction(self.back_action)
        self.forward_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_ArrowForward), "", self); self.forward_action.setToolTip(self.tr("Vorwärts", "Forward"))
        self.forward_action.triggered.connect(lambda: self.current_view() and self.current_view().forward())
        bar.addAction(self.forward_action)
        self.reload_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload), "", self); self.reload_action.setToolTip(self.tr("Neu laden", "Reload"))
        self.reload_action.triggered.connect(lambda: self.current_view() and self.current_view().reload())
        bar.addAction(self.reload_action)
        self.home_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_DirHomeIcon), "", self); self.home_action.setToolTip(self.tr("Startseite", "Home"))
        self.home_action.triggered.connect(self.go_home)
        bar.addAction(self.home_action)

        self.address = AddressLineEdit(self)
        self.address.setPlaceholderText(self.tr("Adresse oder Suchbegriff eingeben", "Enter address or search"))
        self.address.returnPressed.connect(self.navigate)
        self.address.setClearButtonEnabled(True)
        # Give the address field substantially more room, similar to Chromium.
        self.address.setMinimumWidth(520)
        self.address.setSizePolicy(self.address.sizePolicy().horizontalPolicy(), self.address.sizePolicy().verticalPolicy())
        bar.addWidget(self.address)

        # Use a dedicated button so the bookmark star remains clearly visible
        # and is not reduced to the toolbar's normal text/icon size.
        self.star_action = QAction("★", self)
        self.star_action.setToolTip(self.tr("Aktuelle Seite als Lesezeichen hinzufügen", "Add current page to bookmarks"))
        self.star_action.triggered.connect(self.add_bookmark)
        self.star_button = QToolButton(self)
        self.star_button.setDefaultAction(self.star_action)
        self.star_button.setText("★")
        self.star_button.setFixedSize(46, 42)
        self.star_button.setStyleSheet("font-size: 30px; font-weight: bold; padding: 0px; margin: 0px;")
        bar.addWidget(self.star_button)

        # Compact toolbar buttons for Download Manager and Ad Blocker.
        self.download_action = QAction("⇩", self)
        self.download_action.setToolTip(self.tr("Download-Manager", "Download manager"))
        self.download_action.triggered.connect(self.show_download_manager)
        self.download_button = QToolButton(self); self.download_button.setDefaultAction(self.download_action)
        self.download_button.setText("⇩"); self.download_button.setFixedSize(34, 34)
        self.download_button.setStyleSheet("font-size: 24px; font-weight: bold; color: #6ee7ff; border: 1px solid #3285bd; border-radius: 7px; padding: 0px;")
        bar.addWidget(self.download_button)

        self.adblock_action = QAction("🛡", self)
        self.adblock_action.setToolTip(self.tr("Werbeblocker", "Ad blocker"))
        self.adblock_action.triggered.connect(self.show_adblock_settings)
        self.adblock_button = QToolButton(self); self.adblock_button.setDefaultAction(self.adblock_action)
        self.adblock_button.setText("🛡"); self.adblock_button.setFixedSize(34, 34)
        self.adblock_button.setStyleSheet("font-size: 20px; color: #7dd3fc; border: 1px solid #3285bd; border-radius: 7px; padding: 0px;")
        bar.addWidget(self.adblock_button)
        self.update_adblock_button()
        self.newtab_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder), "", self); self.newtab_action.setToolTip(self.tr("Neuer Tab", "New tab"))
        self.newtab_action.triggered.connect(lambda: self.add_tab(self.settings_data["home"]))
        bar.addAction(self.newtab_action)

        menu = QMenu(self.tr("Menü", "Menu"), self)
        menu.addAction(self.tr("Neuer Tab", "New tab"), lambda: self.add_tab(self.settings_data["home"]))
        menu.addAction(self.tr("Lesezeichen", "Bookmarks"), self.show_bookmarks)
        menu.addAction(self.tr("Verlauf", "History"), self.show_history)
        menu.addAction("Downloads-Ordner öffnen", self.open_downloads)
        menu.addSeparator()
        menu.addAction(self.tr("Einstellungen", "Settings"), self.show_settings)
        menu.addAction(self.tr("Über LunaSurfer", "About LunaSurfer"), self.about)
        menu.addSeparator()
        menu.addAction(self.tr("Beenden", "Quit"), self.close)
        self.menu_button = QToolButton()
        self.menu_button.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_TitleBarMenuButton))
        self.menu_button.setIconSize(QSize(28, 28))
        self.menu_button.setToolTip(self.tr("Menü", "Menu"))
        self.menu_button.setMenu(menu)
        self.menu_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        bar.addWidget(self.menu_button)

        # Force a separate toolbar row so the bookmarks bar is always directly
        # below the URL/navigation bar, like Chromium.
        self.addToolBarBreak(Qt.ToolBarArea.TopToolBarArea)

        # Chromium-style bookmarks bar directly below the navigation bar.
        self.bookmarks_bar = QToolBar(self.tr("Lesezeichenleiste", "Bookmarks bar"))
        self.bookmarks_bar.setMovable(False)
        self.bookmarks_bar.setIconSize(QSize(18, 18))
        self.bookmarks_bar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.bookmarks_bar.setMinimumHeight(36)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self.bookmarks_bar)
        self._bookmark_resize_timer = QTimer(self)
        self._bookmark_resize_timer.setSingleShot(True)
        self._bookmark_resize_timer.timeout.connect(self.refresh_bookmarks_bar)
        self.refresh_bookmarks_bar()
        self.bookmarks_bar.setVisible(self.settings_data.get("show_bookmarks_bar", True))

        self.statusBar().showMessage("Bereit / Ready")
        self.apply_browser_design()
        self.restore_or_open_start_page()
        self.set_shortcuts()

    def apply_browser_design(self):
        """Apply the selected LunaSurfer chrome design immediately."""
        design = self.settings_data.get("browser_design", "dark")
        if design == "light":
            css = """
                QMainWindow { background: #f4f6f9; color: #1d2630; }
                QToolBar { background: #ffffff; border-bottom: 1px solid #d6dbe2; spacing: 8px; padding: 8px 10px; }
                QToolBar QToolButton { color: #26313d; padding: 7px; border-radius: 9px; min-width: 34px; min-height: 34px; }
                QToolBar QToolButton:hover { background: #e7edf5; }
                QToolBar QToolButton:pressed { background: #d3e5f8; }
                QLineEdit { background: #ffffff; color: #1d2630; border: 1px solid #b9c4d0; border-radius: 16px; padding: 9px 13px; font-size: 13px; }
                QTabWidget::pane { border: 0; background: #f4f6f9; }
                QTabBar::tab { background: #e7ebf0; color: #293440; padding: 9px 16px; margin-right: 2px; }
                QTabBar::tab:selected { background: #d7e9fa; color: #163d62; }
                QTabWidget QToolButton { min-width: 38px; min-height: 30px; }
                QStatusBar { background: #edf1f5; color: #26313d; }
                QToolTip { background: #ffffff; color: #1d2630; border: 1px solid #9da9b6; border-radius: 3px; padding: 3px 6px; font-size: 11px; }
            """
        elif design == "luna":
            css = """
                QMainWindow { background: #21163a; }
                QToolBar { background: #302052; border: 0; spacing: 8px; padding: 8px 10px; }
                QToolBar QToolButton { color: #f5efff; padding: 7px; border-radius: 9px; min-width: 34px; min-height: 34px; }
                QToolBar QToolButton:hover { background: #513781; }
                QToolBar QToolButton:pressed { background: #7c3fc2; }
                QLineEdit { background: #3a275c; color: #ffffff; border: 1px solid #8061ae; border-radius: 16px; padding: 9px 13px; font-size: 13px; }
                QTabWidget::pane { border: 0; background: #21163a; }
                QTabBar::tab { background: #38265b; color: #eadfff; padding: 9px 16px; margin-right: 2px; }
                QTabBar::tab:selected { background: #7c3fc2; color: white; }
                QTabWidget QToolButton { min-width: 38px; min-height: 30px; }
                QStatusBar { background: #2b1d48; color: #eadfff; }
                QToolTip { background: #352451; color: #ffffff; border: 1px solid #aa83df; border-radius: 3px; padding: 3px 6px; font-size: 11px; }
            """
        elif design == "graphite":
            # Graphite Blue: deep navy graphite surfaces with a clearly saturated, true-blue accent.
            css = """
                QMainWindow { background: #071a36; color: #e8f1ff; }
                QToolBar { background: #0d2850; border-bottom: 1px solid #24569a; spacing: 8px; padding: 8px 10px; }
                QToolBar QToolButton { color: #e8f1ff; padding: 7px; border-radius: 9px; min-width: 34px; min-height: 34px; }
                QToolBar QToolButton:hover { background: #174b86; }
                QToolBar QToolButton:pressed { background: #176fe5; }
                QLineEdit { background: #10345f; color: #f4f8ff; border: 1px solid #3979c5; border-radius: 16px; padding: 9px 13px; font-size: 13px; selection-background-color: #247cff; }
                QLineEdit:focus { border: 1px solid #65adff; background: #123d70; }
                QTabWidget::pane { border: 0; background: #071a36; }
                QTabBar::tab { background: #10325b; color: #d5e7ff; padding: 9px 16px; margin-right: 2px; border-top-left-radius: 7px; border-top-right-radius: 7px; }
                QTabBar::tab:hover { background: #24569a; color: #ffffff; }
                QTabBar::tab:selected { background: #176fe5; color: #ffffff; border-bottom: 2px solid #8bc5ff; }
                QTabWidget QToolButton { min-width: 38px; min-height: 30px; }
                QStatusBar { background: #0d2850; color: #dcecff; border-top: 1px solid #24569a; }
                QToolTip { background: #10345f; color: #ffffff; border: 1px solid #65adff; border-radius: 5px; padding: 4px 7px; font-size: 11px; }
                QMenu { background: #10345f; color: #e8f1ff; border: 1px solid #3979c5; padding: 5px; }
                QMenu::item:selected { background: #176fe5; border-radius: 4px; }
            """
        elif design == "ocean":
            css = """
                QMainWindow { background: #092b35; color: #e5fbff; }
                QToolBar { background: #0d3b49; border-bottom: 1px solid #176477; spacing: 8px; padding: 8px 10px; }
                QToolBar QToolButton { color: #e5fbff; padding: 7px; border-radius: 9px; min-width: 34px; min-height: 34px; }
                QToolBar QToolButton:hover { background: #15586a; }
                QToolBar QToolButton:pressed { background: #00a6a6; }
                QLineEdit { background: #104553; color: #f0feff; border: 1px solid #278397; border-radius: 16px; padding: 9px 13px; font-size: 13px; }
                QTabWidget::pane { border: 0; background: #092b35; }
                QTabBar::tab { background: #104553; color: #d6f7fb; padding: 9px 16px; margin-right: 2px; }
                QTabBar::tab:selected { background: #008c9e; color: white; }
                QTabWidget QToolButton { min-width: 38px; min-height: 30px; }
                QStatusBar { background: #0d3b49; color: #d6f7fb; }
                QToolTip { background: #104553; color: #ffffff; border: 1px solid #4bb4c5; border-radius: 3px; padding: 3px 6px; font-size: 11px; }
            """
        else:
            css = """
                QMainWindow { background: #101827; }
                QToolBar { background: #17263b; border: 0; spacing: 8px; padding: 8px 10px; }
                QToolBar QToolButton { color: #eef4ff; padding: 7px; border-radius: 9px; min-width: 34px; min-height: 34px; }
                QToolBar QToolButton:hover { background: #294564; }
                QToolBar QToolButton:pressed { background: #1769aa; }
                QLineEdit { background: #202f45; color: #f2f6ff; border: 1px solid #3d5878; border-radius: 16px; padding: 9px 13px; font-size: 13px; }
                QTabWidget::pane { border: 0; background: #101827; }
                QTabBar::tab { background: #1c2c42; color: #dce8f8; padding: 9px 16px; margin-right: 2px; }
                QTabBar::tab:selected { background: #1769aa; color: white; }
                QTabWidget QToolButton { min-width: 38px; min-height: 30px; }
                QStatusBar { background: #142238; color: #dce8f8; }
                QToolTip { background: #1b2b42; color: #ffffff; border: 1px solid #6f9fc9; border-radius: 3px; padding: 3px 6px; font-size: 11px; }
            """
        self.setStyleSheet(css)
        # Keep the compact special buttons visually consistent with the selected design.
        if hasattr(self, "new_tab_button"):
            if design == "luna":
                accent, border, fg = "#7c3fc2", "#b28ae8", "#ffffff"
            elif design == "light":
                accent, border, fg = "#d7e9fa", "#6f9fc9", "#163d62"
            elif design == "graphite":
                accent, border, fg = "#245da0", "#78b7ff", "#ffffff"
            elif design == "ocean":
                accent, border, fg = "#008c9e", "#4bb4c5", "#ffffff"
            else:
                accent, border, fg = "#1769aa", "#5fa8e8", "#ffffff"
            self.new_tab_button.setStyleSheet(f"font-size: 21px; font-weight: bold; color: {fg}; background: {accent}; border: 1px solid {border}; border-radius: 5px; margin: 1px;")

    def eventFilter(self, watched, event):
        if watched is self.tabs.tabBar() and event.type() in (QEvent.Type.Resize, QEvent.Type.Show, QEvent.Type.LayoutRequest):
            QTimer.singleShot(0, self.update_new_tab_button_position)
        return super().eventFilter(watched, event)

    def update_new_tab_button_position(self):
        """Place the + button immediately after the last visible tab."""
        if not hasattr(self, "tabs") or self.tabs.count() < 1:
            return
        bar = self.tabs.tabBar()
        last = bar.tabRect(self.tabs.count() - 1)
        x = last.right() + 3
        y = max(1, (bar.height() - self.new_tab_button.height()) // 2)
        # Avoid covering the tab bar's scroll controls when many tabs are open.
        x = min(x, max(0, bar.width() - self.new_tab_button.width() - 2))
        self.new_tab_button.move(x, y)
        self.new_tab_button.raise_()

    def set_shortcuts(self):
        for seq, callback in [
            ("Ctrl+L", lambda: (self.address.setFocus(), self.address.selectAll())),
            ("Ctrl+T", lambda: self.add_tab(self.settings_data["home"])),
            ("Ctrl+W", lambda: self.close_tab(self.tabs.currentIndex())),
            ("Ctrl+R", lambda: self.current_view() and self.current_view().reload()),
            ("Alt+Left", lambda: self.current_view() and self.current_view().back()),
            ("Alt+Right", lambda: self.current_view() and self.current_view().forward()),
        ]:
            action = QAction(self); action.setShortcut(QKeySequence(seq)); action.triggered.connect(callback)
            self.addAction(action)

    def tr(self, de, en):
        """Return the selected application language."""
        return en if self.settings_data.get("language", "de") == "en" else de

    def bookmark_display_title(self, item, root=False):
        """Return a language-aware title without changing saved bookmark data.

        Chromium may import the bookmarks-bar root with a localized name such as
        'Lesezeichenleiste'.  That name is data from the source browser, not a
        fixed LunaSurfer UI translation.  Only the top-level special folder is
        given the current application's display name; normal user folders keep
        their saved names.
        """
        title = (item.get("title") or item.get("url") or self.tr("Ordner", "Folder")).strip()
        if root and (item.get("type") == "folder" or "children" in item):
            normalized = " ".join(title.casefold().split())
            bookmark_bar_names = {
                "lesezeichenleiste", "bookmarks bar", "bookmark bar",
                "bookmarks toolbar", "bookmarks bar folder"
            }
            if normalized in bookmark_bar_names:
                return self.tr("Lesezeichenleiste", "Bookmarks bar")
        return title


    def apply_language_live(self):
        """Update visible application texts immediately after a language change."""
        self.back_action.setToolTip(self.tr("Zurück", "Back"))
        self.forward_action.setToolTip(self.tr("Vorwärts", "Forward"))
        self.reload_action.setToolTip(self.tr("Neu laden", "Reload"))
        self.home_action.setToolTip(self.tr("Startseite", "Home"))
        self.star_action.setToolTip(self.tr("Aktuelle Seite als Lesezeichen hinzufügen", "Add current page to bookmarks"))
        self.download_action.setToolTip(self.tr("Download-Manager", "Download manager"))
        self.adblock_action.setToolTip(self.tr("Werbeblocker", "Ad blocker"))
        self.newtab_action.setToolTip(self.tr("Neuer Tab", "New tab"))
        self.new_tab_button.setToolTip(self.tr("Neuer Tab", "New tab"))
        self.address.setPlaceholderText(self.tr("Adresse oder Suchbegriff eingeben", "Enter address or search"))
        self.bookmarks_bar.setWindowTitle(self.tr("Lesezeichenleiste", "Bookmarks bar"))
        self.statusBar().showMessage(self.tr("Bereit", "Ready"), 3000)
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) in ("Neuer Tab", "New tab"):
                self.tabs.setTabText(i, self.tr("Neuer Tab", "New tab"))
        # Rebuild the popup menu so all menu entries are translated as well.
        menu = QMenu(self.tr("Menü", "Menu"), self)
        menu.addAction(self.tr("Neuer Tab", "New tab"), lambda: self.add_tab(self.settings_data["home"]))
        menu.addAction(self.tr("Lesezeichen", "Bookmarks"), self.show_bookmarks)
        menu.addAction(self.tr("Verlauf", "History"), self.show_history)
        menu.addAction(self.tr("Downloads-Ordner öffnen", "Open downloads folder"), self.open_downloads)
        menu.addSeparator()
        menu.addAction(self.tr("Einstellungen", "Settings"), self.show_settings)
        menu.addAction(self.tr("Über LunaSurfer", "About LunaSurfer"), self.about)
        menu.addSeparator()
        menu.addAction(self.tr("Beenden", "Quit"), self.close)
        self.menu_button.setMenu(menu)
        self.menu_button.setToolTip(self.tr("Menü", "Menu"))
        # The bookmarks toolbar contains dynamically created actions, including
        # the permanent "Manage bookmarks" button. Rebuild it immediately so
        # its texts follow a language change without requiring a restart.
        self.refresh_bookmarks_bar()

    def enter_web_fullscreen(self):
        if self._web_fullscreen:
            return
        self._was_maximized_before_fullscreen = self.isMaximized()
        self._web_fullscreen = True

        # Explicitly hide LunaSurfer's chrome as well.  This is important on
        # desktop/window-manager combinations where showFullScreen() alone is
        # delayed while a WebEngine fullscreen request is being processed.
        # Hide every piece of LunaSurfer chrome, including the navigation toolbar.
        chrome = [self.menuBar(), self.navigation_bar, self.tabs.tabBar(), self.new_tab_button, self.bookmarks_bar, self.statusBar()]
        self._fullscreen_chrome = [(widget, widget.isVisible()) for widget in chrome if widget is not None]
        for widget, _visible in self._fullscreen_chrome:
            widget.hide()

        self.showFullScreen()
        QTimer.singleShot(0, self.showFullScreen)

    def leave_web_fullscreen(self):
        if not self._web_fullscreen:
            return
        self._web_fullscreen = False
        if self._was_maximized_before_fullscreen:
            self.showMaximized()
        else:
            self.showNormal()
        for widget, was_visible in self._fullscreen_chrome:
            if was_visible:
                widget.show()
        self._fullscreen_chrome = []

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape and self._web_fullscreen:
            self.leave_web_fullscreen()
            event.accept()
            return
        super().keyPressEvent(event)

    def current_view(self):
        w = self.tabs.currentWidget()
        return w if isinstance(w, BrowserView) else None

    def add_tab(self, url=None, switch=True):
        view = BrowserView(self)
        page = QWebEnginePage(self.profile, view)
        view.setPage(page)
        view.configure_web_page()
        self.apply_page_theme(view)
        self.apply_font_size(view)
        self.apply_font_size(view)
        index = self.tabs.addTab(view, self.tr("Neuer Tab", "New tab"))
        if switch: self.tabs.setCurrentIndex(index)
        view.load(QUrl(url or self.settings_data.get("home", "https://duckduckgo.com")))
        return view

    def apply_page_theme(self, view):
        """Apply the selected light/dark appearance to a web page."""
        settings = view.page().settings()
        force_dark = getattr(QWebEngineSettings.WebAttribute, "ForceDarkMode", None)
        if force_dark is not None:
            settings.setAttribute(force_dark, self.settings_data.get("theme", "dark") == "dark")

    def apply_font_size(self, view):
        # Apply both WebEngine's font defaults and a visible page scale. Many
        # modern websites define their own CSS font sizes, so DefaultFontSize
        # alone often has no visible effect.
        sizes = {"Klein": 13, "Mittel": 16, "Groß": 19, "Sehr groß": 22}
        scales = {"Klein": 0.90, "Mittel": 1.00, "Groß": 1.15, "Sehr groß": 1.30}
        selected = self.settings_data.get("font_size", "Mittel")
        size = sizes.get(selected, 16)
        view.page().settings().setFontSize(QWebEngineSettings.FontSize.DefaultFontSize, size)
        view.page().settings().setFontSize(QWebEngineSettings.FontSize.DefaultFixedFontSize, size)
        base_zoom = int(self.settings_data.get("default_zoom", 100)) / 100.0
        view.setZoomFactor(base_zoom * scales.get(selected, 1.0))

    def enforce_font_size(self, view):
        # Keep the selected size active after a page has finished loading.
        self.apply_font_size(view)

    def apply_theme_to_all_tabs(self):
        for index in range(self.tabs.count()):
            view = self.tabs.widget(index)
            if isinstance(view, BrowserView):
                self.apply_page_theme(view)
                self.apply_font_size(view)
                view.reload()

    def close_tab(self, index):
        if self.tabs.count() > 1 and self.settings_data.get("confirm_close_multiple_tabs", True):
            answer = QMessageBox.question(self, "Tab schließen", "Möchtest du diesen Tab wirklich schließen?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
        if self.tabs.count() <= 1:
            self.add_tab(self.settings_data.get("home"))
        widget = self.tabs.widget(index)
        self.tabs.removeTab(index)
        if widget: widget.deleteLater()
        QTimer.singleShot(0, self.update_new_tab_button_position)

    def update_tab_title(self, view, title):
        index = self.tabs.indexOf(view)
        if index >= 0:
            self.tabs.setTabText(index, (title or self.tr("Neuer Tab", "New tab"))[:24])
            # A changed page title can make the last tab wider. Recalculate the
            # position after Qt has completed the tab-bar layout, so the + button
            # always follows the actual right edge of the last tab.
            QTimer.singleShot(0, self.update_new_tab_button_position)
            QTimer.singleShot(50, self.update_new_tab_button_position)

    def on_tab_changed(self, index):
        view = self.current_view()
        if view:
            self.address.setText(view.url().toString())
            self.update_navigation()
        elif index >= 0:
            self.address.setText("lunasurfer://settings")
            self.back_action.setEnabled(False)
            self.forward_action.setEnabled(False)

    def update_navigation(self):
        view = self.current_view()
        if view:
            self.back_action.setEnabled(view.history().canGoBack())
            self.forward_action.setEnabled(view.history().canGoForward())

    def navigate(self):
        text = self.address.text().strip()
        if not text: return
        parsed = urllib.parse.urlparse(text)
        if parsed.scheme in ("http", "https"):
            url = text
        elif " " not in text and "." in text:
            url = "https://" + text
        else:
            url = self.settings_data.get("search", "https://duckduckgo.com/?q={}").format(urllib.parse.quote_plus(text))
        view = self.current_view()
        if view: view.load(QUrl(url))

    def go_home(self):
        view = self.current_view()
        if view: view.load(QUrl(self.settings_data.get("home", "https://duckduckgo.com")))

    def add_bookmark(self):
        view = self.current_view()
        if not view: return
        url = view.url().toString()
        if not url: return
        items = read_json(BOOKMARKS_FILE, [])
        if not any(x.get("url") == url for x in items):
            items.append({"title": view.title() or url, "url": url})
            write_json(BOOKMARKS_FILE, items)
        self.refresh_bookmarks_bar()
        self.statusBar().showMessage("Lesezeichen gespeichert", 3000)

    def refresh_bookmarks_bar(self):
        """Build a responsive bookmarks bar with a clean overflow menu."""
        if not hasattr(self, "bookmarks_bar"):
            return
        self.bookmarks_bar.clear()
        items = read_json(BOOKMARKS_FILE, [])
        style = QApplication.style()

        # Reserve space for the permanent management button and the overflow
        # button.  Entries are never squeezed into unreadable widths.
        available = max(180, self.bookmarks_bar.width() - 230)
        used = 0
        visible, overflow = [], []

        def entry_width(item):
            title = self.bookmark_display_title(item, root=True)
            return max(88, min(220, self.fontMetrics().horizontalAdvance(title) + 42))

        for item in items:
            width = entry_width(item)
            if used + width <= available or not visible:
                visible.append(item)
                used += width
            else:
                overflow.append(item)

        def add_menu_entries(menu, entries):
            for item in entries:
                if item.get("type") == "folder" or "children" in item:
                    sub = menu.addMenu((item.get("title") or "Ordner").strip())
                    add_menu_entries(sub, item.get("children", []))
                else:
                    url = item.get("url", "").strip()
                    if url:
                        title = (item.get("title") or url).strip()
                        action = menu.addAction(title)
                        action.setToolTip(url)
                        action.triggered.connect(lambda checked=False, u=url: self.open_bookmark(u))

        def add_visible(item):
            if item.get("type") == "folder" or "children" in item:
                title = self.bookmark_display_title(item, root=True)
                menu = QMenu(title, self)
                add_menu_entries(menu, item.get("children", []))
                button = QToolButton(self.bookmarks_bar)
                button.setText(title)
                button.setMenu(menu)
                button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
                button.setMinimumWidth(88)
                button.setMaximumWidth(220)
                self.bookmarks_bar.addWidget(button)
            else:
                url = item.get("url", "").strip()
                if not url:
                    return
                title = (item.get("title") or url).strip()
                action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload), title, self)
                action.setToolTip(url)
                action.triggered.connect(lambda checked=False, u=url: self.open_bookmark(u))
                self.bookmarks_bar.addAction(action)
                button = self.bookmarks_bar.widgetForAction(action)
                if button is not None:
                    button.setMinimumWidth(88)
                    button.setMaximumWidth(220)
                    button.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
                    button.customContextMenuRequested.connect(lambda pos, u=url, b=button: self.show_bookmark_context_menu(u, b.mapToGlobal(pos)))

        for item in visible:
            add_visible(item)

        if overflow:
            more_menu = QMenu(self.tr("Weitere Lesezeichen", "More bookmarks"), self)
            add_menu_entries(more_menu, overflow)
            more_button = QToolButton(self.bookmarks_bar)
            more_button.setText(self.tr("» Weitere", "» More"))
            more_button.setToolTip(self.tr("Weitere Lesezeichen anzeigen", "Show more bookmarks"))
            more_button.setMenu(more_menu)
            more_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
            self.bookmarks_bar.addWidget(more_button)

        # Flexible spacer keeps the management action anchored at the right.
        spacer = QWidget(self.bookmarks_bar)
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.bookmarks_bar.addWidget(spacer)
        manage = QAction(self.tr("Lesezeichen verwalten", "Manage bookmarks"), self)
        manage.setToolTip(self.tr("Lesezeichen anzeigen und verwalten", "View and manage bookmarks"))
        manage.triggered.connect(self.show_bookmarks)
        self.bookmarks_bar.addAction(manage)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "_bookmark_resize_timer"):
            self._bookmark_resize_timer.start(120)

    def open_bookmark(self, url):
        view = self.current_view()
        if view:
            view.load(QUrl(url))

    def show_bookmark_context_menu(self, url, global_pos):
        """Right-click menu for bookmarks in the bookmarks bar."""
        menu = QMenu(self)
        open_action = menu.addAction(self.tr("Öffnen", "Open"))
        edit_action = menu.addAction(self.tr("Lesezeichen bearbeiten…", "Edit bookmark…"))
        delete_action = menu.addAction(self.tr("Lesezeichen löschen", "Delete bookmark"))
        selected = menu.exec(global_pos)
        if selected == open_action:
            self.open_bookmark(url)
        elif selected == edit_action:
            self.edit_bookmark(url)
        elif selected == delete_action:
            self.delete_bookmark(url)

    def edit_bookmark(self, old_url):
        items = read_json(BOOKMARKS_FILE, [])
        item = next((x for x in items if x.get("url") == old_url), None)
        if item is None:
            return
        title, ok = QInputDialog.getText(self, self.tr("Lesezeichen bearbeiten", "Edit bookmark"), self.tr("Name:", "Name:"), text=item.get("title", ""))
        if not ok:
            return
        url, ok = QInputDialog.getText(self, self.tr("Lesezeichen bearbeiten", "Edit bookmark"), self.tr("Adresse:", "Address:"), text=item.get("url", ""))
        if not ok or not url.strip():
            return
        item["title"] = title.strip() or url.strip()
        item["url"] = url.strip()
        write_json(BOOKMARKS_FILE, items)
        self.refresh_bookmarks_bar()
        self.statusBar().showMessage(self.tr("Lesezeichen geändert", "Bookmark changed"), 3000)

    def delete_bookmark(self, url):
        answer = QMessageBox.question(
            self, self.tr("Lesezeichen löschen", "Delete bookmark"), self.tr("Dieses Lesezeichen wirklich löschen?", "Really delete this bookmark?"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        items = [x for x in read_json(BOOKMARKS_FILE, []) if x.get("url") != url]
        write_json(BOOKMARKS_FILE, items)
        self.refresh_bookmarks_bar()
        self.statusBar().showMessage(self.tr("Lesezeichen gelöscht", "Bookmark deleted"), 3000)

    def show_list_dialog(self, title, path, key):
        dialog = QDialog(self); dialog.setWindowTitle(title); dialog.resize(720, 500)
        layout = QVBoxLayout(dialog)
        items = read_json(path, [])
        for item in items[:300]:
            label = item.get("title", "") + "   —   " + item.get(key, "")
            btn = QPushButton(label); btn.setToolTip(item.get(key, ""))
            btn.clicked.connect(lambda checked=False, u=item.get(key, ""): (self.current_view().load(QUrl(u)) if self.current_view() else None, dialog.accept()))
            layout.addWidget(btn)
        layout.addStretch(1)
        dialog.exec()

    def show_bookmarks(self):
        """Open a searchable, collapsible bookmark manager."""
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("Lesezeichen verwalten", "Manage bookmarks"))
        dialog.resize(940, 650)
        dialog.setMinimumSize(720, 480)
        dialog.setStyleSheet("""
            QDialog { background: #171b23; color: #edf2f8; }
            QLabel { color: #edf2f8; }
            QLineEdit {
                background: #222a36; border: 1px solid #3d4a5e;
                border-radius: 9px; padding: 10px 12px; color: #f4f7fb;
                selection-background-color: #7544b8;
            }
            QTreeWidget {
                background: #1d2430; alternate-background-color: #222b39;
                color: #e8edf5; border: 1px solid #354155;
                border-radius: 10px; padding: 7px;
                outline: 0; selection-background-color: #57358b;
                selection-color: #ffffff;
            }
            QTreeWidget::item { min-height: 30px; padding: 4px 6px; }
            QTreeWidget::item:hover { background: #303b4c; }
            QHeaderView::section {
                background: #252f3e; color: #cbd5e2; border: 0;
                border-bottom: 1px solid #3d4a5e; padding: 9px 8px;
                font-weight: 600;
            }
            QPushButton {
                background: #293548; border: 1px solid #40516a;
                border-radius: 8px; padding: 8px 13px; color: #edf2f8;
            }
            QPushButton:hover { background: #3b4b63; border-color: #7188a8; }
            QPushButton:disabled { color: #778395; background: #202733; border-color: #2c3542; }
            QPushButton#primary { background: #7042aa; border-color: #8b5bc7; font-weight: 600; }
            QPushButton#primary:hover { background: #8252bd; }
        """)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(16, 16, 16, 14)
        layout.setSpacing(11)

        heading = QLabel(self.tr("Deine Lesezeichen", "Your bookmarks"))
        heading.setStyleSheet("font-size: 18px; font-weight: 700; color: #ffffff;")
        layout.addWidget(heading)
        subtitle = QLabel(self.tr("Ordner aufklappen, Einträge suchen und direkt verwalten.", "Expand folders, search entries and manage them directly."))
        subtitle.setStyleSheet("color: #aab6c7;")
        layout.addWidget(subtitle)

        search_row = QHBoxLayout()
        search = QLineEdit()
        search.setPlaceholderText(self.tr("Lesezeichen oder Adresse suchen …", "Search bookmarks or addresses …"))
        search.setClearButtonEnabled(True)
        count_label = QLabel()
        count_label.setMinimumWidth(110)
        count_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        count_label.setStyleSheet("color: #aab6c7; font-weight: 600;")
        search_row.addWidget(search, 1)
        search_row.addWidget(count_label)
        layout.addLayout(search_row)

        bookmark_tree = QTreeWidget()
        bookmark_tree.setColumnCount(2)
        bookmark_tree.setHeaderLabels([self.tr("Name", "Name"), self.tr("Adresse", "Address")])
        bookmark_tree.setAlternatingRowColors(True)
        bookmark_tree.setUniformRowHeights(True)
        bookmark_tree.setRootIsDecorated(True)
        bookmark_tree.setIndentation(22)
        bookmark_tree.setSortingEnabled(False)
        bookmark_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        bookmark_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        bookmark_tree.setColumnWidth(0, 330)
        bookmark_tree.setSelectionBehavior(QTreeWidget.SelectionBehavior.SelectRows)
        bookmark_tree.setEditTriggers(QTreeWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(bookmark_tree, 1)

        buttons = QHBoxLayout()
        open_btn = QPushButton(self.tr("Öffnen", "Open")); open_btn.setObjectName("primary")
        edit_btn = QPushButton(self.tr("Bearbeiten…", "Edit…"))
        delete_btn = QPushButton(self.tr("Löschen", "Delete"))
        import_btn = QPushButton(self.tr("Importieren…", "Import…"))
        export_btn = QPushButton(self.tr("Exportieren…", "Export…"))
        close_btn = QPushButton(self.tr("Schließen", "Close"))
        for button in (open_btn, edit_btn, delete_btn): buttons.addWidget(button)
        buttons.addSpacing(8)
        buttons.addWidget(import_btn); buttons.addWidget(export_btn)
        buttons.addStretch(1); buttons.addWidget(close_btn)
        layout.addLayout(buttons)

        def populate():
            bookmark_tree.clear()
            total = 0
            def add_item(parent, item, root=False, path=()):
                nonlocal total
                if not isinstance(item, dict):
                    return
                is_folder = item.get("type") == "folder" or "children" in item
                title = self.bookmark_display_title(item, root=root) if is_folder else (str(item.get("title") or item.get("url") or "").strip())
                node = QTreeWidgetItem(parent, [title, "" if is_folder else str(item.get("url", "")).strip()])
                node.setData(0, Qt.ItemDataRole.UserRole, "" if is_folder else str(item.get("url", "")).strip())
                node.setData(0, Qt.ItemDataRole.UserRole + 1, "folder" if is_folder else "bookmark")
                node.setData(0, Qt.ItemDataRole.UserRole + 2, tuple(path))
                if is_folder:
                    node.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
                    for index, child in enumerate(item.get("children", [])):
                        add_item(node, child, False, tuple(path) + (index,))
                else:
                    node.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileLinkIcon))
                    total += 1
            for index, entry in enumerate(read_json(BOOKMARKS_FILE, [])):
                add_item(bookmark_tree.invisibleRootItem(), entry, True, (index,))
            count_label.setText(self.tr(f"{total} Einträge", f"{total} items"))
            bookmark_tree.expandAll()
            apply_filter()

        def apply_filter(_text=None):
            needle = search.text().casefold().strip()
            visible_count = 0
            def visit(node):
                nonlocal visible_count
                own = needle in node.text(0).casefold() or needle in node.text(1).casefold()
                child_match = False
                for i in range(node.childCount()):
                    if visit(node.child(i)):
                        child_match = True
                visible = not needle or own or child_match
                node.setHidden(not visible)
                if visible and node.data(0, Qt.ItemDataRole.UserRole + 1) == "bookmark":
                    visible_count += 1
                if needle and child_match:
                    node.setExpanded(True)
                return visible
            root = bookmark_tree.invisibleRootItem()
            for i in range(root.childCount()): visit(root.child(i))
            if needle:
                count_label.setText(self.tr(f"{visible_count} Treffer", f"{visible_count} matches"))
            else:
                count_label.setText(self.tr(f"{visible_count} Einträge", f"{visible_count} items"))

        def selected_node():
            items = bookmark_tree.selectedItems()
            return items[0] if items else None

        def selected_url():
            node = selected_node()
            return node.data(0, Qt.ItemDataRole.UserRole) if node else ""

        def do_open():
            url = selected_url()
            if url:
                self.open_bookmark(url)

        def do_edit():
            url = selected_url()
            if url:
                self.edit_bookmark(url)
                populate()

        def do_delete():
            node = selected_node()
            if not node:
                return
            path = node.data(0, Qt.ItemDataRole.UserRole + 2)
            if path is None:
                return
            kind = node.data(0, Qt.ItemDataRole.UserRole + 1)
            if kind == "folder":
                answer = QMessageBox.question(
                    dialog, self.tr("Ordner löschen", "Delete folder"),
                    self.tr("Diesen Ordner und alle enthaltenen Lesezeichen wirklich löschen?", "Really delete this folder and all bookmarks inside it?"),
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No)
                if answer != QMessageBox.StandardButton.Yes:
                    return
                items = read_json(BOOKMARKS_FILE, [])
                try:
                    parent = items
                    for index in tuple(path)[:-1]:
                        parent = parent[index].setdefault("children", [])
                    del parent[tuple(path)[-1]]
                    write_json(BOOKMARKS_FILE, items)
                    self.refresh_bookmarks_bar(); populate()
                    self.statusBar().showMessage(self.tr("Ordner gelöscht", "Folder deleted"), 3000)
                except (IndexError, KeyError, TypeError):
                    QMessageBox.warning(dialog, self.tr("Fehler", "Error"), self.tr("Der Ordner konnte nicht gelöscht werden.", "The folder could not be deleted."))
            else:
                url = selected_url()
                if url:
                    self.delete_bookmark(url); populate()

        def do_export():
            filename, _ = QFileDialog.getSaveFileName(dialog, self.tr("Lesezeichen exportieren", "Export bookmarks"), str(pathlib.Path.home() / "LunaSurfer-Lesezeichen.html"), "HTML-Dateien (*.html *.htm)")
            if not filename: return
            def export_entries(entries, depth=0):
                rows = []
                for entry in entries if isinstance(entries, list) else []:
                    if not isinstance(entry, dict): continue
                    title = str(entry.get("title") or "").strip()
                    url = str(entry.get("url") or "").strip()
                    children = entry.get("children", [])
                    if entry.get("type") == "folder" or "children" in entry:
                        rows.append("    " * depth + f"<DT><H3>{escape(title)}</H3>")
                        rows.append("    " * depth + "<DL><p>")
                        rows.extend(export_entries(children, depth + 1))
                        rows.append("    " * depth + "</DL><p>")
                    elif url:
                        rows.append("    " * depth + f'<DT><A HREF="{escape(url, quote=True)}">{escape(title or url)}</A>')
                return rows
            content = "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n<TITLE>Bookmarks</TITLE>\n<H1>Bookmarks</H1>\n<DL><p>\n" + "\n".join(export_entries(read_json(BOOKMARKS_FILE, []))) + "\n</DL><p>\n"
            try:
                pathlib.Path(filename).write_text(content, encoding="utf-8")
                self.statusBar().showMessage(self.tr("Lesezeichen exportiert", "Bookmarks exported"), 4000)
                QMessageBox.information(dialog, self.tr("Export", "Export"), self.tr("Die Lesezeichen wurden einschließlich Ordnerstruktur exportiert.", "Bookmarks were exported, including their folder structure."))
            except Exception as exc:
                QMessageBox.warning(dialog, self.tr("Export fehlgeschlagen", "Export failed"), str(exc))

        def do_import():
            filename, _ = QFileDialog.getOpenFileName(dialog, self.tr("Lesezeichen importieren", "Import bookmarks"), str(pathlib.Path.home()), "HTML-Dateien (*.html *.htm)")
            if not filename: return
            try:
                parser = ChromiumBookmarksParser()
                parser.feed(pathlib.Path(filename).read_text(encoding="utf-8", errors="replace"))
                imported = parser.items
                if not imported:
                    QMessageBox.warning(dialog, "Import", self.tr("Keine Lesezeichen in der ausgewählten Datei gefunden.", "No bookmarks found in the selected file.")); return
                answer = QMessageBox.question(dialog, self.tr("Lesezeichen importieren", "Import bookmarks"), f"{len(imported)} Lesezeichen gefunden.\n\nJa: vorhandene Lesezeichen ersetzen\nNein: zu vorhandenen Lesezeichen hinzufügen", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.No)
                if answer == QMessageBox.StandardButton.Cancel: return
                if answer == QMessageBox.StandardButton.Yes:
                    result = imported
                else:
                    result = read_json(BOOKMARKS_FILE, [])
                    existing_urls = set()
                    def collect_urls(entries):
                        for entry in entries if isinstance(entries, list) else []:
                            if not isinstance(entry, dict): continue
                            url = str(entry.get("url", "")).strip()
                            if url: existing_urls.add(url)
                            collect_urls(entry.get("children", []))
                    collect_urls(result)
                    def merge_entries(entries):
                        merged = []
                        for entry in entries if isinstance(entries, list) else []:
                            if not isinstance(entry, dict): continue
                            if entry.get("type") == "folder" or "children" in entry:
                                folder = dict(entry); folder["children"] = merge_entries(entry.get("children", [])); merged.append(folder)
                            else:
                                url = str(entry.get("url", "")).strip()
                                if url and url not in existing_urls:
                                    existing_urls.add(url); merged.append(entry)
                        return merged
                    bookmark_bar_names = {"lesezeichenleiste", "bookmarks bar", "bookmark bar", "bookmarks toolbar", "bookmarks bar folder"}
                    def is_bookmarks_bar(entry):
                        if not isinstance(entry, dict) or not (entry.get("type") == "folder" or "children" in entry): return False
                        return " ".join(str(entry.get("title", "")).casefold().split()) in bookmark_bar_names
                    merged_import = merge_entries(imported)
                    existing_bar = next((entry for entry in result if is_bookmarks_bar(entry)), None)
                    for entry in merged_import:
                        if is_bookmarks_bar(entry):
                            if existing_bar is None:
                                result.insert(0, entry); existing_bar = entry
                            else:
                                existing_bar.setdefault("children", []).extend(entry.get("children", []))
                        else:
                            result.append(entry)
                write_json(BOOKMARKS_FILE, result)
                self.refresh_bookmarks_bar(); populate()
                self.statusBar().showMessage(self.tr("Lesezeichen importiert", "Bookmarks imported"), 4000)
                QMessageBox.information(dialog, self.tr("Import", "Import"), self.tr(f"{len(imported)} Lesezeichen wurden importiert.", f"{len(imported)} bookmark folders/items were imported."))
            except Exception as exc:
                QMessageBox.warning(dialog, self.tr("Import fehlgeschlagen", "Import failed"), str(exc))

        open_btn.clicked.connect(do_open)
        edit_btn.clicked.connect(do_edit)
        delete_btn.clicked.connect(do_delete)
        import_btn.clicked.connect(do_import)
        export_btn.clicked.connect(do_export)
        close_btn.clicked.connect(dialog.accept)
        search.textChanged.connect(apply_filter)
        bookmark_tree.itemDoubleClicked.connect(lambda item, column: (bookmark_tree.setExpanded(item, not item.isExpanded()) if item.data(0, Qt.ItemDataRole.UserRole + 1) == "folder" else do_open()))
        populate()
        dialog.exec()

    def show_history(self): self.show_list_dialog(self.tr("Verlauf", "History"), HISTORY_FILE, "url")

    def update_adblock_button(self):
        enabled = self.settings_data.get("adblock_enabled", True)
        self.adblock_button.setText("🛡" if enabled else "⊘")
        self.adblock_button.setToolTip(self.tr("Werbeblocker aktiv – klicken für Einstellungen", "Ad blocker active – click for settings") if enabled else self.tr("Werbeblocker deaktiviert – klicken für Einstellungen", "Ad blocker disabled – click for settings"))

    def show_adblock_settings(self):
        dialog = QDialog(self); dialog.setWindowTitle(self.tr("Werbeblocker", "Ad blocker")); dialog.resize(520, 360)
        layout = QVBoxLayout(dialog)
        enabled = QCheckBox(self.tr("Werbeblocker aktivieren", "Enable ad blocker")); enabled.setChecked(self.settings_data.get("adblock_enabled", True)); layout.addWidget(enabled)
        layout.addWidget(QLabel(self.tr("Blockierstärke:", "Blocking strength:")))
        strength = QComboBox(); strength.addItem(self.tr("Standard", "Standard"), "standard"); strength.addItem(self.tr("Stark", "Strong"), "strong"); strength.addItem(self.tr("Sehr stark", "Very strong"), "very_strong"); strength.addItem(self.tr("Super stark", "Super strong"), "super_strong"); strength.addItem(self.tr("Mega stark", "Mega strong"), "mega_strong")
        current_strength = self.settings_data.get("adblock_strength", "standard"); strength.setCurrentIndex(max(0, strength.findData(current_strength))); layout.addWidget(strength)
        layout.addWidget(QLabel(self.tr("Eigene Blockiermuster (eine Domain oder ein Muster pro Zeile):", "Custom block patterns (one domain or pattern per line):")))
        patterns = QLineEdit("; ".join(self.settings_data.get("adblock_custom_blocklist", []))); patterns.setPlaceholderText("z. B. example-ads.com")
        layout.addWidget(patterns)
        layout.addWidget(QLabel(self.tr("Whitelist-Domains (mit Semikolon trennen):", "Whitelist domains (separate with semicolons):")))
        whitelist = QLineEdit("; ".join(self.settings_data.get("adblock_whitelist", []))); layout.addWidget(whitelist)
        info = QLabel(self.tr("Der integrierte Blocker filtert bekannte Werbe- und Tracking-Domains. Super stark blockiert zusätzlich eine breitere Auswahl an Werbe-, Analyse- und Tracking-Endpunkten. Mega stark ist für gezielte maximale Blockierung gedacht und filtert zusätzlich URL-/Pfad-Muster für Werbung, Tracking, Telemetrie, Pixel und Attribution. Dadurch können einzelne Webseiten deutlich stärker beeinträchtigt werden. Änderungen gelten für neue Anfragen sofort.", "The built-in blocker filters known advertising and tracking domains. Super strong additionally blocks a broader selection of advertising, analytics and tracking endpoints. Mega strong is intended for targeted maximum blocking and additionally filters URL/path patterns for advertising, tracking, telemetry, pixels and attribution. This can affect individual websites much more strongly. Changes apply to new requests immediately.")); info.setWordWrap(True); layout.addWidget(info)
        buttons = QHBoxLayout(); save = QPushButton(self.tr("Speichern", "Save")); close = QPushButton(self.tr("Abbrechen", "Cancel")); buttons.addStretch(1); buttons.addWidget(save); buttons.addWidget(close); layout.addLayout(buttons)
        def do_save():
            self.settings_data["adblock_enabled"] = enabled.isChecked()
            self.settings_data["adblock_strength"] = strength.currentData()
            self.settings_data["adblock_custom_blocklist"] = [x.strip() for x in patterns.text().split(";") if x.strip()]
            self.settings_data["adblock_whitelist"] = [x.strip() for x in whitelist.text().split(";") if x.strip()]
            write_json(CONFIG_FILE, self.settings_data); self.update_adblock_button(); dialog.accept()
        save.clicked.connect(do_save); close.clicked.connect(dialog.reject); dialog.exec()

    def load_download_history(self):
        """Restore completed downloads from ~/.local/share/lunasurfer/downloads.json."""
        records = read_json(DOWNLOADS_FILE, [])
        if not isinstance(records, list):
            records = []
        for record in records:
            if not isinstance(record, dict) or not record.get("target"):
                continue
            target = pathlib.Path(record["target"]).expanduser()
            stored = dict(record)
            self.download_items.append({
                "download": StoredDownload(stored), "target": target,
                "last_bytes": int(stored.get("received", 0) or 0),
                "last_time": time.monotonic(), "speed": 0, "stored": True,
                "downloaded_at": stored.get("downloaded_at", "")
            })

    def save_download_history(self):
        """Persist completed downloads only; never serialize live Qt objects."""
        records = []
        for item in self.download_items:
            download = item.get("download")
            if not download or not download.isFinished():
                continue
            target = item.get("target")
            if not target:
                continue
            received = int(getattr(download, "receivedBytes", lambda: 0)() or 0)
            total = int(getattr(download, "totalBytes", lambda: 0)() or received)
            records.append({
                "target": str(target), "received": received, "total": total,
                "downloaded_at": item.get("downloaded_at") or time.strftime("%Y-%m-%d %H:%M:%S")
            })
        write_json(DOWNLOADS_FILE, records)

    def show_download_manager(self):
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("Download-Manager", "Download Manager"))
        dialog.resize(980, 650)
        dialog.setMinimumSize(760, 500)
        dialog.setStyleSheet("""
            QDialog { background: #171b23; color: #edf2f8; }
            QLabel { color: #edf2f8; }
            QPushButton {
                background: #293342; border: 1px solid #3b485b;
                border-radius: 8px; padding: 8px 13px; color: #edf2f8;
            }
            QPushButton:hover { background: #354357; border-color: #58708d; }
            QPushButton:disabled { color: #778395; background: #202733; border-color: #2c3542; }
            QLineEdit {
                background: #202733; border: 1px solid #39475a;
                border-radius: 9px; padding: 9px 12px; color: #ffffff;
                selection-background-color: #287fc1;
            }
            QLineEdit:focus { border: 1px solid #399de5; }
            QComboBox {
                background: #202733; border: 1px solid #39475a;
                border-radius: 9px; padding: 8px 12px; color: #ffffff;
            }
            QComboBox QAbstractItemView {
                background: #202733; color: #ffffff; selection-background-color: #287fc1;
            }
            QListWidget { background: transparent; border: 0; outline: 0; }
            QProgressBar {
                border: 0; background: #354153; border-radius: 5px;
                min-height: 9px; max-height: 9px; text-align: center;
            }
            QProgressBar::chunk { background: #299be8; border-radius: 5px; }
        """)

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(13)

        # Header
        title_row = QHBoxLayout()
        icon = QLabel("↓")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setFixedSize(46, 46)
        icon.setStyleSheet("background:#173b59; color:#55b8ff; border-radius:13px; font-size:27px; font-weight:700;")
        title_col = QVBoxLayout()
        title = QLabel(self.tr("Downloads", "Downloads"))
        title.setStyleSheet("font-size:23px; font-weight:700;")
        subtitle = QLabel(self.tr("Alle laufenden und abgeschlossenen Dateien an einem Ort.",
                                  "All active and completed files in one place."))
        subtitle.setStyleSheet("color:#9eabba; font-size:12px;")
        title_col.addWidget(title); title_col.addWidget(subtitle)
        title_row.addWidget(icon); title_row.addSpacing(5); title_row.addLayout(title_col); title_row.addStretch(1)
        layout.addLayout(title_row)

        # Live overview
        stats_row = QHBoxLayout()
        stats_row.setSpacing(9)
        stat_active = QLabel()
        stat_finished = QLabel()
        stat_total = QLabel()
        for label in (stat_active, stat_finished, stat_total):
            label.setMinimumHeight(34)
            label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            label.setStyleSheet("background:#202733; border:1px solid #303c4d; border-radius:8px; padding:6px 11px; color:#cbd5e1; font-weight:600;")
            stats_row.addWidget(label)
        stats_row.addStretch(1)
        layout.addLayout(stats_row)

        # Search and status filter
        top = QHBoxLayout()
        filter_box = QComboBox()
        filter_box.addItem(self.tr("Alle Downloads", "All downloads"), "all")
        filter_box.addItem(self.tr("Laufen", "In progress"), "active")
        filter_box.addItem(self.tr("Abgeschlossen", "Completed"), "finished")
        search = QLineEdit()
        search.setPlaceholderText(self.tr("Dateiname oder Pfad suchen …", "Search filename or path …"))
        search.setClearButtonEnabled(True)
        top.addWidget(filter_box)
        top.addWidget(search, 1)
        layout.addLayout(top)

        lst = QListWidget()
        lst.setSpacing(9)
        lst.setStyleSheet("QListWidget { background:transparent; border:0; outline:0; }")
        layout.addWidget(lst, 1)

        def fmt(n):
            units = ["B", "KB", "MB", "GB", "TB"]
            n = float(max(0, n)); i = 0
            while n >= 1024 and i < len(units) - 1:
                n /= 1024; i += 1
            return f"{n:.1f} {units[i]}"

        def actual_selected():
            qitem = lst.currentItem()
            if qitem is None:
                return None, -1
            idx = qitem.data(Qt.ItemDataRole.UserRole)
            return (self.download_items[idx], idx) if isinstance(idx, int) and 0 <= idx < len(self.download_items) else (None, -1)

        def update_row(item, now):
            """Update an existing download card without replacing its widget."""
            download = item["download"]
            received = getattr(download, "receivedBytes", lambda: 0)()
            total = getattr(download, "totalBytes", lambda: 0)()
            finished = download.isFinished()
            if not finished:
                last_bytes = item.get("last_bytes", received)
                last_time = item.get("last_time", now)
                dt = max(now - last_time, 0.001)
                speed = max(0, received - last_bytes) / dt
                item["speed"] = speed
                item["last_bytes"] = received
                item["last_time"] = now
            else:
                speed = 0

            percent = int(received * 100 / total) if total and total > 0 else (100 if finished else 0)
            ui = item.get("_download_ui")
            if ui is None:
                return
            ui["bar"].setValue(percent)
            if finished:
                ui["bar"].setStyleSheet(
                    "QProgressBar { background:#354153; border:0; border-radius:5px; min-height:9px; max-height:9px; } "
                    "QProgressBar::chunk { background:#26bd83; border-radius:5px; }"
                )
            else:
                ui["bar"].setStyleSheet(
                    "QProgressBar { background:#354153; border:0; border-radius:5px; min-height:9px; max-height:9px; } "
                    "QProgressBar::chunk { background:#279bd8; border-radius:5px; }"
                )
            details_text = f"{fmt(received)} / {fmt(total)}" if total and total > 0 else fmt(received)
            if not finished and speed > 0:
                details_text += f"   ·   {fmt(speed)}/s"
            elif item.get("downloaded_at"):
                details_text += f"   ·   {item['downloaded_at']}"
            ui["details"].setText(details_text)
            ui["state"].setText(self.tr("Fertig", "Completed") if finished else f"{percent} %")
            ui["state"].setStyleSheet(
                ("background:#153d32; color:#5ce0a8;" if finished else "background:#173954; color:#73c7ff;")
                + "border:0; border-radius:8px; padding:7px 9px; font-size:11px; font-weight:800;"
            )

        def make_row(item, now):
            target = item["target"]
            card = QWidget()
            card.setStyleSheet("QWidget#downloadCard { background:#202733; border:1px solid #303c4d; border-radius:12px; }")
            card.setObjectName("downloadCard")
            outer = QHBoxLayout(card)
            outer.setContentsMargins(14, 12, 14, 12)
            outer.setSpacing(13)

            suffix = target.suffix.lower().replace(".", "").upper() or "FILE"
            file_icon = QLabel(suffix[:4])
            file_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            file_icon.setFixedSize(48, 48)
            file_icon.setStyleSheet("background:#263f59; border:0; border-radius:10px; color:#8bd0ff; font-size:11px; font-weight:800;")
            outer.addWidget(file_icon)

            text_col = QVBoxLayout()
            text_col.setSpacing(4)
            name = QLabel(target.name)
            name.setToolTip(str(target))
            name.setStyleSheet("font-size:14px; font-weight:700; color:#f3f6fb; border:0;")
            name.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            path_label = QLabel(str(target.parent))
            path_label.setToolTip(str(target.parent))
            path_label.setStyleSheet("font-size:11px; color:#8f9daf; border:0;")
            path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            text_col.addWidget(name)
            text_col.addWidget(path_label)
            outer.addLayout(text_col, 2)

            progress_col = QVBoxLayout()
            progress_col.setSpacing(7)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setTextVisible(False)
            details = QLabel()
            details.setStyleSheet("font-size:11px; color:#aab6c5; border:0;")
            progress_col.addWidget(bar)
            progress_col.addWidget(details)
            outer.addLayout(progress_col, 2)

            state = QLabel()
            state.setAlignment(Qt.AlignmentFlag.AlignCenter)
            state.setMinimumWidth(88)
            outer.addWidget(state)
            item["_download_ui"] = {"bar": bar, "details": details, "state": state}
            update_row(item, now)
            return card

        def refresh():
            query = search.text().strip().casefold()
            mode = filter_box.currentData()
            now = time.monotonic()
            active_count = sum(not entry["download"].isFinished() for entry in self.download_items)
            finished_count = len(self.download_items) - active_count
            stat_active.setText("●  " + self.tr("Aktiv", "Active") + f"  {active_count}")
            stat_finished.setText("✓  " + self.tr("Fertig", "Completed") + f"  {finished_count}")
            stat_total.setText(self.tr("Gesamt", "Total") + f"  {len(self.download_items)}")

            visible = []
            for index, item in enumerate(self.download_items):
                finished = item["download"].isFinished()
                target = item["target"]
                searchable = (target.name + " " + str(target.parent)).casefold()
                if query and query not in searchable:
                    continue
                if mode == "active" and finished:
                    continue
                if mode == "finished" and not finished:
                    continue
                visible.append((index, item))

            # Keep the existing QListWidgetItems and card widgets while the
            # visible download set is unchanged. This preserves scroll position
            # and avoids flicker every time the 800 ms timer fires.
            current_indices = [
                lst.item(row).data(Qt.ItemDataRole.UserRole)
                for row in range(lst.count())
            ]
            wanted_indices = [index for index, _item in visible]
            if current_indices != wanted_indices:
                selected = actual_selected()
                selected_download = selected[0]["download"] if selected[0] else None
                scroll_value = lst.verticalScrollBar().value()
                lst.clear()
                for index, item in visible:
                    widget = make_row(item, now)
                    qitem = QListWidgetItem()
                    qitem.setData(Qt.ItemDataRole.UserRole, index)
                    qitem.setSizeHint(widget.sizeHint())
                    lst.addItem(qitem)
                    lst.setItemWidget(qitem, widget)
                    if selected_download is not None and item["download"] is selected_download:
                        lst.setCurrentItem(qitem)
                lst.verticalScrollBar().setValue(scroll_value)
            else:
                for row, (_index, item) in enumerate(visible):
                    update_row(item, now)

        def cancel_selected():
            item, _ = actual_selected()
            if item and not item["download"].isFinished():
                item["download"].cancel()
                refresh()

        def open_file():
            item, _ = actual_selected()
            if item and item["target"].exists():
                subprocess.Popen(["xdg-open", str(item["target"])])

        def open_folder_selected():
            item, _ = actual_selected()
            path = item["target"].parent if item else self.download_dir
            path.mkdir(parents=True, exist_ok=True)
            subprocess.Popen(["xdg-open", str(path)])

        def remove_entry():
            item, idx = actual_selected()
            if item is not None:
                self.download_items.pop(idx)
                self.save_download_history()
                refresh()

        def clear_history():
            self.download_items[:] = [entry for entry in self.download_items if not entry["download"].isFinished()]
            self.save_download_history()
            refresh()

        actions = QHBoxLayout()
        cancel = QPushButton(self.tr("Download abbrechen", "Cancel download"))
        open_btn = QPushButton(self.tr("Datei öffnen", "Open file"))
        folder = QPushButton(self.tr("Ordner öffnen", "Open folder"))
        remove = QPushButton(self.tr("Eintrag entfernen", "Remove entry"))
        clear = QPushButton(self.tr("Fertige löschen", "Clear completed"))
        close = QPushButton(self.tr("Schließen", "Close"))
        close.setStyleSheet("background:#087fce; border:1px solid #249ce9; font-weight:700;")
        for button in (cancel, open_btn, folder, remove, clear):
            actions.addWidget(button)
        actions.addStretch(1); actions.addWidget(close)
        layout.addLayout(actions)

        refresh()
        timer = QTimer(dialog)
        timer.timeout.connect(refresh)
        timer.start(800)
        search.textChanged.connect(refresh)
        filter_box.currentIndexChanged.connect(refresh)
        cancel.clicked.connect(cancel_selected)
        open_btn.clicked.connect(open_file)
        folder.clicked.connect(open_folder_selected)
        remove.clicked.connect(remove_entry)
        clear.clicked.connect(clear_history)
        close.clicked.connect(dialog.accept)
        dialog.exec()

    def on_download(self, download):
        suggested = download.suggestedFileName() or "download"
        if self.settings_data.get("ask_download_location", False):
            selected, _ = QFileDialog.getSaveFileName(self, "Download speichern unter", str(self.download_dir / suggested))
            if not selected:
                download.cancel()
                return
            target = pathlib.Path(selected)
            target.parent.mkdir(parents=True, exist_ok=True)
            download.setDownloadDirectory(str(target.parent))
            download.setDownloadFileName(target.name)
            download.accept()
            self.download_items.append({"download": download, "target": target, "last_bytes": 0, "last_time": time.monotonic(), "speed": 0})
            self.watch_download_finished(download, target)
            self.statusBar().showMessage(f"Download gestartet: {target.name}", 5000)
            return
        self.download_dir.mkdir(parents=True, exist_ok=True)
        target = self.download_dir / suggested
        if target.exists():
            stem, suffix = target.stem, target.suffix
            n = 1
            while (self.download_dir / f"{stem} ({n}){suffix}").exists(): n += 1
            target = self.download_dir / f"{stem} ({n}){suffix}"
        download.setDownloadDirectory(str(target.parent))
        download.setDownloadFileName(target.name)
        download.accept()
        self.download_items.append({"download": download, "target": target, "last_bytes": 0, "last_time": time.monotonic(), "speed": 0})
        self.watch_download_finished(download, target)
        self.statusBar().showMessage(f"Download gestartet: {target.name}", 5000)

    def watch_download_finished(self, download, target):
        """Show a small notification when a WebEngine download has finished."""
        def check_finished():
            if download.isFinished():
                for entry in self.download_items:
                    if entry.get("download") is download:
                        entry["downloaded_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                        break
                self.save_download_history()
                self.statusBar().showMessage(f"Download fertig: {target.name}", 8000)
                QMessageBox.information(
                    self,
                    "Download fertig",
                    f"Der Download wurde abgeschlossen:\n{target.name}\n\nGespeichert in:\n{target.parent}"
                )
        download.isFinishedChanged.connect(check_finished)

    def open_downloads(self):
        import subprocess
        self.download_dir.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(["xdg-open", str(self.download_dir)])

    def restore_or_open_start_page(self):
        if self.settings_data.get("startup_mode", "restore" if self.settings_data.get("restore_session", False) else "home") == "restore":
            urls = read_json(SESSION_FILE, [])
            valid = [u for u in urls if isinstance(u, str) and u]
            if valid:
                for url in valid:
                    self.add_tab(url, switch=False)
                self.tabs.setCurrentIndex(0)
                return
        mode = self.settings_data.get("startup_mode", "home")
        self.add_tab("about:blank" if mode == "blank" else self.settings_data.get("home", "https://duckduckgo.com"))

    def closeEvent(self, event):
        if self.settings_data.get("remember_window_size", True):
            g = self.geometry()
            self.settings_data["window_geometry"] = [g.x(), g.y(), g.width(), g.height()]
        else:
            self.settings_data["window_geometry"] = None
        write_json(CONFIG_FILE, self.settings_data)
        self.save_download_history()
        urls = []
        for i in range(self.tabs.count()):
            view = self.tabs.widget(i)
            if view:
                url = view.url().toString()
                if url and url != "about:blank":
                    urls.append(url)
        write_json(SESSION_FILE, urls)
        if self.settings_data.get("clear_history_on_exit", False):
            write_json(HISTORY_FILE, [])
        if self.settings_data.get("clear_cache_on_exit", False):
            self.profile.clearHttpCache()
        if self.settings_data.get("clear_cookies_on_exit", False):
            self.profile.cookieStore().deleteAllCookies()
        event.accept()

    def clear_history(self):
        answer = QMessageBox.question(self, "Verlauf löschen", "Möchtest du den gesamten Verlauf wirklich löschen?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if answer == QMessageBox.StandardButton.Yes:
            write_json(HISTORY_FILE, [])
            self.statusBar().showMessage("Verlauf wurde gelöscht.", 5000)
            QMessageBox.information(self, "Verlauf gelöscht", "Der Browserverlauf wurde gelöscht.")

    def show_settings(self):
        # Settings live in a normal browser tab, like Chromium's chrome://settings.
        for i in range(self.tabs.count()):
            existing = self.tabs.widget(i)
            if getattr(existing, "_lunasurfer_settings_page", False):
                self.tabs.setCurrentIndex(i)
                return
        page = QWidget(self)
        page._lunasurfer_settings_page = True
        page.setObjectName("settingsPage")
        page.setStyleSheet("""
            QWidget#settingsPage, QWidget#settingsContent, QScrollArea#settingsScroll,
            QScrollArea#settingsScroll QWidget#qt_scrollarea_viewport {
                background-color: #11151d; color: #e8edf5; border: 0;
            }
            QWidget#settingsPage QLabel { color: #d5dbea; background: transparent; }
            QWidget#settingsPage QLineEdit, QWidget#settingsPage QComboBox {
                background-color: #202938; color: #f4f7fb;
                border: 1px solid #3a4960; border-radius: 9px;
                padding: 9px 12px; min-height: 24px;
                selection-background-color: #8150c9;
            }
            QWidget#settingsPage QLineEdit:focus, QWidget#settingsPage QComboBox:focus {
                border: 1px solid #a879f5; background-color: #252f40;
            }
            QWidget#settingsPage QComboBox::drop-down {
                border: 0; width: 30px; background: transparent;
            }
            QWidget#settingsPage QComboBox QAbstractItemView {
                background: #202938; color: #f4f7fb;
                selection-background-color: #7040ad; border: 1px solid #46536a;
                padding: 5px;
            }
            QWidget#settingsPage QPushButton {
                background-color: #293548; color: #edf2f8;
                border: 1px solid #40516a; border-radius: 9px;
                padding: 9px 15px; min-height: 25px;
            }
            QWidget#settingsPage QPushButton:hover {
                background-color: #3b4b63; border-color: #a879f5;
            }
            QWidget#settingsPage QPushButton:pressed { background: #7040ad; }
            QWidget#settingsPage QCheckBox { color: #d5dbea; spacing: 10px; padding: 5px 2px; }
            QWidget#settingsPage QCheckBox::indicator {
                width: 17px; height: 17px; border-radius: 5px;
                border: 1px solid #65738a; background: #202938;
            }
            QWidget#settingsPage QCheckBox::indicator:checked {
                background: #8954d4; border: 1px solid #b995f4;
            }
            QScrollArea#settingsScroll { border: 0; }
            QScrollArea#settingsScroll QScrollBar:vertical {
                background: #171e29; width: 11px; margin: 3px; border-radius: 5px;
            }
            QScrollArea#settingsScroll QScrollBar::handle:vertical {
                background: #46536a; min-height: 35px; border-radius: 5px;
            }
            QScrollArea#settingsScroll QScrollBar::handle:vertical:hover { background: #8960c4; }
        """)
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(28, 18, 28, 20)
        page_layout.setSpacing(14)
        scroll = QScrollArea(page); scroll.setObjectName("settingsScroll"); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        content = QWidget(scroll); content.setObjectName("settingsContent")
        content.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        form = QFormLayout(content)
        form.setContentsMargins(14, 12, 14, 18)
        form.setHorizontalSpacing(24); form.setVerticalSpacing(14)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        scroll.setWidget(content)
        heading = QLabel(self.tr("Einstellungen", "Settings"))
        heading.setStyleSheet("font-size: 26px; font-weight: 750; color: #f2f4fa; padding: 2px 4px 8px 4px;")
        page_layout.addWidget(heading)
        page_layout.addWidget(scroll)
        tab_index = self.tabs.addTab(page, "⚙ " + self.tr("Einstellungen", "Settings"))
        self.tabs.setCurrentIndex(tab_index)
        language = QComboBox(); language.addItem("Deutsch", "de"); language.addItem("English", "en"); language.setCurrentIndex(max(0, language.findData(self.settings_data.get("language", "de"))))
        startup = QComboBox(); startup.addItem(self.tr("Startseite öffnen", "Open homepage"), "home"); startup.addItem(self.tr("Letzte Sitzung wiederherstellen", "Restore last session"), "restore"); startup.addItem(self.tr("Leere Seite öffnen", "Open blank page"), "blank")
        startup.setCurrentIndex(max(0, startup.findData(self.settings_data.get("startup_mode", "home"))))
        home = QLineEdit(self.settings_data.get("home", "https://duckduckgo.com"))
        engine = QComboBox(); engines={"Google":"https://www.google.com/search?q={}","DuckDuckGo":"https://duckduckgo.com/?q={}","Bing":"https://www.bing.com/search?q={}"}
        for name,url in engines.items(): engine.addItem(name,url)
        saved_engine=self.settings_data.get("search_engine", "DuckDuckGo"); engine.setCurrentIndex(max(0,engine.findText(saved_engine)))
        theme = QComboBox(); theme.addItem(self.tr("Dunkel", "Dark"), "dark"); theme.addItem(self.tr("Hell", "Light"), "light"); theme.setCurrentIndex(0 if self.settings_data.get("theme", "dark") == "dark" else 1)
        browser_design = QComboBox(); browser_design.addItem(self.tr("Dunkel (Standard)", "Dark (Standard)"), "dark"); browser_design.addItem(self.tr("Hell (Klassisch)", "Light (Classic)"), "light"); browser_design.addItem(self.tr("Luna (Modern)", "Luna (Modern)"), "luna"); browser_design.addItem(self.tr("Graphit-Blau (Elegant)", "Graphite Blue (Elegant)"), "graphite"); browser_design.addItem(self.tr("Ocean (Türkis-Blau)", "Ocean (Teal Blue)"), "ocean"); browser_design.setCurrentIndex(max(0, browser_design.findData(self.settings_data.get("browser_design", "dark"))))
        show_bookmarks_bar = QCheckBox(self.tr("Lesezeichenleiste unter der Adressleiste anzeigen", "Show bookmarks bar below the address bar")); show_bookmarks_bar.setChecked(self.settings_data.get("show_bookmarks_bar", True))
        download_dir = QLineEdit(str(self.download_dir)); choose_download = QPushButton(self.tr("Ordner auswählen…", "Choose folder…")); row=QHBoxLayout(); row.addWidget(download_dir); row.addWidget(choose_download); choose_download.clicked.connect(lambda:self.choose_download_dir(download_dir))
        zoom=QComboBox()
        for value in (50,67,75,80,90,100,110,125,150,175,200): zoom.addItem(f"{value} %",value)
        zoom.setCurrentIndex(max(0,zoom.findData(int(self.settings_data.get("default_zoom",100)))))
        ask_download=QCheckBox(self.tr("Bei jedem Download nach dem Speicherort fragen", "Ask where to save each download")); ask_download.setChecked(self.settings_data.get("ask_download_location",False))
        font_size=QComboBox()
        font_sizes=[("Klein","Small"),("Mittel","Medium"),("Groß","Large"),("Sehr groß","Very large")]
        saved_font=self.settings_data.get("font_size", "Mittel")
        for de,en in font_sizes: font_size.addItem(self.tr(de,en),de)
        font_size.setCurrentIndex(max(0,font_size.findData(saved_font)))
        block=QCheckBox(self.tr("Pop-ups blockieren", "Block pop-ups")); block.setChecked(self.settings_data.get("block_popups",True))
        permission_boxes={}
        for key,de_label,en_label in [("permission_camera","Kamera","Camera"),("permission_microphone","Mikrofon","Microphone"),("permission_location","Standort","Location"),("permission_notifications","Benachrichtigungen","Notifications")]:
            box=QComboBox(); box.addItem(self.tr("Beim Fragen", "Ask"), "ask"); box.addItem(self.tr("Erlauben", "Allow"), "allow"); box.addItem(self.tr("Blockieren", "Block"), "block"); box.setCurrentIndex(max(0,box.findData(self.settings_data.get(key,"ask")))); permission_boxes[key]=box
        dnt=QCheckBox(self.tr("Do Not Track-Anfrage senden", "Send Do Not Track request")); dnt.setChecked(self.settings_data.get("send_dnt",False))
        confirm_tabs=QCheckBox(self.tr("Beim Schließen eines Tabs nachfragen", "Ask when closing a tab")); confirm_tabs.setChecked(self.settings_data.get("confirm_close_multiple_tabs",True))
        clear_history_exit=QCheckBox(self.tr("Verlauf beim Beenden automatisch löschen", "Automatically clear history on exit")); clear_history_exit.setChecked(self.settings_data.get("clear_history_on_exit",False))
        clear_cache_exit=QCheckBox(self.tr("Cache beim Beenden automatisch löschen", "Automatically clear cache on exit")); clear_cache_exit.setChecked(self.settings_data.get("clear_cache_on_exit",False))
        clear_cookies_exit=QCheckBox(self.tr("Cookies beim Beenden automatisch löschen", "Automatically clear cookies on exit")); clear_cookies_exit.setChecked(self.settings_data.get("clear_cookies_on_exit",False))
        remember_window_size=QCheckBox(self.tr("Fenstergröße und Position beim Beenden merken", "Remember window size and position on exit")); remember_window_size.setChecked(self.settings_data.get("remember_window_size",True))
        default_browser=QCheckBox(self.tr("LunaSurfer als Standardbrowser verwenden", "Use LunaSurfer as default browser")); default_browser.setChecked(self.settings_data.get("default_browser",False))
        def add_section(title):
            # A section heading must span BOTH columns of QFormLayout.  The old
            # two-column row squeezed long headings into the narrow label column;
            # stylesheet padding also made the text clip vertically on Qt 6.
            label = QLabel(title)
            label.setWordWrap(False)
            label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            label.setContentsMargins(0, 10, 0, 7)
            label.setMinimumHeight(44)
            label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            label.setStyleSheet(
                "font-size: 15px; font-weight: 700; color: #c6a1ff; "
                "background: transparent; padding: 0; margin: 0; "
                "border-bottom: 1px solid #34264d;"
            )
            # The single-argument overload creates a spanning row, avoiding
            # clipping of headings such as 'Sicherheit und Berechtigungen'.
            form.addRow(label)
        add_section(self.tr("Allgemein", "General"))
        form.addRow(self.tr("Sprache:", "Language:"), language); form.addRow(self.tr("Beim Start:", "On startup:"),startup); form.addRow(self.tr("Startseite:", "Homepage:"),home); form.addRow(self.tr("Suchmaschine:", "Search engine:"),engine); form.addRow(self.tr("Browser-Design:", "Browser design:"),browser_design); form.addRow(self.tr("Webseiten-Design:", "Website appearance:"),theme); form.addRow("",show_bookmarks_bar); form.addRow(self.tr("Download-Ordner:", "Download folder:"),row); form.addRow("",ask_download); form.addRow(self.tr("Standard-Zoom:", "Default zoom:"),zoom); form.addRow(self.tr("Standard-Schriftgröße:", "Default font size:"),font_size)
        add_section(self.tr("Sicherheit und Berechtigungen", "Security and permissions"))
        form.addRow(self.tr("Sicherheit:", "Security:"),block)
        for key, box in permission_boxes.items():
            labels = {"permission_camera": ("Kamera", "Camera"), "permission_microphone": ("Mikrofon", "Microphone"), "permission_location": ("Standort", "Location"), "permission_notifications": ("Benachrichtigungen", "Notifications")}
            de_label, en_label = labels[key]
            form.addRow(self.tr(de_label, en_label) + ":", box)
        form.addRow("",dnt); form.addRow(self.tr("Browser-Verhalten:", "Browser behavior:"),confirm_tabs)
        privacy=QHBoxLayout(); a=QPushButton(self.tr("Verlauf löschen", "Clear history")); b=QPushButton(self.tr("Cache löschen", "Clear cache")); c=QPushButton(self.tr("Cookies löschen", "Clear cookies")); [privacy.addWidget(x) for x in (a,b,c)]; add_section(self.tr("Datenschutz und Browserdaten", "Privacy and browser data"))
        form.addRow(self.tr("Browserdaten:", "Browser data:"),privacy); form.addRow("",clear_history_exit); form.addRow("",clear_cache_exit); form.addRow("",clear_cookies_exit); form.addRow("",remember_window_size); form.addRow("",default_browser); a.clicked.connect(self.clear_history); b.clicked.connect(self.clear_cache); c.clicked.connect(self.clear_cookies)
        buttons=QHBoxLayout(); save=QPushButton(self.tr("Speichern", "Save")); cancel=QPushButton(self.tr("Abbrechen", "Cancel")); buttons.addWidget(save); buttons.addWidget(cancel); form.addRow(buttons)
        save.clicked.connect(lambda:self.save_settings_v39(page,home.text(),engine.currentText(),engine.currentData(),theme.currentData(),show_bookmarks_bar.isChecked(),startup.currentData(),download_dir.text(),ask_download.isChecked(),zoom.currentData(),font_size.currentData(),block.isChecked(),dnt.isChecked(),confirm_tabs.isChecked(),{k:v.currentData() for k,v in permission_boxes.items()},clear_history_exit.isChecked(),clear_cache_exit.isChecked(),clear_cookies_exit.isChecked(),remember_window_size.isChecked(),language.currentData(),default_browser.isChecked(),browser_design.currentData()))
        cancel.clicked.connect(lambda: self.close_settings_page(page))

    def close_settings_page(self, page):
        index = self.tabs.indexOf(page)
        if index >= 0:
            self.tabs.removeTab(index)
            page.deleteLater()
            if self.tabs.count() == 0:
                self.add_tab(self.settings_data.get("home"))
            QTimer.singleShot(0, self.update_new_tab_button_position)

    def save_settings_v39(self, dialog, home, engine_name, search_url, theme, bookmarks, startup_mode, download_dir, ask_download, zoom, font_size, block, dnt, confirm_tabs, permissions, ch, cc, ck, remember_window_size=True, language="de", default_browser=False, browser_design="dark"):
        chosen=pathlib.Path(download_dir.strip() or str(DOWNLOAD_DIR)).expanduser()
        self.settings_data.update({"home":home.strip() or "https://duckduckgo.com","search":search_url,"search_engine":engine_name,"theme":theme,"show_bookmarks_bar":bool(bookmarks),"startup_mode":startup_mode,"restore_session":startup_mode=="restore","download_dir":str(chosen),"default_zoom":int(zoom or 100),"font_size":font_size,"ask_download_location":bool(ask_download),"block_popups":bool(block),"send_dnt":bool(dnt),"confirm_close_multiple_tabs":bool(confirm_tabs),"clear_history_on_exit":bool(ch),"clear_cache_on_exit":bool(cc),"clear_cookies_on_exit":bool(ck),"remember_window_size":bool(remember_window_size),"language":language or "de","default_browser":bool(default_browser),"browser_design":browser_design if browser_design in ("dark", "light", "luna", "graphite", "ocean") else "dark",**permissions})
        self.download_dir=chosen; write_json(CONFIG_FILE,self.settings_data); self.set_default_browser(bool(default_browser)); self.apply_language_live()
        self.bookmarks_bar.setVisible(self.settings_data["show_bookmarks_bar"]); self.apply_browser_design(); self.apply_theme_to_all_tabs()
        for i in range(self.tabs.count()):
            view = self.tabs.widget(i)
            if isinstance(view, BrowserView):
                self.apply_font_size(view)
        self.close_settings_page(dialog)

    def set_default_browser(self, enabled):
        """Register or unregister LunaSurfer as the preferred browser for this user."""
        import subprocess
        try:
            if enabled:
                subprocess.run(["xdg-settings", "set", "default-web-browser", "lunasurfer.desktop"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for mime in ("x-scheme-handler/http", "x-scheme-handler/https", "text/html", "application/xhtml+xml"):
                    subprocess.run(["xdg-mime", "default", "lunasurfer.desktop", mime], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                # Remove LunaSurfer's per-user MIME associations without choosing another browser.
                mimeapps = pathlib.Path.home() / ".config" / "mimeapps.list"
                if mimeapps.exists():
                    text = mimeapps.read_text(errors="ignore")
                    lines = [line for line in text.splitlines() if "lunasurfer.desktop" not in line]
                    mimeapps.write_text("\n".join(lines) + ("\n" if lines else ""))
        except Exception:
            pass

    def choose_download_dir(self, field):
        selected = QFileDialog.getExistingDirectory(self, "Download-Ordner auswählen", field.text() or str(DOWNLOAD_DIR))
        if selected: field.setText(selected)

    def clear_cache(self):
        answer = QMessageBox.question(
            self, "Cache löschen",
            "Möchtest du den Browser-Cache wirklich löschen?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.profile.clearHttpCache()
            self.statusBar().showMessage("Browser-Cache wurde gelöscht.", 5000)
            QMessageBox.information(self, "Cache gelöscht", "Der Browser-Cache wurde gelöscht.")

    def clear_cookies(self):
        answer = QMessageBox.question(
            self, "Cookies löschen",
            "Möchtest du wirklich alle gespeicherten Cookies löschen?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.profile.cookieStore().deleteAllCookies()
            self.statusBar().showMessage("Alle Cookies wurden gelöscht.", 5000)
            QMessageBox.information(self, "Cookies gelöscht", "Alle gespeicherten Cookies wurden gelöscht.")

    def save_settings(self, dialog, home, search, theme, show_bookmarks_bar, restore_session, download_dir, default_zoom, clear_history_on_exit, clear_cache_on_exit, clear_cookies_on_exit):
        chosen = pathlib.Path(download_dir.strip() or str(DOWNLOAD_DIR)).expanduser()
        self.settings_data.update({
            "home": home.strip() or "https://duckduckgo.com", "search": search.strip() or "https://duckduckgo.com/?q={}",
            "theme": theme if theme in ("dark", "light") else "dark", "show_bookmarks_bar": bool(show_bookmarks_bar),
            "restore_session": bool(restore_session), "download_dir": str(chosen), "default_zoom": int(default_zoom or 100),
            "clear_history_on_exit": bool(clear_history_on_exit), "clear_cache_on_exit": bool(clear_cache_on_exit), "clear_cookies_on_exit": bool(clear_cookies_on_exit)
        })
        self.download_dir = chosen; write_json(CONFIG_FILE, self.settings_data); self.bookmarks_bar.setVisible(self.settings_data["show_bookmarks_bar"])
        self.apply_theme_to_all_tabs()
        for i in range(self.tabs.count()):
            view = self.tabs.widget(i)
            if view: self.apply_font_size(view)
        dialog.accept()

    def about(self):
        QMessageBox.about(self, self.tr("Über LunaSurfer", "About LunaSurfer"), f"{APP_NAME} {APP_VERSION}\nQt 6 + QtWebEngine mit auswählbarem hellem/dunklem Webseiten-Design und optionaler Widevine-CDM-Einbindung.\nGoldisoft · 2026")

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("Goldisoft")
    window = LunaSurfer()
    # Desktop launchers pass the requested URL via %U.  Load it after the
    # startup tab has been created so the requested page replaces the homepage.
    requested = next((arg for arg in sys.argv[1:] if arg and not arg.startswith("-")), "")
    if requested:
        url = QUrl.fromUserInput(requested)
        if url.isValid() and not url.isEmpty():
            view = window.current_view()
            if view:
                view.load(url)
            else:
                window.add_tab(url.toString())
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
