#!/usr/bin/env python3
"""LunaSurfer 0.3.28 - Qt 6 / QtWebEngine browser."""
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
    QFormLayout, QPushButton, QHBoxLayout, QLabel, QCheckBox, QComboBox, QStyle, QInputDialog, QListWidget, QListWidgetItem, QProgressBar
)
from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage, QWebEngineSettings, QWebEngineUrlRequestInterceptor
from PySide6.QtWebEngineWidgets import QWebEngineView

APP_NAME = "LunaSurfer"
CONFIG_DIR = pathlib.Path.home() / ".config" / "lunasurfer"
DATA_DIR = pathlib.Path.home() / ".local" / "share" / "lunasurfer"
CONFIG_FILE = CONFIG_DIR / "settings.json"
BOOKMARKS_FILE = DATA_DIR / "bookmarks.json"
HISTORY_FILE = DATA_DIR / "history.json"
SESSION_FILE = DATA_DIR / "session.json"
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
        strength = self.window_ref.settings_data.get("adblock_strength", "standard")
        builtins = standard if strength == "standard" else (strong if strength == "strong" else very_strong)
        custom = [str(x).lower() for x in self.window_ref.settings_data.get("adblock_custom_blocklist", [])]
        if any(token in host or token in url for token in builtins + custom):
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
        self.setWindowTitle("LunaSurfer 0.3.28")
        self.resize(1250, 820)
        self._web_fullscreen = False
        self._was_maximized_before_fullscreen = False
        self._fullscreen_chrome = []
        self.settings_data = read_json(CONFIG_FILE, {
            "home": "https://duckduckgo.com",
            "search": "https://duckduckgo.com/?q={}",
            "dark": True,
            "theme": "dark",
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
        self.bookmarks_bar = QToolBar("Lesezeichenleiste")
        self.bookmarks_bar.setMovable(False)
        self.bookmarks_bar.setIconSize(QSize(18, 18))
        self.bookmarks_bar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.bookmarks_bar.setMinimumHeight(36)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self.bookmarks_bar)
        self.refresh_bookmarks_bar()
        self.bookmarks_bar.setVisible(self.settings_data.get("show_bookmarks_bar", True))

        self.statusBar().showMessage("Bereit / Ready")
        self.setStyleSheet("""
            QMainWindow { background: #101827; }
            QToolBar { background: #17263b; border: 0; spacing: 8px; padding: 8px 10px; }
            QToolBar QToolButton { color: #eef4ff; padding: 7px; border-radius: 9px; min-width: 34px; min-height: 34px; }
            QToolBar QToolButton:hover { background: #294564; }
            QToolBar QToolButton:pressed { background: #1769aa; }
            QToolBar QToolButton:disabled { opacity: 0.45; }
            QLineEdit { background: #202f45; color: #f2f6ff; border: 1px solid #3d5878; border-radius: 16px; padding: 9px 13px; font-size: 13px; }
            QTabWidget::pane { border: 0; background: #101827; }
            QTabBar::tab { background: #1c2c42; color: #dce8f8; padding: 9px 16px; margin-right: 2px; }
            QTabBar::tab:selected { background: #1769aa; color: white; }
            QTabWidget QToolButton { min-width: 38px; min-height: 30px; }
            /* Keep tooltips compact; they should not look like large info windows. */
            QToolTip { font-size: 11px; padding: 3px 6px; border-radius: 3px; }
            QStatusBar { background: #142238; color: #dce8f8; }
            QToolTip { background: #1b2b42; color: #ffffff; border: 1px solid #6f9fc9; border-radius: 3px; padding: 3px 6px; font-size: 11px; }
        """)
        self.restore_or_open_start_page()
        self.set_shortcuts()

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
        self.menu_button.setMenu(menu)
        self.menu_button.setToolTip(self.tr("Menü", "Menu"))

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
        """Rebuild the bookmarks bar, including Chromium bookmark folders."""
        if not hasattr(self, "bookmarks_bar"):
            return
        self.bookmarks_bar.clear()
        items = read_json(BOOKMARKS_FILE, [])
        style = QApplication.style()

        def add_items(parent_toolbar, entries):
            for item in entries:
                if item.get("type") == "folder" or "children" in item:
                    title = (item.get("title") or "Ordner").strip()
                    menu = QMenu(title, self)
                    def fill_menu(target, children):
                        for child in children:
                            if child.get("type") == "folder" or "children" in child:
                                sub = target.addMenu((child.get("title") or "Ordner").strip())
                                fill_menu(sub, child.get("children", []))
                            else:
                                u = child.get("url", "").strip()
                                if u:
                                    a = target.addAction((child.get("title") or u).strip())
                                    a.setToolTip(u)
                                    a.triggered.connect(lambda checked=False, url=u: self.open_bookmark(url))
                    fill_menu(menu, item.get("children", []))
                    button = QToolButton(self.bookmarks_bar)
                    button.setText(title)
                    button.setMenu(menu)
                    button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
                    parent_toolbar.addWidget(button)
                else:
                    url = item.get("url", "").strip()
                    if not url:
                        continue
                    title = (item.get("title") or url).strip()
                    action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload), title, self)
                    action.setToolTip(url)
                    action.triggered.connect(lambda checked=False, u=url: self.open_bookmark(u))
                    parent_toolbar.addAction(action)
                    button = parent_toolbar.widgetForAction(action)
                    if button is not None:
                        button.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
                        button.customContextMenuRequested.connect(lambda pos, u=url, b=button: self.show_bookmark_context_menu(u, b.mapToGlobal(pos)))

        add_items(self.bookmarks_bar, items)
        if items: self.bookmarks_bar.addSeparator()
        manage = QAction("Lesezeichen verwalten", self)
        manage.setToolTip("Lesezeichen anzeigen und verwalten")
        manage.triggered.connect(self.show_bookmarks)
        self.bookmarks_bar.addAction(manage)

    def open_bookmark(self, url):
        view = self.current_view()
        if view:
            view.load(QUrl(url))

    def show_bookmark_context_menu(self, url, global_pos):
        """Right-click menu for bookmarks in the bookmarks bar."""
        menu = QMenu(self)
        open_action = menu.addAction("Öffnen")
        edit_action = menu.addAction("Lesezeichen bearbeiten…")
        delete_action = menu.addAction("Lesezeichen löschen")
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
        title, ok = QInputDialog.getText(self, "Lesezeichen bearbeiten", "Name:", text=item.get("title", ""))
        if not ok:
            return
        url, ok = QInputDialog.getText(self, "Lesezeichen bearbeiten", "Adresse:", text=item.get("url", ""))
        if not ok or not url.strip():
            return
        item["title"] = title.strip() or url.strip()
        item["url"] = url.strip()
        write_json(BOOKMARKS_FILE, items)
        self.refresh_bookmarks_bar()
        self.statusBar().showMessage("Lesezeichen geändert", 3000)

    def delete_bookmark(self, url):
        answer = QMessageBox.question(
            self, "Lesezeichen löschen", "Dieses Lesezeichen wirklich löschen?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        items = [x for x in read_json(BOOKMARKS_FILE, []) if x.get("url") != url]
        write_json(BOOKMARKS_FILE, items)
        self.refresh_bookmarks_bar()
        self.statusBar().showMessage("Lesezeichen gelöscht", 3000)

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
        """Open a bookmark manager with edit/delete controls."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Lesezeichen verwalten")
        dialog.resize(760, 500)
        layout = QVBoxLayout(dialog)

        from PySide6.QtWidgets import QListWidget, QListWidgetItem, QHBoxLayout
        bookmark_list = QListWidget()
        layout.addWidget(bookmark_list)

        def populate():
            bookmark_list.clear()
            for item in read_json(BOOKMARKS_FILE, []):
                title = (item.get("title") or item.get("url") or "").strip()
                url = item.get("url", "").strip()
                row = QListWidgetItem(f"{title}\n{url}")
                row.setData(Qt.ItemDataRole.UserRole, url)
                bookmark_list.addItem(row)

        buttons = QHBoxLayout()
        open_btn = QPushButton("Öffnen")
        edit_btn = QPushButton("Bearbeiten…")
        delete_btn = QPushButton("Löschen")
        import_btn = QPushButton("Importieren…")
        export_btn = QPushButton("Exportieren…")
        close_btn = QPushButton("Schließen")
        buttons.addWidget(open_btn)
        buttons.addWidget(edit_btn)
        buttons.addWidget(delete_btn)
        buttons.addWidget(import_btn)
        buttons.addWidget(export_btn)
        buttons.addStretch(1)
        buttons.addWidget(close_btn)
        layout.addLayout(buttons)

        def selected_url():
            item = bookmark_list.currentItem()
            return item.data(Qt.ItemDataRole.UserRole) if item else ""

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
            url = selected_url()
            if url:
                self.delete_bookmark(url)
                populate()

        def do_export():
            filename, _ = QFileDialog.getSaveFileName(
                dialog, "Lesezeichen exportieren", str(pathlib.Path.home() / "LunaSurfer-Lesezeichen.html"),
                "HTML-Dateien (*.html *.htm)"
            )
            if not filename:
                return
            rows = []
            for entry in read_json(BOOKMARKS_FILE, []):
                url = str(entry.get("url", "")).strip()
                title = str(entry.get("title", "") or url).strip()
                if url:
                    rows.append(f'<DT><A HREF="{escape(url, quote=True)}">{escape(title)}</A>')
            content = "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n<TITLE>Bookmarks</TITLE>\n<H1>Bookmarks</H1>\n<DL><p>\n" + "\n".join(rows) + "\n</DL><p>\n"
            try:
                pathlib.Path(filename).write_text(content, encoding="utf-8")
                self.statusBar().showMessage("Lesezeichen exportiert", 4000)
                QMessageBox.information(dialog, "Export", "Die Lesezeichen wurden im Chromium-kompatiblen HTML-Format exportiert.")
            except Exception as exc:
                QMessageBox.warning(dialog, "Export fehlgeschlagen", str(exc))

        def do_import():
            filename, _ = QFileDialog.getOpenFileName(
                dialog, "Lesezeichen importieren", str(pathlib.Path.home()), "HTML-Dateien (*.html *.htm)"
            )
            if not filename:
                return
            try:
                parser = ChromiumBookmarksParser()
                parser.feed(pathlib.Path(filename).read_text(encoding="utf-8", errors="replace"))
                imported = parser.items
                if not imported:
                    QMessageBox.warning(dialog, "Import", "Keine Lesezeichen in der ausgewählten Datei gefunden.")
                    return
                answer = QMessageBox.question(
                    dialog, "Lesezeichen importieren",
                    f"{len(imported)} Lesezeichen gefunden.\n\nJa: vorhandene Lesezeichen ersetzen\nNein: zu vorhandenen Lesezeichen hinzufügen",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
                    QMessageBox.StandardButton.No,
                )
                if answer == QMessageBox.StandardButton.Cancel:
                    return
                if answer == QMessageBox.StandardButton.Yes:
                    result = imported
                else:
                    result = read_json(BOOKMARKS_FILE, [])
                    existing = {str(x.get("url", "")).strip() for x in result}
                    result.extend(x for x in imported if x["url"] not in existing)
                write_json(BOOKMARKS_FILE, result)
                self.refresh_bookmarks_bar()
                populate()
                self.statusBar().showMessage("Lesezeichen importiert", 4000)
                QMessageBox.information(dialog, "Import", f"{len(imported)} Lesezeichen wurden importiert.")
            except Exception as exc:
                QMessageBox.warning(dialog, "Import fehlgeschlagen", str(exc))

        open_btn.clicked.connect(do_open)
        edit_btn.clicked.connect(do_edit)
        delete_btn.clicked.connect(do_delete)
        import_btn.clicked.connect(do_import)
        export_btn.clicked.connect(do_export)
        bookmark_list.itemDoubleClicked.connect(lambda item: do_open())
        close_btn.clicked.connect(dialog.accept)
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
        strength = QComboBox(); strength.addItem(self.tr("Standard", "Standard"), "standard"); strength.addItem(self.tr("Stark", "Strong"), "strong"); strength.addItem(self.tr("Sehr stark", "Very strong"), "very_strong")
        current_strength = self.settings_data.get("adblock_strength", "standard"); strength.setCurrentIndex(max(0, strength.findData(current_strength))); layout.addWidget(strength)
        layout.addWidget(QLabel(self.tr("Eigene Blockiermuster (eine Domain oder ein Muster pro Zeile):", "Custom block patterns (one domain or pattern per line):")))
        patterns = QLineEdit("; ".join(self.settings_data.get("adblock_custom_blocklist", []))); patterns.setPlaceholderText("z. B. example-ads.com")
        layout.addWidget(patterns)
        layout.addWidget(QLabel(self.tr("Whitelist-Domains (mit Semikolon trennen):", "Whitelist domains (separate with semicolons):")))
        whitelist = QLineEdit("; ".join(self.settings_data.get("adblock_whitelist", []))); layout.addWidget(whitelist)
        info = QLabel(self.tr("Der integrierte Blocker filtert bekannte Werbe- und Tracking-Domains. Änderungen gelten für neue Anfragen sofort.", "The built-in blocker filters known advertising and tracking domains. Changes apply to new requests immediately.")); info.setWordWrap(True); layout.addWidget(info)
        buttons = QHBoxLayout(); save = QPushButton(self.tr("Speichern", "Save")); close = QPushButton(self.tr("Abbrechen", "Cancel")); buttons.addStretch(1); buttons.addWidget(save); buttons.addWidget(close); layout.addLayout(buttons)
        def do_save():
            self.settings_data["adblock_enabled"] = enabled.isChecked()
            self.settings_data["adblock_strength"] = strength.currentData()
            self.settings_data["adblock_custom_blocklist"] = [x.strip() for x in patterns.text().split(";") if x.strip()]
            self.settings_data["adblock_whitelist"] = [x.strip() for x in whitelist.text().split(";") if x.strip()]
            write_json(CONFIG_FILE, self.settings_data); self.update_adblock_button(); dialog.accept()
        save.clicked.connect(do_save); close.clicked.connect(dialog.reject); dialog.exec()

    def show_download_manager(self):
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("Download-Manager", "Download Manager"))
        dialog.resize(900, 520)
        layout = QVBoxLayout(dialog)
        info = QLabel(self.tr("Verwalte laufende und abgeschlossene Downloads.", "Manage active and completed downloads."))
        layout.addWidget(info)
        lst = QListWidget(); layout.addWidget(lst)

        def selected_item():
            row = lst.currentRow()
            return self.download_items[row] if 0 <= row < len(self.download_items) else None

        def refresh():
            current = lst.currentRow()
            lst.clear()
            now = time.monotonic()
            for item in self.download_items:
                d = item["download"]; target = item["target"]; name = target.name
                received = getattr(d, "receivedBytes", lambda: 0)()
                total = getattr(d, "totalBytes", lambda: 0)()
                finished = d.isFinished()
                if not finished:
                    last_b = item.get("last_bytes", received); last_t = item.get("last_time", now)
                    dt = max(now - last_t, 0.001); speed = max(0, received - last_b) / dt
                    item["speed"] = speed; item["last_bytes"] = received; item["last_time"] = now
                else:
                    speed = 0
                percent = int(received * 100 / total) if total and total > 0 else (100 if finished else 0)
                def fmt(n):
                    units=["B","KB","MB","GB"]
                    n=float(max(0,n)); i=0
                    while n>=1024 and i<len(units)-1: n/=1024; i+=1
                    return f"{n:.1f} {units[i]}"
                state = self.tr("Fertig", "Finished") if finished else self.tr("Lädt", "Downloading")
                size = f"{fmt(received)} / {fmt(total)}" if total and total > 0 else fmt(received)
                extra = self.tr(f"{fmt(speed)}/s", f"{fmt(speed)}/s") if not finished else ""
                lst.addItem(f"{name}\n{state} — {percent}% — {size} {extra}")
            if current >= 0 and current < lst.count(): lst.setCurrentRow(current)

        def cancel_selected():
            item = selected_item()
            if item and not item["download"].isFinished():
                item["download"].cancel(); refresh()

        def open_file():
            item = selected_item()
            if item and item["target"].exists(): subprocess.Popen(["xdg-open", str(item["target"])])

        def open_folder_selected():
            item = selected_item()
            path = item["target"].parent if item else self.download_dir
            path.mkdir(parents=True, exist_ok=True); subprocess.Popen(["xdg-open", str(path)])

        def remove_entry():
            row = lst.currentRow()
            if 0 <= row < len(self.download_items):
                self.download_items.pop(row); refresh()

        def delete_file():
            item = selected_item()
            if not item: return
            target = item["target"]
            if not target.exists():
                remove_entry(); return
            answer = QMessageBox.question(dialog, self.tr("Datei löschen", "Delete file"), self.tr(f"Soll die Datei wirklich von der Festplatte gelöscht werden?\n\n{target.name}", f"Really delete this file from disk?\n\n{target.name}"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if answer == QMessageBox.StandardButton.Yes:
                try: target.unlink(); remove_entry()
                except Exception as exc: QMessageBox.warning(dialog, self.tr("Fehler", "Error"), str(exc))

        def clear_history():
            self.download_items[:] = [i for i in self.download_items if not i["download"].isFinished()]
            refresh()

        refresh()
        timer = QTimer(dialog); timer.timeout.connect(refresh); timer.start(700)
        buttons1 = QHBoxLayout()
        cancel = QPushButton(self.tr("Abbrechen", "Cancel download")); open_btn = QPushButton(self.tr("Datei öffnen", "Open file")); folder = QPushButton(self.tr("Ordner öffnen", "Open folder"))
        buttons1.addWidget(cancel); buttons1.addWidget(open_btn); buttons1.addWidget(folder); buttons1.addStretch(1); layout.addLayout(buttons1)
        buttons2 = QHBoxLayout()
        remove = QPushButton(self.tr("Aus Liste entfernen", "Remove from list")); delete = QPushButton(self.tr("Datei löschen", "Delete file")); clear = QPushButton(self.tr("Verlauf löschen", "Clear history")); close = QPushButton(self.tr("Schließen", "Close"))
        buttons2.addWidget(remove); buttons2.addWidget(delete); buttons2.addWidget(clear); buttons2.addStretch(1); buttons2.addWidget(close); layout.addLayout(buttons2)
        cancel.clicked.connect(cancel_selected); open_btn.clicked.connect(open_file); folder.clicked.connect(open_folder_selected); remove.clicked.connect(remove_entry); delete.clicked.connect(delete_file); clear.clicked.connect(clear_history); close.clicked.connect(dialog.accept)
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
        dialog = QDialog(self); dialog.setWindowTitle(self.tr("LunaSurfer – Einstellungen", "LunaSurfer – Settings"))
        language = QComboBox(); language.addItem("Deutsch", "de"); language.addItem("English", "en"); language.setCurrentIndex(max(0, language.findData(self.settings_data.get("language", "de"))))
        form = QFormLayout(dialog)
        startup = QComboBox(); startup.addItem(self.tr("Startseite öffnen", "Open homepage"), "home"); startup.addItem(self.tr("Letzte Sitzung wiederherstellen", "Restore last session"), "restore"); startup.addItem(self.tr("Leere Seite öffnen", "Open blank page"), "blank")
        startup.setCurrentIndex(max(0, startup.findData(self.settings_data.get("startup_mode", "home"))))
        home = QLineEdit(self.settings_data.get("home", "https://duckduckgo.com"))
        engine = QComboBox(); engines={"Google":"https://www.google.com/search?q={}","DuckDuckGo":"https://duckduckgo.com/?q={}","Bing":"https://www.bing.com/search?q={}"}
        for name,url in engines.items(): engine.addItem(name,url)
        saved_engine=self.settings_data.get("search_engine", "DuckDuckGo"); engine.setCurrentIndex(max(0,engine.findText(saved_engine)))
        theme = QComboBox(); theme.addItem(self.tr("Dunkel", "Dark"), "dark"); theme.addItem(self.tr("Hell", "Light"), "light"); theme.setCurrentIndex(0 if self.settings_data.get("theme", "dark") == "dark" else 1)
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
            box=QComboBox(); box.addItem(self.tr("Beim Fragen", "Ask"), "ask"); box.addItem(self.tr("Erlauben", "Allow"), "allow"); box.addItem(self.tr("Blockieren", "Block"), "block"); box.setCurrentIndex(max(0,box.findData(self.settings_data.get(key,"ask")))); permission_boxes[key]=box; form.addRow(self.tr(de_label,en_label)+":",box)
        dnt=QCheckBox(self.tr("Do Not Track-Anfrage senden", "Send Do Not Track request")); dnt.setChecked(self.settings_data.get("send_dnt",False))
        confirm_tabs=QCheckBox(self.tr("Beim Schließen eines Tabs nachfragen", "Ask when closing a tab")); confirm_tabs.setChecked(self.settings_data.get("confirm_close_multiple_tabs",True))
        clear_history_exit=QCheckBox(self.tr("Verlauf beim Beenden automatisch löschen", "Automatically clear history on exit")); clear_history_exit.setChecked(self.settings_data.get("clear_history_on_exit",False))
        clear_cache_exit=QCheckBox(self.tr("Cache beim Beenden automatisch löschen", "Automatically clear cache on exit")); clear_cache_exit.setChecked(self.settings_data.get("clear_cache_on_exit",False))
        clear_cookies_exit=QCheckBox(self.tr("Cookies beim Beenden automatisch löschen", "Automatically clear cookies on exit")); clear_cookies_exit.setChecked(self.settings_data.get("clear_cookies_on_exit",False))
        remember_window_size=QCheckBox(self.tr("Fenstergröße und Position beim Beenden merken", "Remember window size and position on exit")); remember_window_size.setChecked(self.settings_data.get("remember_window_size",True))
        default_browser=QCheckBox(self.tr("LunaSurfer als Standardbrowser verwenden", "Use LunaSurfer as default browser")); default_browser.setChecked(self.settings_data.get("default_browser",False))
        form.addRow(self.tr("Sprache:", "Language:"), language); form.addRow(self.tr("Beim Start:", "On startup:"),startup); form.addRow(self.tr("Startseite:", "Homepage:"),home); form.addRow(self.tr("Suchmaschine:", "Search engine:"),engine); form.addRow(self.tr("Webseiten-Design:", "Website appearance:"),theme); form.addRow("",show_bookmarks_bar); form.addRow(self.tr("Download-Ordner:", "Download folder:"),row); form.addRow("",ask_download); form.addRow(self.tr("Standard-Zoom:", "Default zoom:"),zoom); form.addRow(self.tr("Standard-Schriftgröße:", "Default font size:"),font_size); form.addRow(self.tr("Sicherheit:", "Security:"),block); form.addRow("",dnt); form.addRow(self.tr("Browser-Verhalten:", "Browser behavior:"),confirm_tabs)
        privacy=QHBoxLayout(); a=QPushButton(self.tr("Verlauf löschen", "Clear history")); b=QPushButton(self.tr("Cache löschen", "Clear cache")); c=QPushButton(self.tr("Cookies löschen", "Clear cookies")); [privacy.addWidget(x) for x in (a,b,c)]; form.addRow(self.tr("Browserdaten:", "Browser data:"),privacy); form.addRow("",clear_history_exit); form.addRow("",clear_cache_exit); form.addRow("",clear_cookies_exit); form.addRow("",remember_window_size); form.addRow("",default_browser); a.clicked.connect(self.clear_history); b.clicked.connect(self.clear_cache); c.clicked.connect(self.clear_cookies)
        buttons=QHBoxLayout(); save=QPushButton(self.tr("Speichern", "Save")); cancel=QPushButton(self.tr("Abbrechen", "Cancel")); buttons.addWidget(save); buttons.addWidget(cancel); form.addRow(buttons)
        save.clicked.connect(lambda:self.save_settings_v39(dialog,home.text(),engine.currentText(),engine.currentData(),theme.currentData(),show_bookmarks_bar.isChecked(),startup.currentData(),download_dir.text(),ask_download.isChecked(),zoom.currentData(),font_size.currentData(),block.isChecked(),dnt.isChecked(),confirm_tabs.isChecked(),{k:v.currentData() for k,v in permission_boxes.items()},clear_history_exit.isChecked(),clear_cache_exit.isChecked(),clear_cookies_exit.isChecked(),remember_window_size.isChecked(),language.currentData(),default_browser.isChecked()))
        cancel.clicked.connect(dialog.reject); dialog.exec()

    def save_settings_v39(self, dialog, home, engine_name, search_url, theme, bookmarks, startup_mode, download_dir, ask_download, zoom, font_size, block, dnt, confirm_tabs, permissions, ch, cc, ck, remember_window_size=True, language="de", default_browser=False):
        chosen=pathlib.Path(download_dir.strip() or str(DOWNLOAD_DIR)).expanduser()
        self.settings_data.update({"home":home.strip() or "https://duckduckgo.com","search":search_url,"search_engine":engine_name,"theme":theme,"show_bookmarks_bar":bool(bookmarks),"startup_mode":startup_mode,"restore_session":startup_mode=="restore","download_dir":str(chosen),"default_zoom":int(zoom or 100),"font_size":font_size,"ask_download_location":bool(ask_download),"block_popups":bool(block),"send_dnt":bool(dnt),"confirm_close_multiple_tabs":bool(confirm_tabs),"clear_history_on_exit":bool(ch),"clear_cache_on_exit":bool(cc),"clear_cookies_on_exit":bool(ck),"remember_window_size":bool(remember_window_size),"language":language or "de","default_browser":bool(default_browser),**permissions})
        old_language = self.settings_data.get("language", "de")
        self.download_dir=chosen; write_json(CONFIG_FILE,self.settings_data); self.set_default_browser(bool(default_browser)); self.apply_language_live()
        self.bookmarks_bar.setVisible(self.settings_data["show_bookmarks_bar"]); self.apply_theme_to_all_tabs()
        for i in range(self.tabs.count()): self.apply_font_size(self.tabs.widget(i))
        dialog.accept()

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
        QMessageBox.about(self, self.tr("Über LunaSurfer", "About LunaSurfer"), "LunaSurfer 0.3.27\nQt 6 + QtWebEngine mit auswählbarem hellem/dunklem Webseiten-Design und optionaler Widevine-CDM-Einbindung.\nGoldisoft · 2026")

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
