#!/usr/bin/env python3
"""LunaSurfer 0.3.4 - Qt 6 / QtWebEngine browser with editable bookmarks."""
import json
import pathlib
import sys
import urllib.parse
import os

# Keep QtWebEngine's own helper selection. Forcing a system helper can mix
# Qt installations and leave the browser surface blank on some Debian systems.
# Widevine is passed only when the local CDM exists.
WIDEVINE_CDM = pathlib.Path("/opt/WidevineCdm/gmp-widevinecdm/latest/libwidevinecdm.so")
if WIDEVINE_CDM.is_file():
    existing_flags = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "").strip()
    widevine_flag = f"--widevine-path={WIDEVINE_CDM}"
    if widevine_flag not in existing_flags:
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (existing_flags + " " + widevine_flag).strip()

from PySide6.QtCore import QUrl, QSize, Qt
from PySide6.QtGui import QAction, QKeySequence, QIcon
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QToolBar, QLineEdit, QToolButton,
    QVBoxLayout, QWidget, QMenu, QFileDialog, QMessageBox, QDialog,
    QFormLayout, QPushButton, QHBoxLayout, QLabel, QCheckBox, QComboBox, QStyle, QInputDialog
)
from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage, QWebEngineSettings
from PySide6.QtWebEngineWidgets import QWebEngineView

APP_NAME = "LunaSurfer"
CONFIG_DIR = pathlib.Path.home() / ".config" / "lunasurfer"
DATA_DIR = pathlib.Path.home() / ".local" / "share" / "lunasurfer"
CONFIG_FILE = CONFIG_DIR / "settings.json"
BOOKMARKS_FILE = DATA_DIR / "bookmarks.json"
HISTORY_FILE = DATA_DIR / "history.json"
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

class BrowserView(QWebEngineView):
    def __init__(self, window):
        super().__init__()
        self.window_ref = window
        self.titleChanged.connect(self.on_title)
        self.urlChanged.connect(self.on_url)
        self.loadProgress.connect(lambda p: window.statusBar().showMessage(f"Laden … {p}%"))
        self.loadFinished.connect(self.on_load_finished)
        self.renderProcessTerminated.connect(self.on_render_process_terminated)
        self.page().settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        self.page().settings().setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        self.page().settings().setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)
        self.page().fullScreenRequested.connect(self.handle_fullscreen)

    def contextMenuEvent(self, event):
        """Show QtWebEngine's full context menu with German labels."""
        menu = self.createStandardContextMenu()
        translations = {
            "back": "Zurück", "forward": "Vorwärts", "reload": "Neu laden",
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
        self.window_ref.add_tab("about:blank", switch=True)
        return self.window_ref.current_view()

    def on_title(self, title):
        self.window_ref.update_tab_title(self, title)

    def on_url(self, url):
        if self.window_ref.current_view() is self:
            self.window_ref.address.setText(url.toString())

    def on_load_finished(self, ok):
        url = self.url().toString()
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

    def on_render_process_terminated(self, status, exit_code):
        self.window_ref.statusBar().showMessage(
            f"WebEngine-Prozess beendet (Status {status}, Code {exit_code}). Seite neu laden.", 10000
        )

    def handle_fullscreen(self, request):
        request.accept()
        if request.toggleOn():
            self.window_ref.showFullScreen()
        else:
            self.window_ref.showNormal()

class LunaSurfer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LunaSurfer 0.3.4")
        self.resize(1250, 820)
        self.settings_data = read_json(CONFIG_FILE, {
            "home": "https://duckduckgo.com",
            "search": "https://duckduckgo.com/?q={}",
            "dark": True,
            "theme": "dark",
            "show_bookmarks_bar": True
        })
        self.profile = QWebEngineProfile("LunaSurfer", self)
        self.profile.setPersistentStoragePath(str(DATA_DIR / "webengine"))
        self.profile.setCachePath(str(pathlib.Path.home() / ".cache" / "lunasurfer" / "webengine"))
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)
        self.profile.downloadRequested.connect(self.on_download)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setMovable(True)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.on_tab_changed)
        self.setCentralWidget(self.tabs)

        bar = QToolBar("Navigation")
        bar.setMovable(False)
        bar.setIconSize(QSize(28, 28))
        bar.setMinimumHeight(54)
        self.addToolBar(bar)

        style = QApplication.style()
        self.back_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_ArrowBack), "", self); self.back_action.setToolTip("Zurück")
        self.back_action.triggered.connect(lambda: self.current_view() and self.current_view().back())
        bar.addAction(self.back_action)
        self.forward_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_ArrowForward), "", self); self.forward_action.setToolTip("Vorwärts")
        self.forward_action.triggered.connect(lambda: self.current_view() and self.current_view().forward())
        bar.addAction(self.forward_action)
        reload_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload), "", self); reload_action.setToolTip("Neu laden")
        reload_action.triggered.connect(lambda: self.current_view() and self.current_view().reload())
        bar.addAction(reload_action)
        home_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_DirHomeIcon), "", self); home_action.setToolTip("Startseite")
        home_action.triggered.connect(self.go_home)
        bar.addAction(home_action)

        self.address = QLineEdit()
        self.address.setPlaceholderText("Adresse oder Suchbegriff eingeben")
        self.address.returnPressed.connect(self.navigate)
        self.address.setClearButtonEnabled(True)
        # Give the address field substantially more room, similar to Chromium.
        self.address.setMinimumWidth(520)
        self.address.setSizePolicy(self.address.sizePolicy().horizontalPolicy(), self.address.sizePolicy().verticalPolicy())
        bar.addWidget(self.address)

        star = QAction("★", self)
        star.setToolTip("Aktuelle Seite als Lesezeichen hinzufügen")
        star.triggered.connect(self.add_bookmark)
        bar.addAction(star)
        newtab = QAction(style.standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder), "", self); newtab.setToolTip("Neuer Tab")
        newtab.triggered.connect(lambda: self.add_tab(self.settings_data["home"]))
        bar.addAction(newtab)

        menu = QMenu("Menü", self)
        menu.addAction("Neuer Tab", lambda: self.add_tab(self.settings_data["home"]))
        menu.addAction("Lesezeichen", self.show_bookmarks)
        menu.addAction("Verlauf", self.show_history)
        menu.addAction("Downloads-Ordner öffnen", self.open_downloads)
        menu.addSeparator()
        menu.addAction("Einstellungen", self.show_settings)
        menu.addAction("Über LunaSurfer", self.about)
        menu_button = QToolButton()
        menu_button.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_TitleBarMenuButton))
        menu_button.setIconSize(QSize(28, 28))
        menu_button.setToolTip("Menü")
        menu_button.setMenu(menu)
        menu_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        bar.addWidget(menu_button)

        # Chromium-style bookmarks bar directly below the navigation bar.
        self.bookmarks_bar = QToolBar("Lesezeichenleiste")
        self.bookmarks_bar.setMovable(False)
        self.bookmarks_bar.setIconSize(QSize(18, 18))
        self.bookmarks_bar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.bookmarks_bar.setMinimumHeight(36)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self.bookmarks_bar)
        self.refresh_bookmarks_bar()
        self.bookmarks_bar.setVisible(self.settings_data.get("show_bookmarks_bar", True))

        self.statusBar().showMessage("Bereit")
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
            QStatusBar { background: #142238; color: #dce8f8; }
        """)
        self.add_tab(self.settings_data.get("home", "https://duckduckgo.com"))
        self.set_shortcuts()

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

    def current_view(self):
        w = self.tabs.currentWidget()
        return w if isinstance(w, BrowserView) else None

    def add_tab(self, url=None, switch=True):
        view = BrowserView(self)
        page = QWebEnginePage(self.profile, view)
        view.setPage(page)
        self.apply_page_theme(view)
        index = self.tabs.addTab(view, "Neuer Tab")
        if switch: self.tabs.setCurrentIndex(index)
        view.load(QUrl(url or self.settings_data.get("home", "https://duckduckgo.com")))
        return view

    def apply_page_theme(self, view):
        """Apply the selected light/dark appearance to a web page."""
        settings = view.page().settings()
        force_dark = getattr(QWebEngineSettings.WebAttribute, "ForceDarkMode", None)
        if force_dark is not None:
            settings.setAttribute(force_dark, self.settings_data.get("theme", "dark") == "dark")

    def apply_theme_to_all_tabs(self):
        for index in range(self.tabs.count()):
            view = self.tabs.widget(index)
            if isinstance(view, BrowserView):
                self.apply_page_theme(view)
                # Reload so the rendering engine applies the new scheme immediately.
                view.reload()

    def close_tab(self, index):
        if self.tabs.count() <= 1:
            self.add_tab(self.settings_data.get("home"))
        widget = self.tabs.widget(index)
        self.tabs.removeTab(index)
        if widget: widget.deleteLater()

    def update_tab_title(self, view, title):
        index = self.tabs.indexOf(view)
        if index >= 0: self.tabs.setTabText(index, (title or "Neuer Tab")[:24])

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
        """Rebuild the bookmarks bar from the saved bookmarks."""
        if not hasattr(self, "bookmarks_bar"):
            return
        self.bookmarks_bar.clear()
        items = read_json(BOOKMARKS_FILE, [])
        style = QApplication.style()
        for item in items:
            url = item.get("url", "").strip()
            if not url:
                continue
            title = (item.get("title") or url).strip()
            action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload), title, self)
            action.setToolTip(url)
            action.triggered.connect(lambda checked=False, u=url: self.open_bookmark(u))
            self.bookmarks_bar.addAction(action)
            # Chromium-like editing: right-click a bookmark directly in the bar.
            button = self.bookmarks_bar.widgetForAction(action)
            if button is not None:
                button.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
                button.customContextMenuRequested.connect(
                    lambda pos, u=url, b=button: self.show_bookmark_context_menu(u, b.mapToGlobal(pos))
                )
        if items:
            self.bookmarks_bar.addSeparator()
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
        close_btn = QPushButton("Schließen")
        buttons.addWidget(open_btn)
        buttons.addWidget(edit_btn)
        buttons.addWidget(delete_btn)
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

        open_btn.clicked.connect(do_open)
        edit_btn.clicked.connect(do_edit)
        delete_btn.clicked.connect(do_delete)
        bookmark_list.itemDoubleClicked.connect(lambda item: do_open())
        close_btn.clicked.connect(dialog.accept)
        populate()
        dialog.exec()

    def show_history(self): self.show_list_dialog("Verlauf", HISTORY_FILE, "url")

    def on_download(self, download):
        suggested = download.suggestedFileName() or "download"
        DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
        target = DOWNLOAD_DIR / suggested
        if target.exists():
            stem, suffix = target.stem, target.suffix
            n = 1
            while (DOWNLOAD_DIR / f"{stem} ({n}){suffix}").exists(): n += 1
            target = DOWNLOAD_DIR / f"{stem} ({n}){suffix}"
        download.setDownloadDirectory(str(target.parent))
        download.setDownloadFileName(target.name)
        download.accept()
        self.statusBar().showMessage(f"Download gestartet: {target.name}", 5000)

    def open_downloads(self):
        import subprocess
        DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(["xdg-open", str(DOWNLOAD_DIR)])

    def show_settings(self):
        dialog = QDialog(self); dialog.setWindowTitle("LunaSurfer – Einstellungen")
        form = QFormLayout(dialog)
        home = QLineEdit(self.settings_data.get("home", "https://duckduckgo.com"))
        search = QLineEdit(self.settings_data.get("search", "https://duckduckgo.com/?q={}"))
        theme = QComboBox()
        theme.addItem("Dunkel", "dark")
        theme.addItem("Hell", "light")
        current_theme = self.settings_data.get("theme", "dark")
        theme.setCurrentIndex(0 if current_theme == "dark" else 1)
        show_bookmarks_bar = QCheckBox("Lesezeichenleiste unter der Adressleiste anzeigen")
        show_bookmarks_bar.setChecked(self.settings_data.get("show_bookmarks_bar", True))
        form.addRow("Startseite:", home)
        form.addRow("Such-URL ({} = Suchbegriff):", search)
        form.addRow("Webseiten-Design:", theme)
        form.addRow("", show_bookmarks_bar)
        buttons = QHBoxLayout()
        save = QPushButton("Speichern"); cancel = QPushButton("Abbrechen")
        buttons.addWidget(save); buttons.addWidget(cancel); form.addRow(buttons)
        save.clicked.connect(lambda: self.save_settings(dialog, home.text(), search.text(), theme.currentData(), show_bookmarks_bar.isChecked()))
        cancel.clicked.connect(dialog.reject)
        dialog.exec()

    def save_settings(self, dialog, home, search, theme, show_bookmarks_bar):
        self.settings_data["home"] = home.strip() or "https://duckduckgo.com"
        self.settings_data["search"] = search.strip() or "https://duckduckgo.com/?q={}"
        self.settings_data["theme"] = theme if theme in ("dark", "light") else "dark"
        self.settings_data["show_bookmarks_bar"] = bool(show_bookmarks_bar)
        write_json(CONFIG_FILE, self.settings_data)
        self.bookmarks_bar.setVisible(self.settings_data["show_bookmarks_bar"])
        self.apply_theme_to_all_tabs()
        dialog.accept()

    def about(self):
        QMessageBox.about(self, "Über LunaSurfer", "LunaSurfer 0.3.4\nQt 6 + QtWebEngine mit auswählbarem hellem/dunklem Webseiten-Design und optionaler Widevine-CDM-Einbindung.\nGoldisoft · 2026")

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("Goldisoft")
    window = LunaSurfer()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
