#!/usr/bin/env python3
"""LunaSurfer 0.3.38 - Qt 6 / QtWebEngine browser."""
import json
import pathlib
import sys
import urllib.parse
import os
import subprocess
import time
import shutil
import base64
import secrets
import string
import re
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

from PySide6.QtCore import QUrl, QSize, Qt, QTimer, QEvent, QObject, Slot, QTranslator, QLocale, QLibraryInfo, QFile, QIODevice
from PySide6.QtGui import QAction, QKeySequence, QIcon
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QToolBar, QLineEdit, QToolButton,
    QVBoxLayout, QWidget, QMenu, QFileDialog, QMessageBox, QDialog,
    QFormLayout, QPushButton, QHBoxLayout, QLabel, QCheckBox, QComboBox, QStyle, QInputDialog, QListWidget, QListWidgetItem, QTreeWidget, QTreeWidgetItem, QHeaderView, QProgressBar, QSizePolicy, QScrollArea, QDockWidget, QDialogButtonBox, QGroupBox, QTextBrowser
)
from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage, QWebEngineSettings, QWebEngineUrlRequestInterceptor, QWebEngineScript
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebChannel import QWebChannel
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

APP_NAME = "LunaSurfer"
_VERSION_FILE = pathlib.Path(__file__).resolve().with_name("VERSION")
try:
    APP_VERSION = _VERSION_FILE.read_text(encoding="utf-8").strip() or "0.3.35"
except OSError:
    APP_VERSION = "0.3.33"
CONFIG_DIR = pathlib.Path.home() / ".config" / "lunasurfer"
DATA_DIR = pathlib.Path.home() / ".local" / "share" / "lunasurfer"
CONFIG_FILE = CONFIG_DIR / "settings.json"
BOOKMARKS_FILE = DATA_DIR / "bookmarks.json"
HISTORY_FILE = DATA_DIR / "history.json"
SESSION_FILE = DATA_DIR / "session.json"
DOWNLOADS_FILE = DATA_DIR / "downloads.json"
PASSWORDS_FILE = DATA_DIR / "passwords.enc"
DOWNLOAD_DIR = pathlib.Path.home() / "Downloads"
CLEAR_WEB_DATA_MARKER = DATA_DIR / ".clear_web_data_on_start"

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



# Privacy mitigation injected before page scripts run. Noise is stable per
# origin (so a site remains functional) but differs between sites.
FINGERPRINT_SESSION_SEED = secrets.randbits(32)

FINGERPRINT_PROTECTION_JS = r"""
(() => {
  'use strict';
  try {
    const level = __LUNASURFER_FP_LEVEL__;
    const state = window.__lunaSurferFingerprintState ||
      (window.__lunaSurferFingerprintState = {enabled: true, level});
    state.enabled = true;
    state.level = level;
    if (state.installed) return;
    state.installed = true;

    const host = String(location.hostname || 'local').toLowerCase();
    let seed = 2166136261;
    for (let i = 0; i < host.length; i++) {
      seed ^= host.charCodeAt(i);
      seed = Math.imul(seed, 16777619);
    }
    const noise = (tag) => {
      let x = (seed ^ (tag >>> 0)) >>> 0;
      x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
      return x >>> 0;
    };
    const protectedAt = (minimum) => state.enabled && state.level >= minimum;
    const wrapMethod = (object, name, wrapper) => {
      try {
        if (!object || typeof object[name] !== 'function') return;
        const raw = object[name];
        Object.defineProperty(object, name, {
          configurable: true, writable: true, value: function(...args) {
            return wrapper.call(this, raw, args);
          }
        });
      } catch (_) {}
    };
    const dynamicGetter = (object, name, minimum, safeValue) => {
      try {
        const d = Object.getOwnPropertyDescriptor(object, name);
        if (!d || !d.configurable) return;
        const originalGet = d.get;
        const originalValue = d.value;
        Object.defineProperty(object, name, {
          configurable: true, enumerable: d.enumerable,
          get() {
            if (protectedAt(minimum)) return typeof safeValue === 'function' ? safeValue.call(this) : safeValue;
            return originalGet ? originalGet.call(this) : originalValue;
          }
        });
      } catch (_) {}
    };

    // Brave-inspired hardware farbling: values are stable for this site in
    // this browser session, but differ across first-party hosts and sessions.
    // Keep values within common desktop buckets to avoid implausible readings.
    const sessionSalt = (__LUNASURFER_FP_SESSION_SEED__ >>> 0);
    const siteChoice = (tag, choices) =>
      choices[noise((tag ^ sessionSalt) >>> 0) % choices.length];

    // Dynamic getters can be switched on/off immediately in already-open pages.
    // Canvas, WebGL and WebAudio code below is intentionally left unchanged.
    dynamicGetter(Navigator.prototype, 'hardwareConcurrency', 1,
      () => siteChoice(0x48434f52, [2, 4, 8]));
    // Keep device memory in one common desktop bucket instead of exposing
    // the real 8 GB value or varying it between sites.
    dynamicGetter(Navigator.prototype, 'deviceMemory', 3, 4);
    // Match Chromium's common Linux desktop platform token and the reduced UA.
    dynamicGetter(Navigator.prototype, 'platform', 1, 'Linux x86_64');
    dynamicGetter(Navigator.prototype, 'doNotTrack', 3, '1');
    dynamicGetter(Navigator.prototype, 'connection', 3, undefined);
    dynamicGetter(Navigator.prototype, 'battery', 3, undefined);
    try {
      const battery = Object.getOwnPropertyDescriptor(Navigator.prototype, 'getBattery');
      if (battery && battery.configurable) {
        const rawGetBattery = battery.value;
        Object.defineProperty(Navigator.prototype, 'getBattery', {
          configurable: true, writable: true, value: function(...args) {
            if (protectedAt(3)) return Promise.reject(new DOMException('Not supported', 'NotSupportedError'));
            return rawGetBattery.apply(this, args);
          }
        });
      }
    } catch (_) {}

    // Canvas: alter only data extracted by scripts, not the displayed canvas.
    const canvasProto = window.HTMLCanvasElement && HTMLCanvasElement.prototype;
    const contextProto = window.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype;
    const rawGetImageData = contextProto && contextProto.getImageData;
    const perturbImage = (img) => {
      try {
        const data = img && img.data;
        if (!data || data.length < 4) return img;
        const count = Math.floor(data.length / 4);
        for (let p = 0; p < count; p++) {
          const base = p * 4;
          for (let c = 0; c < 3; c++) {
            const bits = noise(0x51f15e ^ ((p * 0x9e3779b9) >>> 0) ^ (c * 0x45d9f3b)) & 3;
            data[base + c] = (data[base + c] & 0xFC) | bits;
          }
        }
      } catch (_) {}
      return img;
    };
    wrapMethod(contextProto, 'getImageData', function(raw, args) {
      const result = raw.apply(this, args);
      return protectedAt(1) ? perturbImage(result) : result;
    });
    const alterCanvasCopy = (canvas) => {
      try {
        const copy = document.createElement('canvas');
        copy.width = canvas.width; copy.height = canvas.height;
        const ctx = copy.getContext('2d');
        if (!ctx || !rawGetImageData || !copy.width || !copy.height) return canvas;
        ctx.drawImage(canvas, 0, 0);
        const w = Math.min(copy.width, 1024), h = Math.min(copy.height, 1024);
        const pixels = rawGetImageData.call(ctx, 0, 0, w, h);
        perturbImage(pixels);
        ctx.putImageData(pixels, 0, 0);
        return copy;
      } catch (_) { return canvas; }
    };
    wrapMethod(canvasProto, 'toDataURL', function(raw, args) {
      return raw.apply(protectedAt(1) ? alterCanvasCopy(this) : this, args);
    });
    wrapMethod(canvasProto, 'toBlob', function(raw, args) {
      return raw.apply(protectedAt(1) ? alterCanvasCopy(this) : this, args);
    });

    // WebGL: mask identifying strings and perturb readback only.
    const maskWebGL = (proto) => {
      wrapMethod(proto, 'getParameter', function(raw, args) {
        if (protectedAt(2)) {
          const param = args[0];
          if (param === 0x9245 || param === 0x1F00) return 'WebKit';
          if (param === 0x9246 || param === 0x1F01) return 'WebGL';
        }
        return raw.apply(this, args);
      });
      wrapMethod(proto, 'getExtension', function(raw, args) {
        if (protectedAt(2) && String(args[0]).toLowerCase() === 'webgl_debug_renderer_info') return null;
        return raw.apply(this, args);
      });
      wrapMethod(proto, 'getSupportedExtensions', function(raw, args) {
        const list = raw.apply(this, args);
        return protectedAt(2) && Array.isArray(list)
          ? list.filter(x => String(x).toLowerCase() !== 'webgl_debug_renderer_info') : list;
      });
      wrapMethod(proto, 'readPixels', function(raw, args) {
        const result = raw.apply(this, args);
        try {
          const format = args[4], type = args[5], pixels = args[6];
          if (protectedAt(2) && format === 0x1908 && type === 0x1401 &&
              pixels && ArrayBuffer.isView(pixels) && pixels.length >= 4) {
            for (let p = 0; p < Math.floor(pixels.length / 4); p++) {
              const base = p * 4;
              for (let c = 0; c < 3; c++) {
                const bits = noise(0x6a09e667 ^ ((p * 0x9e3779b9) >>> 0) ^ (c * 0xbb67ae85)) & 3;
                pixels[base + c] = (pixels[base + c] & 0xFC) | bits;
              }
            }
          }
        } catch (_) {}
        return result;
      });
    };
    if (window.WebGLRenderingContext) maskWebGL(WebGLRenderingContext.prototype);
    if (window.WebGL2RenderingContext) maskWebGL(WebGL2RenderingContext.prototype);

    // Brave-inspired WebAudio farbling. Brave's native implementation derives
    // a stable key from the session and eTLD+1 and protects AudioBuffer and
    // AnalyserNode readback APIs. This JS compatibility layer uses a tiny,
    // deterministic amplitude factor so the waveform shape is preserved.
    const audioSessionSeed = (__LUNASURFER_FP_SESSION_SEED__ >>> 0);
    const hostParts = host.split('.').filter(Boolean);
    const siteKey = hostParts.length > 1 ? hostParts.slice(-2).join('.') : host;
    let siteHash = 2166136261;
    for (let i = 0; i < siteKey.length; i++) {
      siteHash ^= siteKey.charCodeAt(i);
      siteHash = Math.imul(siteHash, 16777619);
    }
    let audioSeed = (siteHash ^ audioSessionSeed ^ 0x7f4a7c15) >>> 0;
    audioSeed ^= audioSeed >>> 16; audioSeed = Math.imul(audioSeed, 0x7feb352d);
    audioSeed ^= audioSeed >>> 15; audioSeed = Math.imul(audioSeed, 0x846ca68b);
    audioSeed ^= audioSeed >>> 16;
    // ±0.01%: enough to perturb exact hashes while avoiding audible noise.
    const audioScale = 1 + ((((audioSeed >>> 0) / 4294967295) * 2) - 1) * 0.0001;
    const farbledAudioArrays = new WeakSet();
    const farbleAudioArray = (array, once = true) => {
      if (!protectedAt(1) || !array || !ArrayBuffer.isView(array) || (once && farbledAudioArrays.has(array))) return array;
      try {
        if (array instanceof Float32Array) {
          for (let i = 0; i < array.length; i++) array[i] *= audioScale;
        } else if (array instanceof Uint8Array || array instanceof Uint8ClampedArray) {
          for (let i = 0; i < array.length; i++) {
            array[i] = Math.max(0, Math.min(255, Math.round(128 + (array[i] - 128) * audioScale)));
          }
        } else if (array instanceof Float64Array) {
          for (let i = 0; i < array.length; i++) array[i] *= audioScale;
        }
          if (once) farbledAudioArrays.add(array);
      } catch (_) {}
      return array;
    };

    const audioBufferProto = window.AudioBuffer && AudioBuffer.prototype;
    wrapMethod(audioBufferProto, 'getChannelData', function(raw, args) {
      const result = raw.apply(this, args);
      return farbleAudioArray(result);
    });
    wrapMethod(audioBufferProto, 'copyFromChannel', function(raw, args) {
      const result = raw.apply(this, args);
      farbleAudioArray(args[0], false);
      return result;
    });

    const analyserProto = window.AnalyserNode && AnalyserNode.prototype;
    for (const method of ['getFloatTimeDomainData', 'getByteTimeDomainData',
                          'getFloatFrequencyData', 'getByteFrequencyData']) {
      wrapMethod(analyserProto, method, function(raw, args) {
        const result = raw.apply(this, args);
        farbleAudioArray(args[0], false);
        return result;
      });
    }

    // Reduce high-entropy UA Client Hints at every protection level.
    if (window.NavigatorUAData && NavigatorUAData.prototype) {
      wrapMethod(NavigatorUAData.prototype, 'getHighEntropyValues', function(raw, args) {
        return raw.apply(this, args).then(values => {
          if (!protectedAt(1)) return values;
          const hints = args[0] || [];
          const safe = Object.assign({}, values);
          if (hints.includes('architecture')) safe.architecture = 'x86';
          if (hints.includes('bitness')) safe.bitness = '64';
          if (hints.includes('model')) safe.model = '';
          if (hints.includes('platform')) safe.platform = 'Linux';
          if (hints.includes('platformVersion')) safe.platformVersion = '0.0.0';
          if (hints.includes('wow64')) safe.wow64 = false;
          // Keep Client Hints aligned with the selected Chromium User-Agent version.
          // patch/build numbers through high-entropy Client Hints.
          const reducedBrands = [
            {brand: 'Chromium', version: '__LUNASURFER_UA_MAJOR__'},
            {brand: 'Not(A:Brand', version: '99'}
          ];
          if (hints.includes('brands')) safe.brands = reducedBrands;
          if (hints.includes('fullVersionList')) {
            safe.fullVersionList = [
              {brand: 'Chromium', version: '__LUNASURFER_UA_FULL_VERSION__'},
              {brand: 'Not(A:Brand', version: '99.0.0.0'}
            ];
          }
          if (hints.includes('uaFullVersion')) safe.uaFullVersion = '__LUNASURFER_UA_FULL_VERSION__';
          if (hints.includes('formFactors')) safe.formFactors = ['Desktop'];
          return safe;
        });
      });
    }
  } catch (_) {}
})();
"""


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

    def mouseDoubleClickEvent(self, event):
        # A double-click anywhere in the address field selects the complete URL,
        # matching the expected browser address-bar behavior.
        super().mouseDoubleClickEvent(event)
        self.selectAll()

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


class LoginCaptureBridge(QObject):
    """Forwards submitted login fields to LunaSurfer's local password manager."""
    def __init__(self, window, view):
        super().__init__(view)
        self.window_ref = window
        self.view_ref = view

    @Slot(str, str)
    def diagnostic(self, event, details=""):
        try:
            self.window_ref._password_debug_log("js_" + str(event)[:64], str(details)[:240])
        except Exception:
            pass

    @Slot(str, str, str, result=str)
    def capture(self, page_url, username, password):
        try:
            return self.window_ref.capture_login_submission(self.view_ref, page_url, username, password)
        except Exception:
            return "continue"

    @Slot(str, bool, result=str)
    def suggestions(self, page_url, interactive):
        try:
            related_url = getattr(self.view_ref, "_password_flow_origin_url", "")
            return self.window_ref.password_suggestions(page_url, interactive, related_url)
        except Exception:
            return "[]"

    @Slot(str, str)
    def bindCredentialToRelyingParty(self, page_url, username):
        try:
            related_url = getattr(self.view_ref, "_password_flow_origin_url", "")
            self.window_ref.bind_password_entry_to_relying_party(page_url, username, related_url)
        except Exception:
            pass

    @Slot(str, str, str, result=str)
    def confirmSave(self, page_url, username, password):
        try:
            related_url = getattr(self.view_ref, "_password_flow_origin_url", "")
            return self.window_ref.confirm_login_save(page_url, username, password, related_url)
        except Exception:
            return "no"


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
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, self.window_ref.settings_data.get("javascript_enabled", True))
        # Allow websites to copy text after an explicit user action.  Many modern
        # pages use navigator.clipboard.writeText() for their own Copy buttons.
        clipboard_attr = getattr(QWebEngineSettings.WebAttribute, "JavascriptCanAccessClipboard", None)
        if clipboard_attr is not None:
            settings.setAttribute(clipboard_attr, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)
        page.fullScreenRequested.connect(self.handle_fullscreen)
        # Handle camera, microphone, location and notification permissions in LunaSurfer.
        page.permissionRequested.connect(self.window_ref.handle_permission_request)
        self.login_channel = QWebChannel(page)
        self.login_bridge = LoginCaptureBridge(self.window_ref, self)
        self.login_channel.registerObject('lunaLoginBridge', self.login_bridge)
        page.setWebChannel(self.login_channel)

    def contextMenuEvent(self, event):
        """Show LunaSurfer's own context menu without QtWebEngine's native menu.

        QtWebEngine's native RenderViewContextMenu has crashed on some Debian/
        Raspberry Pi builds while recursively building link actions.  Building
        a small QMenu ourselves avoids createStandardContextMenu() and pageAction()
        entirely, while keeping the browser's URL-based new-tab action.
        """
        try:
            link_url = QUrl()
            try:
                data = self.page().contextMenuData()
                candidate = data.linkUrl()
                if candidate and candidate.isValid() and not candidate.isEmpty():
                    link_url = QUrl(candidate.toString())
            except (AttributeError, RuntimeError, TypeError):
                pass

            global_pos = event.globalPos()
            local_pos = event.pos()
            event.accept()

            # contextMenuData().linkUrl() can be stale on some QtWebEngine builds.
            # Always hit-test the DOM at the actual pointer position first, and
            # use Qt's URL only if the DOM lookup finds no anchor.
            js = """
                (function(x, y) {
                    const nodes = document.elementsFromPoint
                        ? document.elementsFromPoint(x, y)
                        : [document.elementFromPoint(x, y)];
                    for (const node of nodes) {
                        let el = node;
                        while (el) {
                            if (el.matches && el.matches('a[href]')) return el.href;
                            el = el.parentElement;
                        }
                    }
                    return '';
                })(%d, %d)
            """ % (local_pos.x(), local_pos.y())
            fallback_url = link_url.toString()
            self.page().runJavaScript(
                js,
                lambda result, gp=global_pos, fallback=fallback_url:
                    self._show_context_menu_at(gp, result if result else fallback)
            )
            return
        except Exception as exc:
            try:
                self.window_ref.statusBar().showMessage(f"Kontextmenü: {exc}", 6000)
            except Exception:
                pass
            # Do not call the QtWebEngine native fallback here: that is the
            # menu-construction path implicated by the crash backtrace.
            try:
                event.accept()
            except Exception:
                pass

    def _show_context_menu_at(self, global_pos, clicked_link=""):
        """Build a lightweight, icon-free menu using only ordinary QMenu actions."""
        menu = QMenu(self)
        is_english = self.window_ref.settings_data.get("language", "de") == "en"

        labels = {
            "back": "Back" if is_english else "Zurück",
            "forward": "Forward" if is_english else "Vorwärts",
            "reload": "Reload" if is_english else "Neu laden",
            "open_link": "Open link in new tab" if is_english else "Link in neuem Tab öffnen",
            "open_page": "Open page in new tab" if is_english else "Seite in neuem Tab öffnen",
            "copy_link": "Copy link address" if is_english else "Link-Adresse kopieren",
            "copy_page": "Copy page address" if is_english else "Seitenadresse kopieren",
            "save_page": "Save page as…" if is_english else "Seite speichern unter…",
            "view_source": "View page source" if is_english else "Quelltext anzeigen",
            "reload_cache": "Reload (bypass cache)" if is_english else "Neu laden (Cache umgehen)",
            "devtools": "Open developer tools (F12)" if is_english else "Entwicklerwerkzeuge öffnen (F12)",
            "copy_selection": "Copy selection" if is_english else "Auswahl kopieren",
            "cut": "Cut" if is_english else "Ausschneiden",
            "copy": "Copy" if is_english else "Kopieren",
            "paste": "Paste" if is_english else "Einfügen",
        }

        history = self.history()
        back_action = menu.addAction(labels["back"], self.back)
        back_action.setEnabled(history.canGoBack())
        forward_action = menu.addAction(labels["forward"], self.forward)
        forward_action.setEnabled(history.canGoForward())
        menu.addAction(labels["reload"], self.reload)
        menu.addSeparator()

        has_link = bool(clicked_link)
        if has_link:
            menu.addAction(
                labels["open_link"],
                lambda u=clicked_link: self.window_ref.add_tab(u, switch=True)
            )
            menu.addAction(
                labels["copy_link"],
                lambda u=clicked_link: QApplication.clipboard().setText(u)
            )
        else:
            menu.addAction(
                labels["open_page"],
                lambda u=self.url().toString(): self.window_ref.add_tab(u, switch=True)
            )
            menu.addAction(
                labels["copy_page"],
                lambda u=self.url().toString(): QApplication.clipboard().setText(u)
            )

        try:
            selected = self.page().selectedText()
        except (AttributeError, RuntimeError):
            selected = ""
        if selected:
            menu.addAction(
                labels["copy_selection"],
                lambda value=selected: QApplication.clipboard().setText(value)
            )

        # Standard editing commands for editable page fields and text selections.
        # Keep these as explicit WebEngine actions so the custom menu remains
        # independent of QtWebEngine's crash-prone native context menu.
        menu.addSeparator()
        menu.addAction(
            labels["cut"],
            lambda: self.page().triggerAction(QWebEnginePage.WebAction.Cut)
        )
        menu.addAction(
            labels["copy"],
            lambda: self.page().triggerAction(QWebEnginePage.WebAction.Copy)
        )
        menu.addAction(
            labels["paste"],
            lambda: self.page().triggerAction(QWebEnginePage.WebAction.Paste)
        )

        menu.addSeparator()
        menu.addAction(labels["save_page"], self.save_page_as)
        # Use the explicit WebEngine ViewSource action, not the native context menu.
        menu.addAction(
            labels["view_source"],
            lambda: self.page().triggerAction(QWebEnginePage.WebAction.ViewSource)
        )
        menu.addAction(labels["reload_cache"], self.reload_bypass_cache)
        menu.addAction(labels["devtools"], self.window_ref.show_devtools)
        menu.exec(global_pos)

    def save_page_as(self):
        """Ask for the exact destination before triggering QtWebEngine's Save Page."""
        title = (self.title() or "Webseite").strip()
        safe_title = "".join(ch for ch in title if ch not in '<>:"/\\\\|?*').strip() or "Webseite"
        suggested = self.window_ref.download_dir / (safe_title[:100] + ".mhtml")
        is_english = self.window_ref.settings_data.get("language", "de") == "en"
        dialog = QFileDialog(self.window_ref)
        dialog.setWindowTitle("Save page as" if is_english else "Seite speichern unter")
        dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        dialog.setFileMode(QFileDialog.FileMode.AnyFile)
        dialog.setNameFilters(
            ["Web page (*.mhtml)", "All files (*.*)"] if is_english else
            ["Webseite (*.mhtml)", "Alle Dateien (*.*)"]
        )
        dialog.setDirectory(str(suggested.parent))
        dialog.selectFile(suggested.name)
        dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        # The native GTK/Qt chooser ignores LunaSurfer's selected UI language.
        # Use Qt's widget dialog and explicitly translate its standard buttons.
        button_box = dialog.findChild(QDialogButtonBox)
        if button_box is not None:
            accept_button = button_box.button(QDialogButtonBox.StandardButton.Save)
            cancel_button = button_box.button(QDialogButtonBox.StandardButton.Cancel)
            if accept_button is not None:
                accept_button.setText("Save" if is_english else "Speichern")
            if cancel_button is not None:
                cancel_button.setText("Cancel" if is_english else "Abbrechen")
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        selected = dialog.selectedFiles()[0] if dialog.selectedFiles() else ""
        if not selected:
            return
        target = pathlib.Path(selected).expanduser()
        if not target.suffix:
            target = target.with_suffix(".mhtml")
        target.parent.mkdir(parents=True, exist_ok=True)
        self.window_ref._next_download_path = target
        self.page().triggerAction(QWebEnginePage.WebAction.SavePage)

    def reload_bypass_cache(self):
        action = getattr(QWebEnginePage.WebAction, "ReloadAndBypassCache", None)
        if action is not None:
            self.page().triggerAction(action)
        else:
            self.page().profile().clearHttpCache()
            self.reload()

    def createWindow(self, window_type):
        if self.window_ref.settings_data.get("block_popups", True):
            self.window_ref.statusBar().showMessage("Pop-up wurde blockiert.", 4000)
            return None
        self.window_ref.add_tab("about:blank", switch=True)
        return self.window_ref.current_view()

    def on_title(self, title):
        self.window_ref.update_tab_title(self, title)

    def on_url(self, url):
        current_url = url.toString()
        previous_url = getattr(self, "_password_last_url", "")
        try:
            previous = urllib.parse.urlparse(previous_url)
            current = urllib.parse.urlparse(current_url)
            previous_host = (previous.hostname or "").lower()
            current_host = (current.hostname or "").lower()
            flow_origin = getattr(self, "_password_flow_origin_url", "")
            flow_host = (urllib.parse.urlparse(flow_origin).hostname or "").lower() if flow_origin else ""
            if previous_host and current_host and previous_host != current_host:
                if flow_host and current_host == flow_host:
                    # The authentication hand-off returned to the originating site.
                    self._password_flow_origin_url = ""
                elif not flow_host:
                    self._password_flow_origin_url = f"{previous.scheme}://{previous.netloc}/"
        except Exception:
            pass
        self._password_last_url = current_url
        pending = getattr(self.window_ref, "_pending_login_save", None)
        if pending and pending.get("view") is self:
            try:
                target_host = (urllib.parse.urlparse(current_url).hostname or "").lower()
                if (pending.get("site_key") == "accounts.google.com"
                        and target_host in pending.get("continue_hosts", set())):
                    QTimer.singleShot(250, lambda p=pending: self.window_ref._finish_pending_login_save(p))
            except Exception:
                pass
        if self.window_ref.current_view() is self:
            self.window_ref.address.setText(current_url)
        if current_url != getattr(self, "_last_language_checked_url", None):
            self._last_language_checked_url = current_url

    def _check_page_language_for_translation(self, url):
        """Offer German translation when a loaded page declares another language."""
        if not url.startswith(("http://", "https://")):
            return
        # Avoid offering translation on Google Translate's own translated view.
        if "translate.google." in url:
            return
        js = r"""
            (() => {
                const html = document.documentElement;
                let lang = (html.getAttribute('lang') || '').trim().toLowerCase();
                if (!lang) {
                    const meta = document.querySelector('meta[http-equiv="content-language"], meta[name="language"]');
                    if (meta) lang = (meta.content || '').trim().toLowerCase().split(',')[0];
                }
                if (!lang) {
                    const text = (document.body ? document.body.innerText : '').slice(0, 12000).toLowerCase();
                    const en = (text.match(/\b(the|and|you|this|that|with|for|your|what|is|are)\b/g) || []).length;
                    const de = (text.match(/\b(der|die|das|und|ist|sind|mit|für|ein|eine|nicht|auf)\b/g) || []).length;
                    if (en >= 4 && en > de * 1.25) lang = 'en';
                    else if (de >= 3) lang = 'de';
                }
                return lang;
            })();
        """
        view = self
        def language_ready(language):
            try:
                if self.window_ref.current_view() is not view:
                    return
                language = (language or "").strip().lower().replace("_", "-")
                if not language or language in ("de", "de-de", "de-at", "de-ch") or language.startswith("de-"):
                    return
                if self.window_ref._translation_notice_url == url:
                    return
                self.window_ref._translation_notice_url = url
                self.window_ref.offer_page_translation(url, language)
            except RuntimeError:
                pass
        self.page().runJavaScript(js, language_ready)

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
            self._check_page_language_for_translation(url)
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
            "cookie_mode": "all",
            "ask_download_location": False,
            "send_dnt": False,
            "confirm_close_multiple_tabs": True,
            "remember_window_size": True,
            "window_geometry": None,
            "font_size": "Mittel",
            "website_readability": "normal",
            "website_color_mode": "normal",
            "language": "de",
            "default_browser": False,
            "adblock_enabled": True,
            "adblock_whitelist": [],
            "adblock_custom_blocklist": [],
            "adblock_strength": "standard",
            "fingerprint_enabled": True,
            "fingerprint_strength": "standard",
            "user_agent_mode": "privacy",
            "user_agent_custom": ""
        })
        self.settings_data.setdefault("translation_provider", "google")
        self.settings_data.setdefault("website_color_mode", "normal")
        if self.settings_data.get("website_color_mode") not in ("normal", "black"):
            self.settings_data["website_color_mode"] = "normal"
        self.settings_data.setdefault("fingerprint_enabled", True)
        self.settings_data.setdefault("fingerprint_strength", "standard")
        if self.settings_data.get("remember_window_size", True):
            geometry = self.settings_data.get("window_geometry")
            if isinstance(geometry, (list, tuple)) and len(geometry) == 4:
                try:
                    self.setGeometry(*[int(v) for v in geometry])
                except (TypeError, ValueError):
                    pass
        # A full privacy wipe is finalized before QtWebEngine opens its profile.
        # This safely removes origin storage (Local Storage, IndexedDB, Service Workers, etc.).
        if CLEAR_WEB_DATA_MARKER.exists():
            for data_path in (DATA_DIR / "webengine", pathlib.Path.home() / ".cache" / "lunasurfer" / "webengine"):
                try:
                    shutil.rmtree(data_path, ignore_errors=True)
                except Exception:
                    pass
            try:
                CLEAR_WEB_DATA_MARKER.unlink(missing_ok=True)
            except Exception:
                pass
        self._password_fernet = None
        self._password_entries = []
        self._password_unlock_prompted = False
        # Suppress repeated automatic unlock prompts after an explicit cancel.
        self._password_unlock_suppressed_until = 0.0
        self._pending_login_save = None
        self._password_lock_timer = QTimer(self)
        self._password_lock_timer.setSingleShot(True)
        self._password_lock_timer.timeout.connect(self.lock_password_manager)
        self.profile = QWebEngineProfile("LunaSurfer", self)
        self._native_user_agent = self.profile.httpUserAgent()
        self.settings_data.setdefault("user_agent_mode", "privacy")
        self.settings_data.setdefault("user_agent_custom", "")
        if self.settings_data.get("user_agent_mode") not in ("privacy", "native", "custom"):
            self.settings_data["user_agent_mode"] = "privacy"
        self.apply_user_agent()
        self.profile.setPersistentStoragePath(str(DATA_DIR / "webengine"))
        self.profile.setCachePath(str(pathlib.Path.home() / ".cache" / "lunasurfer" / "webengine"))
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies)
        self.cookie_store = self.profile.cookieStore()
        self.cookie_filter_callback = self.filter_cookies
        self.cookie_store.setCookieFilter(self.cookie_filter_callback)
        self.apply_cookie_mode()
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

        # Chromium-style developer tools, docked to the right. A single tools
        # page follows the currently selected browser tab.
        self.devtools_view = QWebEngineView(self)
        # Keep the inspector comfortably wide: 590 px is roughly 15.6 cm
        # at 96 DPI, about 5 cm wider than the previous 400 px setting.
        self.devtools_view.setMinimumWidth(590)
        self.devtools_page = QWebEnginePage(self.profile, self.devtools_view)
        self.devtools_view.setPage(self.devtools_page)
        self.devtools_dock = QDockWidget(self.tr("Entwicklerwerkzeuge", "Developer tools"), self)
        self.devtools_dock.setMinimumWidth(590)
        self.devtools_dock.setObjectName("developerToolsDock")
        self.devtools_dock.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)
        self.devtools_dock.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetClosable | QDockWidget.DockWidgetFeature.DockWidgetMovable)
        self.devtools_dock.setWidget(self.devtools_view)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.devtools_dock)
        self.devtools_dock.hide()
        self._devtools_inspected_page = None
        self.devtools_dock.visibilityChanged.connect(self._on_devtools_visibility_changed)

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

        # Whole-page translation is delegated to Google Translate's page proxy.
        # The original URL is retained per tab so users can return with one click.
        self._translation_originals = {}
        self._translation_notice_url = None
        self._translation_notice_button = None
        self.translate_button = QToolButton(self)
        self.translate_button.setText("文")
        self.translate_button.setToolTip(self.tr("Webseite übersetzen", "Translate webpage"))
        self.translate_button.setFixedSize(42, 42)
        self.translate_button.setStyleSheet("font-size: 22px; font-weight: 600; border-radius: 8px; padding: 2px;")
        translate_menu = QMenu(self.translate_button)
        for lang_code, lang_name in [("de", "Deutsch"), ("en", "English"), ("fr", "Français"), ("it", "Italiano"), ("nl", "Nederlands"), ("es", "Español"), ("pt", "Português"), ("pl", "Polski"), ("ru", "Русский"), ("tr", "Türkçe"), ("ja", "日本語"), ("zh-CN", "中文")]:
            act = translate_menu.addAction(lang_name)
            act.triggered.connect(lambda checked=False, code=lang_code: self.translate_current_page_selected(code))
        translate_menu.addSeparator()
        original_action = translate_menu.addAction(self.tr("Originalseite anzeigen", "Show original page"))
        original_action.triggered.connect(self.show_original_page)
        self.translate_button.setMenu(translate_menu)
        self.translate_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        # Keep the bookmark star directly beside the address field, as in the
        # earlier LunaSurfer toolbar layout.
        # (The translation control follows the star.)
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
        bar.addWidget(self.translate_button)

        # One-click access to unlock the encrypted vault before signing in.
        self.password_action = QAction("PW", self)
        self.password_action.setToolTip(self.tr(
            "Passwortmanager entsperren – gespeicherte Logins automatisch ausfüllen (Strg+Umschalt+L)",
            "Unlock password manager – autofill saved logins (Ctrl+Shift+L)"))
        self.password_action.setShortcut(QKeySequence("Ctrl+Shift+L"))
        self.password_action.triggered.connect(self.show_password_manager)
        self.addAction(self.password_action)
        self.password_button = QToolButton(self)
        self.password_button.setDefaultAction(self.password_action)
        self.password_button.setText("PW")
        self.password_button.setFixedSize(36, 34)
        self.password_button.setStyleSheet("font-size: 14px; font-weight: 700; color: #f5d76e; border: 1px solid #8b7538; border-radius: 7px; padding: 0px;")
        bar.addWidget(self.password_button)

        # Compact toolbar buttons for Download Manager and Ad Blocker.
        self.download_action = QAction("⇩", self)
        self.download_action.setToolTip(self.tr("Download-Manager", "Download manager"))
        self.download_action.triggered.connect(self.show_download_manager)
        self.download_button = QToolButton(self); self.download_button.setDefaultAction(self.download_action)
        self.download_button.setText("⇩"); self.download_button.setFixedSize(34, 34)
        self.download_button.setStyleSheet("font-size: 24px; font-weight: bold; color: #6ee7ff; border: 1px solid #3285bd; border-radius: 7px; padding: 0px;")
        bar.addWidget(self.download_button)

        self.adblock_action = QAction("🛡", self)
        self.adblock_action.setToolTip(self.tr("Schutz & Privatsphäre", "Protection & privacy"))
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
        menu.addAction(self.tr("Downloads-Ordner öffnen", "Open downloads folder"), self.open_downloads)
        menu.addSeparator()
        menu.addAction(self.tr("Einstellungen", "Settings"), self.show_settings)
        menu.addAction(self.tr("Anleitung", "User guide"), self.show_manual)
        menu.addAction(self.tr("Entwicklerwerkzeuge (F12)", "Developer tools (F12)"), self.toggle_devtools)
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

    def _bind_devtools_to_current_page(self):
        view = self.current_view()
        if not view:
            return
        page = view.page()
        try:
            page.setDevToolsPage(self.devtools_page)
            self._devtools_inspected_page = page
        except Exception as exc:
            self.statusBar().showMessage(f"DevTools konnten nicht verbunden werden: {exc}", 6000)

    def _on_devtools_visibility_changed(self, visible):
        if visible:
            self._bind_devtools_to_current_page()
            self.devtools_view.setFocus()

    def show_devtools(self):
        self._bind_devtools_to_current_page()
        self.devtools_dock.show()
        self.devtools_dock.raise_()
        # Request the wider inspector on the right. The minimum width above
        # prevents Qt from shrinking it below the requested usable width.
        self.resizeDocks([self.devtools_dock], [610], Qt.Orientation.Horizontal)

    def toggle_devtools(self):
        if self.devtools_dock.isVisible():
            self.devtools_dock.hide()
        else:
            self.show_devtools()

    def set_shortcuts(self):
        for seq, callback in [
            ("Ctrl+L", lambda: (self.address.setFocus(), self.address.selectAll())),
            ("Ctrl+T", lambda: self.add_tab(self.settings_data["home"])),
            ("Ctrl+W", lambda: self.close_tab(self.tabs.currentIndex())),
            ("Ctrl+R", lambda: self.current_view() and self.current_view().reload()),
            ("F12", self.toggle_devtools),
            ("Alt+Left", lambda: self.current_view() and self.current_view().back()),
            ("Alt+Right", lambda: self.current_view() and self.current_view().forward()),
        ]:
            action = QAction(self); action.setShortcut(QKeySequence(seq)); action.triggered.connect(callback)
            self.addAction(action)

    def tr(self, de, en):
        """Return the selected application language."""
        return en if self.settings_data.get("language", "de") == "en" else de

    def handle_permission_request(self, permission):
        """Ask the user for website permissions and optionally remember the decision."""
        try:
            origin = permission.origin().toString()
            raw_type = str(permission.permissionType()).lower()
            # Qt 6.8 enum names include AudioCapture, VideoCapture, Geolocation,
            # and Notifications. Match by stable suffix to tolerate enum formatting.
            if "audiocapture" in raw_type:
                key, label = "permission_microphone", self.tr("Mikrofon", "Microphone")
            elif "videocapture" in raw_type:
                key, label = "permission_camera", self.tr("Kamera", "Camera")
            elif "geolocation" in raw_type:
                key, label = "permission_location", self.tr("Standort", "Location")
            elif "notification" in raw_type:
                key, label = "permission_notifications", self.tr("Benachrichtigungen", "Notifications")
            else:
                # Do not silently grant permission types not managed by the settings.
                permission.deny()
                return

            host = QUrl(origin).host() or origin
            remembered = self.settings_data.setdefault("remembered_permissions", {})
            site_permissions = remembered.get(origin, {})
            saved_choice = site_permissions.get(key)
            global_choice = self.settings_data.get(key, "ask")

            choice = global_choice if global_choice in ("allow", "block") else saved_choice
            if choice == "allow":
                permission.grant()
                return
            if choice == "block":
                permission.deny()
                return

            dialog = QMessageBox(self)
            dialog.setIcon(QMessageBox.Icon.Question)
            dialog.setWindowTitle(self.tr("Berechtigungsanfrage", "Permission request"))
            dialog.setText(self.tr(
                f"{host} möchte auf folgende Funktion zugreifen:\n{label}",
                f"{host} wants to access the following feature:\n{label}"
            ))
            remember_box = QCheckBox(self.tr(
                "Diese Entscheidung für diese Webseite merken",
                "Remember this decision for this website"
            ), dialog)
            dialog.setCheckBox(remember_box)
            allow_button = dialog.addButton(self.tr("Erlauben", "Allow"), QMessageBox.ButtonRole.AcceptRole)
            block_button = dialog.addButton(self.tr("Blockieren", "Block"), QMessageBox.ButtonRole.RejectRole)
            dialog.exec()
            allowed = dialog.clickedButton() == allow_button
            if remember_box.isChecked():
                remembered.setdefault(origin, {})[key] = "allow" if allowed else "block"
                self.settings_data["remembered_permissions"] = remembered
                write_json(CONFIG_FILE, self.settings_data)
            if allowed:
                permission.grant()
            else:
                permission.deny()
        except Exception as exc:
            try:
                permission.deny()
            except Exception:
                pass
            try:
                self.statusBar().showMessage(self.tr(
                    f"Berechtigungsfehler: {exc}", f"Permission error: {exc}"
                ), 8000)
            except Exception:
                pass

    def confirm_action(self, title, message):
        """Show a confirmation dialog with buttons in the selected UI language."""
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Question)
        dialog.setWindowTitle(title)
        dialog.setText(message)
        dialog.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        dialog.setDefaultButton(QMessageBox.StandardButton.No)
        yes_button = dialog.button(QMessageBox.StandardButton.Yes)
        no_button = dialog.button(QMessageBox.StandardButton.No)
        if yes_button is not None:
            yes_button.setText(self.tr("Ja", "Yes"))
        if no_button is not None:
            no_button.setText(self.tr("Nein", "No"))
        return dialog.exec() == QMessageBox.StandardButton.Yes

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
        menu.addAction(self.tr("Anleitung", "User guide"), self.show_manual)
        menu.addAction(self.tr("Entwicklerwerkzeuge (F12)", "Developer tools (F12)"), self.toggle_devtools)
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

    def effective_user_agent(self):
        """Return the configured HTTP User-Agent without changing the engine."""
        mode = self.settings_data.get("user_agent_mode", "privacy")
        if mode == "native":
            return getattr(self, "_native_user_agent", self.profile.httpUserAgent())
        if mode == "custom":
            custom = str(self.settings_data.get("user_agent_custom", "")).strip()
            if custom:
                return custom
        # Preserve the previous behavior: the reduced UA is coupled to the
        # fingerprint-protection switch unless the user explicitly overrides it.
        if not self.settings_data.get("fingerprint_enabled", True):
            return getattr(self, "_native_user_agent", self.profile.httpUserAgent())
        return ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

    def apply_user_agent(self, reload_tabs=False):
        """Apply the selected User-Agent immediately to the shared profile."""
        try:
            if hasattr(self, "profile"):
                self.profile.setHttpUserAgent(self.effective_user_agent())
        except Exception:
            pass
        if reload_tabs and hasattr(self, "tabs"):
            for index in range(self.tabs.count()):
                view = self.tabs.widget(index)
                if isinstance(view, BrowserView):
                    view.reload()

    def fingerprint_script_source(self, level):
        """Build the protection script with UA Client Hints matching the UA version."""
        import re
        ua = self.effective_user_agent()
        match = re.search(r"(?:Chrome|Chromium)/(\d+(?:\.\d+){0,3})", ua)
        if match:
            full_version = match.group(1)
            parts = full_version.split(".")
            while len(parts) < 4:
                parts.append("0")
        else:
            match_native = re.search(r"(?:Chrome|Chromium)/(\d+(?:\.\d+){0,3})", getattr(self, "_native_user_agent", ""))
            full_version = match_native.group(1) if match_native else "122.0.0.0"
            parts = full_version.split(".")
            while len(parts) < 4:
                parts.append("0")
        return (FINGERPRINT_PROTECTION_JS
                .replace("__LUNASURFER_FP_LEVEL__", str(level))
                .replace("__LUNASURFER_FP_SESSION_SEED__", str(FINGERPRINT_SESSION_SEED))
                .replace("__LUNASURFER_UA_MAJOR__", parts[0])
                .replace("__LUNASURFER_UA_FULL_VERSION__", ".".join(parts[:4])))

    def apply_fingerprint_to_view(self, view):
        """Synchronize the current document after navigation completes."""
        if not isinstance(view, BrowserView):
            return
        if self.settings_data.get("fingerprint_enabled", True):
            levels = {"standard": 1, "strong": 2, "maximum": 3}
            level = levels.get(self.settings_data.get("fingerprint_strength", "standard"), 1)
            view.page().runJavaScript(self.fingerprint_script_source(level))
        else:
            view.page().runJavaScript("if (window.__lunaSurferFingerprintState) window.__lunaSurferFingerprintState.enabled = false;")

    def apply_fingerprint_protection_live(self):
        """Update fingerprint defenses in every existing and future page without restarting."""
        enabled = bool(self.settings_data.get("fingerprint_enabled", True))
        levels = {"standard": 1, "strong": 2, "maximum": 3}
        level = levels.get(self.settings_data.get("fingerprint_strength", "standard"), 1)
        self.apply_user_agent()
        source = self.fingerprint_script_source(level)
        disable_source = "if (window.__lunaSurferFingerprintState) window.__lunaSurferFingerprintState.enabled = false;"
        for index in range(self.tabs.count()):
            view = self.tabs.widget(index)
            if not isinstance(view, BrowserView):
                continue
            page = view.page()
            scripts = page.scripts()
            for old_script in scripts.find("LunaSurferFingerprintProtection"):
                scripts.remove(old_script)
            if enabled:
                script = QWebEngineScript()
                script.setName("LunaSurferFingerprintProtection")
                script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
                script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
                script.setRunsOnSubFrames(True)
                script.setSourceCode(source)
                scripts.insert(script)
                # Also patch the currently loaded document immediately.
                page.runJavaScript(source)
            else:
                # Existing wrappers become pass-through immediately; no reload.
                page.runJavaScript(disable_source)

    def add_tab(self, url=None, switch=True):
        view = BrowserView(self)
        page = QWebEnginePage(self.profile, view)
        view.setPage(page)
        view.configure_web_page()
        # Register login capture before the first real navigation so even an
        # authentication URL opened directly receives the DocumentReady hook.
        self.install_login_capture(view)
        # Install protection before the first page script executes.
        if self.settings_data.get("fingerprint_enabled", True):
            levels = {"standard": 1, "strong": 2, "maximum": 3}
            level = levels.get(self.settings_data.get("fingerprint_strength", "standard"), 1)
            privacy_script = QWebEngineScript()
            privacy_script.setName("LunaSurferFingerprintProtection")
            privacy_script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
            privacy_script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
            privacy_script.setRunsOnSubFrames(True)
            privacy_script.setSourceCode(self.fingerprint_script_source(level))
            page.scripts().insert(privacy_script)
        self.apply_page_theme(view)
        readability_script = QWebEngineScript()
        readability_script.setName("LunaSurferWebsiteReadability")
        readability_script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        readability_script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        readability_script.setRunsOnSubFrames(False)
        readability_script.setSourceCode(self.readability_script())
        page.scripts().insert(readability_script)
        color_script = QWebEngineScript()
        color_script.setName("LunaSurferWebsiteColorMode")
        color_script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        color_script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        color_script.setRunsOnSubFrames(True)
        color_script.setSourceCode(self.website_color_script())
        page.scripts().insert(color_script)
        self.apply_font_size(view)
        index = self.tabs.addTab(view, self.tr("Neuer Tab", "New tab"))
        if switch: self.tabs.setCurrentIndex(index)
        view.loadFinished.connect(lambda ok, v=view: self.install_login_capture(v) if ok else None)
        view.loadFinished.connect(lambda ok, v=view: self.autofill_saved_login(v) if ok else None)
        view.loadFinished.connect(lambda ok, v=view: self.apply_fingerprint_to_view(v) if ok else None)
        view.loadFinished.connect(lambda ok, v=view: self.apply_readability_to_view(v) if ok else None)
        view.loadFinished.connect(lambda ok, v=view: self.apply_website_color_to_view(v) if ok else None)
        initial_url = url or self.settings_data.get("home", "https://duckduckgo.com")
        view._password_last_url = initial_url
        view._password_flow_origin_url = ""
        view.load(QUrl(initial_url))
        return view

    def apply_page_theme(self, view):
        """Apply the selected light/dark appearance to a web page."""
        settings = view.page().settings()
        force_dark = getattr(QWebEngineSettings.WebAttribute, "ForceDarkMode", None)
        if force_dark is not None:
            # The dedicated black website mode uses its own CSS palette. Disable
            # Chromium auto-darkening there so image/video colors remain untouched.
            black_mode = self.settings_data.get("website_color_mode", "normal") == "black"
            settings.setAttribute(force_dark, (self.settings_data.get("theme", "dark") == "dark") and not black_mode)

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

    def readability_script(self, mode=None):
        """Return a conservative readability stylesheet injector for web pages.

        It changes text contrast only; it deliberately leaves page backgrounds,
        images, video, canvas and SVG charts/graphics untouched.
        """
        mode = mode or self.settings_data.get("website_readability", "normal")
        return r"""(() => {
          const mode = __MODE__;
          const id = 'lunasurfer-readable-text-style';
          const install = () => {
            const root = document.documentElement;
            if (!root) return;
            root.removeAttribute('data-luna-readability');
            const old = document.getElementById(id);
            if (old) old.remove();
            if (mode === 'normal') return;
            root.setAttribute('data-luna-readability', mode);
            const style = document.createElement('style');
            style.id = id;
            const softness = mode === 'relaxed' ? '68%' : (mode === 'softer' ? '80%' : '90%');
            style.textContent = `
              /* Reduce text opacity against each site's own background. No page-wide
                 filter, forced palette, or changes to image/video/canvas/SVG content. */
              html[data-luna-readability] :where(p, span, li, td, th, label, small, summary, blockquote, dt, dd, figcaption, time, h1, h2, h3, h4, h5, h6, button, input, select, textarea) {
                color: color-mix(in srgb, currentColor ${softness}, transparent) !important;
              }
              html[data-luna-readability] :where(a, a:visited) {
                color: color-mix(in srgb, currentColor ${softness}, transparent) !important;
                text-decoration-color: currentColor !important;
              }
            `;
            (document.head || root).appendChild(style);
          };
          install();
          if (!window.__lunaReadabilityObserver) {
            window.__lunaReadabilityObserver = new MutationObserver(() => {
              if (!document.getElementById(id) && mode !== 'normal') install();
            });
            window.__lunaReadabilityObserver.observe(document.documentElement, {childList: true, subtree: true});
          }
        })();""".replace('__MODE__', json.dumps(mode))

    def apply_readability_to_view(self, view):
        mode = self.settings_data.get("website_readability", "normal")
        view.page().runJavaScript(self.readability_script(mode))

    def website_color_script(self, mode=None):
        """Apply a black page palette without filtering image/video/graphic pixels."""
        mode = mode or self.settings_data.get("website_color_mode", "normal")
        return r"""(() => {
          const mode = __MODE__;
          const id = 'lunasurfer-black-website-style';
          const install = () => {
            const root = document.documentElement;
            if (!root) return;
            const old = document.getElementById(id);
            if (old) old.remove();
            root.removeAttribute('data-luna-black-site');
            if (mode !== 'black') return;
            root.setAttribute('data-luna-black-site', 'true');
            const style = document.createElement('style');
            style.id = id;
            style.textContent = `
              html[data-luna-black-site],
              html[data-luna-black-site] body {
                background-color: #000000 !important;
                color: #f2f2f2 !important;
                color-scheme: dark !important;
              }
              html[data-luna-black-site] body :not(img):not(video):not(canvas):not(svg):not(svg *):not(iframe):not(picture):not(source):not(input):not(textarea):not(select):not(button):not(option):not(optgroup):not(a):not(a *) {
                color: #eeeeee !important;
                background-color: transparent !important;
                border-color: #414141 !important;
                box-shadow: none !important;
              }
              html[data-luna-black-site] body a,
              html[data-luna-black-site] body a * ,
              html[data-luna-black-site] body a:visited {
                color: #8ab4f8 !important;
                background-color: transparent !important;
                text-decoration-color: currentColor !important;
              }
              html[data-luna-black-site] body input,
              html[data-luna-black-site] body textarea,
              html[data-luna-black-site] body select,
              html[data-luna-black-site] body button,
              html[data-luna-black-site] body option,
              html[data-luna-black-site] body optgroup {
                color: #f5f5f5 !important;
                background-color: #111111 !important;
                border: 1px solid #555555 !important;
                color-scheme: dark !important;
              }
              html[data-luna-black-site] :where(input, textarea)::placeholder {
                color: #aaaaaa !important;
                opacity: 1 !important;
              }
              html[data-luna-black-site] :where(pre, code, kbd, samp) {
                background-color: #101010 !important;
                color: #eeeeee !important;
              }
              html[data-luna-black-site] ::selection {
                background: #444444 !important;
                color: #ffffff !important;
              }
            `;
            (document.head || root).appendChild(style);
          };
          install();
          if (!window.__lunaBlackWebsiteObserver && document.documentElement) {
            window.__lunaBlackWebsiteObserver = new MutationObserver(() => {
              if (mode === 'black' && !document.getElementById(id)) install();
            });
            window.__lunaBlackWebsiteObserver.observe(document.documentElement, {childList: true, subtree: true});
          }
        })();""".replace('__MODE__', json.dumps(mode))

    def apply_website_color_to_view(self, view):
        mode = self.settings_data.get("website_color_mode", "normal")
        view.page().runJavaScript(self.website_color_script(mode))

    def apply_theme_to_all_tabs(self):
        for index in range(self.tabs.count()):
            view = self.tabs.widget(index)
            if isinstance(view, BrowserView):
                self.apply_page_theme(view)
                self.apply_font_size(view)
                scripts = view.page().scripts()
                for old_script in scripts.find("LunaSurferWebsiteReadability"):
                    scripts.remove(old_script)
                readability_script = QWebEngineScript()
                readability_script.setName("LunaSurferWebsiteReadability")
                readability_script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
                readability_script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
                readability_script.setRunsOnSubFrames(False)
                readability_script.setSourceCode(self.readability_script())
                scripts.insert(readability_script)
                for old_script in scripts.find("LunaSurferWebsiteColorMode"):
                    scripts.remove(old_script)
                color_script = QWebEngineScript()
                color_script.setName("LunaSurferWebsiteColorMode")
                color_script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
                color_script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
                color_script.setRunsOnSubFrames(True)
                color_script.setSourceCode(self.website_color_script())
                scripts.insert(color_script)
                self.apply_website_color_to_view(view)
                view.reload()

    def close_tab(self, index):
        if self.tabs.count() > 1 and self.settings_data.get("confirm_close_multiple_tabs", True):
            answer = QMessageBox.question(self, self.tr("Tab schließen", "Close tab"), self.tr("Möchtest du diesen Tab wirklich schließen?", "Do you really want to close this tab?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
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
            if self.devtools_dock.isVisible():
                self._bind_devtools_to_current_page()
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

    def offer_page_translation(self, url, detected_language):
        """Show a small status-bar prompt with a one-click German translation action."""
        is_english = self.settings_data.get("language", "de") == "en"
        message = ("This page does not appear to be in German. Translate it?"
                   if is_english else
                   "Diese Seite scheint nicht auf Deutsch zu sein. Übersetzen?")
        action_text = "Translate" if is_english else "Übersetzen"
        try:
            if self._translation_notice_button is not None:
                self.statusBar().removeWidget(self._translation_notice_button)
                self._translation_notice_button.deleteLater()
            button = QToolButton(self)
            button.setText(action_text)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setStyleSheet("QToolButton { color: #8bd5ff; font-weight: 600; padding: 2px 9px; }")
            button.clicked.connect(lambda checked=False, u=url: self._translate_noticed_page(u))
            self._translation_notice_button = button
            self.statusBar().showMessage(message, 12000)
            self.statusBar().addPermanentWidget(button)
            QTimer.singleShot(12000, lambda b=button: self._clear_translation_notice(b))
        except Exception:
            self.statusBar().showMessage(message, 8000)

    def _clear_translation_notice(self, button):
        if self._translation_notice_button is button:
            self.statusBar().removeWidget(button)
            button.deleteLater()
            self._translation_notice_button = None

    def _translate_noticed_page(self, source_url):
        view = self.current_view()
        if not view:
            return
        self._translation_originals[id(view)] = source_url
        if self._translation_notice_button is not None:
            self._clear_translation_notice(self._translation_notice_button)
        self.translate_current_page_selected("de")

    def translate_current_page_selected(self, target_language="de"):
        """Use the provider selected in Settings for both manual and automatic translation."""
        provider = self.settings_data.get("translation_provider", "google")
        try:
            saved = read_json(CONFIG_FILE, {})
            provider = saved.get("translation_provider", provider)
        except Exception:
            pass
        if provider not in ("google", "mymemory"):
            provider = "google"
        self.settings_data["translation_provider"] = provider
        if provider == "mymemory":
            self.statusBar().showMessage(
                self.tr("Anbieter: MyMemory – Übersetzung wird gestartet …",
                        "Provider: MyMemory – starting translation …"), 10000)
            self.translate_current_page_mymemory(target_language)
        else:
            self.statusBar().showMessage(
                self.tr("Anbieter: Google Translate – ganze Webseite wird geladen …",
                        "Provider: Google Translate – loading whole webpage …"), 8000)
            self.translate_current_page(target_language)

    def translate_current_page_mymemory(self, target_language="de"):
        """Translate visible text nodes through MyMemory without navigating to Google."""
        view = self.current_view()
        if not view:
            return
        source_url = view.url().toString()
        if not source_url or not source_url.startswith(("http://", "https://")):
            QMessageBox.information(self, self.tr("Übersetzung", "Translation"),
                self.tr("Bitte zuerst eine normale Webseite öffnen.", "Open a regular webpage first."))
            return
        self._translation_originals[id(view)] = source_url
        lang = str(target_language or "de")
        script = r"""(async function(target) {
            const blocked = new Set(['SCRIPT','STYLE','NOSCRIPT','TEXTAREA','INPUT','SELECT','OPTION']);
            const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
            const nodes = [];
            let node;
            while ((node = walker.nextNode())) {
                const parent = node.parentElement;
                if (!parent || blocked.has(parent.tagName) || parent.closest('[contenteditable="true"]')) continue;
                const value = node.nodeValue || '';
                if (value.trim().length < 2) continue;
                nodes.push({node, original:value});
            }
            let translated = 0, failed = 0;
            for (let i=0; i<nodes.length; i++) {
                const item = nodes[i], trimmed = item.original.trim();
                if (trimmed.length > 450) { failed++; continue; }
                try {
                    const endpoint = 'https://api.mymemory.translated.net/get?q=' +
                        encodeURIComponent(trimmed) + '&langpair=' +
                        encodeURIComponent('autodetect|' + target);
                    const response = await fetch(endpoint);
                    if (!response.ok) throw new Error('HTTP ' + response.status);
                    const data = await response.json();
                    const result = data && data.responseData && data.responseData.translatedText;
                    if (data.responseStatus === 200 && typeof result === 'string' && result) {
                        item.node.nodeValue = item.original.replace(trimmed, result);
                        translated++;
                    } else failed++;
                } catch (e) { failed++; }
                if (i % 6 === 5) await new Promise(resolve => setTimeout(resolve, 300));
            }
            return 'done:' + translated + ':' + failed;
        })(""" + json.dumps(lang) + r""")"""
        def finished(result):
            if isinstance(result, str) and result.startswith("done:"):
                count = result.split(":")[1]
                self.statusBar().showMessage(
                    self.tr("MyMemory: ", "MyMemory: ") + count +
                    self.tr(" Textabschnitte übersetzt.", " text sections translated."), 10000)
            else:
                self.statusBar().showMessage(
                    self.tr("MyMemory konnte die Seite nicht übersetzen. Verbindung oder Tageslimit prüfen.",
                            "MyMemory could not translate the page. Check connection or daily quota."), 12000)
        view.page().runJavaScript(script, finished)

    def translate_current_page(self, target_language="de"):
        """Open a translated whole-page view and remember its source URL per tab."""
        view = self.current_view()
        if not view:
            return
        source_url = view.url().toString()
        if not source_url or not source_url.startswith(("http://", "https://")):
            QMessageBox.information(self, self.tr("Übersetzung", "Translation"),
                self.tr("Bitte zuerst eine normale Webseite öffnen.", "Open a regular webpage first."))
            return
        self._translation_originals[id(view)] = source_url
        translated_url = "https://translate.google.com/translate?sl=auto&tl=" + target_language + "&u=" + urllib.parse.quote(source_url, safe="")
        view.load(QUrl(translated_url))
        self.statusBar().showMessage(self.tr("Übersetzte Webseite wird geladen …", "Loading translated webpage …"), 5000)

    def show_original_page(self):
        view = self.current_view()
        if not view:
            return
        original_url = self._translation_originals.get(id(view))
        if original_url:
            view.load(QUrl(original_url))
        else:
            QMessageBox.information(self, self.tr("Originalseite", "Original page"),
                self.tr("Für diesen Tab ist keine ursprüngliche Seitenadresse gespeichert.", "No original page URL is saved for this tab."))

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
                    QMessageBox.warning(dialog, self.tr("Import", "Import"), self.tr("Keine Lesezeichen in der ausgewählten Datei gefunden.", "No bookmarks found in the selected file.")); return
                answer = QMessageBox.question(dialog, self.tr("Lesezeichen importieren", "Import bookmarks"), self.tr(f"{len(imported)} Lesezeichen gefunden.\n\nJa: vorhandene Lesezeichen ersetzen\nNein: zu vorhandenen Lesezeichen hinzufügen", f"{len(imported)} bookmarks found.\n\nYes: replace existing bookmarks\nNo: add to existing bookmarks"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.No)
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
        self.adblock_button.setToolTip(self.tr("Schutz-Einstellungen: Werbeblocker und Fingerprint", "Protection settings: ad blocker and fingerprint"))

    def show_permission_manager(self):
        """View and edit remembered per-website camera, microphone, location and notification decisions."""
        remembered = self.settings_data.setdefault("remembered_permissions", {})
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("Gespeicherte Webseiten-Berechtigungen", "Saved website permissions"))
        dialog.resize(720, 460)
        dialog.setStyleSheet("""
            QDialog { background: #0b1d36; color: #f2f6ff; }
            QLabel { color: #f2f6ff; }
            QTreeWidget { background: #102a49; color: #f2f6ff; border: 1px solid #34577d; }
            QHeaderView::section { background: #17385f; color: #ffffff; padding: 6px; border: 1px solid #34577d; }
            QComboBox { background: #17385f; color: #ffffff; padding: 5px; border: 1px solid #5488bd; }
            QPushButton { background: #24496f; color: #ffffff; border: 1px solid #6b9ac8; border-radius: 5px; padding: 6px 12px; }
            QPushButton:hover { background: #176fe5; }
        """)
        layout = QVBoxLayout(dialog)
        intro = QLabel(self.tr(
            "Hier kannst du gespeicherte Entscheidungen pro Webseite ändern oder entfernen. Änderungen werden sofort gespeichert.",
            "Change or remove remembered decisions for each website. Changes are saved immediately."
        ))
        intro.setWordWrap(True)
        layout.addWidget(intro)
        tree = QTreeWidget(dialog)
        tree.setColumnCount(4)
        tree.setHeaderLabels([
            self.tr("Webseite", "Website"),
            self.tr("Berechtigung", "Permission"),
            self.tr("Entscheidung", "Decision"),
            self.tr("Aktion", "Action")
        ])
        tree.setRootIsDecorated(False)
        tree.setAlternatingRowColors(True)
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        labels = {
            "permission_camera": self.tr("Kamera", "Camera"),
            "permission_microphone": self.tr("Mikrofon", "Microphone"),
            "permission_location": self.tr("Standort", "Location"),
            "permission_notifications": self.tr("Benachrichtigungen", "Notifications")
        }
        for origin in sorted(list(remembered.keys()), key=str.casefold):
            site_values = remembered.get(origin, {})
            if not isinstance(site_values, dict):
                continue
            for key in labels:
                decision = site_values.get(key)
                if decision not in ("allow", "block"):
                    continue
                item = QTreeWidgetItem([origin, labels[key], "", ""])
                item.setData(0, Qt.ItemDataRole.UserRole, (origin, key))
                tree.addTopLevelItem(item)
                choice = QComboBox(tree)
                choice.addItem(self.tr("Erlauben", "Allow"), "allow")
                choice.addItem(self.tr("Blockieren", "Block"), "block")
                choice.setCurrentIndex(max(0, choice.findData(decision)))
                def save_choice(value, site=origin, perm=key):
                    self.settings_data.setdefault("remembered_permissions", {}).setdefault(site, {})[perm] = value
                    write_json(CONFIG_FILE, self.settings_data)
                choice.currentIndexChanged.connect(lambda _idx, combo=choice, fn=save_choice: fn(combo.currentData()))
                tree.setItemWidget(item, 2, choice)
                remove = QPushButton(self.tr("Entfernen", "Remove"), tree)
                def remove_permission(_checked=False, row=item, site=origin, perm=key):
                    values = self.settings_data.setdefault("remembered_permissions", {}).get(site, {})
                    values.pop(perm, None)
                    if not values:
                        self.settings_data["remembered_permissions"].pop(site, None)
                    write_json(CONFIG_FILE, self.settings_data)
                    index = tree.indexOfTopLevelItem(row)
                    if index >= 0:
                        tree.takeTopLevelItem(index)
                remove.clicked.connect(remove_permission)
                tree.setItemWidget(item, 3, remove)
        layout.addWidget(tree, 1)
        buttons = QHBoxLayout()
        clear_all = QPushButton(self.tr("Alle gespeicherten Berechtigungen löschen", "Clear all saved permissions"))
        close = QPushButton(self.tr("Schließen", "Close"))
        buttons.addWidget(clear_all)
        buttons.addStretch(1)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        def clear_permissions():
            if not self.confirm_action(
                self.tr("Alle Berechtigungen löschen", "Clear all permissions"),
                self.tr("Möchtest du wirklich alle gespeicherten Webseiten-Berechtigungen löschen?",
                        "Do you really want to clear all saved website permissions?")
            ):
                return
            self.settings_data["remembered_permissions"] = {}
            write_json(CONFIG_FILE, self.settings_data)
            tree.clear()
        clear_all.clicked.connect(clear_permissions)
        close.clicked.connect(dialog.accept)
        dialog.exec()

    def show_adblock_settings(self):
        """Open the combined ad-blocker and fingerprint-protection panel."""
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("Schutz & Privatsphäre", "Protection & privacy"))
        dialog.resize(620, 540)
        # Explicit high-contrast styling: the application theme previously
        # left QLabel/QCheckBox text to the desktop palette, which could make
        # dark text appear on the dark privacy-panel background.
        dialog.setStyleSheet("""
            QDialog {
                background-color: #0b1d36;
                color: #f2f6ff;
            }
            QDialog QLabel, QDialog QCheckBox {
                color: #f2f6ff;
                background: transparent;
                font-size: 10pt;
            }
            QDialog QLabel {
                padding-top: 3px;
                padding-bottom: 3px;
            }
            QDialog QCheckBox {
                spacing: 8px;
                font-weight: 600;
            }
            QDialog QLineEdit, QDialog QComboBox {
                background-color: #17385f;
                color: #ffffff;
                selection-background-color: #2878d0;
                selection-color: #ffffff;
                border: 1px solid #5488bd;
                border-radius: 6px;
                padding: 6px 8px;
                min-height: 22px;
            }
            QDialog QComboBox QAbstractItemView {
                background-color: #17385f;
                color: #ffffff;
                selection-background-color: #2878d0;
                selection-color: #ffffff;
                border: 1px solid #5488bd;
            }
            QDialog QTabWidget::pane {
                background-color: #0b1d36;
                border: 1px solid #34577d;
                top: -1px;
            }
            QDialog QTabBar::tab {
                background-color: #17385f;
                color: #e8f1ff;
                padding: 9px 13px;
                border: 1px solid #34577d;
                border-bottom: none;
            }
            QDialog QTabBar::tab:selected {
                background-color: #176fe5;
                color: #ffffff;
                font-weight: 700;
            }
            QDialog QPushButton {
                background-color: #24496f;
                color: #ffffff;
                border: 1px solid #6b9ac8;
                border-radius: 5px;
                padding: 6px 14px;
                min-width: 76px;
            }
            QDialog QPushButton:hover {
                background-color: #176fe5;
            }
            QDialog QPushButton:pressed {
                background-color: #104b9b;
            }
        """)
        outer = QVBoxLayout(dialog)
        tabs = QTabWidget(dialog)

        # Ad blocker tab
        ad_tab = QWidget(dialog)
        ad_layout = QVBoxLayout(ad_tab)
        enabled = QCheckBox(self.tr("Werbeblocker aktivieren", "Enable ad blocker"))
        enabled.setChecked(self.settings_data.get("adblock_enabled", True))
        ad_layout.addWidget(enabled)
        ad_layout.addWidget(QLabel(self.tr("Blockierstärke:", "Blocking strength:")))
        strength = QComboBox()
        for label_de, label_en, value in [
            ("Standard", "Standard", "standard"),
            ("Stark", "Strong", "strong"),
            ("Sehr stark", "Very strong", "very_strong"),
            ("Super stark", "Super strong", "super_strong"),
            ("Mega stark", "Mega strong", "mega_strong"),
        ]:
            strength.addItem(self.tr(label_de, label_en), value)
        current_strength = self.settings_data.get("adblock_strength", "standard")
        strength.setCurrentIndex(max(0, strength.findData(current_strength)))
        ad_layout.addWidget(strength)
        ad_layout.addWidget(QLabel(self.tr(
            "Eigene Blockiermuster (mit Semikolon trennen):",
            "Custom block patterns (separate with semicolons):")))
        patterns = QLineEdit("; ".join(self.settings_data.get("adblock_custom_blocklist", [])))
        patterns.setPlaceholderText("z. B. example-ads.com")
        ad_layout.addWidget(patterns)
        ad_layout.addWidget(QLabel(self.tr(
            "Whitelist-Domains (mit Semikolon trennen):",
            "Whitelist domains (separate with semicolons):")))
        whitelist = QLineEdit("; ".join(self.settings_data.get("adblock_whitelist", [])))
        ad_layout.addWidget(whitelist)
        ad_info = QLabel(self.tr(
            "Der Werbeblocker filtert bekannte Werbe- und Tracking-Domains. Höhere Stufen blockieren mehr, können aber einzelne Webseiten beeinträchtigen.",
            "The ad blocker filters known advertising and tracking domains. Higher levels block more, but may affect some websites."))
        ad_info.setWordWrap(True)
        ad_layout.addWidget(ad_info)
        ad_layout.addStretch(1)
        tabs.addTab(ad_tab, self.tr("Werbeblocker", "Ad blocker"))

        # Fingerprint protection tab
        fp_tab = QWidget(dialog)
        fp_layout = QVBoxLayout(fp_tab)
        fp_enabled = QCheckBox(self.tr("Fingerprint-Schutz aktivieren", "Enable fingerprint protection"))
        fp_enabled.setChecked(self.settings_data.get("fingerprint_enabled", True))
        fp_layout.addWidget(fp_enabled)
        fp_layout.addWidget(QLabel(self.tr("Schutzstufe:", "Protection level:")))
        fp_strength = QComboBox()
        for label_de, label_en, value in [
            ("Standard", "Standard", "standard"),
            ("Stark", "Strong", "strong"),
            ("Maximum", "Maximum", "maximum"),
        ]:
            fp_strength.addItem(self.tr(label_de, label_en), value)
        current_fp = self.settings_data.get("fingerprint_strength", "standard")
        fp_strength.setCurrentIndex(max(0, fp_strength.findData(current_fp)))
        fp_layout.addWidget(fp_strength)
        fp_info = QLabel(self.tr(
            "Standard: Canvas-, Audio- und grundlegender Hardware-Schutz. Stark: zusätzlich WebGL-Maskierung. Maximum: zusätzliche Abschirmung von Hardwareangaben und Browser-Client-Hints. Änderungen werden sofort angewendet; ein Neustart ist nicht nötig.",
            "Standard: canvas, audio and basic hardware protection. Strong: additionally masks WebGL identifiers. Maximum: additional hardware and browser client-hint protection. Changes apply immediately; no restart is required."))
        fp_info.setWordWrap(True)
        fp_layout.addWidget(fp_info)
        fp_layout.addStretch(1)
        tabs.addTab(fp_tab, self.tr("Fingerprint-Schutz", "Fingerprint protection"))

        outer.addWidget(tabs)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        save = QPushButton(self.tr("Speichern", "Save"))
        cancel = QPushButton(self.tr("Abbrechen", "Cancel"))
        buttons.addWidget(save)
        buttons.addWidget(cancel)
        outer.addLayout(buttons)

        def do_save():
            self.settings_data["adblock_enabled"] = enabled.isChecked()
            self.settings_data["adblock_strength"] = strength.currentData()
            self.settings_data["adblock_custom_blocklist"] = [x.strip() for x in patterns.text().split(";") if x.strip()]
            self.settings_data["adblock_whitelist"] = [x.strip() for x in whitelist.text().split(";") if x.strip()]
            self.settings_data["fingerprint_enabled"] = fp_enabled.isChecked()
            self.settings_data["fingerprint_strength"] = fp_strength.currentData()
            write_json(CONFIG_FILE, self.settings_data)
            self.update_adblock_button()
            self.apply_fingerprint_protection_live()
            dialog.accept()

        save.clicked.connect(do_save)
        cancel.clicked.connect(dialog.reject)
        dialog.exec()

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

            # Newest downloads are stored at the end of download_items;
            # show them first without changing their stable backing indices.
            visible.reverse()

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
        explicit_target = getattr(self, "_next_download_path", None)
        if explicit_target is not None:
            self._next_download_path = None
            target = pathlib.Path(explicit_target)
            target.parent.mkdir(parents=True, exist_ok=True)
            download.setDownloadDirectory(str(target.parent))
            download.setDownloadFileName(target.name)
            download.accept()
            self.download_items.append({"download": download, "target": target, "last_bytes": 0, "last_time": time.monotonic(), "speed": 0})
            self.watch_download_finished(download, target)
            self.statusBar().showMessage(f"Download gestartet: {target.name}", 5000)
            return
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
        if self.confirm_action(
            self.tr("Verlauf löschen", "Clear history"),
            self.tr("Möchtest du den gesamten Verlauf wirklich löschen?", "Do you really want to delete the entire browsing history?")
        ):
            write_json(HISTORY_FILE, [])
            self.statusBar().showMessage("Verlauf wurde gelöscht.", 5000)
            QMessageBox.information(self, self.tr("Verlauf gelöscht", "History cleared"), self.tr("Der Browserverlauf wurde gelöscht.", "The browsing history has been cleared."))

    # ---- Encrypted password manager -------------------------------------------------
    @staticmethod
    def _password_site_key(url):
        """Canonical website identity: ignore scheme and leading www, retain non-default ports."""
        try:
            parsed = urllib.parse.urlparse(str(url or "").strip())
            host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
            if host.startswith("www."):
                host = host[4:]
            if not host:
                return ""
            port = parsed.port
            if port in (80, 443):
                port = None
            return host if port is None else f"{host}:{port}"
        except (ValueError, UnicodeError):
            return ""

    @staticmethod
    def _password_hosts_match(left, right):
        """Match the same host or a true subdomain pair, never sibling domains."""
        def host_only(value):
            try:
                parsed = urllib.parse.urlparse(str(value or "").strip() if "://" in str(value or "") else "//" + str(value or "").strip())
                return (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
            except (ValueError, UnicodeError):
                return ""
        a, b = host_only(left), host_only(right)
        return bool(a and b and (a == b or a.endswith("." + b) or b.endswith("." + a)))

    def _password_entry_matches_sites(self, entry, site_keys):
        stored = entry.get("site_key") or self._password_site_key(entry.get("url", ""))
        candidates = [stored, entry.get("url", "")]
        candidates.extend(entry.get("related_sites", []) or [])
        return any(self._password_hosts_match(candidate, wanted)
                   for candidate in candidates for wanted in site_keys if candidate and wanted)

    def _password_key(self, master_password, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))

    @staticmethod
    def _secure_password_storage_permissions():
        """Restrict the vault directory and file to the current Unix user."""
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(DATA_DIR, 0o700)
            if PASSWORDS_FILE.exists():
                os.chmod(PASSWORDS_FILE, 0o600)
        except OSError:
            pass

    def _password_file_data(self):
        self._secure_password_storage_permissions()
        return read_json(PASSWORDS_FILE, {})

    def _password_setup_or_unlock(self):
        data = self._password_file_data()
        if data.get("salt"):
            master, ok = QInputDialog.getText(self, self.tr("Passwortmanager entsperren", "Unlock password manager"), self.tr("Master-Passwort:", "Master password:"), QLineEdit.EchoMode.Password)
            if not ok or not master:
                self._password_unlock_suppressed_until = time.monotonic() + 60.0
                return False
            try:
                salt = base64.b64decode(data["salt"])
                fernet = Fernet(self._password_key(master, salt))
                payload = json.loads(fernet.decrypt(data["token"].encode()).decode("utf-8"))
            except (InvalidToken, ValueError, KeyError, TypeError, json.JSONDecodeError):
                QMessageBox.warning(self, self.tr("Falsches Passwort", "Incorrect password"), self.tr("Das Master-Passwort ist falsch oder die Passwortdatei beschädigt.", "The master password is incorrect or the password file is damaged."))
                return False
            self._password_fernet = fernet
            self._password_entries = payload if isinstance(payload, list) else []
        else:
            first, ok = QInputDialog.getText(self, self.tr("Passwortmanager einrichten", "Set up password manager"), self.tr("Neues Master-Passwort (mindestens 10 Zeichen):", "New master password (at least 10 characters):"), QLineEdit.EchoMode.Password)
            if not ok:
                self._password_unlock_suppressed_until = time.monotonic() + 60.0
                return False
            if len(first) < 10:
                QMessageBox.warning(self, self.tr("Zu kurz", "Too short"), self.tr("Bitte mindestens 10 Zeichen verwenden.", "Please use at least 10 characters.")); return False
            second, ok = QInputDialog.getText(self, self.tr("Master-Passwort bestätigen", "Confirm master password"), self.tr("Master-Passwort erneut eingeben:", "Enter master password again:"), QLineEdit.EchoMode.Password)
            if not ok or first != second:
                QMessageBox.warning(self, self.tr("Keine Übereinstimmung", "Passwords do not match"), self.tr("Die Passwörter stimmen nicht überein.", "The passwords do not match.")); return False
            salt = secrets.token_bytes(16)
            self._password_fernet = Fernet(self._password_key(first, salt))
            self._password_entries = []
            self._save_password_entries(salt)
        self._password_lock_timer.start(5 * 60 * 1000)
        return True

    def _save_password_entries(self, salt=None):
        if not self._password_fernet: return
        old = self._password_file_data()
        if salt is None:
            try: salt = base64.b64decode(old["salt"])
            except Exception: salt = secrets.token_bytes(16)
        token = self._password_fernet.encrypt(json.dumps(self._password_entries, ensure_ascii=False).encode()).decode()
        write_json(PASSWORDS_FILE, {"version": 1, "salt": base64.b64encode(salt).decode(), "token": token})
        self._secure_password_storage_permissions()

    def _password_export_key(self, export_password, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        return base64.urlsafe_b64encode(kdf.derive(export_password.encode("utf-8")))

    def _password_vault_file_dialog(self, save=False):
        """Show a Qt-localized file dialog instead of untranslated native OS labels."""
        dialog = QFileDialog(self)
        dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        dialog.setWindowTitle(self.tr(
            "Verschlüsselten Tresor exportieren" if save else "Verschlüsselten Tresor importieren",
            "Export encrypted vault" if save else "Import encrypted vault"))
        dialog.setNameFilter(self.tr(
            "LunaSurfer Tresor (*.lsv);;Alle Dateien (*)",
            "LunaSurfer vault (*.lsv);;All files (*)"))
        dialog.setDefaultSuffix("lsv")
        if save:
            dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
            dialog.setFileMode(QFileDialog.FileMode.AnyFile)
            dialog.selectFile(str(pathlib.Path.home() / "lunasurfer-passwords.lsv"))
        else:
            dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptOpen)
            dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
            dialog.setDirectory(str(pathlib.Path.home()))
        labels = (
            (QFileDialog.DialogLabel.LookIn,
             self.tr("Suchen in:", "Look in:")),
            (QFileDialog.DialogLabel.FileName,
             self.tr("Dateiname:", "File name:")),
            (QFileDialog.DialogLabel.FileType,
             self.tr("Dateityp:", "File type:")),
            (QFileDialog.DialogLabel.Accept,
             self.tr("Speichern", "Save") if save else self.tr("Öffnen", "Open")),
            (QFileDialog.DialogLabel.Reject,
             self.tr("Abbrechen", "Cancel")),
        )
        for label, value in labels:
            dialog.setLabelText(label, value)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return ""
        selected = dialog.selectedFiles()
        return selected[0] if selected else ""

    def change_master_password(self):
        """Re-encrypt the complete in-memory vault with a fresh master key and salt."""
        data = self._password_file_data()
        old_password, ok = QInputDialog.getText(
            self, self.tr("Master-Passwort ändern", "Change master password"),
            self.tr("Aktuelles Master-Passwort:", "Current master password:"),
            QLineEdit.EchoMode.Password)
        if not ok or not old_password:
            return
        try:
            old_salt = base64.b64decode(data["salt"], validate=True)
            old_cipher = Fernet(self._password_key(old_password, old_salt))
            verified_entries = json.loads(old_cipher.decrypt(data["token"].encode("ascii")).decode("utf-8"))
            if not isinstance(verified_entries, list):
                raise ValueError("Invalid vault contents")
        except Exception:
            QMessageBox.warning(self, self.tr("Falsches Passwort", "Incorrect password"),
                self.tr("Das aktuelle Master-Passwort ist falsch oder der Tresor beschädigt.",
                        "The current master password is incorrect or the vault is damaged."))
            return

        first, ok = QInputDialog.getText(
            self, self.tr("Neues Master-Passwort", "New master password"),
            self.tr("Neues Master-Passwort (mindestens 10 Zeichen):",
                    "New master password (at least 10 characters):"),
            QLineEdit.EchoMode.Password)
        if not ok:
            return
        if len(first) < 10:
            QMessageBox.warning(self, self.tr("Zu kurz", "Too short"),
                self.tr("Bitte mindestens 10 Zeichen verwenden.", "Please use at least 10 characters."))
            return
        second, ok = QInputDialog.getText(
            self, self.tr("Master-Passwort bestätigen", "Confirm master password"),
            self.tr("Neues Master-Passwort erneut eingeben:",
                    "Enter the new master password again:"),
            QLineEdit.EchoMode.Password)
        if not ok or first != second:
            QMessageBox.warning(self, self.tr("Keine Übereinstimmung", "Passwords do not match"),
                self.tr("Die Passwörter stimmen nicht überein.", "The passwords do not match."))
            return

        try:
            new_salt = secrets.token_bytes(16)
            new_cipher = Fernet(self._password_key(first, new_salt))
            token = new_cipher.encrypt(json.dumps(
                verified_entries, ensure_ascii=False).encode("utf-8")).decode("ascii")
            # write_json uses a temporary file and atomic replace; the old vault
            # remains intact if encryption or writing fails.
            write_json(PASSWORDS_FILE, {
                "version": 1,
                "salt": base64.b64encode(new_salt).decode("ascii"),
                "token": token
            })
            self._secure_password_storage_permissions()
            self._password_fernet = new_cipher
            self._password_entries = verified_entries
            QMessageBox.information(self, self.tr("Master-Passwort geändert", "Master password changed"),
                self.tr("Der Tresor wurde mit dem neuen Master-Passwort verschlüsselt. "
                        "Bewahre es sicher auf; es kann nicht wiederhergestellt werden.",
                        "The vault has been re-encrypted with the new master password. "
                        "Keep it safe; it cannot be recovered."))
            self._touch_password_manager()
        except Exception as exc:
            QMessageBox.critical(self, self.tr("Ändern fehlgeschlagen", "Change failed"), str(exc))

    def export_password_vault(self):
        """Export a portable encrypted backup protected by a separate passphrase."""
        if not self._password_fernet and not self._password_setup_or_unlock():
            return
        self._touch_password_manager()
        path = self._password_vault_file_dialog(save=True)
        if not path:
            return
        first, ok = QInputDialog.getText(self, self.tr("Export-Passwort", "Export password"),
            self.tr("Eigenes Passwort für diese Exportdatei (mindestens 10 Zeichen):", "Choose a password for this export file (at least 10 characters):"),
            QLineEdit.EchoMode.Password)
        if not ok:
            return
        if len(first) < 10:
            QMessageBox.warning(self, self.tr("Zu kurz", "Too short"),
                self.tr("Bitte mindestens 10 Zeichen verwenden.", "Use at least 10 characters."))
            return
        second, ok = QInputDialog.getText(self, self.tr("Export-Passwort bestätigen", "Confirm export password"),
            self.tr("Export-Passwort erneut eingeben:", "Enter the export password again:"), QLineEdit.EchoMode.Password)
        if not ok or first != second:
            QMessageBox.warning(self, self.tr("Keine Übereinstimmung", "Passwords do not match"),
                self.tr("Die Passwörter stimmen nicht überein.", "The passwords do not match."))
            return
        try:
            salt = secrets.token_bytes(16)
            cipher = Fernet(self._password_export_key(first, salt))
            payload = json.dumps({"format": "LunaSurferEncryptedVault", "version": 1,
                                  "entries": self._password_entries},
                                 ensure_ascii=False).encode("utf-8")
            envelope = {"format": "LunaSurferEncryptedVault", "version": 1,
                        "kdf": "PBKDF2-HMAC-SHA256", "iterations": 600000,
                        "salt": base64.b64encode(salt).decode("ascii"),
                        "token": cipher.encrypt(payload).decode("ascii")}
            pathlib.Path(path).write_text(json.dumps(envelope, indent=2), encoding="utf-8")
            try: os.chmod(path, 0o600)
            except OSError: pass
            QMessageBox.information(self, self.tr("Export abgeschlossen", "Export complete"),
                self.tr("Der Tresor wurde verschlüsselt exportiert. Bewahre Exportdatei und Export-Passwort getrennt auf.",
                        "The vault was exported in encrypted form. Keep the export file and export password separately."))
        except Exception as exc:
            QMessageBox.critical(self, self.tr("Export fehlgeschlagen", "Export failed"), str(exc))

    def import_password_vault(self):
        """Decrypt and safely merge a previously exported vault into this vault."""
        if not self._password_fernet and not self._password_setup_or_unlock():
            return
        self._touch_password_manager()
        path = self._password_vault_file_dialog(save=False)
        if not path:
            return
        export_password, ok = QInputDialog.getText(self, self.tr("Export-Passwort", "Export password"),
            self.tr("Passwort eingeben, mit dem die Exportdatei verschlüsselt wurde:", "Enter the password used to encrypt this export file:"),
            QLineEdit.EchoMode.Password)
        if not ok or not export_password:
            return
        try:
            envelope = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
            if envelope.get("format") != "LunaSurferEncryptedVault" or envelope.get("version") != 1:
                raise ValueError("Unsupported encrypted vault format")
            salt = base64.b64decode(envelope["salt"], validate=True)
            if len(salt) != 16:
                raise ValueError("Invalid salt")
            cipher = Fernet(self._password_export_key(export_password, salt))
            payload = json.loads(cipher.decrypt(envelope["token"].encode("ascii")).decode("utf-8"))
            imported = payload.get("entries") if payload.get("format") == "LunaSurferEncryptedVault" else None
            if not isinstance(imported, list):
                raise ValueError("Invalid password entry list")
            clean = []
            for entry in imported:
                if not isinstance(entry, dict):
                    continue
                url = str(entry.get("url") or "").strip()
                username = str(entry.get("username") or "")
                password = str(entry.get("password") or "")
                raw_url = url if "://" in url else "https://" + url
                parsed = urllib.parse.urlparse(raw_url)
                site_key = self._password_site_key(raw_url)
                if parsed.scheme not in ("http", "https") or not parsed.hostname or not site_key or not username or not password:
                    continue
                clean.append({"url": f"{parsed.scheme}://{parsed.netloc}/",
                              "site_key": site_key, "username": username, "password": password})
            if not clean:
                QMessageBox.information(self, self.tr("Nichts zu importieren", "Nothing to import"),
                    self.tr("Die Exportdatei enthält keine gültigen Logins.", "The export contains no valid logins."))
                return
            if not self.confirm_action(self.tr("Passwörter importieren", "Import passwords"),
                self.tr(f"{len(clean)} Login(s) gefunden. Einträge derselben Website und desselben Benutzernamens werden aktualisiert; andere bleiben erhalten.",
                        f"Found {len(clean)} login(s). Entries for the same website and username will be updated; all others will be kept.")):
                return
            merged = {(e.get("site_key") or self._password_site_key(e.get("url")), e.get("username")): i
                      for i, e in enumerate(self._password_entries)}
            added = updated = 0
            for entry in clean:
                key = (entry["site_key"], entry["username"])
                if key in merged:
                    self._password_entries[merged[key]] = entry
                    updated += 1
                else:
                    merged[key] = len(self._password_entries)
                    self._password_entries.append(entry)
                    added += 1
            self._save_password_entries()
            self._touch_password_manager()
            refresh_callback = getattr(self, "_password_manager_refresh_callback", None)
            if callable(refresh_callback):
                refresh_callback()
            QMessageBox.information(self, self.tr("Import abgeschlossen", "Import complete"),
                self.tr(f"{added} neu, {updated} aktualisiert.", f"{added} new, {updated} updated."))
        except (InvalidToken, ValueError, KeyError, TypeError, json.JSONDecodeError, OSError) as exc:
            QMessageBox.warning(self, self.tr("Import fehlgeschlagen", "Import failed"),
                self.tr("Falsches Export-Passwort oder beschädigte Exportdatei.", "Incorrect export password or damaged export file.") + f"\n{exc}")

    def lock_password_manager(self):
        self._password_fernet = None
        self._password_entries = []

    def _touch_password_manager(self):
        if self._password_fernet:
            self._password_lock_timer.start(5 * 60 * 1000)

    def delete_all_saved_passwords(self):
        """Delete every saved login while preserving the master-password vault."""
        data = self._password_file_data()
        if not data.get("salt") or not data.get("token"):
            QMessageBox.information(
                self,
                self.tr("Keine Passwörter vorhanden", "No passwords stored"),
                self.tr("Es sind noch keine gespeicherten Passwörter vorhanden.", "There are no saved passwords to delete.")
            )
            return
        # Require the master password even if the vault is currently unlocked.
        was_unlocked = self._password_fernet is not None
        if not self._password_setup_or_unlock():
            return
        if not self.confirm_action(
            self.tr("Alle Passwörter löschen", "Delete all passwords"),
            self.tr("Möchtest du wirklich ALLE gespeicherten Website-Anmeldedaten unwiderruflich löschen? Das Master-Passwort bleibt bestehen.",
                    "Do you really want to permanently delete ALL saved website logins? The master password will remain.")
        ):
            if not was_unlocked:
                self.lock_password_manager()
            return
        self._password_entries = []
        self._save_password_entries()
        self._touch_password_manager()
        QMessageBox.information(
            self,
            self.tr("Passwörter gelöscht", "Passwords deleted"),
            self.tr("Alle gespeicherten Website-Passwörter wurden gelöscht. Das Master-Passwort bleibt bestehen.",
                    "All saved website passwords have been deleted. The master password remains.")
        )

    def _password_edit_dialog(self, entry=None):
        entry = entry or {}
        current_view = self.tabs.currentWidget() if hasattr(self, "tabs") else None
        current_url = current_view.url().toString() if isinstance(current_view, QWebEngineView) else "https://"
        default_url = entry.get("url") or (current_url if current_url.startswith(("http://", "https://")) else "https://")
        dialog = QDialog(self); dialog.setWindowTitle(self.tr("Anmeldedaten", "Login details")); dialog.resize(460, 250)
        form = QFormLayout(dialog)
        site = QLineEdit(default_url); site.setPlaceholderText("https://example.com/")
        username = QLineEdit(entry.get("username", "")); password = QLineEdit(entry.get("password", "")); password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow(self.tr("Webseite (wird automatisch zugeordnet)", "Website (matched automatically)"), site); form.addRow(self.tr("Benutzername", "Username"), username); form.addRow(self.tr("Passwort", "Password"), password)
        reveal = QCheckBox(self.tr("Passwort anzeigen", "Show password")); reveal.toggled.connect(lambda checked: password.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)); form.addRow(reveal)
        gen = QPushButton(self.tr("Sicheres Passwort erzeugen", "Generate secure password"))
        def generate():
            alphabet = string.ascii_letters + string.digits + "!@#$%&*+-_"
            password.setText(''.join(secrets.choice(alphabet) for _ in range(20)))
        gen.clicked.connect(generate); form.addRow(gen)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel); buttons.accepted.connect(dialog.accept); buttons.rejected.connect(dialog.reject); form.addRow(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted: return None
        raw_site = site.text().strip()
        if "://" not in raw_site:
            raw_site = "https://" + raw_site
        parsed = urllib.parse.urlparse(raw_site)
        site_key = self._password_site_key(raw_site)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or not site_key or not username.text() or not password.text():
            QMessageBox.warning(self, self.tr("Ungültige Eingabe", "Invalid input"), self.tr("Bitte eine gültige Webseitenadresse, Benutzernamen und Passwort eingeben.", "Enter a valid website address, username and password.")); return None
        return {"url": f"{parsed.scheme}://{parsed.netloc}/", "site_key": site_key, "username": username.text(), "password": password.text()}

    def show_password_manager(self):
        if not self._password_fernet and not self._password_setup_or_unlock(): return
        self._touch_password_manager()
        dialog = QDialog(self); dialog.setWindowTitle(self.tr("LunaSurfer – Passwortmanager", "LunaSurfer – Password manager")); dialog.resize(700, 430)
        layout = QVBoxLayout(dialog)
        info = QLabel(self.tr("Passwörter werden lokal verschlüsselt gespeichert. Das Master-Passwort kann nicht wiederhergestellt werden.", "Passwords are encrypted locally. The master password cannot be recovered.")); info.setWordWrap(True); layout.addWidget(info)
        tree = QTreeWidget(); tree.setHeaderLabels([self.tr("Website", "Website"), self.tr("Benutzername", "Username")]); layout.addWidget(tree)
        def refresh():
            tree.clear()
            for item in self._password_entries:
                node = QTreeWidgetItem([urllib.parse.urlparse(item["url"]).netloc, item["username"]]); node.setData(0, Qt.ItemDataRole.UserRole, item); tree.addTopLevelItem(node)
        refresh()
        self._password_manager_refresh_callback = refresh
        buttons = QHBoxLayout()
        add = QPushButton(self.tr("Hinzufügen", "Add"))
        edit = QPushButton(self.tr("Bearbeiten", "Edit"))
        delete = QPushButton(self.tr("Löschen", "Delete"))
        export_btn = QPushButton(self.tr("Verschlüsselt exportieren…", "Export encrypted…"))
        import_btn = QPushButton(self.tr("Verschlüsselt importieren…", "Import encrypted…"))
        change_master_btn = QPushButton(self.tr("Master-Passwort ändern…", "Change master password…"))
        lock = QPushButton(self.tr("Jetzt sperren", "Lock now"))
        for button in (add, edit, delete, export_btn, import_btn, change_master_btn):
            buttons.addWidget(button)
        buttons.addStretch(1); buttons.addWidget(lock); layout.addLayout(buttons)
        change_master_btn.clicked.connect(self.change_master_password)
        export_btn.clicked.connect(self.export_password_vault)
        import_btn.clicked.connect(self.import_password_vault)
        def add_entry():
            value = self._password_edit_dialog()
            if value:
                self._password_entries.append(value); self._save_password_entries(); refresh(); self._touch_password_manager()
        def edit_entry():
            node = tree.currentItem()
            if not node: return
            old = node.data(0, Qt.ItemDataRole.UserRole); value = self._password_edit_dialog(old)
            if value:
                idx = self._password_entries.index(old); self._password_entries[idx] = value; self._save_password_entries(); refresh(); self._touch_password_manager()
        def delete_entry():
            node = tree.currentItem()
            if node and self.confirm_action(self.tr("Passwort löschen", "Delete password"), self.tr("Diesen gespeicherten Login wirklich löschen?", "Really delete this saved login?")):
                self._password_entries.remove(node.data(0, Qt.ItemDataRole.UserRole)); self._save_password_entries(); refresh(); self._touch_password_manager()
        add.clicked.connect(add_entry); edit.clicked.connect(edit_entry); delete.clicked.connect(delete_entry)
        def lock_now():
            self.lock_password_manager(); dialog.accept()
        lock.clicked.connect(lock_now)
        def manager_finished(_result=0):
            self._password_manager_refresh_callback = None
            self._touch_password_manager()
        dialog.finished.connect(manager_finished)
        dialog.exec()
        current_view = self.tabs.currentWidget()
        if isinstance(current_view, QWebEngineView):
            self.autofill_saved_login(current_view)

    def install_login_capture(self, view):
        """Install Chromium-like login save and autofill hooks for this page."""
        try:
            u = urllib.parse.urlparse(view.url().toString())
            self._password_debug_log("capture_install_called", f"host={u.hostname or ''} path={u.path or ''}")
        except Exception:
            self._password_debug_log("capture_install_called", "url_unavailable")
        script = r"""
        (() => {
          if (window.__lunaPasswordHooks === 'ready' || window.__lunaPasswordHooks === 'connecting') return;
          window.__lunaPasswordHooks = 'connecting';
          let channelAttempts = 0;
          const init = () => {
            if (!window.qt || !qt.webChannelTransport || !window.QWebChannel) return false;
            new QWebChannel(qt.webChannelTransport, channel => {
              const bridge = channel.objects.lunaLoginBridge;
              window.__lunaPasswordHooks = 'ready';
              try { bridge.diagnostic('bridge_ready', location.hostname + location.pathname); } catch (_) {}
              let lastFieldSignature = '';
              const reportFields = () => {
                const fields = [...document.querySelectorAll('input')];
                const pw = fields.filter(e => (e.type||'').toLowerCase() === 'password').length;
                const visiblePw = fields.filter(e => (e.type||'').toLowerCase() === 'password' && e.getClientRects().length).length;
                const signature = fields.length + ':' + pw + ':' + visiblePw;
                if (signature === lastFieldSignature) return;
                lastFieldSignature = signature;
                try { bridge.diagnostic('dom_scan', 'inputs=' + fields.length + ' password_fields=' + pw + ' visible_password_fields=' + visiblePw); } catch (_) {}
                if (visiblePw) {
                  try { bridge.diagnostic('password_field_detected', 'host=' + location.hostname + ' path=' + location.pathname); } catch (_) {}
                }
              };
              reportFields();
              setTimeout(reportFields, 1200);
              setTimeout(reportFields, 3500);
              let suggestionBox = null;
              const visible = e => e && e.getClientRects().length;
              const usernameFor = pass => {
                // 7Pass/Joyn can render the e-mail and password controls in
                // separate forms/containers. Search the password form first,
                // then the complete visible document as a safe fallback.
                const form = pass && pass.form ? pass.form : document;
                const collect = root => [...root.querySelectorAll('input')].filter(e =>
                  e !== pass && visible(e) &&
                  !['password','hidden','submit','button','checkbox','radio','search','tel','number'].includes((e.type||'').toLowerCase()) &&
                  !e.disabled && !e.readOnly);
                const rank = candidates =>
                  candidates.find(e => /^(username|email|login|user)$/.test((e.autocomplete||'').toLowerCase())) ||
                  candidates.find(e => /email|user(name)?|login|account/i.test((e.name||'')+' '+(e.id||'')+' '+(e.getAttribute('aria-label')||''))) ||
                  candidates.find(e => (e.type||'').toLowerCase() === 'email') ||
                  candidates.find(e => (e.type||'').toLowerCase() === 'text') || null;
                const local = rank(collect(form));
                if (local) return local;
                return rank(collect(document));
              };
              const hideSuggestions = () => {
                if (suggestionBox) suggestionBox.remove();
                suggestionBox = null;
              };
              const showSuggestions = (field, pass) => {
                hideSuggestions();
                if (!field && pass) field = usernameFor(pass);
                // Interactive focus may request an unlock prompt when the user
                // has disabled the "must already be unlocked" requirement.
                bridge.suggestions(location.href, true, raw => {
                  let entries = [];
                  try { entries = JSON.parse(raw || '[]'); } catch (_) {}
                  if (!entries.length || (field && !field.isConnected)) return;
                  const box = document.createElement('div');
                  box.style.cssText = 'position:fixed;z-index:2147483647;background:#202938;color:#fff;border:1px solid #8954d4;border-radius:8px;padding:6px;box-shadow:0 6px 24px #0008;font:14px sans-serif;min-width:230px;';
                  const anchor = field || pass; if (!anchor) return; const rect = anchor.getBoundingClientRect();
                  box.style.left = Math.max(6, Math.min(rect.left, innerWidth-270)) + 'px';
                  box.style.top = Math.min(innerHeight-100, rect.bottom+4) + 'px';
                  entries.forEach(item => {
                    const b = document.createElement('button');
                    b.type = 'button';
                    b.textContent = item.username;
                    b.style.cssText = 'display:block;width:100%;text-align:left;padding:9px;border:0;border-radius:5px;background:transparent;color:#fff;cursor:pointer;';
                    b.addEventListener('mouseenter', () => b.style.background='#39465c');
                    b.addEventListener('mouseleave', () => b.style.background='transparent');
                    b.addEventListener('mousedown', e => e.preventDefault());
                    b.addEventListener('click', () => {
                      const set = (el, value) => {
                        if (!el) return;
                        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
                        setter.call(el, value);
                        el.dispatchEvent(new Event('input',{bubbles:true}));
                        el.dispatchEvent(new Event('change',{bubbles:true}));
                      };
                      const userField = field || usernameFor(pass);
                      if (userField) set(userField, item.username);
                      // The user's explicit choice binds this shared-provider credential
                      // to the relying party encoded in the current auth URL (e.g. 7Pass cd10=Joyn).
                      try { bridge.bindCredentialToRelyingParty(location.href, item.username); } catch (_) {}
                      // Multi-step identity providers (7Pass/Joyn) ask for the
                      // e-mail first and create the password field only after
                      // the user advances. Keep the chosen credential briefly
                      // in tab-scoped sessionStorage so the next step can fill
                      // the password without requiring a second selection.
                      try {
                        sessionStorage.setItem('__luna_login_user', item.username || '');
                        if (!pass && item.password) {
                          sessionStorage.setItem('__luna_pending_step_credential', JSON.stringify({username:item.username || '', password:item.password, created:Date.now()}));
                        }
                      } catch (_) {}
                      if (pass) set(pass, item.password);
                      hideSuggestions();
                      if (pass) pass.focus();
                    });
                    box.appendChild(b);
                  });
                  document.body.appendChild(box);
                  suggestionBox = box;
                  setTimeout(() => {
                    const close = e => { if (suggestionBox && !suggestionBox.contains(e.target)) { hideSuggestions(); document.removeEventListener('mousedown',close,true); } };
                    document.addEventListener('mousedown',close,true);
                  }, 0);
                });
              };
              // Automatically fill only when exactly one credential matches this origin.
              // Never submit the form automatically; the user remains in control.
              const setNativeValue = (el, value) => {
                if (!el) return;
                const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
                const desc = Object.getOwnPropertyDescriptor(proto, 'value');
                if (desc && desc.set) desc.set.call(el, value); else el.value = value;
                el.dispatchEvent(new Event('input', {bubbles:true}));
                el.dispatchEvent(new Event('change', {bubbles:true}));
              };
              const tryAutofill = () => {
                const pass = [...document.querySelectorAll('input[type=password]')].find(visible);
                if (!pass) return;
                // Complete a user-selected first-step login (e-mail page ->
                // password page). The temporary credential is scoped to this
                // tab/origin and is removed immediately after filling or expiry.
                try {
                  const rawPending = sessionStorage.getItem('__luna_pending_step_credential');
                  if (rawPending) {
                    const pending = JSON.parse(rawPending);
                    if (!pending.created || Date.now() - pending.created > 120000) {
                      sessionStorage.removeItem('__luna_pending_step_credential');
                    } else if (pending.password) {
                      const userField = usernameFor(pass);
                      if (userField && !userField.value && pending.username) setNativeValue(userField, pending.username);
                      if (!pass.value) setNativeValue(pass, pending.password);
                      sessionStorage.removeItem('__luna_pending_step_credential');
                      try { sessionStorage.setItem('__luna_login_user', pending.username || ''); } catch (_) {}
                      return;
                    }
                  }
                } catch (_) {}
                // Passive page scans never open a master-password prompt.
                bridge.suggestions(location.href, false, raw => {
                  let entries = [];
                  try { entries = JSON.parse(raw || '[]'); } catch (_) {}
                  if (entries.length !== 1) return;
                  const item = entries[0];
                  const userField = usernameFor(pass);
                  if (userField && !userField.value) setNativeValue(userField, item.username || '');
                  if (!pass.value) setNativeValue(pass, item.password || '');
                  try { sessionStorage.setItem('__luna_login_user', item.username || ''); } catch (_) {}
                });
              };
              // Sites often render login fields after the initial document load.
              let autofillQueued = false;
              const queueAutofill = () => {
                if (autofillQueued) return;
                autofillQueued = true;
                setTimeout(() => { autofillQueued = false; tryAutofill(); }, 180);
              };
              window.__lunaPasswordRescan = queueAutofill;
              let domScanQueued = false;
              new MutationObserver(() => {
                if (!domScanQueued) {
                  domScanQueued = true;
                  setTimeout(() => { domScanQueued = false; reportFields(); queueAutofill(); }, 100);
                }
              }).observe(document.documentElement, {childList:true, subtree:true, attributes:true, attributeFilter:['type','autocomplete','name','id']});
              window.addEventListener('pageshow', queueAutofill, true);
              window.addEventListener('focus', queueAutofill, true);
              window.addEventListener('popstate', queueAutofill, true);
              window.addEventListener('hashchange', queueAutofill, true);
              const originalPushState = history.pushState;
              history.pushState = function() {
                const result = originalPushState.apply(this, arguments);
                queueAutofill();
                return result;
              };
              const originalReplaceState = history.replaceState;
              history.replaceState = function() {
                const result = originalReplaceState.apply(this, arguments);
                queueAutofill();
                return result;
              };
              queueAutofill();
              setTimeout(queueAutofill, 700);
              setTimeout(queueAutofill, 1800);
              // Remember a selected Google account before the account chooser
              // navigates to the password challenge. Values stay in sessionStorage
              // and are never written to diagnostics.
              const rememberGoogleAccountFromTarget = target => {
                if (location.hostname.toLowerCase() !== 'accounts.google.com' || !target) return;
                const candidates = [];
                let node = target;
                for (let depth = 0; node && depth < 6; depth++, node = node.parentElement) candidates.push(node);
                for (const el of candidates) {
                  const values = [el.getAttribute && el.getAttribute('data-identifier'),
                    el.getAttribute && el.getAttribute('data-email'),
                    el.getAttribute && el.getAttribute('email'),
                    el.getAttribute && el.getAttribute('aria-label'),
                    el.innerText || el.textContent || ''];
                  for (const value of values) {
                    const match = String(value || '').match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
                    if (match) {
                      try { sessionStorage.setItem('__luna_login_user', match[0]); } catch (_) {}
                      return;
                    }
                  }
                }
              };
              // Remember a username entered on an earlier step (e.g. QRZ's
              // username -> Next -> password flow). sessionStorage is origin-scoped.
              const rememberUser = field => {
                if (!field || field.type === 'password') return;
                const hint = ((field.name||'')+' '+(field.id||'')+' '+(field.autocomplete||'')).toLowerCase();
                if (/user|email|login|account/.test(hint) || field.type === 'email' || (field.type === 'text' && !document.querySelector('input[type=password]'))) {
                  const value = (field.value || '').trim();
                  if (value) { try { sessionStorage.setItem('__luna_login_user', value); } catch (_) {} }
                }
              };
              document.addEventListener('input', event => rememberUser(event.target), true);
              document.addEventListener('change', event => rememberUser(event.target), true);
              document.addEventListener('focusin', event => {
                const field = event.target;
                if (!(field instanceof HTMLInputElement)) return;
                if (field.type === 'password') {
                  try { bridge.diagnostic('password_field_focus', 'host=' + location.hostname + ' path=' + location.pathname); } catch (_) {}
                  showSuggestions(usernameFor(field), field);
                } else {
                  // Multi-step identity providers (notably 7Pass/Joyn) show
                  // the e-mail field on a separate page before creating the
                  // password field. Offer the saved login at this first step;
                  // do not require a password input to exist yet.
                  const hint = (field.name||'')+' '+(field.id||'')+' '+(field.autocomplete||'')+' '+
                    (field.getAttribute('aria-label')||'')+' '+(field.getAttribute('placeholder')||'');
                  const isUsername = /username|e-?mail|email|user|login|account/i.test(hint) ||
                    field.type === 'email' || (field.type === 'text' && /signin|login|auth/i.test(location.pathname) && /7pass|joyn/i.test(location.hostname));
                  if (isUsername) {
                    const pass = (field.form || document).querySelector('input[type=password]') || document.querySelector('input[type=password]');
                    try { bridge.diagnostic('username_field_focus', 'host=' + location.hostname + ' path=' + location.pathname + ' password_present=' + !!pass); } catch (_) {}
                    showSuggestions(field, pass);
                  }
                }
              }, true);
              // Google uses a multi-step, JavaScript-driven sign-in flow. Its
              // password form can be submitted by a button/Enter handler without
              // producing the ordinary form-submit event in every embedded view.
              // Capture the entered credentials at the user action as a fallback.
              let lastActionCapture = '';
              let lastActionCaptureAt = 0;
              const captureCurrentLogin = () => {
                const pass = [...document.querySelectorAll('input[type=password]')].find(e => visible(e) && e.value);
                if (!pass) return;
                const userField = usernameFor(pass);
                let username = userField && userField.value ? userField.value.trim() : '';
                if (!username) { try { username = sessionStorage.getItem('__luna_login_user') || ''; } catch (_) {} }
                if (!username || !/^https?:/i.test(location.href)) return;
                const signature = location.href + '\n' + username + '\n' + pass.value;
                const now = Date.now();
                if (signature === lastActionCapture && now - lastActionCaptureAt < 5000) return;
                lastActionCapture = signature;
                lastActionCaptureAt = now;
                try { bridge.diagnostic('submit_action_seen', 'host=' + location.hostname + ' path=' + location.pathname); } catch (_) {}
                bridge.capture(location.href, username, pass.value, result => {
                  try { bridge.diagnostic('capture_reply', String(result || 'empty')); } catch (_) {}
                });
              };
              // Capture synchronously in the capture phase, before Google's
              // React handlers can clear/replace the password field or navigate.
              // pointerdown covers mouse/touch; click and Enter are fallbacks.
              document.addEventListener('pointerdown', event => {
                rememberGoogleAccountFromTarget(event.target);
                captureCurrentLogin();
              }, true);
              document.addEventListener('click', event => {
                rememberGoogleAccountFromTarget(event.target);
                captureCurrentLogin();
              }, true);
              document.addEventListener('keydown', event => {
                if (event.key === 'Enter') captureCurrentLogin();
              }, true);
              document.addEventListener('submit', event => {
                if (window.__lunaResumeSubmit) { window.__lunaResumeSubmit=false; return; }
                const form = event.target;
                if (!(form instanceof HTMLFormElement)) return;
                const pass = [...form.querySelectorAll('input[type=password]')].find(e => e.value);
                const user = pass && usernameFor(pass);
                let username = user && user.value ? user.value.trim() : '';
                if (!username) { try { username = sessionStorage.getItem('__luna_login_user') || ''; } catch (_) {} }
                if (!pass || !username || !/^https?:/i.test(location.href)) return;
                try { bridge.diagnostic('form_submit_seen', 'host=' + location.hostname + ' path=' + location.pathname); } catch (_) {}
                event.preventDefault();
                const pageUrl = location.href, password = pass.value;
                const submitter = event.submitter;
                bridge.capture(pageUrl, username, password, result => {
                  if (result === 'continue') {
                    window.__lunaResumeSubmit = true;
                    try { form.requestSubmit(submitter || undefined); } catch (_) { form.submit(); }
                    // For single-page applications, confirm only if the password field
                    // is cleared or removed after the server/client accepts the login.
                    setTimeout(() => {
                      const still = form.isConnected && form.querySelector('input[type=password]');
                      const here = new URL(location.href);
                      const googleAuthStep = here.hostname.toLowerCase() === 'accounts.google.com' &&
                        (/\/signin|\/challenge|\/v3\/signin/i.test(here.pathname));
                      if ((!still || !still.value) && !googleAuthStep) {
                        bridge.confirmSave(pageUrl, username, password, () => {});
                        try { sessionStorage.removeItem('__luna_login_user'); } catch (_) {}
                      }
                    }, 2200);
                  }
                });
              }, true);
            });
            return true;
          };
          const waitForTransport = () => {
            if (init()) return;
            channelAttempts += 1;
            if (channelAttempts < 80) {
              setTimeout(waitForTransport, 250);
            } else {
              window.__lunaPasswordHooks = false;
              try { console.warn('LunaSurfer password bridge unavailable after retries'); } catch (_) {}
            }
          };
          const load = () => {
            if (window.QWebChannel) { waitForTransport(); return; }
            if (window.__lunaQWebChannelLoading) { waitForTransport(); return; }
            window.__lunaQWebChannelLoading = true;
            const s = document.createElement('script');
            s.src = 'qrc:///qtwebchannel/qwebchannel.js';
            s.onload = () => { window.__lunaQWebChannelLoading = false; waitForTransport(); };
            s.onerror = () => {
              window.__lunaQWebChannelLoading = false;
              channelAttempts += 1;
              if (channelAttempts < 80) setTimeout(load, 250);
              else window.__lunaPasswordHooks = false;
            };
            (document.head || document.documentElement).appendChild(s);
          };
          load();
        })();
        """
        try:
            page = view.page()
            # Install persistently at DOM-ready, before site code can finish
            # replacing dynamic login forms. This also covers full navigations
            # between Google identifier, accountchooser and challenge pages.
            collection = page.scripts()
            for previous in collection.find("LunaSurferPasswordManagerCapture"):
                collection.remove(previous)
            # Embed Qt's own QWebChannel client from its registered Qt resource.
            # This avoids relying on a dynamically appended qrc: script element,
            # which can be delayed or rejected by strict page CSP policies.
            channel_source = ""
            try:
                channel_file = QFile(":/qtwebchannel/qwebchannel.js")
                if channel_file.open(QIODevice.OpenModeFlag.ReadOnly):
                    channel_source = bytes(channel_file.readAll()).decode("utf-8", errors="replace")
                    channel_file.close()
            except Exception:
                channel_source = ""
            capture_source = (channel_source + "\n;\n" if channel_source else "") + script
            capture_script = QWebEngineScript()
            capture_script.setName("LunaSurferPasswordManagerCapture")
            capture_script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentReady)
            capture_script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
            capture_script.setRunsOnSubFrames(True)
            capture_script.setSourceCode(capture_source)
            collection.insert(capture_script)
            self._password_debug_log(
                "capture_script_registered",
                "injection=document_ready subframes=true qwebchannel_embedded=" + str(bool(channel_source)).lower()
            )
            # Also start on the already-loaded document; the persistent script
            # handles all subsequent navigations automatically.
            page.runJavaScript(capture_source)
        except Exception as exc:
            self._password_debug_log("capture_script_register_error", type(exc).__name__)

    def _password_debug_log(self, event, details=""):
        """Write privacy-safe password-manager diagnostics; never log credentials."""
        try:
            log_dir = os.path.join(os.path.expanduser("~"), ".cache", "lunasurfer")
            os.makedirs(log_dir, mode=0o700, exist_ok=True)
            log_path = os.path.join(log_dir, "password-manager-debug.log")
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(f"[{stamp}] {event} {details}\n")
            try:
                os.chmod(log_path, 0o600)
            except Exception:
                pass
        except Exception:
            pass

    def capture_login_submission(self, view, page_url, username, password):
        """Temporarily hold a submitted login until success can be detected."""
        parsed = urllib.parse.urlparse(page_url)
        current = urllib.parse.urlparse(view.url().toString())
        self._password_debug_log("capture_called", f"host={parsed.hostname or ''} path={parsed.path or ''} current_host={current.hostname or ''}")
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or self._password_site_key(page_url) != self._password_site_key(view.url().toString())):
            return "continue"
        username, password = str(username or "").strip(), str(password or "")
        if not username or not password:
            return "continue"
        related_url = getattr(view, "_password_flow_origin_url", "")
        # Keep the destination requested by the identity provider. Google often
        # finishes by redirecting from accounts.google.com straight to this URL.
        continue_hosts = set()
        try:
            for value in urllib.parse.parse_qs(parsed.query).get("continue", []):
                target = urllib.parse.urlparse(urllib.parse.unquote(value))
                if target.hostname:
                    continue_hosts.add(target.hostname.lower())
        except Exception:
            pass
        self._pending_login_save = {
            "view": view, "url": f"{parsed.scheme}://{parsed.netloc}/",
            "site_key": self._password_site_key(page_url),
            "related_url": related_url,
            "continue_hosts": continue_hosts,
            "username": username, "password": password
        }
        self._password_debug_log("capture_accepted", f"host={parsed.hostname or ''} user_present={bool(username)} password_present={bool(password)}")
        # Navigation success is checked after the submit has had time to complete.
        QTimer.singleShot(2600, lambda v=view: self._check_pending_login_success(v))
        return "continue"

    def _check_pending_login_success(self, view):
        pending = getattr(self, "_pending_login_save", None)
        if not pending or pending.get("view") is not view:
            return
        try:
            view.page().runJavaScript(
                """(() => {
                    const visible = e => !!(e && e.getClientRects().length &&
                        getComputedStyle(e).visibility !== 'hidden' &&
                        getComputedStyle(e).display !== 'none');
                    const p = [...document.querySelectorAll('input[type=password]')].find(visible);
                    const bodyText = (document.body && document.body.innerText || '').slice(0, 3200);
                    const alerts = [...document.querySelectorAll('[role="alert"], [aria-live="assertive"], [aria-live="polite"]')]
                      .filter(visible).map(e => (e.innerText || e.textContent || '').trim()).filter(Boolean).join(' ');
                    return JSON.stringify({
                        url: location.href,
                        passwordPresent: !!p,
                        passwordValue: !!(p && p.value),
                        errorText: alerts + ' ' + bodyText
                    });
                })()""",
                lambda raw: self._evaluate_pending_login_success(pending, raw)
            )
        except Exception:
            pass

    def _evaluate_pending_login_success(self, pending, raw):
        if getattr(self, "_pending_login_save", None) is not pending:
            return
        try:
            state = json.loads(raw or "{}")
            current = urllib.parse.urlparse(state.get("url", ""))
        except Exception:
            return
        host = (current.hostname or "").lower()
        path = (current.path or "").lower()
        self._password_debug_log("success_probe", f"host={host} path={path} password_field={bool(state.get('passwordPresent'))} password_filled={bool(state.get('passwordValue'))}")
        is_google_auth_step = host == "accounts.google.com" and (
            "/signin" in path or "/challenge" in path or "/v3/signin" in path
        )
        # Google changes the challenge URL after accepting the password (for
        # example /challenge/ipp for phone approval or /challenge/totp for a code).
        # That transition is a reliable success signal even if Chromium still
        # exposes a stale password input in the document for a short time.
        challenge_match = re.search(r"/challenge/([^/?#]+)", path)
        challenge_step = challenge_match.group(1).lower() if challenge_match else ""
        google_password_step = challenge_step in {"pwd", "password"} or bool(
            re.search(r"/signin/(?:v\d+/)?password(?:/|$)", path)
        )
        google_next_challenge = bool(
            host == "accounts.google.com" and challenge_step and not google_password_step
        )
        # A completed Google login returns to the destination in the original
        # continue= parameter (for this test: www.google.com). Treat that
        # observed return as success even if the old password DOM is stale.
        pending_hosts = pending.get("continue_hosts", set())
        google_returned_to_destination = bool(
            pending.get("site_key") == "accounts.google.com"
            and host and host in pending_hosts
        )
        page_text = str(state.get("errorText", "") or "")
        # Avoid generic phrases such as "Try again" which can appear in
        # unrelated Google help text. Only explicit credential rejection blocks
        # the save prompt.
        google_rejected = host == "accounts.google.com" and re.search(
            r"wrong password|incorrect password|falsches passwort|"
            r"passwort ist falsch|password is incorrect|"
            r"couldn.t sign you in with this password|"
            r"falsche anmeldedaten",
            page_text, re.IGNORECASE
        )
        if google_rejected:
            self._password_debug_log("rejected", f"host={host} path={path}")
            self._pending_login_save = None
            return
        if google_next_challenge or google_returned_to_destination:
            self._finish_pending_login_save(pending)
            return
        if not state.get("passwordPresent") or not state.get("passwordValue"):
            self._finish_pending_login_save(pending)
            return
        # If Google still shows its password step, keep checking briefly for
        # the next challenge/result screen rather than discarding immediately.
        if is_google_auth_step:
            attempts = int(pending.get("google_wait_attempts", 0))
            if attempts < 40:
                pending["google_wait_attempts"] = attempts + 1
                QTimer.singleShot(1500, lambda v=pending["view"]: self._check_pending_login_success(v))
            else:
                self._password_debug_log("success_timeout", f"host={host} path={path} phase=google_auth")
                self._pending_login_save = None
            return
        # A still-visible password field may mean the site is processing or
        # rejected the credentials. Keep a bounded retry window rather than
        # silently abandoning the save check after the first delayed probe.
        attempts = int(pending.get("success_wait_attempts", 0))
        if attempts < 20:
            pending["success_wait_attempts"] = attempts + 1
            QTimer.singleShot(1500, lambda v=pending["view"]: self._check_pending_login_success(v))
        else:
            self._password_debug_log("success_timeout", f"host={host} path={path} phase=general")
            self._pending_login_save = None

    def _finish_pending_login_save(self, pending):
        if getattr(self, "_pending_login_save", None) is not pending:
            return
        self._password_debug_log("login_success_detected", f"host={urllib.parse.urlparse(pending.get('url', '')).hostname or ''}")
        self._pending_login_save = None
        self.confirm_login_save(
            pending["url"], pending["username"], pending["password"],
            pending.get("related_url", "")
        )

    def confirm_login_save(self, page_url, username, password, related_url=""):
        """Show save/update prompt after success and retain observed login-site relations."""
        parsed = urllib.parse.urlparse(page_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return "no"
        if not self.settings_data.get("password_auto_save", True):
            self._password_debug_log("save_prompt_skipped", "reason=auto_save_disabled")
            return "no"
        if not self._password_fernet and not self._password_setup_or_unlock():
            self._password_debug_log("save_prompt_skipped", "reason=vault_locked_or_unlock_cancelled")
            return "no"
        self._password_debug_log("save_prompt_shown", f"host={parsed.hostname or ''}")
        origin = f"{parsed.scheme}://{parsed.netloc}/"
        site_key = self._password_site_key(page_url)
        related_key = self._password_site_key(related_url) if related_url else ""
        # Updating a saved login must be scoped to the actual page where the
        # successful login occurred. A shared email address, stale tab URL, or
        # authentication return URL must never cause another site's entry to
        # be overwritten (e.g. GitHub replacing Joyn).
        existing = next((e for e in self._password_entries
                         if (e.get("site_key") or self._password_site_key(e.get("url", ""))) == site_key
                         and e.get("username", "").strip().casefold() == username.strip().casefold()), None)
        if existing and existing.get("password") == password:
            return "no"
        title = self.tr("Passwort aktualisieren?", "Update password?") if existing else self.tr("Passwort speichern?", "Save password?")
        message = self.tr(
            f"Das Passwort für {username} auf {parsed.hostname} {'aktualisieren' if existing else 'speichern'}?",
            f"{'Update' if existing else 'Save'} the password for {username} on {parsed.hostname}?"
        )
        answer = QMessageBox.question(
            self, title, message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        if answer != QMessageBox.StandardButton.Yes:
            return "no"
        value = {"url": origin, "site_key": site_key, "username": username, "password": password}
        if existing:
            existing.update(value)
            related_sites = list(existing.get("related_sites", []) or [])
            if related_key and related_key != site_key and related_key not in related_sites:
                related_sites.append(related_key)
            existing["related_sites"] = related_sites
        else:
            value["related_sites"] = [related_key] if related_key and related_key != site_key else []
            self._password_entries.append(value)
        self._save_password_entries()
        self._touch_password_manager()
        self.statusBar().showMessage(self.tr("Anmeldedaten verschlüsselt gespeichert.", "Login details saved securely."), 5000)
        return "yes"

    def bind_password_entry_to_relying_party(self, page_url, username, related_url=""):
        """Persist the user's explicit choice for an auth provider's relying party."""
        try:
            parsed = urllib.parse.urlparse(page_url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or not self._password_fernet:
                return False
            relying = []
            for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=False):
                if not re.search(r"continue|return|redirect|callback|cd10|service|client", key, re.I):
                    continue
                for _ in range(2):
                    value = urllib.parse.unquote(value)
                    target = urllib.parse.urlparse(value)
                    if target.scheme in ("http", "https") and target.hostname:
                        candidate = self._password_site_key(value)
                        if candidate and candidate not in relying:
                            relying.append(candidate)
                        break
            if not relying:
                return False
            changed = False
            for entry in self._password_entries:
                if (entry.get("username", "").lower() == str(username or "").lower()
                        and self._password_hosts_match(entry.get("site_key") or entry.get("url", ""), parsed.hostname)):
                    services = list(entry.get("service_sites", []) or [])
                    for key in relying:
                        if key not in services:
                            services.append(key)
                            changed = True
                    if services:
                        entry["service_sites"] = services
            if changed:
                self._save_password_entries()
            return changed
        except Exception:
            return False

    def password_suggestions(self, page_url, interactive=False, related_url=""):
        """Return same-site credentials passively; related-site credentials only after focus."""
        parsed = urllib.parse.urlparse(page_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return "[]"
        # Secure default: the vault must be unlocked first. If the user disables
        # that requirement, ask for the master password only after they focus a
        # login field; never interrupt ordinary page loads with an unlock prompt.
        if not self._password_fernet:
            if not (interactive and not self.settings_data.get("password_unlock_required", True)):
                return "[]"
            # A cancelled prompt is a deliberate choice. Ignore repeated focus,
            # DOM and SPA events for one minute; manual manager opening is unaffected.
            if time.monotonic() < getattr(self, "_password_unlock_suppressed_until", 0.0):
                return "[]"
            if not self._password_setup_or_unlock():
                return "[]"
        site_key = self._password_site_key(page_url)
        related_key = self._password_site_key(related_url) if related_url else ""
        # Identity providers often carry the relying-party site in a return
        # parameter (Google: continue=..., 7Pass/Joyn: cd10=...). When present,
        # that destination is the authoritative credential scope. Do not offer
        # unrelated accounts merely because they were previously associated
        # with the shared authentication host.
        relying_party_keys = []
        try:
            parsed_page = urllib.parse.urlparse(page_url)
            for key, raw_value in urllib.parse.parse_qsl(parsed_page.query, keep_blank_values=False):
                if not re.search(r"continue|return|redirect|callback|cd10|service|client", key, re.I):
                    continue
                value = raw_value
                for _ in range(2):
                    value = urllib.parse.unquote(value)
                    candidate = urllib.parse.urlparse(value)
                    if candidate.scheme in ("http", "https") and candidate.hostname:
                        target_key = self._password_site_key(value)
                        if target_key and target_key not in relying_party_keys:
                            relying_party_keys.append(target_key)
                        break
        except Exception:
            relying_party_keys = []
        # An explicit relying-party URL (e.g. 7Pass cd10=Joyn) scopes the list
        # to credentials the user has previously associated with that service.
        # On the first visit only, offer unbound credentials saved on this exact
        # identity-provider host; the user's selection is then persisted above.
        effective_keys = list(relying_party_keys) if relying_party_keys else []
        matches = []
        changed = False
        service_bound = []
        if relying_party_keys:
            for entry in self._password_entries:
                bound = entry.get("service_sites", []) or []
                if any(self._password_hosts_match(saved, wanted) for saved in bound for wanted in relying_party_keys):
                    service_bound.append(entry)
        for entry in self._password_entries:
            if not entry.get("username"):
                continue
            if relying_party_keys:
                bound = entry.get("service_sites", []) or []
                if service_bound:
                    site_match = entry in service_bound
                else:
                    # Bootstrap candidates must be saved for the current auth host;
                    # unrelated Google-site credentials are never included.
                    stored = entry.get("site_key") or self._password_site_key(entry.get("url", ""))
                    site_match = (self._password_hosts_match(stored, site_key)
                                  or self._password_entry_matches_sites(entry, relying_party_keys))
            else:
                # A previous top-level URL is not proof that the current site
                # is part of the same login flow. Match ordinary sites strictly
                # against the current page host. Cross-site credentials are
                # offered only when the current authentication URL explicitly
                # names its relying party (handled above).
                site_match = self._password_entry_matches_sites(entry, [site_key])
            if site_match:
                matches.append(entry)
        if changed:
            self._save_password_entries()
        self._touch_password_manager()
        return json.dumps(matches, ensure_ascii=False)

    def autofill_saved_login(self, view):
        """Re-trigger the page-side autofill scan after each completed navigation."""
        try:
            view.page().runJavaScript(
                "if (window.__lunaPasswordRescan) window.__lunaPasswordRescan();"
            )
        except Exception:
            pass


    def show_manual(self):
        """Display the built-in guide in the selected application language."""
        en = self.settings_data.get("language", "de") == "en"
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("LunaSurfer – Anleitung", "LunaSurfer – User guide"))
        dialog.resize(900, 760)
        dialog.setStyleSheet("QDialog{background:#11151d;color:#e8edf5} QTextBrowser{background:#171e29;color:#e8edf5;border:1px solid #344158;border-radius:10px;padding:18px} QPushButton{background:#293548;color:#edf2f8;border:1px solid #40516a;border-radius:8px;padding:9px 20px;min-width:90px} QPushButton:hover{border-color:#a879f5;background:#3b4b63}")
        layout = QVBoxLayout(dialog)
        browser = QTextBrowser(dialog)
        browser.setReadOnly(True)
        browser.setOpenExternalLinks(True)
        style = "<style>body{font-family:sans-serif;line-height:1.55;color:#e8edf5;font-size:14px}h1{color:#c7a6ff;font-size:27px}h2{color:#b99af0;font-size:19px;margin-top:26px;border-bottom:1px solid #39465b;padding-bottom:5px}p,li{color:#d5dbea}.tip{background:#222d3d;border-left:4px solid #9870d5;padding:10px 14px;border-radius:5px}</style>"
        if en:
            content = """<h1>LunaSurfer – Complete user guide</h1>
<p>This guide describes the browser and every control currently shown on the Settings page, plus the separate Protection &amp; Privacy panel. The names below correspond to the English interface.</p>
<h2>1. General</h2>
<ul>
<li><b>Language:</b> switches the LunaSurfer interface between Deutsch and English. The guide follows this choice and opens in one language only.</li>
<li><b>On startup:</b> <i>Open homepage</i> loads the configured homepage; <i>Restore last session</i> reopens the previous browsing session; <i>Open blank page</i> starts without loading a website.</li>
<li><b>Homepage:</b> sets the page opened by Home and by a new tab when the selected startup behavior uses it. Enter a complete URL, including https://.</li>
<li><b>Search engine:</b> chooses Google, DuckDuckGo or Bing for searches entered as plain text in the address bar.</li>
<li><b>Translation provider:</b> <i>Google Translate (whole webpage)</i> sends the page to Google Translate for full-page translation. <i>MyMemory</i> translates visible text sections without an API key and has a free daily limit. Translation quality and availability depend on the provider.</li>
<li><b>Browser design:</b> selects the browser chrome appearance: Dark (Standard), Light (Classic), Luna (Modern), Graphite Blue (Elegant) or Ocean (Teal Blue).</li>
<li><b>Website appearance:</b> selects the browser's light or dark theme setting. This is separate from the Browser design and from the Website colors option below.</li>
<li><b>Show bookmarks bar below the address bar:</b> shows or hides the bookmarks toolbar.</li>
<li><b>Download folder:</b> displays the folder used for downloaded files. Use <i>Choose folder…</i> to select another directory.</li>
<li><b>Ask where to save each download:</b> when enabled, asks for a destination for every new download; otherwise the configured download folder is used.</li>
<li><b>Default zoom:</b> sets the initial page zoom. Available values range from 50% to 200%; individual pages may still be zoomed separately.</li>
<li><b>Default font size:</b> sets Small, Medium, Large or Very large as the default web text size.</li>
<li><b>Website readability:</b> <i>Normal</i> leaves pages unchanged. Gentle, Softer and Relaxed contrast apply progressively different softer readability adjustments. If a page looks incorrect, return to Normal. Images and videos are intended to remain unchanged.</li>
<li><b>Website colors:</b> <i>Original</i> keeps site colors; <i>Black mode</i> requests black backgrounds. Some sites may not render perfectly in forced dark mode.</li>
</ul>
<h2>2. Security and permissions</h2>
<ul><li><b>Block pop-ups:</b> blocks unwanted pop-up windows. Disable only temporarily if a trusted site needs a pop-up for a sign-in or payment flow.</li><li><b>Enable JavaScript:</b> allows websites to run scripts. Many modern sites require it; disabling it can improve restriction but may break menus, sign-in, video and other features.</li></ul>
<h2>3. User-Agent management</h2>
<ul>
<li><b>Mode – Privacy default (reduced Chrome UA):</b> presents a reduced Chrome-style browser identification to limit exposed version and platform details.</li>
<li><b>Native browser User-Agent:</b> uses the browser engine's normal User-Agent string.</li>
<li><b>Custom User-Agent:</b> uses the exact string entered under <i>Custom value</i>. Enter a complete valid User-Agent; an empty custom value cannot be saved.</li>
<li><b>Current:</b> shows the effective User-Agent string. It can be selected and copied.</li>
<li><b>Important:</b> changing the User-Agent changes browser identification, not the actual browser engine or its capabilities. Client Hints may also be reduced when fingerprint protection is active.</li>
</ul>
<h2>4. Password manager</h2>
<ul>
<li><b>Open password manager…:</b> opens the encrypted website-login vault. Use the master password to unlock it and manage saved entries.</li>
<li><b>Delete all passwords…:</b> removes all saved website logins. The master password remains in place. This action does not change passwords stored at the websites themselves.</li>
<li><b>Offer to save passwords after successful sign-in:</b> controls whether LunaSurfer offers to save a detected successful login.</li>
<li><b>Password manager must be unlocked before autofill:</b> when enabled, unlock the vault before automatic filling. When disabled, LunaSurfer asks for the master password when a login field is focused.</li>
<li>Credentials are associated with their website, not merely with an email address. The same email may be used for different services; each service must have its own entry. Always check the site and account before accepting a save/update prompt.</li>
<li>Keep the master password safe. If it is lost, the encrypted vault may not be recoverable. Use secure backups and never share the master password.</li>
</ul>
<h2>5. Website permissions</h2>
<p><b>Edit saved website permissions…</b> opens the manager for decisions remembered for individual websites. The global defaults below apply when a site requests access:</p>
<ul><li><b>Camera, Microphone, Location, Notifications:</b> each can be set to <i>Ask</i>, <i>Allow</i> or <i>Block</i>. Ask prompts when a site requests access; Allow grants the relevant permission; Block denies it. Grant access only to sites you trust and when the feature is needed.</li>
<li><b>Send Do Not Track request:</b> sends the optional DNT signal. Websites are not required to honor it.</li>
<li><b>Browser behavior – Ask when closing a tab:</b> asks for confirmation before closing tabs, helping prevent accidental closure.</li></ul>
<h2>6. Privacy and browser data</h2>
<ul>
<li><b>Cookie mode – Allow all cookies:</b> permits first- and third-party cookies. This offers the broadest compatibility but allows more cross-site storage.</li>
<li><b>Block third-party cookies:</b> blocks cookies from domains other than the site being visited. Some embedded content or sign-in flows may be affected.</li>
<li><b>Block all cookies:</b> prevents sites from storing cookies and can break logins, preferences and shopping carts.</li>
<li><b>Allow session cookies only:</b> permits temporary session cookies but restricts persistent cookie storage. Site behavior and sign-in persistence may be affected.</li>
<li><b>Clear history:</b> deletes the recorded browsing history.</li><li><b>Clear cache:</b> removes cached page resources. The next visit may load more slowly while files are downloaded again.</li><li><b>Clear cookies:</b> removes website cookies and may sign you out or reset site preferences.</li><li><b>Clear everything:</b> performs the browser-data cleanup action for the available history, cache and cookie data. Review the confirmation carefully.</li>
<li><b>Automatically clear history/cache/cookies on exit:</b> each checkbox independently clears that data category when LunaSurfer closes.</li>
<li><b>Remember window size and position on exit:</b> restores the last browser window geometry at the next launch.</li>
<li><b>Use LunaSurfer as default browser:</b> asks the desktop environment to register LunaSurfer as the preferred browser for web links.</li>
</ul>
<h2>7. Separate Protection &amp; Privacy panel</h2>
<p>Open this panel with the shield button in the toolbar. It has two tabs:</p>
<h3>Ad blocker</h3><ul>
<li><b>Enable ad blocker:</b> turns filtering on or off.</li><li><b>Blocking strength:</b> Standard, Strong, Very strong, Super strong or Mega strong. Higher levels filter more patterns but can break site features or hide content.</li>
<li><b>Custom block patterns:</b> add domains or patterns separated by semicolons, for example <code>example-ads.com; tracker.example</code>.</li>
<li><b>Whitelist domains:</b> list domains that should be exempted from ad-block filtering, separated by semicolons. Use this for trusted sites that do not work correctly.</li>
</ul>
<h3>Fingerprint protection</h3><ul>
<li><b>Enable fingerprint protection:</b> activates measures intended to reduce identifying browser and device signals.</li>
<li><b>Protection level – Standard:</b> Canvas, audio and basic hardware protection.</li><li><b>Strong:</b> adds WebGL identifier masking.</li><li><b>Maximum:</b> adds further shielding of hardware details and browser Client Hints.</li>
<li>Changes are applied immediately; a browser restart is not normally required. Stronger protection can affect compatibility and does not guarantee anonymity.</li>
</ul>
<h2>8. Saving and applying changes</h2><p>Use <b>Save</b> to store the Settings page choices. Use <b>Cancel</b> to close without saving the pending changes. Some settings apply immediately; others take effect after the current pages reload. The protection panel has its own Save and Cancel buttons.</p>
<h2>9. Other browser features</h2><ul><li><b>Bookmarks:</b> use the star to save a page; manage folders and import/export bookmarks from the bookmarks manager.</li><li><b>Downloads:</b> review current and completed transfers in the download manager. Check the destination folder and available disk space if a download fails.</li><li><b>Website translation:</b> use the translation control to choose a target language or return to the original page. Translation is provided by the selected provider and may contain errors.</li><li><b>Tabs and keyboard shortcuts:</b> Ctrl+T opens a new tab; Ctrl+W closes the current tab; Ctrl+L focuses and selects the address bar; Ctrl+R reloads the current page; Alt+Left Arrow goes back; Alt+Right Arrow goes forward; Ctrl+Shift+L opens the password manager; F12 shows or hides Developer Tools. These shortcuts work while the LunaSurfer window is active. A website or focused input field may handle some keys differently depending on the context.</li></ul>
<h2>10. Complete keyboard shortcut reference</h2>
<table border="1" cellpadding="7" cellspacing="0"><tr><th>Shortcut</th><th>Action</th></tr>
<tr><td><b>Ctrl+L</b></td><td>Focuses the address bar and selects its current text, ready to type a URL or search.</td></tr>
<tr><td><b>Ctrl+T</b></td><td>Opens a new tab using the configured homepage.</td></tr>
<tr><td><b>Ctrl+W</b></td><td>Closes the active tab.</td></tr>
<tr><td><b>Ctrl+R</b></td><td>Reloads the page in the active tab.</td></tr>
<tr><td><b>Alt+Left Arrow</b></td><td>Returns to the previous page in the current tab's history.</td></tr>
<tr><td><b>Alt+Right Arrow</b></td><td>Moves forward in the current tab's history.</td></tr>
<tr><td><b>Ctrl+Shift+L</b></td><td>Opens the password manager. If the vault is locked, follow the unlock prompt.</td></tr>
<tr><td><b>F12</b></td><td>Shows or hides the Developer Tools panel. It is intended for diagnostics and advanced website inspection. The panel may contain technical information about the current page, requests and scripts.</td></tr></table>
<p><b>Usage notes:</b> The LunaSurfer window must be active. Shortcuts are context-sensitive: while typing in a website field, the website or field may consume a key combination. Press F12 again to hide Developer Tools. Developer Tools are intended for advanced users; changing page code or storage can affect the current website session.</p>
<h2>10. Troubleshooting and safety</h2><ul><li>If a website breaks, test whether JavaScript, cookies, pop-up blocking, ad blocking or fingerprint protection is responsible. Change one setting at a time.</li><li>If autofill does not appear, unlock the vault and check that an entry exists for the exact website.</li><li>If media does not play, check system codecs and browser compatibility. Protected streaming may require supported DRM components.</li><li>Check the domain before entering credentials. Keep LunaSurfer and Debian updated from trusted sources.</li></ul>
<p class='tip'><b>Privacy note:</b> privacy controls reduce selected browser signals and requests; they do not make a user anonymous. Websites, network providers and the operating system may still process activity data.</p><p><i>Goldisoft · LunaSurfer 0.3.38</i></p>"""
        else:
            content = """<h1>LunaSurfer – Vollständige Anleitung</h1>
<p>Diese Anleitung erklärt den Browser und sämtliche Einträge der aktuellen Einstellungsseite sowie das separate Fenster „Schutz &amp; Privatsphäre“. Die Bezeichnungen entsprechen der deutschen Programmoberfläche.</p>
<h2>1. Allgemein</h2>
<ul>
<li><b>Sprache:</b> stellt die LunaSurfer-Oberfläche auf Deutsch oder Englisch um. Die Anleitung öffnet sich passend zu dieser Auswahl und zeigt immer nur eine Sprache.</li>
<li><b>Beim Start:</b> <i>Startseite öffnen</i> lädt die eingestellte Startseite; <i>Letzte Sitzung wiederherstellen</i> öffnet die vorherige Browsersitzung erneut; <i>Leere Seite öffnen</i> startet ohne eine Website zu laden.</li>
<li><b>Startseite:</b> legt fest, welche Seite über die Startseitenfunktion und – abhängig vom Startverhalten – in einem neuen Tab geöffnet wird. Gib eine vollständige Adresse einschließlich https:// ein.</li>
<li><b>Suchmaschine:</b> bestimmt, ob Suchbegriffe aus der Adressleiste mit Google, DuckDuckGo oder Bing gesucht werden.</li>
<li><b>Übersetzungsanbieter:</b> <i>Google Translate (ganze Webseite)</i> öffnet die vollständige Seite zur Übersetzung bei Google Translate. <i>MyMemory (ohne API-Schlüssel)</i> übersetzt sichtbare Textabschnitte und besitzt ein kostenloses Tageslimit. Qualität und Verfügbarkeit hängen vom Anbieter ab.</li>
<li><b>Browser-Design:</b> wählt das Aussehen der Browseroberfläche: Dunkel (Standard), Hell (Klassisch), Luna (Modern), Graphit-Blau (Elegant) oder Ocean (Türkis-Blau).</li>
<li><b>Webseiten-Design:</b> wählt die helle oder dunkle Darstellungseinstellung des Browsers. Diese Einstellung ist unabhängig vom Browser-Design und von der Webseiten-Farbgebung.</li>
<li><b>Lesezeichenleiste unter der Adressleiste anzeigen:</b> blendet die Lesezeichenleiste ein oder aus.</li>
<li><b>Download-Ordner:</b> zeigt den Ordner, in dem heruntergeladene Dateien gespeichert werden. Mit <i>Ordner auswählen…</i> kannst du ein anderes Verzeichnis festlegen.</li>
<li><b>Bei jedem Download nach dem Speicherort fragen:</b> fragt bei jedem neuen Download nach dem Ziel. Ist die Option aus, wird der eingestellte Download-Ordner verwendet.</li>
<li><b>Standard-Zoom:</b> legt die anfängliche Webseitenvergrößerung fest. Möglich sind 50 % bis 200 %. Einzelne Seiten können zusätzlich separat gezoomt werden.</li>
<li><b>Standard-Schriftgröße:</b> stellt die Standardschrift auf Klein, Mittel, Groß oder Sehr groß.</li>
<li><b>Webseiten-Lesbarkeit:</b> <i>Normal</i> lässt Webseiten unverändert. Sanfter, Weicher und Entspannter Kontrast wenden unterschiedliche, zunehmend angepasste Lesbarkeitsdarstellungen an. Wenn eine Seite falsch aussieht, stelle Normal ein. Bilder und Videos sollen unverändert bleiben.</li>
<li><b>Webseiten-Farbgebung:</b> <i>Original</i> behält die Website-Farben bei; <i>Schwarzmodus</i> fordert schwarze Hintergründe an. Bei erzwungenem Dunkelmodus können einzelne Seiten fehlerhaft dargestellt werden.</li>
</ul>
<h2>2. Sicherheit und Berechtigungen</h2>
<ul><li><b>Pop-ups blockieren:</b> blockiert unerwünschte Popup-Fenster. Deaktiviere die Funktion nur vorübergehend, wenn eine vertrauenswürdige Website ein Popup etwa für Anmeldung oder Bezahlung benötigt.</li><li><b>JavaScript aktivieren:</b> erlaubt Websites die Ausführung von Skripten. Viele moderne Seiten benötigen JavaScript. Das Deaktivieren kann Funktionen einschränken, aber auch Menüs, Anmeldung, Videos und andere Inhalte unbrauchbar machen.</li></ul>
<h2>3. User-Agent-Verwaltung</h2>
<ul>
<li><b>Datenschutz-Standard (reduzierter Chrome-UA):</b> verwendet eine reduzierte Chrome-ähnliche Browserkennung, um weniger genaue Versions- und Plattformdetails preiszugeben.</li>
<li><b>Nativer Browser-User-Agent:</b> verwendet die normale User-Agent-Kennung der Browser-Engine.</li>
<li><b>Eigener User-Agent:</b> verwendet genau den Text, den du unter <i>Eigener Wert</i> einträgst. Trage eine vollständige gültige User-Agent-Zeichenfolge ein. Ein leerer eigener Wert kann nicht gespeichert werden.</li>
<li><b>Aktuell:</b> zeigt die tatsächlich verwendete User-Agent-Zeichenfolge an. Der Text kann markiert und kopiert werden.</li>
<li><b>Wichtig:</b> Der User-Agent verändert die Browserkennung, nicht die Browser-Engine oder deren tatsächliche Fähigkeiten. Bei aktivem Fingerprint-Schutz können auch Client Hints reduziert werden.</li>
</ul>
<h2>4. Passwortmanager</h2>
<ul>
<li><b>Passwortmanager öffnen…:</b> öffnet den verschlüsselten Tresor für Website-Anmeldungen. Entsperre ihn mit dem Master-Passwort, um Einträge zu verwalten.</li>
<li><b>Alle Passwörter löschen…:</b> entfernt alle gespeicherten Website-Zugangsdaten. Das Master-Passwort bleibt bestehen. Die Passwörter auf den Websites selbst werden dadurch nicht geändert.</li>
<li><b>Passwörter nach erfolgreicher Anmeldung zum Speichern anbieten:</b> legt fest, ob LunaSurfer nach einer erkannten erfolgreichen Anmeldung das Speichern der Zugangsdaten anbietet.</li>
<li><b>Passwortmanager muss vor dem automatischen Ausfüllen entsperrt sein:</b> ist die Option aktiviert, muss der Tresor vor dem automatischen Ausfüllen entsperrt werden. Ist sie deaktiviert, fragt LunaSurfer erst beim Anklicken eines Anmeldefeldes nach dem Master-Passwort.</li>
<li>Zugangsdaten werden der jeweiligen Website zugeordnet, nicht nur anhand der E-Mail-Adresse. Dieselbe E-Mail kann bei verschiedenen Diensten verwendet werden; jeder Dienst benötigt einen eigenen Eintrag. Prüfe Website und Konto immer, bevor du ein Speichern oder Aktualisieren bestätigst.</li>
<li>Bewahre das Master-Passwort sicher auf. Bei Verlust kann der verschlüsselte Tresor möglicherweise nicht wiederhergestellt werden. Erstelle sichere Sicherungskopien und gib das Master-Passwort niemals weiter.</li>
</ul>
<h2>5. Webseiten-Berechtigungen</h2>
<p><b>Gespeicherte Webseiten-Berechtigungen bearbeiten…</b> öffnet die Verwaltung gespeicherter Entscheidungen für einzelne Websites. Die folgenden allgemeinen Vorgaben gelten, wenn eine Website Zugriff anfordert:</p>
<ul><li><b>Kamera, Mikrofon, Standort, Benachrichtigungen:</b> jede Berechtigung kann auf <i>Beim Fragen</i>, <i>Erlauben</i> oder <i>Blockieren</i> gestellt werden. Beim Fragen erscheint eine Abfrage; Erlauben gewährt den Zugriff; Blockieren verweigert ihn. Erlaube Zugriff nur vertrauenswürdigen Websites und nur bei Bedarf.</li>
<li><b>Do Not Track-Anfrage senden:</b> sendet das optionale DNT-Signal. Websites sind nicht verpflichtet, es zu beachten.</li>
<li><b>Browser-Verhalten – Beim Schließen eines Tabs nachfragen:</b> fragt vor dem Schließen von Tabs nach und hilft so, versehentliches Schließen zu verhindern.</li></ul>
<h2>6. Datenschutz und Browserdaten</h2>
<ul>
<li><b>Cookie-Modus – Alle Cookies erlauben:</b> erlaubt Cookies von der besuchten Website und Drittanbietern. Das bietet die beste Kompatibilität, ermöglicht aber mehr seitenübergreifende Speicherung.</li>
<li><b>Drittanbieter-Cookies blockieren:</b> blockiert Cookies von anderen Domains als der gerade besuchten Website. Eingebettete Inhalte oder Anmeldevorgänge können dadurch beeinträchtigt werden.</li>
<li><b>Alle Cookies blockieren:</b> verhindert, dass Websites Cookies speichern. Anmeldungen, Einstellungen und Warenkörbe können dadurch nicht funktionieren.</li>
<li><b>Nur Sitzungscookies erlauben:</b> erlaubt vorübergehende Sitzungscookies, beschränkt aber dauerhafte Cookies. Das Verhalten von Websites und die Anmeldung können beeinträchtigt werden.</li>
<li><b>Verlauf löschen:</b> löscht den gespeicherten Browserverlauf.</li><li><b>Cache löschen:</b> entfernt zwischengespeicherte Webseitendateien. Beim nächsten Besuch kann das Laden länger dauern, weil Dateien erneut heruntergeladen werden.</li><li><b>Cookies löschen:</b> entfernt Website-Cookies. Dadurch wirst du möglicherweise abgemeldet oder Website-Einstellungen werden zurückgesetzt.</li><li><b>Alles löschen:</b> führt die Browserdaten-Löschung für die verfügbaren Verlaufs-, Cache- und Cookie-Daten aus. Lies die Bestätigungsabfrage sorgfältig.</li>
<li><b>Verlauf/Cache/Cookies beim Beenden automatisch löschen:</b> jede Option löscht die jeweilige Datenkategorie unabhängig von den anderen beim Schließen von LunaSurfer.</li>
<li><b>Fenstergröße und Position beim Beenden merken:</b> stellt beim nächsten Start die zuletzt verwendete Fenstergröße und Position wieder her.</li>
<li><b>LunaSurfer als Standardbrowser verwenden:</b> bittet die Desktop-Umgebung, LunaSurfer als bevorzugten Browser für Weblinks einzutragen.</li>
</ul>
<h2>7. Separates Fenster „Schutz &amp; Privatsphäre“</h2>
<p>Öffne dieses Fenster über die Schild-Schaltfläche in der Symbolleiste. Es enthält zwei Registerkarten:</p>
<h3>Werbeblocker</h3><ul>
<li><b>Werbeblocker aktivieren:</b> schaltet die Filterung ein oder aus.</li><li><b>Blockierstärke:</b> Standard, Stark, Sehr stark, Super stark oder Mega stark. Höhere Stufen filtern mehr Muster, können aber Funktionen stören oder Inhalte ausblenden.</li>
<li><b>Eigene Blockiermuster:</b> füge Domains oder Muster ein, getrennt durch Semikolons, zum Beispiel <code>example-ads.com; tracker.example</code>.</li>
<li><b>Whitelist-Domains:</b> Domains, die von der Werbeblocker-Filterung ausgenommen werden sollen, ebenfalls durch Semikolons trennen. Das hilft bei vertrauenswürdigen Seiten, die sonst nicht richtig funktionieren.</li>
</ul>
<h3>Fingerprint-Schutz</h3><ul>
<li><b>Fingerprint-Schutz aktivieren:</b> schaltet Maßnahmen ein, die identifizierende Browser- und Gerätesignale reduzieren sollen.</li>
<li><b>Schutzstufe – Standard:</b> Canvas-, Audio- und grundlegender Hardware-Schutz.</li><li><b>Stark:</b> ergänzt die Maskierung von WebGL-Kennungen.</li><li><b>Maximum:</b> schirmt zusätzlich Hardwareangaben und Browser-Client-Hints ab.</li>
<li>Änderungen werden sofort angewendet; ein Browserneustart ist normalerweise nicht erforderlich. Stärkerer Schutz kann die Kompatibilität beeinträchtigen und garantiert keine Anonymität.</li>
</ul>
<h2>8. Änderungen speichern und anwenden</h2><p>Mit <b>Speichern</b> werden die Einstellungen übernommen. <b>Abbrechen</b> schließt die Einstellungsseite, ohne die noch offenen Änderungen zu speichern. Manche Einstellungen wirken sofort, andere nach dem Neuladen der geöffneten Seiten. Das Schutzfenster besitzt eigene Schaltflächen zum Speichern und Abbrechen.</p>
<h2>9. Weitere Browserfunktionen</h2><ul><li><b>Lesezeichen:</b> mit dem Stern speicherst du eine Seite. In der Lesezeichenverwaltung kannst du Ordner organisieren sowie Lesezeichen importieren und exportieren.</li><li><b>Downloads:</b> im Download-Manager siehst du laufende und abgeschlossene Downloads. Prüfe bei Problemen den Zielordner und den freien Speicherplatz.</li><li><b>Webseiten übersetzen:</b> über die Übersetzungsfunktion wählst du eine Zielsprache oder kehrst zur Originalseite zurück. Die Übersetzung erfolgt durch den eingestellten Anbieter und kann Fehler enthalten.</li><li><b>Tabs und Tastenkürzel:</b> Strg+T öffnet einen neuen Tab; Strg+W schließt den aktuellen Tab; Strg+L aktiviert die Adressleiste und markiert deren Inhalt; Strg+R lädt die aktuelle Seite neu; Alt+Pfeil links geht zurück; Alt+Pfeil rechts geht vorwärts; Strg+Umschalt+L öffnet den Passwortmanager; F12 blendet die Entwicklerwerkzeuge ein oder aus. Die Tastenkürzel funktionieren, wenn das LunaSurfer-Fenster aktiv ist. Je nach Situation können Websites oder gerade aktive Eingabefelder einzelne Tasten anders verarbeiten.</li></ul>
<h2>10. Vollständige Übersicht der Tastenkürzel</h2>
<table border="1" cellpadding="7" cellspacing="0"><tr><th>Tastenkürzel</th><th>Funktion</th></tr>
<tr><td><b>Strg+L</b></td><td>Aktiviert die Adressleiste und markiert den vorhandenen Text, damit du direkt eine Adresse oder Suche eingeben kannst.</td></tr>
<tr><td><b>Strg+T</b></td><td>Öffnet einen neuen Tab mit der eingestellten Startseite.</td></tr>
<tr><td><b>Strg+W</b></td><td>Schließt den aktiven Tab.</td></tr>
<tr><td><b>Strg+R</b></td><td>Lädt die Seite im aktiven Tab neu.</td></tr>
<tr><td><b>Alt+Pfeil links</b></td><td>Wechselt im Verlauf des aktuellen Tabs zur vorherigen Seite zurück.</td></tr>
<tr><td><b>Alt+Pfeil rechts</b></td><td>Wechselt im Verlauf des aktuellen Tabs wieder vorwärts.</td></tr>
<tr><td><b>Strg+Umschalt+L</b></td><td>Öffnet den Passwortmanager. Ist der Tresor gesperrt, folge der Aufforderung zum Entsperren.</td></tr>
<tr><td><b>F12</b></td><td>Blendet das Fenster der Entwicklerwerkzeuge ein oder aus. Es dient zur Fehlersuche und zur erweiterten Untersuchung von Webseiten. Dort können technische Informationen zur aktuellen Seite, zu Netzwerkanfragen und Skripten angezeigt werden.</td></tr></table>
<p><b>Hinweise zur Verwendung:</b> Das LunaSurfer-Fenster muss aktiv sein. Tastenkürzel hängen vom aktuellen Kontext ab: Beim Schreiben in einem Webseitenfeld kann die Website oder das Eingabefeld eine Tastenkombination selbst verarbeiten. Mit erneutem Drücken von F12 blendest du die Entwicklerwerkzeuge wieder aus. Die Entwicklerwerkzeuge richten sich an erfahrene Nutzer; Änderungen an Seitencode oder Speicher können die aktuelle Sitzung der Website beeinflussen.</p>
<h2>10. Fehlerbehebung und Sicherheit</h2><ul><li>Wenn eine Website nicht funktioniert, prüfe JavaScript, Cookies, Pop-up-Blockierung, Werbeblocker und Fingerprint-Schutz. Ändere immer nur eine Einstellung auf einmal.</li><li>Wenn automatisches Ausfüllen nicht erscheint, entsperre den Tresor und prüfe, ob ein Eintrag für genau diese Website vorhanden ist.</li><li>Wenn Medien nicht abgespielt werden, prüfe System-Codecs und Browserkompatibilität. Geschützte Streams benötigen möglicherweise unterstützte DRM-Komponenten.</li><li>Prüfe die Domain, bevor du Zugangsdaten eingibst. Halte LunaSurfer und Debian über vertrauenswürdige Quellen aktuell.</li></ul>
<p class='tip'><b>Hinweis zum Datenschutz:</b> Datenschutzfunktionen reduzieren ausgewählte Browser-Signale und Anfragen. Sie machen dich nicht anonym. Websites, Netzwerkanbieter und das Betriebssystem können weiterhin Nutzungsdaten verarbeiten.</p><p><i>Goldisoft · LunaSurfer 0.3.38</i></p>"""
        browser.setHtml("<!doctype html><html><head><meta charset='utf-8'>" + style + "</head><body>" + content + "</body></html>")
        layout.addWidget(browser)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        close_button = QPushButton(self.tr("Schließen", "Close"), dialog)
        close_button.clicked.connect(dialog.accept)
        buttons.addWidget(close_button)
        layout.addLayout(buttons)
        dialog.exec()

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
        translation_provider = QComboBox()
        translation_provider.addItem(self.tr("Google Translate (ganze Webseite)", "Google Translate (whole webpage)"), "google")
        translation_provider.addItem(self.tr("MyMemory (ohne API-Schlüssel)", "MyMemory (no API key)"), "mymemory")
        translation_provider.setCurrentIndex(max(0, translation_provider.findData(
            self.settings_data.get("translation_provider", "google"))))
        translation_help = QLabel(self.tr(
            "Google übersetzt die komplette Webseite. MyMemory übersetzt sichtbare Textabschnitte und hat ein kostenloses Tageslimit.",
            "Google translates the whole webpage. MyMemory translates visible text sections and has a free daily limit."
        ))
        translation_help.setWordWrap(True)
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
        readability = QComboBox()
        readability.addItem(self.tr("Normal – Webseiten unverändert", "Normal – leave websites unchanged"), "normal")
        readability.addItem(self.tr("Sanfter Kontrast", "Gentle contrast"), "soft")
        readability.addItem(self.tr("Weicher Kontrast", "Softer contrast"), "softer")
        readability.addItem(self.tr("Entspannter Kontrast", "Relaxed contrast"), "relaxed")
        readability.setCurrentIndex(max(0, readability.findData(self.settings_data.get("website_readability", "normal"))))
        website_color = QComboBox()
        website_color.addItem(self.tr("Original – Webseitenfarben beibehalten", "Original – keep website colors"), "normal")
        website_color.addItem(self.tr("Schwarzmodus – schwarze Hintergründe", "Black mode – black backgrounds"), "black")
        website_color.setCurrentIndex(max(0, website_color.findData(self.settings_data.get("website_color_mode", "normal"))))
        block=QCheckBox(self.tr("Pop-ups blockieren", "Block pop-ups")); block.setChecked(self.settings_data.get("block_popups",True))
        javascript=QCheckBox(self.tr("JavaScript aktivieren", "Enable JavaScript")); javascript.setChecked(self.settings_data.get("javascript_enabled", True))
        permission_boxes={}
        for key,de_label,en_label in [("permission_camera","Kamera","Camera"),("permission_microphone","Mikrofon","Microphone"),("permission_location","Standort","Location"),("permission_notifications","Benachrichtigungen","Notifications")]:
            box=QComboBox(); box.addItem(self.tr("Beim Fragen", "Ask"), "ask"); box.addItem(self.tr("Erlauben", "Allow"), "allow"); box.addItem(self.tr("Blockieren", "Block"), "block"); box.setCurrentIndex(max(0,box.findData(self.settings_data.get(key,"ask")))); permission_boxes[key]=box
        dnt=QCheckBox(self.tr("Do Not Track-Anfrage senden", "Send Do Not Track request")); dnt.setChecked(self.settings_data.get("send_dnt",False))
        confirm_tabs=QCheckBox(self.tr("Beim Schließen eines Tabs nachfragen", "Ask when closing a tab")); confirm_tabs.setChecked(self.settings_data.get("confirm_close_multiple_tabs",True))
        clear_history_exit=QCheckBox(self.tr("Verlauf beim Beenden automatisch löschen", "Automatically clear history on exit")); clear_history_exit.setChecked(self.settings_data.get("clear_history_on_exit",False))
        clear_cache_exit=QCheckBox(self.tr("Cache beim Beenden automatisch löschen", "Automatically clear cache on exit")); clear_cache_exit.setChecked(self.settings_data.get("clear_cache_on_exit",False))
        clear_cookies_exit=QCheckBox(self.tr("Cookies beim Beenden automatisch löschen", "Automatically clear cookies on exit")); clear_cookies_exit.setChecked(self.settings_data.get("clear_cookies_on_exit",False))
        cookie_mode = QComboBox()
        cookie_modes = [
            ("Alle Cookies erlauben", "Allow all cookies", "all"),
            ("Drittanbieter-Cookies blockieren", "Block third-party cookies", "third"),
            ("Alle Cookies blockieren", "Block all cookies", "none"),
            ("Nur Sitzungscookies erlauben", "Allow session cookies only", "session"),
        ]
        for de_label, en_label, value in cookie_modes:
            cookie_mode.addItem(self.tr(de_label, en_label), value)
        cookie_mode.setCurrentIndex(max(0, cookie_mode.findData(self.settings_data.get("cookie_mode", "all"))))
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
        form.addRow(self.tr("Sprache:", "Language:"), language); form.addRow(self.tr("Beim Start:", "On startup:"),startup); form.addRow(self.tr("Startseite:", "Homepage:"),home); form.addRow(self.tr("Suchmaschine:", "Search engine:"),engine); form.addRow(self.tr("Übersetzungsanbieter:", "Translation provider:"), translation_provider); form.addRow("", translation_help); form.addRow(self.tr("Browser-Design:", "Browser design:"),browser_design); form.addRow(self.tr("Webseiten-Design:", "Website appearance:"),theme); form.addRow("",show_bookmarks_bar); form.addRow(self.tr("Download-Ordner:", "Download folder:"),row); form.addRow("",ask_download); form.addRow(self.tr("Standard-Zoom:", "Default zoom:"),zoom); form.addRow(self.tr("Standard-Schriftgröße:", "Default font size:"),font_size); form.addRow(self.tr("Webseiten-Lesbarkeit:", "Website readability:"), readability); form.addRow(self.tr("Webseiten-Farbgebung:", "Website colors:"), website_color)
        add_section(self.tr("Sicherheit und Berechtigungen", "Security and permissions"))
        form.addRow(self.tr("Sicherheit:", "Security:"),block); form.addRow("", javascript)
        add_section(self.tr("User-Agent-Verwaltung", "User-Agent management"))
        ua_mode = QComboBox()
        ua_mode.addItem(self.tr("Datenschutz-Standard (reduzierter Chrome-UA)", "Privacy default (reduced Chrome UA)"), "privacy")
        ua_mode.addItem(self.tr("Nativer Browser-User-Agent", "Native browser User-Agent"), "native")
        ua_mode.addItem(self.tr("Eigener User-Agent", "Custom User-Agent"), "custom")
        ua_mode.setCurrentIndex(max(0, ua_mode.findData(self.settings_data.get("user_agent_mode", "privacy"))))
        ua_custom = QLineEdit(str(self.settings_data.get("user_agent_custom", "")))
        ua_custom.setPlaceholderText(self.tr("Vollständigen User-Agent eintragen…", "Enter a complete User-Agent string…"))
        ua_current = QLabel(self.effective_user_agent())
        ua_current.setWordWrap(True)
        ua_current.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        ua_help = QLabel(self.tr(
            "Der User-Agent beeinflusst die Browserkennung. Die Browser-Engine und ihre Funktionen werden dadurch nicht geändert. Client Hints werden bei aktivem Fingerprint-Schutz passend zur Chromium-Version reduziert.",
            "The User-Agent changes the browser identification, not the browser engine or its capabilities. With fingerprint protection enabled, Client Hints are reduced to match the Chromium version."
        ))
        ua_help.setWordWrap(True)
        def update_ua_preview(*_):
            mode = ua_mode.currentData()
            if mode == "native":
                preview = self._native_user_agent
            elif mode == "custom":
                preview = ua_custom.text().strip() or self.tr("Noch kein eigener User-Agent eingetragen", "No custom User-Agent entered yet")
            else:
                preview = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36") if self.settings_data.get("fingerprint_enabled", True) else self._native_user_agent
            ua_current.setText(preview)
        ua_mode.currentIndexChanged.connect(lambda _=0: (ua_custom.setEnabled(ua_mode.currentData() == "custom"), update_ua_preview()))
        ua_custom.textChanged.connect(update_ua_preview)
        ua_custom.setEnabled(ua_mode.currentData() == "custom")
        update_ua_preview()
        form.addRow(self.tr("Modus:", "Mode:"), ua_mode)
        form.addRow(self.tr("Eigener Wert:", "Custom value:"), ua_custom)
        form.addRow(self.tr("Aktuell:", "Current:"), ua_current)
        form.addRow("", ua_help)
        password_auto_save = QCheckBox(self.tr("Passwörter nach erfolgreicher Anmeldung zum Speichern anbieten", "Offer to save passwords after successful sign-in"))
        password_auto_save.setChecked(self.settings_data.get("password_auto_save", True))
        password_unlock_required = QCheckBox(self.tr("Passwortmanager muss vor dem automatischen Ausfüllen entsperrt sein", "Password manager must be unlocked before autofill"))
        password_unlock_required.setChecked(self.settings_data.get("password_unlock_required", True))
        password_unlock_required.setToolTip(self.tr(
            "Wenn deaktiviert, fragt LunaSurfer erst beim Anklicken eines Login-Feldes nach dem Master-Passwort.",
            "When disabled, LunaSurfer asks for the master password only when you focus a login field."
        ))
        password_manager_button = QPushButton(self.tr("Passwortmanager öffnen…", "Open password manager…"))
        password_manager_button.setToolTip(self.tr("Gespeicherte Website-Anmeldedaten verschlüsselt verwalten", "Manage encrypted saved website logins"))
        password_manager_button.clicked.connect(self.show_password_manager)
        delete_passwords_button = QPushButton(self.tr("Alle Passwörter löschen…", "Delete all passwords…"))
        delete_passwords_button.setToolTip(self.tr("Alle gespeicherten Website-Anmeldedaten löschen; das Master-Passwort bleibt bestehen", "Delete all saved website logins; the master password remains"))
        delete_passwords_button.clicked.connect(self.delete_all_saved_passwords)
        form.addRow(self.tr("Passwörter:", "Passwords:"), password_manager_button)
        form.addRow("", delete_passwords_button)
        form.addRow("", password_auto_save)
        form.addRow("", password_unlock_required)
        manage_permissions = QPushButton(self.tr(
            "Gespeicherte Webseiten-Berechtigungen bearbeiten…",
            "Edit saved website permissions…"
        ))
        manage_permissions.setToolTip(self.tr(
            "Gespeicherte Entscheidungen für einzelne Webseiten verwalten",
            "Manage saved permission decisions for individual websites"
        ))
        manage_permissions.clicked.connect(self.show_permission_manager)
        form.addRow(self.tr("Webseiten-Berechtigungen:", "Website permissions:"), manage_permissions)
        for key, box in permission_boxes.items():
            labels = {"permission_camera": ("Kamera", "Camera"), "permission_microphone": ("Mikrofon", "Microphone"), "permission_location": ("Standort", "Location"), "permission_notifications": ("Benachrichtigungen", "Notifications")}
            de_label, en_label = labels[key]
            form.addRow(self.tr(de_label, en_label) + ":", box)
        form.addRow("",dnt); form.addRow(self.tr("Browser-Verhalten:", "Browser behavior:"),confirm_tabs)
        privacy=QHBoxLayout(); a=QPushButton(self.tr("Verlauf löschen", "Clear history")); b=QPushButton(self.tr("Cache löschen", "Clear cache")); c=QPushButton(self.tr("Cookies löschen", "Clear cookies")); [privacy.addWidget(x) for x in (a,b,c)]
        clear_all = QPushButton(self.tr("Alles löschen", "Clear everything"))
        clear_all.setStyleSheet("QPushButton { background-color: #b3261e; color: white; font-weight: 600; padding: 8px 14px; border-radius: 5px; } QPushButton:hover { background-color: #d13b32; }")
        add_section(self.tr("Datenschutz und Browserdaten", "Privacy and browser data"))
        form.addRow(self.tr("Cookie-Modus:", "Cookie mode:"), cookie_mode); form.addRow(self.tr("Browserdaten:", "Browser data:"),privacy); form.addRow("", clear_all); form.addRow("",clear_history_exit); form.addRow("",clear_cache_exit); form.addRow("",clear_cookies_exit); form.addRow("",remember_window_size); form.addRow("",default_browser); a.clicked.connect(self.clear_history); b.clicked.connect(self.clear_cache); c.clicked.connect(self.clear_cookies); clear_all.clicked.connect(self.clear_all_browser_data)
        buttons=QHBoxLayout(); save=QPushButton(self.tr("Speichern", "Save")); cancel=QPushButton(self.tr("Abbrechen", "Cancel")); buttons.addWidget(save); buttons.addWidget(cancel); form.addRow(buttons)
        save.clicked.connect(lambda:self.save_settings_v39(page,home.text(),engine.currentText(),engine.currentData(),theme.currentData(),show_bookmarks_bar.isChecked(),startup.currentData(),download_dir.text(),ask_download.isChecked(),zoom.currentData(),font_size.currentData(),block.isChecked(),dnt.isChecked(),confirm_tabs.isChecked(),{k:v.currentData() for k,v in permission_boxes.items()},clear_history_exit.isChecked(),clear_cache_exit.isChecked(),clear_cookies_exit.isChecked(),remember_window_size.isChecked(),language.currentData(),default_browser.isChecked(),browser_design.currentData(),javascript.isChecked(),cookie_mode.currentData(),password_auto_save.isChecked(),password_unlock_required.isChecked(),readability.currentData(),website_color.currentData(),ua_mode.currentData(),ua_custom.text(),translation_provider.currentData()))
        cancel.clicked.connect(lambda: self.close_settings_page(page))

    def close_settings_page(self, page):
        index = self.tabs.indexOf(page)
        if index >= 0:
            self.tabs.removeTab(index)
            page.deleteLater()
            if self.tabs.count() == 0:
                self.add_tab(self.settings_data.get("home"))
            QTimer.singleShot(0, self.update_new_tab_button_position)

    def save_settings_v39(self, dialog, home, engine_name, search_url, theme, bookmarks, startup_mode, download_dir, ask_download, zoom, font_size, block, dnt, confirm_tabs, permissions, ch, cc, ck, remember_window_size=True, language="de", default_browser=False, browser_design="dark", javascript_enabled=True, cookie_mode="all", password_auto_save=True, password_unlock_required=True, website_readability="normal", website_color_mode="normal", user_agent_mode="privacy", user_agent_custom="", translation_provider="google"):
        if user_agent_mode == "custom" and not str(user_agent_custom).strip():
            QMessageBox.warning(self, self.tr("User-Agent fehlt", "User-Agent missing"), self.tr("Bitte einen vollständigen User-Agent eintragen oder einen anderen Modus auswählen.", "Enter a complete User-Agent or select another mode."))
            return
        chosen=pathlib.Path(download_dir.strip() or str(DOWNLOAD_DIR)).expanduser()
        previous_translation_provider = self.settings_data.get("translation_provider", "google")
        selected_translation_provider = translation_provider if translation_provider in ("google", "mymemory") else "google"
        self.settings_data.update({"home":home.strip() or "https://duckduckgo.com","search":search_url,"search_engine":engine_name,"theme":theme,"show_bookmarks_bar":bool(bookmarks),"startup_mode":startup_mode,"restore_session":startup_mode=="restore","download_dir":str(chosen),"default_zoom":int(zoom or 100),"font_size":font_size,"ask_download_location":bool(ask_download),"block_popups":bool(block),"javascript_enabled":bool(javascript_enabled),"send_dnt":bool(dnt),"confirm_close_multiple_tabs":bool(confirm_tabs),"clear_history_on_exit":bool(ch),"clear_cache_on_exit":bool(cc),"clear_cookies_on_exit":bool(ck),"cookie_mode":cookie_mode if cookie_mode in ("all","third","none","session") else "all","remember_window_size":bool(remember_window_size),"language":language or "de","default_browser":bool(default_browser),"browser_design":browser_design if browser_design in ("dark", "light", "luna", "graphite", "ocean") else "dark","password_auto_save":bool(password_auto_save),"password_unlock_required":bool(password_unlock_required),"website_readability": website_readability if website_readability in ("normal", "soft", "softer", "relaxed") else "normal", "website_color_mode": website_color_mode if website_color_mode in ("normal", "black") else "normal", "user_agent_mode": user_agent_mode if user_agent_mode in ("privacy", "native", "custom") else "privacy", "user_agent_custom": str(user_agent_custom).strip(), "translation_provider": selected_translation_provider,**permissions})
        self.download_dir=chosen
        write_json(CONFIG_FILE, self.settings_data)

        # Apply the selected translation provider immediately; do not require a restart.
        # Rebuild the language menu so every action uses the current provider dispatcher.
        try:
            translate_menu = QMenu(self.translate_button)
            for lang_code, lang_name in [
                ("de", "Deutsch"), ("en", "English"), ("fr", "Français"),
                ("it", "Italiano"), ("nl", "Nederlands"), ("es", "Español"),
                ("pt", "Português"), ("pl", "Polski"), ("ru", "Русский"),
                ("tr", "Türkçe"), ("ja", "日本語"), ("zh-CN", "中文")
            ]:
                action = translate_menu.addAction(lang_name)
                action.triggered.connect(
                    lambda checked=False, code=lang_code: self.translate_current_page_selected(code)
                )
            translate_menu.addSeparator()
            original_action = translate_menu.addAction(
                self.tr("Originalseite anzeigen", "Show original page")
            )
            original_action.triggered.connect(self.show_original_page)
            self.translate_button.setMenu(translate_menu)
            self.translate_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
            self.translate_button.setEnabled(True)
            self.translate_button.setVisible(True)
            self.translate_button.update()
            self.navigation_bar.update()
            provider_label = "MyMemory" if self.settings_data.get("translation_provider") == "mymemory" else "Google Translate"
            self.statusBar().showMessage(
                self.tr("Übersetzungsanbieter sofort übernommen: ", "Translation provider applied immediately: ")
                + provider_label, 6000
            )
        except Exception as exc:
            self.statusBar().showMessage(
                self.tr("Übersetzungsmenü konnte nicht aktualisiert werden: ", "Could not refresh translation menu: ")
                + str(exc), 10000
            )

        self.apply_cookie_mode(); self.set_default_browser(bool(default_browser)); self.apply_language_live()
        self.apply_fingerprint_protection_live()
        if selected_translation_provider != previous_translation_provider:
            self._translation_notice_url = None
            if self._translation_notice_button is not None:
                self._clear_translation_notice(self._translation_notice_button)
        for index in range(self.tabs.count()):
            view = self.tabs.widget(index)
            if isinstance(view, BrowserView):
                view.reload()
        self.bookmarks_bar.setVisible(self.settings_data["show_bookmarks_bar"]); self.apply_browser_design(); self.apply_theme_to_all_tabs()
        for i in range(self.tabs.count()):
            view = self.tabs.widget(i)
            if isinstance(view, BrowserView):
                view.page().settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, self.settings_data["javascript_enabled"])
        for i in range(self.tabs.count()):
            view = self.tabs.widget(i)
            if isinstance(view, BrowserView):
                self.apply_font_size(view)
        self.close_settings_page(dialog)
        if selected_translation_provider != previous_translation_provider:
            def refresh_translation_prompt():
                view = self.current_view()
                if isinstance(view, BrowserView):
                    current_url = view.url().toString()
                    if current_url.startswith(("http://", "https://")):
                        view._last_language_checked_url = None
                        view._check_page_language_for_translation(current_url)
            QTimer.singleShot(1400, refresh_translation_prompt)

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
        if self.confirm_action(
            self.tr("Cache löschen", "Clear cache"),
            self.tr("Möchtest du den Browser-Cache wirklich löschen?", "Do you really want to clear the browser cache?")
        ):
            self.profile.clearHttpCache()
            self.statusBar().showMessage("Browser-Cache wurde gelöscht.", 5000)
            QMessageBox.information(self, self.tr("Cache gelöscht", "Cache cleared"), self.tr("Der Browser-Cache wurde gelöscht.", "The browser cache has been cleared."))

    def clear_all_browser_data(self):
        title = self.tr("Alle Browserdaten löschen", "Clear all browser data")
        message = self.tr(
            "Möchtest du wirklich alle Browserdaten löschen?\n\nVerlauf, Cache, Cookies, Anmeldesitzungen, Local Storage, IndexedDB und weitere Website-Daten werden entfernt. Du wirst auf Webseiten abgemeldet.\n\nLesezeichen und gespeicherte Passwörter bleiben erhalten. Die vollständige Löschung wird beim nächsten Neustart von LunaSurfer abgeschlossen.",
            "Do you really want to clear all browser data?\n\nHistory, cache, cookies, sign-in sessions, Local Storage, IndexedDB and other website data will be removed. You will be signed out of websites.\n\nBookmarks and saved passwords will be kept. The full cleanup will finish the next time LunaSurfer starts."
        )
        if not self.confirm_action(title, message):
            return

        # Clear immediately available data and mark the persistent WebEngine profile
        # for a complete wipe before it is reopened on the next application start.
        write_json(HISTORY_FILE, [])
        write_json(SESSION_FILE, [])
        try:
            self.profile.clearHttpCache()
            self.profile.clearAllVisitedLinks()
            self.profile.cookieStore().deleteAllCookies()
        except Exception:
            pass
        for index in range(self.tabs.count()):
            view = self.tabs.widget(index)
            if isinstance(view, QWebEngineView):
                script = """(async () => {
                    try { localStorage.clear(); sessionStorage.clear(); } catch (e) {}
                    try { const dbs = await indexedDB.databases(); await Promise.all(dbs.map(db => db.name ? new Promise(resolve => { const req = indexedDB.deleteDatabase(db.name); req.onsuccess = req.onerror = req.onblocked = () => resolve(); }) : Promise.resolve())); } catch (e) {}
                    try { if (window.caches) { const keys = await caches.keys(); await Promise.all(keys.map(k => caches.delete(k))); } } catch (e) {}
                    try { if (navigator.serviceWorker) { const regs = await navigator.serviceWorker.getRegistrations(); await Promise.all(regs.map(r => r.unregister())); } } catch (e) {}
                })();"""
                try:
                    view.page().runJavaScript(script)
                except Exception:
                    pass
        try:
            CLEAR_WEB_DATA_MARKER.parent.mkdir(parents=True, exist_ok=True)
            CLEAR_WEB_DATA_MARKER.write_text("1\n", encoding="utf-8")
        except Exception as exc:
            QMessageBox.warning(self, title, self.tr(f"Die vollständige Löschung konnte nicht vorgemerkt werden: {exc}", f"Could not schedule the complete cleanup: {exc}"))
            return
        self.statusBar().showMessage(self.tr("Browserdaten gelöscht; vollständige Bereinigung nach Neustart.", "Browser data cleared; full cleanup will finish after restart."), 8000)
        QMessageBox.information(self, title, self.tr("Die Browserdaten werden gelöscht. Bitte LunaSurfer neu starten, damit auch alle gespeicherten Website-Daten vollständig entfernt werden. Lesezeichen und gespeicherte Passwörter bleiben erhalten.", "Browser data is being cleared. Please restart LunaSurfer to remove all stored website data completely. Bookmarks and saved passwords will be kept."))

    def filter_cookies(self, request):
        """Apply the selected first/third-party cookie policy."""
        mode = self.settings_data.get("cookie_mode", "all")
        if mode == "none":
            return False
        if mode == "third":
            return not bool(request.thirdParty)
        return True

    def apply_cookie_mode(self):
        """Apply persistence behavior; cookie filtering is handled by CookieStore."""
        mode = self.settings_data.get("cookie_mode", "all")
        policy = QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies if mode == "session" else QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies
        self.profile.setPersistentCookiesPolicy(policy)

    def clear_cookies(self):
        if self.confirm_action(
            self.tr("Cookies löschen", "Clear cookies"),
            self.tr("Möchtest du wirklich alle gespeicherten Cookies löschen?", "Do you really want to delete all stored cookies?")
        ):
            self.profile.cookieStore().deleteAllCookies()
            self.statusBar().showMessage("Alle Cookies wurden gelöscht.", 5000)
            QMessageBox.information(self, self.tr("Cookies gelöscht", "Cookies cleared"), self.tr("Alle gespeicherten Cookies wurden gelöscht.", "All stored cookies have been cleared."))

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
        QMessageBox.about(self, self.tr("Über LunaSurfer", "About LunaSurfer"), f"{APP_NAME} {APP_VERSION}\n" + self.tr("Qt 6 + QtWebEngine mit auswählbarem hellem/dunklem Webseiten-Design und optionaler Widevine-CDM-Einbindung.", "Qt 6 + QtWebEngine with selectable light/dark website appearance and optional Widevine CDM integration.") + "\nGoldisoft · 2026")

def main():
    # Force Qt's own file chooser widgets instead of the desktop-native GTK
    # dialog, which may display English labels independently of LunaSurfer.
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeDialogs, True)
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("Goldisoft")
    # Install the matching Qt widget translations before creating the window.
    # The browser's saved language setting controls the dialog language too.
    try:
        saved_language = read_json(CONFIG_FILE, {}).get("language", "de")
    except Exception:
        saved_language = "de"
    qt_translator = QTranslator(app)
    translations_path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    qt_language = "en" if saved_language == "en" else "de"
    if qt_translator.load(f"qtbase_{qt_language}", translations_path):
        app.installTranslator(qt_translator)
    QLocale.setDefault(QLocale(qt_language))
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
