#!/usr/bin/env python3
"""LunaSurfer 0.3.49 - Qt 6 / QtWebEngine browser."""
import json
import copy
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

from PySide6.QtCore import QUrl, QSize, QPoint, Qt, QTimer, QEvent, QObject, Slot, Signal, QThread, QTranslator, QLocale, QLibraryInfo, QFile, QIODevice
from PySide6.QtGui import QAction, QKeySequence, QIcon
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QToolBar, QLineEdit, QToolButton, QWidgetAction,
    QVBoxLayout, QWidget, QMenu, QFileDialog, QMessageBox, QDialog,
    QFormLayout, QPushButton, QHBoxLayout, QLabel, QCheckBox, QComboBox, QStyle, QInputDialog, QListWidget, QListWidgetItem, QTreeWidget, QTreeWidgetItem, QHeaderView, QProgressBar, QSizePolicy, QScrollArea, QDockWidget, QDialogButtonBox, QGroupBox, QTextBrowser
)
from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage, QWebEngineSettings, QWebEngineUrlRequestInterceptor, QWebEngineScript
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebChannel import QWebChannel
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2.low_level import hash_secret_raw, Type as Argon2Type
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

APP_NAME = "LunaSurfer"
_VERSION_FILE = pathlib.Path(__file__).resolve().with_name("VERSION")
try:
    APP_VERSION = _VERSION_FILE.read_text(encoding="utf-8").strip() or "0.3.35"
except OSError:
    APP_VERSION = "0.3.49"
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


def safe_download_filename(value):
    """Reduce a server-supplied download name to a safe single filename."""
    name = str(value or "download").replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip().rstrip(". ")
    if name in ("", ".", ".."):
        name = "download"
    return name[:180]



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




# Portuguese (Portugal) interface catalogue.
RUSSIAN_UI = {'Manage bookmarks': 'Управление закладками',
 '» More': '» Ещё',
 'Clear all browser data': 'Очистить все данные браузера',
 'Find on this page': 'Найти на странице',
 'Matches 0 of 0': 'Совпадений: 0 из 0',
 'Previous match': 'Предыдущее совпадение',
 'Next match': 'Следующее совпадение',
 'Close find bar': 'Закрыть панель поиска',
 'Developer tools': 'Инструменты разработчика',
 'Back': 'Назад',
 'Forward': 'Вперёд',
 'Reload': 'Обновить',
 'Home': 'Домой',
 'Enter address or search': 'Введите адрес или поисковый запрос',
 'Translate webpage': 'Перевести страницу',
 'Show original page': 'Показать оригинал страницы',
 'Add current page to bookmarks': 'Добавить текущую страницу в закладки',
 'Unlock password manager – autofill saved logins (Ctrl+Shift+L)': 'Разблокировать менеджер паролей — '
                                                                   'автозаполнение сохранённых учётных '
                                                                   'данных (Ctrl+Shift+L)',
 'Download manager': 'Менеджер загрузок',
 'Protection & privacy': 'Защита и конфиденциальность',
 'New tab': 'Новая вкладка',
 'Menu': 'Меню',
 'Bookmarks': 'Закладки',
 'History': 'История',
 'Open downloads folder': 'Открыть папку загрузок',
 'Settings': 'Настройки',
 'User guide': 'Руководство пользователя',
 'Developer tools (F12)': 'Инструменты разработчика (F12)',
 'About LunaSurfer': 'О программе LunaSurfer',
 'Quit': 'Выход',
 'Bookmarks bar': 'Панель закладок',
 'Ad blocker': 'Блокировщик рекламы',
 'Ready': 'Готово',
 'Loading translated webpage …': 'Загрузка переведённой страницы…',
 'View and manage bookmarks': 'Просмотр и управление закладками',
 'Open': 'Открыть',
 'Edit bookmark…': 'Изменить закладку…',
 'Delete bookmark': 'Удалить закладку',
 'Edit bookmark': 'Изменить закладку',
 'Name:': 'Имя:',
 'Address:': 'Адрес:',
 'Bookmark changed': 'Закладка изменена',
 'Really delete this bookmark?': 'Действительно удалить эту закладку?',
 'Bookmark deleted': 'Закладка удалена',
 'Your bookmarks': 'Ваши закладки',
 'Expand folders, search entries and manage them directly.': 'Раскрывайте папки, ищите записи и управляйте '
                                                             'ими прямо здесь.',
 'Search bookmarks or addresses …': 'Поиск закладок или адресов…',
 'Edit…': 'Изменить…',
 'Delete': 'Удалить',
 'Import…': 'Импорт…',
 'Export…': 'Экспорт…',
 'Close': 'Закрыть',
 'Protection settings: ad blocker and fingerprint': 'Настройки защиты: блокировщик рекламы и защита от '
                                                    'цифрового отпечатка',
 'Saved website permissions': 'Сохранённые разрешения сайтов',
 'Change or remove remembered decisions for each website. Changes are saved immediately.': 'Изменяйте или '
                                                                                           'удаляйте '
                                                                                           'сохранённые '
                                                                                           'решения для '
                                                                                           'каждого сайта. '
                                                                                           'Изменения '
                                                                                           'сохраняются '
                                                                                           'сразу.',
 'Camera': 'Камера',
 'Microphone': 'Микрофон',
 'Location': 'Местоположение',
 'Notifications': 'Уведомления',
 'Clear all saved permissions': 'Удалить все сохранённые разрешения',
 'Enable ad blocker': 'Включить блокировщик рекламы',
 'The ad blocker filters known advertising and tracking domains. Higher levels block more, but may affect some websites.': 'Блокировщик '
                                                                                                                           'рекламы '
                                                                                                                           'фильтрует '
                                                                                                                           'известные '
                                                                                                                           'рекламные '
                                                                                                                           'и '
                                                                                                                           'отслеживающие '
                                                                                                                           'домены. '
                                                                                                                           'Более '
                                                                                                                           'высокий '
                                                                                                                           'уровень '
                                                                                                                           'блокирует '
                                                                                                                           'больше, '
                                                                                                                           'но '
                                                                                                                           'может '
                                                                                                                           'влиять '
                                                                                                                           'на '
                                                                                                                           'работу '
                                                                                                                           'некоторых '
                                                                                                                           'сайтов.',
 'Enable fingerprint protection': 'Включить защиту от цифрового отпечатка',
 'Fingerprint protection': 'Защита от цифрового отпечатка',
 'Save': 'Сохранить',
 'Cancel': 'Отмена',
 'Download Manager': 'Менеджер загрузок',
 'Downloads': 'Загрузки',
 'All active and completed files in one place.': 'Все активные и завершённые загрузки в одном месте.',
 'All downloads': 'Все загрузки',
 'In progress': 'Выполняется',
 'Paused': 'Приостановлено',
 'Completed': 'Завершено',
 'Failed / cancelled': 'Ошибка / отменено',
 'Search filename or path …': 'Поиск по имени файла или пути…',
 'Cancel download': 'Отменить загрузку',
 'Open file': 'Открыть файл',
 'Open folder': 'Открыть папку',
 'Remove entry': 'Удалить запись',
 'Clear completed': 'Очистить завершённые',
 'Clear history': 'Очистить историю',
 'Change master password': 'Изменить мастер-пароль',
 'Current master password:': 'Текущий мастер-пароль:',
 'New master password': 'Новый мастер-пароль',
 'New master password (at least 10 characters):': 'Новый мастер-пароль (не менее 10 символов):',
 'Confirm master password': 'Подтвердите мастер-пароль',
 'Enter the new master password again:': 'Введите новый мастер-пароль ещё раз:',
 'Export password': 'Пароль экспорта',
 'Choose a password for this export file (at least 10 characters):': 'Задайте пароль для этого файла '
                                                                     'экспорта (не менее 10 символов):',
 'Confirm export password': 'Подтвердите пароль экспорта',
 'Enter the export password again:': 'Введите пароль экспорта ещё раз:',
 'Enter the password used to encrypt this export file:': 'Введите пароль, использованный для шифрования '
                                                         'файла экспорта:',
 'Passwords deleted': 'Пароли удалены',
 'All saved website passwords have been deleted. The master password remains.': 'Все сохранённые пароли '
                                                                                'сайтов удалены. '
                                                                                'Мастер-пароль сохранён.',
 'Login details': 'Данные для входа',
 'Website (matched automatically)': 'Сайт (определяется автоматически)',
 'Username': 'Имя пользователя',
 'Password': 'Пароль',
 'Show password': 'Показать пароль',
 'Generate secure password': 'Создать надёжный пароль',
 'LunaSurfer – Password manager': 'LunaSurfer — Менеджер паролей',
 'Passwords are encrypted locally. The master password cannot be recovered.': 'Пароли шифруются локально. '
                                                                              'Мастер-пароль невозможно '
                                                                              'восстановить.',
 'Add': 'Добавить',
 'Edit': 'Изменить',
 'Export encrypted…': 'Экспортировать в зашифрованном виде…',
 'Import encrypted…': 'Импортировать зашифрованные данные…',
 'Change master password…': 'Изменить мастер-пароль…',
 'Lock now': 'Заблокировать',
 'Update password?': 'Обновить пароль?',
 'Save password?': 'Сохранить пароль?',
 'Login details saved securely.': 'Данные для входа надёжно сохранены.',
 'LunaSurfer – User guide': 'LunaSurfer — Руководство пользователя',
 'Open homepage': 'Открыть домашнюю страницу',
 'Restore last session': 'Восстановить предыдущий сеанс',
 'Open blank page': 'Открыть пустую страницу',
 'Google Translate (whole webpage)': 'Google Переводчик (вся веб-страница)',
 'MyMemory (no API key)': 'MyMemory (без ключа API)',
 'Google translates the whole webpage. MyMemory translates visible text sections and has a free daily limit.': 'Google '
                                                                                                               'переводит '
                                                                                                               'всю '
                                                                                                               'веб-страницу. '
                                                                                                               'MyMemory '
                                                                                                               'переводит '
                                                                                                               'видимые '
                                                                                                               'фрагменты '
                                                                                                               'текста '
                                                                                                               'и '
                                                                                                               'имеет '
                                                                                                               'дневной '
                                                                                                               'бесплатный '
                                                                                                               'лимит.',
 'Dark': 'Тёмная',
 'Light': 'Светлая',
 'Dark (Standard)': 'Тёмная (стандартная)',
 'Light (Classic)': 'Светлая (классическая)',
 'Luna (Modern)': 'Luna (современная)',
 'Graphite Blue (Elegant)': 'Графитово-синяя (элегантная)',
 'Ocean (Teal Blue)': 'Океан (бирюзово-синий)',
 'Show bookmarks bar below the address bar': 'Показывать панель закладок под адресной строкой',
 'Choose folder…': 'Выбрать папку…',
 'Ask where to save each download': 'Спрашивать, куда сохранять каждый файл',
 'Show security warning for executable downloads': 'Показывать предупреждение безопасности для исполняемых '
                                                   'файлов',
 'Show popup when a download finishes': 'Показывать уведомление по завершении загрузки',
 'Block pop-ups': 'Блокировать всплывающие окна',
 'Enable JavaScript': 'Включить JavaScript',
 'Send Do Not Track request': 'Отправлять запрос Do Not Track',
 'Ask when closing a tab': 'Спрашивать при закрытии вкладки',
 'Automatically clear history on exit': 'Автоматически очищать историю при выходе',
 'Automatically clear cache on exit': 'Автоматически очищать кэш при выходе',
 'Automatically clear cookies on exit': 'Автоматически удалять cookie при выходе',
 'Remember window size and position on exit': 'Запоминать размер и положение окна при выходе',
 'Use LunaSurfer as default browser': 'Использовать LunaSurfer как браузер по умолчанию',
 'General': 'Общие',
 'Language:': 'Язык:',
 'On startup:': 'При запуске:',
 'Homepage:': 'Домашняя страница:',
 'Search engine:': 'Поисковая система:',
 'Translation provider:': 'Служба перевода:',
 'Browser design:': 'Оформление браузера:',
 'Website appearance:': 'Внешний вид сайтов:',
 'Download folder:': 'Папка загрузок:',
 'Default zoom:': 'Масштаб по умолчанию:',
 'Default font size:': 'Размер шрифта по умолчанию:',
 'Website readability:': 'Читаемость сайтов:',
 'Website colors:': 'Цвета сайтов:',
 'Security and permissions': 'Безопасность и разрешения',
 'Security:': 'Безопасность:',
 'User-Agent management': 'Управление User-Agent',
 'Privacy default (reduced Chrome UA)': 'Режим конфиденциальности (сокращённый Chrome UA)',
 'Native browser User-Agent': 'Собственный User-Agent браузера',
 'Custom User-Agent': 'Пользовательский User-Agent',
 'Enter a complete User-Agent string…': 'Введите полную строку User-Agent…',
 'Mode:': 'Режим:',
 'Custom value:': 'Пользовательское значение:',
 'Current:': 'Текущее значение:',
 'Offer to save passwords after successful sign-in': 'Предлагать сохранять пароли после успешного входа',
 'Password manager must be unlocked before autofill': 'Перед автозаполнением необходимо разблокировать '
                                                      'менеджер паролей',
 'Open password manager…': 'Открыть менеджер паролей…',
 'Manage encrypted saved website logins': 'Управление зашифрованными сохранёнными учётными данными сайтов',
 'Delete all passwords…': 'Удалить все пароли…',
 'Passwords:': 'Пароли:',
 'Edit saved website permissions…': 'Изменить сохранённые разрешения сайтов…',
 'Website permissions:': 'Разрешения сайтов:',
 'Browser behavior:': 'Поведение браузера:',
 'Clear cache': 'Очистить кэш',
 'Clear cookies': 'Удалить cookie',
 'Clear everything': 'Очистить всё',
 'Privacy and browser data': 'Конфиденциальность и данные браузера',
 'Cookie mode:': 'Режим cookie:',
 'Browser data:': 'Данные браузера:',
 'Permission request': 'Запрос разрешения',
 'Remember this decision for this website': 'Запомнить это решение для данного сайта',
 'Allow': 'Разрешить',
 'Block': 'Заблокировать',
 'Yes': 'Да',
 'No': 'Нет',
 'Close tab': 'Закрыть вкладку',
 'Do you really want to close this tab?': 'Вы действительно хотите закрыть эту вкладку?',
 'Stop loading': 'Остановить загрузку',
 'Translation': 'Перевод',
 'Open a regular webpage first.': 'Сначала откройте обычную веб-страницу.',
 'Original page': 'Исходная страница',
 'No original page URL is saved for this tab.': 'Для этой вкладки не сохранён адрес исходной страницы.',
 'More bookmarks': 'Другие закладки',
 'Show more bookmarks': 'Показать больше закладок',
 'Name': 'Имя',
 'Address': 'Адрес',
 'Export bookmarks': 'Экспорт закладок',
 'Import bookmarks': 'Импорт закладок',
 'Website': 'Веб-сайт',
 'Permission': 'Разрешение',
 'Decision': 'Решение',
 'Action': 'Действие',
 'Blocking strength:': 'Уровень блокировки:',
 'Protection level:': 'Уровень защиты:',
 'File no longer present': 'Файл больше не существует',
 'Cancelled': 'Отменено',
 'Failed': 'Ошибка',
 'Interrupted': 'Прервано',
 'Ⅱ Pause': 'Ⅱ Пауза',
 'Download security warning': 'Предупреждение безопасности загрузки',
 'This file may be dangerous': 'Этот файл может быть опасен',
 'Do not show this security warning again': 'Больше не показывать это предупреждение безопасности',
 'Download anyway': 'Всё равно загрузить',
 'History cleared': 'История очищена',
 'The browsing history has been cleared.': 'История просмотров очищена.',
 'Unlock password manager': 'Разблокировать менеджер паролей',
 'Master password:': 'Мастер-пароль:',
 'Set up password manager': 'Настроить менеджер паролей',
 'Enter master password again:': 'Введите мастер-пароль ещё раз:',
 'Look in:': 'Папка:',
 'File name:': 'Имя файла:',
 'File type:': 'Тип файла:',
 'Too short': 'Слишком короткий пароль',
 'Please use at least 10 characters.': 'Используйте не менее 10 символов.',
 'Passwords do not match': 'Пароли не совпадают',
 'The passwords do not match.': 'Пароли не совпадают.',
 'Master password changed': 'Мастер-пароль изменён',
 'Use at least 10 characters.': 'Используйте не менее 10 символов.',
 'Export complete': 'Экспорт завершён',
 'Import complete': 'Импорт завершён',
 'No passwords stored': 'Сохранённых паролей нет',
 'There are no saved passwords to delete.': 'Нет сохранённых паролей для удаления.',
 'Delete all passwords': 'Удалить все пароли',
 'Invalid input': 'Некорректные данные',
 'Ask': 'Спрашивать',
 'User-Agent missing': 'User-Agent не указан',
 'Cache cleared': 'Кэш очищен',
 'Cookies cleared': 'Cookie удалены',
 'Folder': 'Папка',
 'Delete folder': 'Удалить папку',
 'Bookmarks exported': 'Закладки экспортированы',
 'Export': 'Экспорт',
 'Bookmarks imported': 'Закладки импортированы',
 'Import': 'Импорт',
 'Remove': 'Удалить',
 'Clear all permissions': 'Удалить все разрешения',
 'Total': 'Всего',
 'Download cancelled.': 'Загрузка отменена.',
 'Download failed or cancelled.': 'Ошибка загрузки или загрузка отменена.',
 'Incorrect password': 'Неверный пароль',
 'Change failed': 'Не удалось изменить',
 'Export failed': 'Ошибка экспорта',
 'Nothing to import': 'Нет данных для импорта',
 'Import passwords': 'Импорт паролей',
 'Import failed': 'Ошибка импорта',
 'Delete password': 'Удалить пароль',
 'Really delete this saved login?': 'Действительно удалить эти сохранённые данные для входа?',
 'Folder deleted': 'Папка удалена',
 '▶ Resume': '▶ Продолжить',
 'Download': 'Загрузка',
 'Unknown': 'Неизвестно',
 'Download complete': 'Загрузка завершена',
 'Error': 'Ошибка',
 'Active': 'Активно',
 'Saved in:': 'Сохранено в:',
 'Clipboard': 'Буфер обмена',
 'Allow all cookies': 'Разрешить все cookie',
 'Block third-party cookies': 'Блокировать сторонние cookie',
 'Block all cookies': 'Блокировать все cookie',
 'Allow session cookies only': 'Разрешать только сеансовые cookie',
 'Strong': 'Высокий',
 'Very strong': 'Очень высокий',
 'Super strong': 'Сверхвысокий',
 'Mega strong': 'Максимальный',
 'Ultra strong': 'Ультравысокий',
 'Maximum': 'Максимум',
 'Standard': 'Стандартный',
 'Small': 'Маленький',
 'Medium': 'Средний',
 'Large': 'Большой',
 'Very large': 'Очень большой',
 'Export encrypted vault': 'Экспортировать зашифрованное хранилище',
 'Import encrypted vault': 'Импортировать зашифрованное хранилище',
 'New': 'Новый',
 'Updated': 'Обновлено',
 'Save image as': 'Сохранить изображение как',
 'Save page as': 'Сохранить страницу как',
 'All files (*.*)': 'Все файлы (*.*)',
 'Web page (*.mhtml)': 'Веб-страница (*.mhtml)',
 'Do you really want to delete the entire browsing history?': 'Действительно удалить всю историю просмотров?',
 'LunaSurfer vault (*.lsv);;All files (*)': 'Хранилище LunaSurfer (*.lsv);;Все файлы (*)',
 'Normal – leave websites unchanged': 'Обычный — не изменять сайты',
 'Gentle contrast': 'Мягкий контраст',
 'Softer contrast': 'Более мягкий контраст',
 'Relaxed contrast': 'Умеренный контраст',
 'Original – keep website colors': 'Оригинальный — сохранить цвета сайта',
 'Black mode – black backgrounds': 'Чёрный режим — чёрный фон',
 'Custom block patterns (separate with semicolons):': 'Пользовательские шаблоны блокировки (разделяйте '
                                                      'точкой с запятой):',
 'Whitelist domains (separate with semicolons):': 'Домены белого списка (разделяйте точкой с запятой):',
 'The download has finished:': 'Загрузка завершена:',
 ' items': ' элементов',
 ' matches': ' совпадений',
 'Do you really want to clear all browser data?\n\nHistory, cache, cookies, sign-in sessions, Local Storage, IndexedDB and other website data will be removed. You will be signed out of websites.\n\nBookmarks and saved passwords will be kept. The full cleanup will finish the next time LunaSurfer starts.': 'Действительно '
                                                                                                                                                                                                                                                                                                                  'очистить '
                                                                                                                                                                                                                                                                                                                  'все '
                                                                                                                                                                                                                                                                                                                  'данные '
                                                                                                                                                                                                                                                                                                                  'браузера?\n'
                                                                                                                                                                                                                                                                                                                  '\n'
                                                                                                                                                                                                                                                                                                                  'История, '
                                                                                                                                                                                                                                                                                                                  'кэш, '
                                                                                                                                                                                                                                                                                                                  'cookie, '
                                                                                                                                                                                                                                                                                                                  'сеансы '
                                                                                                                                                                                                                                                                                                                  'входа, '
                                                                                                                                                                                                                                                                                                                  'Local '
                                                                                                                                                                                                                                                                                                                  'Storage, '
                                                                                                                                                                                                                                                                                                                  'IndexedDB '
                                                                                                                                                                                                                                                                                                                  'и '
                                                                                                                                                                                                                                                                                                                  'другие '
                                                                                                                                                                                                                                                                                                                  'данные '
                                                                                                                                                                                                                                                                                                                  'сайтов '
                                                                                                                                                                                                                                                                                                                  'будут '
                                                                                                                                                                                                                                                                                                                  'удалены. '
                                                                                                                                                                                                                                                                                                                  'Вы '
                                                                                                                                                                                                                                                                                                                  'выйдете '
                                                                                                                                                                                                                                                                                                                  'из '
                                                                                                                                                                                                                                                                                                                  'учётных '
                                                                                                                                                                                                                                                                                                                  'записей '
                                                                                                                                                                                                                                                                                                                  'на '
                                                                                                                                                                                                                                                                                                                  'сайтах.\n'
                                                                                                                                                                                                                                                                                                                  '\n'
                                                                                                                                                                                                                                                                                                                  'Закладки '
                                                                                                                                                                                                                                                                                                                  'и '
                                                                                                                                                                                                                                                                                                                  'сохранённые '
                                                                                                                                                                                                                                                                                                                  'пароли '
                                                                                                                                                                                                                                                                                                                  'останутся. '
                                                                                                                                                                                                                                                                                                                  'Полная '
                                                                                                                                                                                                                                                                                                                  'очистка '
                                                                                                                                                                                                                                                                                                                  'завершится '
                                                                                                                                                                                                                                                                                                                  'при '
                                                                                                                                                                                                                                                                                                                  'следующем '
                                                                                                                                                                                                                                                                                                                  'запуске '
                                                                                                                                                                                                                                                                                                                  'LunaSurfer.',
 'Standard: canvas, audio and basic hardware protection. Strong: additionally masks WebGL identifiers. Maximum: additional hardware and browser client-hint protection. Changes apply immediately; no restart is required.': 'Стандартный: '
                                                                                                                                                                                                                             'защита '
                                                                                                                                                                                                                             'Canvas, '
                                                                                                                                                                                                                             'аудио '
                                                                                                                                                                                                                             'и '
                                                                                                                                                                                                                             'основных '
                                                                                                                                                                                                                             'данных '
                                                                                                                                                                                                                             'оборудования. '
                                                                                                                                                                                                                             'Высокий: '
                                                                                                                                                                                                                             'дополнительно '
                                                                                                                                                                                                                             'скрывает '
                                                                                                                                                                                                                             'идентификаторы '
                                                                                                                                                                                                                             'WebGL. '
                                                                                                                                                                                                                             'Максимальный: '
                                                                                                                                                                                                                             'дополнительная '
                                                                                                                                                                                                                             'защита '
                                                                                                                                                                                                                             'данных '
                                                                                                                                                                                                                             'оборудования '
                                                                                                                                                                                                                             'и '
                                                                                                                                                                                                                             'Client '
                                                                                                                                                                                                                             'Hints '
                                                                                                                                                                                                                             'браузера. '
                                                                                                                                                                                                                             'Изменения '
                                                                                                                                                                                                                             'применяются '
                                                                                                                                                                                                                             'сразу, '
                                                                                                                                                                                                                             'перезапуск '
                                                                                                                                                                                                                             'не '
                                                                                                                                                                                                                             'требуется.',
 'The User-Agent changes the browser identification, not the browser engine or its capabilities. With fingerprint protection enabled, Client Hints are reduced to match the Chromium version.': 'User-Agent '
                                                                                                                                                                                                'изменяет '
                                                                                                                                                                                                'идентификацию '
                                                                                                                                                                                                'браузера, '
                                                                                                                                                                                                'но '
                                                                                                                                                                                                'не '
                                                                                                                                                                                                'его '
                                                                                                                                                                                                'движок '
                                                                                                                                                                                                'и '
                                                                                                                                                                                                'возможности. '
                                                                                                                                                                                                'При '
                                                                                                                                                                                                'включённой '
                                                                                                                                                                                                'защите '
                                                                                                                                                                                                'от '
                                                                                                                                                                                                'цифрового '
                                                                                                                                                                                                'отпечатка '
                                                                                                                                                                                                'Client '
                                                                                                                                                                                                'Hints '
                                                                                                                                                                                                'сокращаются '
                                                                                                                                                                                                'в '
                                                                                                                                                                                                'соответствии '
                                                                                                                                                                                                'с '
                                                                                                                                                                                                'версией '
                                                                                                                                                                                                'Chromium.',
 'When disabled, LunaSurfer asks for the master password only when you focus a login field.': 'Если функция '
                                                                                              'отключена, '
                                                                                              'LunaSurfer '
                                                                                              'запрашивает '
                                                                                              'мастер-пароль '
                                                                                              'только при '
                                                                                              'переходе к '
                                                                                              'полю входа.',
 'Delete all saved website logins; the master password remains': 'Удалить все сохранённые данные входа на '
                                                                 'сайты; мастер-пароль останется',
 'Manage saved permission decisions for individual websites': 'Управление сохранёнными разрешениями для '
                                                              'отдельных сайтов',
 'Do you really want to clear the browser cache?': 'Действительно очистить кэш браузера?',
 'Browser data cleared; full cleanup will finish after restart.': 'Данные браузера очищены; полная очистка '
                                                                  'завершится после перезапуска.',
 'Browser data is being cleared. Please restart LunaSurfer to remove all stored website data completely. Bookmarks and saved passwords will be kept.': 'Выполняется '
                                                                                                                                                       'очистка '
                                                                                                                                                       'данных '
                                                                                                                                                       'браузера. '
                                                                                                                                                       'Перезапустите '
                                                                                                                                                       'LunaSurfer, '
                                                                                                                                                       'чтобы '
                                                                                                                                                       'полностью '
                                                                                                                                                       'удалить '
                                                                                                                                                       'все '
                                                                                                                                                       'сохранённые '
                                                                                                                                                       'данные '
                                                                                                                                                       'сайтов. '
                                                                                                                                                       'Закладки '
                                                                                                                                                       'и '
                                                                                                                                                       'пароли '
                                                                                                                                                       'останутся.',
 'Do you really want to delete all stored cookies?': 'Действительно удалить все сохранённые cookie?',
 'Provider: MyMemory – starting translation …': 'Служба: MyMemory — запуск перевода…',
 'Provider: Google Translate – loading whole webpage …': 'Служба: Google Переводчик — загрузка всей '
                                                         'веб-страницы…',
 'This file can run programs or scripts. Only download it if you trust the source.': 'Этот файл может '
                                                                                     'запускать программы '
                                                                                     'или сценарии. '
                                                                                     'Загружайте его, только '
                                                                                     'если доверяете '
                                                                                     'источнику.',
 'The vault has been re-encrypted with the new master password. Keep it safe; it cannot be recovered.': 'Хранилище '
                                                                                                        'повторно '
                                                                                                        'зашифровано '
                                                                                                        'новым '
                                                                                                        'мастер-паролем. '
                                                                                                        'Храните '
                                                                                                        'его '
                                                                                                        'надёжно: '
                                                                                                        'восстановить '
                                                                                                        'его '
                                                                                                        'невозможно.',
 'The vault was exported in encrypted form. Keep the export file and export password separately.': 'Хранилище '
                                                                                                   'экспортировано '
                                                                                                   'в '
                                                                                                   'зашифрованном '
                                                                                                   'виде. '
                                                                                                   'Храните '
                                                                                                   'файл '
                                                                                                   'экспорта '
                                                                                                   'и пароль '
                                                                                                   'отдельно.',
 'Do you really want to permanently delete ALL saved website logins? The master password will remain.': 'Действительно '
                                                                                                        'навсегда '
                                                                                                        'удалить '
                                                                                                        'ВСЕ '
                                                                                                        'сохранённые '
                                                                                                        'данные '
                                                                                                        'входа '
                                                                                                        'на '
                                                                                                        'сайты? '
                                                                                                        'Мастер-пароль '
                                                                                                        'останется.',
 'Enter a valid website address, username and password.': 'Введите корректный адрес сайта, имя пользователя '
                                                          'и пароль.',
 'Enter a complete User-Agent or select another mode.': 'Введите полный User-Agent или выберите другой '
                                                        'режим.',
 'The browser cache has been cleared.': 'Кэш браузера очищен.',
 'All stored cookies have been cleared.': 'Все сохранённые cookie удалены.',
 'MyMemory could not translate the page. Check connection or daily quota.': 'MyMemory не удалось перевести '
                                                                            'страницу. Проверьте подключение '
                                                                            'или дневной лимит.',
 'Really delete this folder and all bookmarks inside it?': 'Действительно удалить эту папку и все закладки '
                                                           'внутри неё?',
 'Bookmarks were exported, including their folder structure.': 'Закладки экспортированы вместе со структурой '
                                                               'папок.',
 'Do you really want to clear all saved website permissions?': 'Действительно удалить все сохранённые '
                                                               'разрешения сайтов?',
 'Download source: ': 'Источник загрузки: ',
 'The current master password is incorrect or the vault is damaged.': 'Текущий мастер-пароль неверен или '
                                                                      'хранилище повреждено.',
 'The export contains no valid logins.': 'В экспорте нет корректных данных для входа.',
 'Translation provider applied immediately: ': 'Служба перевода применена немедленно: ',
 'Qt 6 + QtWebEngine with selectable light/dark website appearance and optional Widevine CDM integration.': 'Qt '
                                                                                                            '6 '
                                                                                                            '+ '
                                                                                                            'QtWebEngine '
                                                                                                            'с '
                                                                                                            'выбором '
                                                                                                            'светлого '
                                                                                                            'или '
                                                                                                            'тёмного '
                                                                                                            'оформления '
                                                                                                            'сайтов '
                                                                                                            'и '
                                                                                                            'дополнительной '
                                                                                                            'поддержкой '
                                                                                                            'Widevine '
                                                                                                            'CDM.',
 ' text sections translated.': ' фрагментов текста переведено.',
 'No bookmarks found in the selected file.': 'В выбранном файле закладки не найдены.',
 'The master password is incorrect or the vault is damaged.': 'Мастер-пароль неверен или хранилище '
                                                              'повреждено.',
 'Incorrect export password or damaged export file.': 'Неверный пароль экспорта или файл повреждён.',
 'No custom User-Agent entered yet': 'Пользовательский User-Agent ещё не задан',
 'Could not refresh translation menu: ': 'Не удалось обновить меню перевода: ',
 'MyMemory: ': 'MyMemory: ',
 'The folder could not be deleted.': 'Не удалось удалить папку.'}

# Japanese (Japan) interface catalogue.
JAPANESE_UI = {'Manage bookmarks': 'ブックマークの管理',
 '» More': '» その他',
 'Clear all browser data': 'ブラウザーのデータをすべて消去',
 'Find on this page': 'ページ内を検索',
 'Matches 0 of 0': '一致: 0 / 0',
 'Previous match': '前の一致',
 'Next match': '次の一致',
 'Close find bar': '検索バーを閉じる',
 'Developer tools': '開発者ツール',
 'Back': '戻る',
 'Forward': '進む',
 'Reload': '再読み込み',
 'Home': 'ホーム',
 'Enter address or search': 'アドレスまたは検索語句を入力',
 'Translate webpage': 'ウェブページを翻訳',
 'Show original page': '元のページを表示',
 'Add current page to bookmarks': '現在のページをブックマークに追加',
 'Unlock password manager – autofill saved logins (Ctrl+Shift+L)': 'パスワードマネージャーをロック解除 – 保存したログイン情報を自動入力 '
                                                                   '(Ctrl+Shift+L)',
 'Download manager': 'ダウンロードマネージャー',
 'Protection & privacy': '保護とプライバシー',
 'New tab': '新しいタブ',
 'Menu': 'メニュー',
 'Bookmarks': 'ブックマーク',
 'History': '履歴',
 'Open downloads folder': 'ダウンロードフォルダーを開く',
 'Settings': '設定',
 'User guide': 'ユーザーガイド',
 'Developer tools (F12)': '開発者ツール (F12)',
 'About LunaSurfer': 'LunaSurfer について',
 'Quit': '終了',
 'Bookmarks bar': 'ブックマークバー',
 'Ad blocker': '広告ブロッカー',
 'Ready': '準備完了',
 'Loading translated webpage …': '翻訳したウェブページを読み込み中…',
 'View and manage bookmarks': 'ブックマークの表示と管理',
 'Open': '開く',
 'Edit bookmark…': 'ブックマークを編集…',
 'Delete bookmark': 'ブックマークを削除',
 'Edit bookmark': 'ブックマークを編集',
 'Name:': '名前:',
 'Address:': 'アドレス:',
 'Bookmark changed': 'ブックマークを変更しました',
 'Really delete this bookmark?': 'このブックマークを本当に削除しますか？',
 'Bookmark deleted': 'ブックマークを削除しました',
 'Your bookmarks': 'ブックマーク',
 'Expand folders, search entries and manage them directly.': 'フォルダーを展開し、項目を検索して直接管理できます。',
 'Search bookmarks or addresses …': 'ブックマークまたはアドレスを検索…',
 'Edit…': '編集…',
 'Delete': '削除',
 'Import…': 'インポート…',
 'Export…': 'エクスポート…',
 'Close': '閉じる',
 'Protection settings: ad blocker and fingerprint': '保護設定: 広告ブロッカーとフィンガープリント',
 'Saved website permissions': '保存済みウェブサイト権限',
 'Change or remove remembered decisions for each website. Changes are saved immediately.': 'ウェブサイトごとに記憶された設定を変更または削除します。変更はすぐに保存されます。',
 'Camera': 'カメラ',
 'Microphone': 'マイク',
 'Location': '位置情報',
 'Notifications': '通知',
 'Clear all saved permissions': '保存済みの権限をすべて消去',
 'Enable ad blocker': '広告ブロッカーを有効にする',
 'The ad blocker filters known advertising and tracking domains. Higher levels block more, but may affect some websites.': '広告ブロッカーは既知の広告・追跡ドメインをフィルターします。強度を上げるとより多く遮断しますが、一部のサイトに影響する場合があります。',
 'Enable fingerprint protection': 'フィンガープリント保護を有効にする',
 'Fingerprint protection': 'フィンガープリント保護',
 'Save': '保存',
 'Cancel': 'キャンセル',
 'Download Manager': 'ダウンロードマネージャー',
 'Downloads': 'ダウンロード',
 'All active and completed files in one place.': '進行中および完了したファイルをまとめて管理します。',
 'All downloads': 'すべてのダウンロード',
 'In progress': '進行中',
 'Paused': '一時停止',
 'Completed': '完了',
 'Failed / cancelled': '失敗 / キャンセル',
 'Search filename or path …': 'ファイル名またはパスを検索…',
 'Cancel download': 'ダウンロードをキャンセル',
 'Open file': 'ファイルを開く',
 'Open folder': 'フォルダーを開く',
 'Remove entry': '項目を削除',
 'Clear completed': '完了項目を消去',
 'Clear history': '履歴を消去',
 'Change master password': 'マスターパスワードを変更',
 'Current master password:': '現在のマスターパスワード:',
 'New master password': '新しいマスターパスワード',
 'New master password (at least 10 characters):': '新しいマスターパスワード (10文字以上):',
 'Confirm master password': 'マスターパスワードの確認',
 'Enter the new master password again:': '新しいマスターパスワードをもう一度入力してください:',
 'Export password': 'エクスポート用パスワード',
 'Choose a password for this export file (at least 10 characters):': 'このエクスポートファイルのパスワードを設定してください (10文字以上):',
 'Confirm export password': 'エクスポート用パスワードの確認',
 'Enter the export password again:': 'エクスポート用パスワードをもう一度入力してください:',
 'Enter the password used to encrypt this export file:': 'このエクスポートファイルの暗号化に使用したパスワードを入力してください:',
 'Passwords deleted': 'パスワードを削除しました',
 'All saved website passwords have been deleted. The master password remains.': '保存されたウェブサイトのパスワードをすべて削除しました。マスターパスワードは保持されます。',
 'Login details': 'ログイン情報',
 'Website (matched automatically)': 'ウェブサイト (自動照合)',
 'Username': 'ユーザー名',
 'Password': 'パスワード',
 'Show password': 'パスワードを表示',
 'Generate secure password': '安全なパスワードを生成',
 'LunaSurfer – Password manager': 'LunaSurfer – パスワードマネージャー',
 'Passwords are encrypted locally. The master password cannot be recovered.': 'パスワードはローカルで暗号化されます。マスターパスワードを復元することはできません。',
 'Add': '追加',
 'Edit': '編集',
 'Export encrypted…': '暗号化してエクスポート…',
 'Import encrypted…': '暗号化データをインポート…',
 'Change master password…': 'マスターパスワードを変更…',
 'Lock now': '今すぐロック',
 'Update password?': 'パスワードを更新しますか？',
 'Save password?': 'パスワードを保存しますか？',
 'Login details saved securely.': 'ログイン情報を安全に保存しました。',
 'LunaSurfer – User guide': 'LunaSurfer – ユーザーガイド',
 'Open homepage': 'ホームページを開く',
 'Restore last session': '前回のセッションを復元',
 'Open blank page': '空白ページを開く',
 'Google Translate (whole webpage)': 'Google 翻訳 (ウェブページ全体)',
 'MyMemory (no API key)': 'MyMemory (APIキー不要)',
 'Google translates the whole webpage. MyMemory translates visible text sections and has a free daily limit.': 'Google '
                                                                                                               'はウェブページ全体を翻訳します。MyMemory '
                                                                                                               'は表示されているテキスト部分を翻訳し、1日あたりの無料利用制限があります。',
 'Dark': 'ダーク',
 'Light': 'ライト',
 'Dark (Standard)': 'ダーク (標準)',
 'Light (Classic)': 'ライト (クラシック)',
 'Luna (Modern)': 'Luna (モダン)',
 'Graphite Blue (Elegant)': 'グラファイトブルー (エレガント)',
 'Ocean (Teal Blue)': 'オーシャン (ティールブルー)',
 'Show bookmarks bar below the address bar': 'アドレスバーの下にブックマークバーを表示',
 'Choose folder…': 'フォルダーを選択…',
 'Ask where to save each download': 'ダウンロードごとに保存先を確認',
 'Show security warning for executable downloads': '実行可能ファイルのダウンロード時にセキュリティ警告を表示',
 'Show popup when a download finishes': 'ダウンロード完了時にポップアップを表示',
 'Block pop-ups': 'ポップアップをブロック',
 'Enable JavaScript': 'JavaScriptを有効にする',
 'Send Do Not Track request': 'Do Not Track リクエストを送信',
 'Ask when closing a tab': 'タブを閉じるときに確認',
 'Automatically clear history on exit': '終了時に履歴を自動消去',
 'Automatically clear cache on exit': '終了時にキャッシュを自動消去',
 'Automatically clear cookies on exit': '終了時にCookieを自動消去',
 'Remember window size and position on exit': '終了時にウィンドウのサイズと位置を記憶',
 'Use LunaSurfer as default browser': 'LunaSurferを既定のブラウザーにする',
 'General': '一般',
 'Language:': '言語:',
 'On startup:': '起動時:',
 'Homepage:': 'ホームページ:',
 'Search engine:': '検索エンジン:',
 'Translation provider:': '翻訳サービス:',
 'Browser design:': 'ブラウザーのデザイン:',
 'Website appearance:': 'ウェブサイトの表示:',
 'Download folder:': 'ダウンロードフォルダー:',
 'Default zoom:': '既定のズーム:',
 'Default font size:': '既定のフォントサイズ:',
 'Website readability:': 'ウェブサイトの読みやすさ:',
 'Website colors:': 'ウェブサイトの色:',
 'Security and permissions': 'セキュリティと権限',
 'Security:': 'セキュリティ:',
 'User-Agent management': 'User-Agent の管理',
 'Privacy default (reduced Chrome UA)': 'プライバシー優先 (短縮版 Chrome UA)',
 'Native browser User-Agent': 'ブラウザー標準の User-Agent',
 'Custom User-Agent': 'カスタム User-Agent',
 'Enter a complete User-Agent string…': '完全な User-Agent 文字列を入力…',
 'Mode:': 'モード:',
 'Custom value:': 'カスタム値:',
 'Current:': '現在:',
 'Offer to save passwords after successful sign-in': 'ログイン成功後にパスワードの保存を提案',
 'Password manager must be unlocked before autofill': '自動入力の前にパスワードマネージャーのロック解除が必要',
 'Open password manager…': 'パスワードマネージャーを開く…',
 'Manage encrypted saved website logins': '暗号化された保存済みウェブサイトログインを管理',
 'Delete all passwords…': 'すべてのパスワードを削除…',
 'Passwords:': 'パスワード:',
 'Edit saved website permissions…': '保存済みウェブサイト権限を編集…',
 'Website permissions:': 'ウェブサイトの権限:',
 'Browser behavior:': 'ブラウザーの動作:',
 'Clear cache': 'キャッシュを消去',
 'Clear cookies': 'Cookieを消去',
 'Clear everything': 'すべて消去',
 'Privacy and browser data': 'プライバシーとブラウザーデータ',
 'Cookie mode:': 'Cookieモード:',
 'Browser data:': 'ブラウザーデータ:',
 'Permission request': '権限のリクエスト',
 'Remember this decision for this website': 'このウェブサイトについての選択を記憶',
 'Allow': '許可',
 'Block': 'ブロック',
 'Yes': 'はい',
 'No': 'いいえ',
 'Close tab': 'タブを閉じる',
 'Do you really want to close this tab?': 'このタブを本当に閉じますか？',
 'Stop loading': '読み込みを停止',
 'Translation': '翻訳',
 'Open a regular webpage first.': '先に通常のウェブページを開いてください。',
 'Original page': '元のページ',
 'No original page URL is saved for this tab.': 'このタブには元のページのURLが保存されていません。',
 'More bookmarks': 'その他のブックマーク',
 'Show more bookmarks': 'さらにブックマークを表示',
 'Name': '名前',
 'Address': 'アドレス',
 'Export bookmarks': 'ブックマークをエクスポート',
 'Import bookmarks': 'ブックマークをインポート',
 'Website': 'ウェブサイト',
 'Permission': '権限',
 'Decision': '選択',
 'Action': '操作',
 'Blocking strength:': 'ブロック強度:',
 'Protection level:': '保護レベル:',
 'File no longer present': 'ファイルが見つかりません',
 'Cancelled': 'キャンセル済み',
 'Failed': '失敗',
 'Interrupted': '中断',
 'Ⅱ Pause': 'Ⅱ 一時停止',
 'Download security warning': 'ダウンロードのセキュリティ警告',
 'This file may be dangerous': 'このファイルは危険な可能性があります',
 'Do not show this security warning again': '今後このセキュリティ警告を表示しない',
 'Download anyway': 'それでもダウンロード',
 'History cleared': '履歴を消去しました',
 'The browsing history has been cleared.': '閲覧履歴を消去しました。',
 'Unlock password manager': 'パスワードマネージャーのロック解除',
 'Master password:': 'マスターパスワード:',
 'Set up password manager': 'パスワードマネージャーを設定',
 'Enter master password again:': 'マスターパスワードをもう一度入力してください:',
 'Look in:': '場所:',
 'File name:': 'ファイル名:',
 'File type:': 'ファイルの種類:',
 'Too short': '短すぎます',
 'Please use at least 10 characters.': '10文字以上で入力してください。',
 'Passwords do not match': 'パスワードが一致しません',
 'The passwords do not match.': 'パスワードが一致しません。',
 'Master password changed': 'マスターパスワードを変更しました',
 'Use at least 10 characters.': '10文字以上で入力してください。',
 'Export complete': 'エクスポート完了',
 'Import complete': 'インポート完了',
 'No passwords stored': '保存されたパスワードはありません',
 'There are no saved passwords to delete.': '削除する保存済みパスワードはありません。',
 'Delete all passwords': 'すべてのパスワードを削除',
 'Invalid input': '入力が無効です',
 'Ask': '確認する',
 'User-Agent missing': 'User-Agent が未入力です',
 'Cache cleared': 'キャッシュを消去しました',
 'Cookies cleared': 'Cookieを消去しました',
 'Folder': 'フォルダー',
 'Delete folder': 'フォルダーを削除',
 'Bookmarks exported': 'ブックマークをエクスポートしました',
 'Export': 'エクスポート',
 'Bookmarks imported': 'ブックマークをインポートしました',
 'Import': 'インポート',
 'Remove': '削除',
 'Clear all permissions': 'すべての権限を消去',
 'Total': '合計',
 'Download cancelled.': 'ダウンロードをキャンセルしました。',
 'Download failed or cancelled.': 'ダウンロードに失敗したか、キャンセルされました。',
 'Incorrect password': 'パスワードが正しくありません',
 'Change failed': '変更に失敗しました',
 'Export failed': 'エクスポートに失敗しました',
 'Nothing to import': 'インポートするものがありません',
 'Import passwords': 'パスワードをインポート',
 'Import failed': 'インポートに失敗しました',
 'Delete password': 'パスワードを削除',
 'Really delete this saved login?': 'この保存済みログイン情報を本当に削除しますか？',
 'Folder deleted': 'フォルダーを削除しました',
 '▶ Resume': '▶ 再開',
 'Download': 'ダウンロード',
 'Unknown': '不明',
 'Download complete': 'ダウンロード完了',
 'Error': 'エラー',
 'Active': '有効',
 'Saved in:': '保存先:',
 'Clipboard': 'クリップボード',
 'Allow all cookies': 'すべてのCookieを許可',
 'Block third-party cookies': 'サードパーティCookieをブロック',
 'Block all cookies': 'すべてのCookieをブロック',
 'Allow session cookies only': 'セッションCookieのみ許可',
 'Strong': '強い',
 'Very strong': '非常に強い',
 'Super strong': '極めて強い',
 'Mega strong': '非常に強力',
 'Ultra strong': '最高レベル',
 'Maximum': '最大',
 'Standard': '標準',
 'Small': '小',
 'Medium': '中',
 'Large': '大',
 'Very large': '特大',
 'Export encrypted vault': '暗号化された保管庫をエクスポート',
 'Import encrypted vault': '暗号化された保管庫をインポート',
 'New': '新規',
 'Updated': '更新済み',
 'Save image as': '画像を名前を付けて保存',
 'Save page as': 'ページを名前を付けて保存',
 'All files (*.*)': 'すべてのファイル (*.*)',
 'Web page (*.mhtml)': 'ウェブページ (*.mhtml)',
 'Do you really want to delete the entire browsing history?': '閲覧履歴をすべて本当に削除しますか？',
 'LunaSurfer vault (*.lsv);;All files (*)': 'LunaSurfer保管庫 (*.lsv);;すべてのファイル (*)',
 'Normal – leave websites unchanged': '標準 – ウェブサイトを変更しない',
 'Gentle contrast': '弱いコントラスト',
 'Softer contrast': 'より柔らかいコントラスト',
 'Relaxed contrast': '控えめなコントラスト',
 'Original – keep website colors': 'オリジナル – ウェブサイトの色を維持',
 'Black mode – black backgrounds': 'ブラックモード – 背景を黒にする',
 'Custom block patterns (separate with semicolons):': 'カスタムブロックパターン (セミコロンで区切る):',
 'Whitelist domains (separate with semicolons):': '許可リストのドメイン (セミコロンで区切る):',
 'The download has finished:': 'ダウンロードが完了しました:',
 ' items': ' 件',
 ' matches': ' 件一致',
 'Do you really want to clear all browser data?\n\nHistory, cache, cookies, sign-in sessions, Local Storage, IndexedDB and other website data will be removed. You will be signed out of websites.\n\nBookmarks and saved passwords will be kept. The full cleanup will finish the next time LunaSurfer starts.': 'ブラウザーのデータをすべて消去しますか？\n'
                                                                                                                                                                                                                                                                                                                  '\n'
                                                                                                                                                                                                                                                                                                                  '履歴、キャッシュ、Cookie、ログインセッション、Local '
                                                                                                                                                                                                                                                                                                                  'Storage、IndexedDB、その他のウェブサイトデータが削除されます。ウェブサイトからログアウトされます。\n'
                                                                                                                                                                                                                                                                                                                  '\n'
                                                                                                                                                                                                                                                                                                                  'ブックマークと保存済みパスワードは保持されます。完全な消去は次回のLunaSurfer起動時に完了します。',
 'Standard: canvas, audio and basic hardware protection. Strong: additionally masks WebGL identifiers. Maximum: additional hardware and browser client-hint protection. Changes apply immediately; no restart is required.': '標準: '
                                                                                                                                                                                                                             'Canvas、音声、基本的なハードウェア情報を保護します。強: '
                                                                                                                                                                                                                             'WebGL識別情報もマスクします。最大: '
                                                                                                                                                                                                                             'ハードウェア情報とブラウザーのClient '
                                                                                                                                                                                                                             'Hintsも保護します。変更はすぐに適用され、再起動は不要です。',
 'The User-Agent changes the browser identification, not the browser engine or its capabilities. With fingerprint protection enabled, Client Hints are reduced to match the Chromium version.': 'User-Agentはブラウザーの識別情報を変更するもので、ブラウザーエンジンや機能は変更しません。フィンガープリント保護が有効な場合、Client '
                                                                                                                                                                                                'HintsはChromiumのバージョンに合わせて制限されます。',
 'When disabled, LunaSurfer asks for the master password only when you focus a login field.': '無効にすると、ログイン欄にフォーカスしたときだけLunaSurferがマスターパスワードを要求します。',
 'Delete all saved website logins; the master password remains': '保存済みのウェブサイトログインをすべて削除します。マスターパスワードは保持されます',
 'Manage saved permission decisions for individual websites': 'ウェブサイトごとに保存された権限の選択を管理',
 'Do you really want to clear the browser cache?': 'ブラウザーのキャッシュを本当に消去しますか？',
 'Browser data cleared; full cleanup will finish after restart.': 'ブラウザーデータを消去しました。完全な消去は再起動後に完了します。',
 'Browser data is being cleared. Please restart LunaSurfer to remove all stored website data completely. Bookmarks and saved passwords will be kept.': 'ブラウザーデータを消去しています。保存されたウェブサイトデータを完全に削除するにはLunaSurferを再起動してください。ブックマークと保存済みパスワードは保持されます。',
 'Do you really want to delete all stored cookies?': '保存されたCookieをすべて本当に削除しますか？',
 'Provider: MyMemory – starting translation …': '翻訳サービス: MyMemory – 翻訳を開始しています…',
 'Provider: Google Translate – loading whole webpage …': '翻訳サービス: Google 翻訳 – ウェブページ全体を読み込んでいます…',
 'This file can run programs or scripts. Only download it if you trust the source.': 'このファイルはプログラムやスクリプトを実行する可能性があります。信頼できる提供元からのみダウンロードしてください。',
 'The vault has been re-encrypted with the new master password. Keep it safe; it cannot be recovered.': '保管庫は新しいマスターパスワードで再暗号化されました。復元できないため、安全に保管してください。',
 'The vault was exported in encrypted form. Keep the export file and export password separately.': '保管庫は暗号化された形式でエクスポートされました。エクスポートファイルとパスワードは別々に保管してください。',
 'Do you really want to permanently delete ALL saved website logins? The master password will remain.': '保存済みのウェブサイトログインをすべて完全に削除しますか？マスターパスワードは保持されます。',
 'Enter a valid website address, username and password.': '有効なウェブサイトアドレス、ユーザー名、パスワードを入力してください。',
 'Enter a complete User-Agent or select another mode.': '完全なUser-Agentを入力するか、別のモードを選択してください。',
 'The browser cache has been cleared.': 'ブラウザーのキャッシュを消去しました。',
 'All stored cookies have been cleared.': '保存されたCookieをすべて消去しました。',
 'MyMemory could not translate the page. Check connection or daily quota.': 'MyMemoryでページを翻訳できませんでした。接続または1日の利用上限を確認してください。',
 'Really delete this folder and all bookmarks inside it?': 'このフォルダーと中のブックマークをすべて本当に削除しますか？',
 'Bookmarks were exported, including their folder structure.': 'フォルダー構造を含めてブックマークをエクスポートしました。',
 'Do you really want to clear all saved website permissions?': '保存済みのウェブサイト権限をすべて本当に消去しますか？',
 'Download source: ': 'ダウンロード元: ',
 'The current master password is incorrect or the vault is damaged.': '現在のマスターパスワードが正しくないか、保管庫が破損しています。',
 'The export contains no valid logins.': 'エクスポートに有効なログイン情報が含まれていません。',
 'Translation provider applied immediately: ': '翻訳サービスをすぐに適用しました: ',
 'Qt 6 + QtWebEngine with selectable light/dark website appearance and optional Widevine CDM integration.': 'Qt '
                                                                                                            '6 '
                                                                                                            '+ '
                                                                                                            'QtWebEngineを使用。ウェブサイトのライト/ダーク表示を選択でき、Widevine '
                                                                                                            'CDMの統合にも対応します。',
 ' text sections translated.': ' 件のテキスト部分を翻訳しました。',
 'No bookmarks found in the selected file.': '選択したファイルにブックマークが見つかりません。',
 'The master password is incorrect or the vault is damaged.': 'マスターパスワードが正しくないか、保管庫が破損しています。',
 'Incorrect export password or damaged export file.': 'エクスポート用パスワードが正しくないか、エクスポートファイルが破損しています。',
 'No custom User-Agent entered yet': 'カスタムUser-Agentはまだ入力されていません',
 'Could not refresh translation menu: ': '翻訳メニューを更新できませんでした: ',
 'MyMemory: ': 'MyMemory: ',
 'The folder could not be deleted.': 'フォルダーを削除できませんでした。'}

# Simplified Chinese (China) interface catalogue.
CHINESE_UI = {'Manage bookmarks': '管理书签', '» More': '» 更多', 'Clear all browser data': '清除所有浏览器数据', 'Find on this page': '在页面中查找', 'Matches 0 of 0': '匹配项 0 / 0', 'Previous match': '上一个匹配项', 'Next match': '下一个匹配项', 'Close find bar': '关闭查找栏', 'Developer tools': '开发者工具', 'Back': '后退', 'Forward': '前进', 'Reload': '重新加载', 'Home': '主页', 'Enter address or search': '输入网址或搜索', 'Translate webpage': '翻译网页', 'Show original page': '显示原始网页', 'Add current page to bookmarks': '将当前页面添加到书签', 'Unlock password manager – autofill saved logins (Ctrl+Shift+L)': '解锁密码管理器 – 自动填充已保存的登录信息 (Ctrl+Shift+L)', 'Download manager': '下载管理器', 'Protection & privacy': '保护与隐私', 'New tab': '新建标签页', 'Menu': '菜单', 'Bookmarks': '书签', 'History': '历史记录', 'Open downloads folder': '打开下载文件夹', 'Settings': '设置', 'User guide': '用户指南', 'Developer tools (F12)': '开发者工具 (F12)', 'About LunaSurfer': '关于 LunaSurfer', 'Quit': '退出', 'Bookmarks bar': '书签栏', 'Ad blocker': '广告拦截器', 'Ready': '就绪', 'Loading translated webpage …': '正在加载翻译后的网页…', 'View and manage bookmarks': '查看和管理书签', 'Open': '打开', 'Edit bookmark…': '编辑书签…', 'Delete bookmark': '删除书签', 'Edit bookmark': '编辑书签', 'Name:': '名称：', 'Address:': '地址：', 'Bookmark changed': '书签已更改', 'Really delete this bookmark?': '确定要删除此书签吗？', 'Bookmark deleted': '书签已删除', 'Your bookmarks': '您的书签', 'Expand folders, search entries and manage them directly.': '展开文件夹、搜索条目并直接进行管理。', 'Search bookmarks or addresses …': '搜索书签或网址…', 'Edit…': '编辑…', 'Delete': '删除', 'Import…': '导入…', 'Export…': '导出…', 'Close': '关闭', 'Protection settings: ad blocker and fingerprint': '保护设置：广告拦截与浏览器指纹', 'Saved website permissions': '已保存的网站权限', 'Change or remove remembered decisions for each website. Changes are saved immediately.': '更改或删除各网站已记住的权限决定。更改会立即保存。', 'Camera': '摄像头', 'Microphone': '麦克风', 'Location': '位置', 'Notifications': '通知', 'Clear all saved permissions': '清除所有已保存的权限', 'Enable ad blocker': '启用广告拦截器', 'The ad blocker filters known advertising and tracking domains. Higher levels block more, but may affect some websites.': '广告拦截器会过滤已知的广告和跟踪域名。更高级别可拦截更多内容，但可能影响某些网站。', 'Enable fingerprint protection': '启用指纹保护', 'Fingerprint protection': '指纹保护', 'Save': '保存', 'Cancel': '取消', 'Download Manager': '下载管理器', 'Downloads': '下载', 'All active and completed files in one place.': '在一个位置查看所有正在下载和已完成的文件。', 'All downloads': '所有下载', 'In progress': '正在进行', 'Paused': '已暂停', 'Completed': '已完成', 'Failed / cancelled': '失败 / 已取消', 'Search filename or path …': '搜索文件名或路径…', 'Cancel download': '取消下载', 'Open file': '打开文件', 'Open folder': '打开文件夹', 'Remove entry': '移除条目', 'Clear completed': '清除已完成项目', 'Clear history': '清除历史记录', 'Change master password': '更改主密码', 'Current master password:': '当前主密码：', 'New master password': '新主密码', 'New master password (at least 10 characters):': '新主密码（至少 10 个字符）：', 'Confirm master password': '确认主密码', 'Enter the new master password again:': '请再次输入新主密码：', 'Export password': '导出密码', 'Choose a password for this export file (at least 10 characters):': '为此导出文件设置密码（至少 10 个字符）：', 'Confirm export password': '确认导出密码', 'Enter the export password again:': '请再次输入导出密码：', 'Enter the password used to encrypt this export file:': '请输入用于加密此导出文件的密码：', 'Passwords deleted': '密码已删除', 'All saved website passwords have been deleted. The master password remains.': '所有已保存的网站密码均已删除。主密码仍然保留。', 'Login details': '登录信息', 'Website (matched automatically)': '网站（自动匹配）', 'Username': '用户名', 'Password': '密码', 'Show password': '显示密码', 'Generate secure password': '生成安全密码', 'LunaSurfer – Password manager': 'LunaSurfer – 密码管理器', 'Passwords are encrypted locally. The master password cannot be recovered.': '密码在本地加密。主密码无法找回。', 'Add': '添加', 'Edit': '编辑', 'Export encrypted…': '加密导出…', 'Import encrypted…': '加密导入…', 'Change master password…': '更改主密码…', 'Lock now': '立即锁定', 'Update password?': '更新密码？', 'Save password?': '保存密码？', 'Login details saved securely.': '登录信息已安全保存。', 'LunaSurfer – User guide': 'LunaSurfer – 用户指南', 'Open homepage': '打开主页', 'Restore last session': '恢复上次会话', 'Open blank page': '打开空白页', 'Google Translate (whole webpage)': 'Google 翻译（整个网页）', 'MyMemory (no API key)': 'MyMemory（无需 API 密钥）', 'Google translates the whole webpage. MyMemory translates visible text sections and has a free daily limit.': 'Google 会翻译整个网页。MyMemory 会翻译可见文本片段，并设有每日免费额度。', 'Dark': '深色', 'Light': '浅色', 'Dark (Standard)': '深色（标准）', 'Light (Classic)': '浅色（经典）', 'Luna (Modern)': 'Luna（现代）', 'Graphite Blue (Elegant)': '石墨蓝（优雅）', 'Ocean (Teal Blue)': '海洋（蓝绿色）', 'Show bookmarks bar below the address bar': '在地址栏下方显示书签栏', 'Choose folder…': '选择文件夹…', 'Ask where to save each download': '每次下载时询问保存位置', 'Show security warning for executable downloads': '下载可执行文件时显示安全警告', 'Show popup when a download finishes': '下载完成时显示弹出通知', 'Block pop-ups': '阻止弹出窗口', 'Enable JavaScript': '启用 JavaScript', 'Send Do Not Track request': '发送“请勿跟踪”请求', 'Ask when closing a tab': '关闭标签页时询问', 'Automatically clear history on exit': '退出时自动清除历史记录', 'Automatically clear cache on exit': '退出时自动清除缓存', 'Automatically clear cookies on exit': '退出时自动清除 Cookie', 'Remember window size and position on exit': '退出时记住窗口大小和位置', 'Use LunaSurfer as default browser': '将 LunaSurfer 设为默认浏览器', 'General': '常规', 'Language:': '语言：', 'On startup:': '启动时：', 'Homepage:': '主页：', 'Search engine:': '搜索引擎：', 'Translation provider:': '翻译服务：', 'Browser design:': '浏览器外观：', 'Website appearance:': '网站显示模式：', 'Download folder:': '下载文件夹：', 'Default zoom:': '默认缩放：', 'Default font size:': '默认字体大小：', 'Website readability:': '网站可读性：', 'Website colors:': '网站颜色：', 'Security and permissions': '安全与权限', 'Security:': '安全：', 'User-Agent management': 'User-Agent 管理', 'Privacy default (reduced Chrome UA)': '隐私默认设置（精简 Chrome UA）', 'Native browser User-Agent': '浏览器原生 User-Agent', 'Custom User-Agent': '自定义 User-Agent', 'Enter a complete User-Agent string…': '输入完整的 User-Agent 字符串…', 'Mode:': '模式：', 'Custom value:': '自定义值：', 'Current:': '当前：', 'Offer to save passwords after successful sign-in': '成功登录后提示保存密码', 'Password manager must be unlocked before autofill': '自动填充前必须解锁密码管理器', 'Open password manager…': '打开密码管理器…', 'Manage encrypted saved website logins': '管理已加密保存的网站登录信息', 'Delete all passwords…': '删除所有密码…', 'Passwords:': '密码：', 'Edit saved website permissions…': '编辑已保存的网站权限…', 'Website permissions:': '网站权限：', 'Browser behavior:': '浏览器行为：', 'Clear cache': '清除缓存', 'Clear cookies': '清除 Cookie', 'Clear everything': '清除全部', 'Privacy and browser data': '隐私和浏览器数据', 'Cookie mode:': 'Cookie 模式：', 'Browser data:': '浏览器数据：', 'Permission request': '权限请求', 'Remember this decision for this website': '记住对此网站的决定', 'Allow': '允许', 'Block': '阻止', 'Yes': '是', 'No': '否', 'Close tab': '关闭标签页', 'Do you really want to close this tab?': '确定要关闭此标签页吗？', 'Stop loading': '停止加载', 'Translation': '翻译', 'Open a regular webpage first.': '请先打开普通网页。', 'Original page': '原始网页', 'No original page URL is saved for this tab.': '此标签页没有保存原始网页网址。', 'More bookmarks': '更多书签', 'Show more bookmarks': '显示更多书签', 'Name': '名称', 'Address': '地址', 'Export bookmarks': '导出书签', 'Import bookmarks': '导入书签', 'Website': '网站', 'Permission': '权限', 'Decision': '决定', 'Action': '操作', 'Blocking strength:': '拦截强度：', 'Protection level:': '保护级别：', 'File no longer present': '文件已不存在', 'Cancelled': '已取消', 'Failed': '失败', 'Interrupted': '已中断', 'Ⅱ Pause': 'Ⅱ 暂停', 'Download security warning': '下载安全警告', 'This file may be dangerous': '此文件可能存在危险', 'Do not show this security warning again': '不再显示此安全警告', 'Download anyway': '仍然下载', 'History cleared': '历史记录已清除', 'The browsing history has been cleared.': '浏览历史记录已清除。', 'Unlock password manager': '解锁密码管理器', 'Master password:': '主密码：', 'Set up password manager': '设置密码管理器', 'Enter master password again:': '请再次输入主密码：', 'Look in:': '查找位置：', 'File name:': '文件名：', 'File type:': '文件类型：', 'Too short': '太短', 'Please use at least 10 characters.': '请至少使用 10 个字符。', 'Passwords do not match': '密码不匹配', 'The passwords do not match.': '两次输入的密码不一致。', 'Master password changed': '主密码已更改', 'Use at least 10 characters.': '请至少使用 10 个字符。', 'Export complete': '导出完成', 'Import complete': '导入完成', 'No passwords stored': '没有已保存的密码', 'There are no saved passwords to delete.': '没有可删除的已保存密码。', 'Delete all passwords': '删除所有密码', 'Invalid input': '输入无效', 'Ask': '询问', 'User-Agent missing': '缺少 User-Agent', 'Cache cleared': '缓存已清除', 'Cookies cleared': 'Cookie 已清除', 'Folder': '文件夹', 'Delete folder': '删除文件夹', 'Bookmarks exported': '书签已导出', 'Export': '导出', 'Bookmarks imported': '书签已导入', 'Import': '导入', 'Remove': '移除', 'Clear all permissions': '清除所有权限', 'Total': '总计', 'Download cancelled.': '下载已取消。', 'Download failed or cancelled.': '下载失败或已取消。', 'Incorrect password': '密码错误', 'Change failed': '更改失败', 'Export failed': '导出失败', 'Nothing to import': '没有可导入的内容', 'Import passwords': '导入密码', 'Import failed': '导入失败', 'Delete password': '删除密码', 'Really delete this saved login?': '确定要删除此已保存的登录信息吗？', 'Folder deleted': '文件夹已删除', '▶ Resume': '▶ 继续', 'Download': '下载', 'Unknown': '未知', 'Download complete': '下载完成', 'Error': '错误', 'Active': '活动', 'Saved in:': '保存位置：', 'Clipboard': '剪贴板', 'Allow all cookies': '允许所有 Cookie', 'Block third-party cookies': '阻止第三方 Cookie', 'Block all cookies': '阻止所有 Cookie', 'Allow session cookies only': '仅允许会话 Cookie', 'Strong': '强', 'Very strong': '非常强', 'Super strong': '超强', 'Mega strong': '极强', 'Ultra strong': '极致强', 'Maximum': '最高', 'Standard': '标准', 'Small': '小', 'Medium': '中', 'Large': '大', 'Very large': '特大', 'Export encrypted vault': '导出加密密码库', 'Import encrypted vault': '导入加密密码库', 'New': '新建', 'Updated': '已更新', 'Save image as': '图片另存为', 'Save page as': '网页另存为', 'All files (*.*)': '所有文件 (*.*)', 'Web page (*.mhtml)': '网页 (*.mhtml)', 'Do you really want to delete the entire browsing history?': '确定要删除全部浏览历史记录吗？', 'LunaSurfer vault (*.lsv);;All files (*)': 'LunaSurfer 密码库 (*.lsv);;所有文件 (*)', 'Normal – leave websites unchanged': '正常 – 保持网站原样', 'Gentle contrast': '柔和对比度', 'Softer contrast': '更柔和的对比度', 'Relaxed contrast': '舒缓对比度', 'Original – keep website colors': '原始 – 保留网站颜色', 'Black mode – black backgrounds': '黑色模式 – 黑色背景', 'Custom block patterns (separate with semicolons):': '自定义拦截规则（用分号分隔）：', 'Whitelist domains (separate with semicolons):': '允许列表域名（用分号分隔）：', 'The download has finished:': '下载已完成：', ' items': ' 项', ' matches': ' 个匹配项', 'Do you really want to clear all browser data?\n\nHistory, cache, cookies, sign-in sessions, Local Storage, IndexedDB and other website data will be removed. You will be signed out of websites.\n\nBookmarks and saved passwords will be kept. The full cleanup will finish the next time LunaSurfer starts.': '确定要清除所有浏览器数据吗？\n\n历史记录、缓存、Cookie、登录会话、Local Storage、IndexedDB 及其他网站数据都将被删除。您将退出各网站的登录状态。\n\n书签和已保存的密码将保留。完整清理将在 LunaSurfer 下次启动时完成。', 'Standard: canvas, audio and basic hardware protection. Strong: additionally masks WebGL identifiers. Maximum: additional hardware and browser client-hint protection. Changes apply immediately; no restart is required.': '标准：保护 Canvas、音频和基本硬件信息。强：额外隐藏 WebGL 标识符。最高：进一步保护硬件信息和浏览器 Client Hints。更改立即生效，无需重启。', 'The User-Agent changes the browser identification, not the browser engine or its capabilities. With fingerprint protection enabled, Client Hints are reduced to match the Chromium version.': 'User-Agent 会更改浏览器标识，而不会更改浏览器引擎或其功能。启用指纹保护后，Client Hints 会被精简，以匹配 Chromium 版本。', 'When disabled, LunaSurfer asks for the master password only when you focus a login field.': '禁用后，只有当您选中登录输入框时，LunaSurfer 才会询问主密码。', 'Delete all saved website logins; the master password remains': '删除所有已保存的网站登录信息；主密码将保留', 'Manage saved permission decisions for individual websites': '管理各个网站已保存的权限决定', 'Do you really want to clear the browser cache?': '确定要清除浏览器缓存吗？', 'Browser data cleared; full cleanup will finish after restart.': '浏览器数据已清除；完整清理将在重启后完成。', 'Browser data is being cleared. Please restart LunaSurfer to remove all stored website data completely. Bookmarks and saved passwords will be kept.': '正在清除浏览器数据。请重新启动 LunaSurfer，以彻底删除所有已存储的网站数据。书签和已保存的密码将予以保留。', 'Do you really want to delete all stored cookies?': '确定要删除所有已存储的 Cookie 吗？', 'Provider: MyMemory – starting translation …': '服务：MyMemory – 正在开始翻译…', 'Provider: Google Translate – loading whole webpage …': '服务：Google 翻译 – 正在加载整个网页…', 'This file can run programs or scripts. Only download it if you trust the source.': '此文件可以运行程序或脚本。请仅在信任来源时下载。', 'The vault has been re-encrypted with the new master password. Keep it safe; it cannot be recovered.': '密码库已使用新的主密码重新加密。请妥善保管主密码，因为它无法找回。', 'The vault was exported in encrypted form. Keep the export file and export password separately.': '密码库已加密导出。请将导出文件和导出密码分开保存。', 'Do you really want to permanently delete ALL saved website logins? The master password will remain.': '确定要永久删除所有已保存的网站登录信息吗？主密码将保留。', 'Enter a valid website address, username and password.': '请输入有效的网站地址、用户名和密码。', 'Enter a complete User-Agent or select another mode.': '请输入完整的 User-Agent，或选择其他模式。', 'The browser cache has been cleared.': '浏览器缓存已清除。', 'All stored cookies have been cleared.': '所有已存储的 Cookie 均已清除。', 'MyMemory could not translate the page. Check connection or daily quota.': 'MyMemory 无法翻译此页面。请检查网络连接或每日使用额度。', 'Really delete this folder and all bookmarks inside it?': '确定要删除此文件夹及其中的所有书签吗？', 'Bookmarks were exported, including their folder structure.': '书签已导出，文件夹结构也已保留。', 'Do you really want to clear all saved website permissions?': '确定要清除所有已保存的网站权限吗？', 'Download source: ': '下载来源：', 'The current master password is incorrect or the vault is damaged.': '当前主密码不正确，或密码库已损坏。', 'The export contains no valid logins.': '导出文件中不包含有效的登录信息。', 'Translation provider applied immediately: ': '翻译服务已立即应用：', 'Qt 6 + QtWebEngine with selectable light/dark website appearance and optional Widevine CDM integration.': '基于 Qt 6 和 QtWebEngine，可选择网站浅色/深色显示模式，并可选集成 Widevine CDM。', ' text sections translated.': ' 个文本片段已翻译。', 'No bookmarks found in the selected file.': '所选文件中未找到书签。', 'The master password is incorrect or the vault is damaged.': '主密码不正确，或密码库已损坏。', 'Incorrect export password or damaged export file.': '导出密码不正确，或导出文件已损坏。', 'No custom User-Agent entered yet': '尚未输入自定义 User-Agent', 'Could not refresh translation menu: ': '无法刷新翻译菜单：', 'MyMemory: ': 'MyMemory：', 'The folder could not be deleted.': '无法删除该文件夹。'}


PORTUGUESE_UI = {'Manage bookmarks': 'Gerir marcadores', '» More': '» Mais', 'Clear all browser data': 'Limpar todos os dados do navegador', 'Find on this page': 'Localizar nesta página', 'Matches 0 of 0': 'Correspondências: 0 de 0', 'Previous match': 'Correspondência anterior', 'Next match': 'Correspondência seguinte', 'Close find bar': 'Fechar barra de pesquisa', 'Developer tools': 'Ferramentas de programador', 'Back': 'Anterior', 'Forward': 'Seguinte', 'Reload': 'Recarregar', 'Home': 'Início', 'Enter address or search': 'Introduza um endereço ou pesquise', 'Translate webpage': 'Traduzir página Web', 'Show original page': 'Mostrar página original', 'Add current page to bookmarks': 'Adicionar página atual aos marcadores', 'Unlock password manager – autofill saved logins (Ctrl+Shift+L)': 'Desbloquear gestor de palavras-passe – preencher dados guardados (Ctrl+Shift+L)', 'Download manager': 'Gestor de transferências', 'Protection & privacy': 'Proteção e privacidade', 'New tab': 'Novo separador', 'Menu': 'Menu', 'Bookmarks': 'Marcadores', 'History': 'Histórico', 'Open downloads folder': 'Abrir pasta de transferências', 'Settings': 'Definições', 'User guide': 'Manual do utilizador', 'Developer tools (F12)': 'Ferramentas de programador (F12)', 'About LunaSurfer': 'Acerca do LunaSurfer', 'Quit': 'Sair', 'Bookmarks bar': 'Barra de marcadores', 'Ad blocker': 'Bloqueador de anúncios', 'Ready': 'Pronto', 'Loading translated webpage …': 'A carregar página traduzida…', 'View and manage bookmarks': 'Ver e gerir marcadores', 'Open': 'Abrir', 'Edit bookmark…': 'Editar marcador…', 'Delete bookmark': 'Eliminar marcador', 'Edit bookmark': 'Editar marcador', 'Name:': 'Nome:', 'Address:': 'Endereço:', 'Bookmark changed': 'Marcador alterado', 'Really delete this bookmark?': 'Pretende mesmo eliminar este marcador?', 'Bookmark deleted': 'Marcador eliminado', 'Your bookmarks': 'Os seus marcadores', 'Expand folders, search entries and manage them directly.': 'Expanda pastas, pesquise entradas e faça a gestão diretamente.', 'Search bookmarks or addresses …': 'Pesquisar marcadores ou endereços…', 'Edit…': 'Editar…', 'Delete': 'Eliminar', 'Import…': 'Importar…', 'Export…': 'Exportar…', 'Close': 'Fechar', 'Protection settings: ad blocker and fingerprint': 'Definições de proteção: bloqueador de anúncios e impressão digital', 'Saved website permissions': 'Permissões de sites guardadas', 'Change or remove remembered decisions for each website. Changes are saved immediately.': 'Altere ou remova decisões guardadas para cada site. As alterações são guardadas imediatamente.', 'Camera': 'Câmara', 'Microphone': 'Microfone', 'Location': 'Localização', 'Notifications': 'Notificações', 'Clear all saved permissions': 'Limpar todas as permissões guardadas', 'Enable ad blocker': 'Ativar bloqueador de anúncios', 'The ad blocker filters known advertising and tracking domains. Higher levels block more, but may affect some websites.': 'O bloqueador filtra domínios conhecidos de publicidade e rastreio. Níveis superiores bloqueiam mais, mas podem afetar alguns sites.', 'Enable fingerprint protection': 'Ativar proteção contra impressão digital', 'Fingerprint protection': 'Proteção contra impressão digital', 'Save': 'Guardar', 'Cancel': 'Cancelar', 'Download Manager': 'Gestor de transferências', 'Downloads': 'Transferências', 'All active and completed files in one place.': 'Todos os ficheiros ativos e concluídos num só local.', 'All downloads': 'Todas as transferências', 'In progress': 'Em curso', 'Paused': 'Em pausa', 'Completed': 'Concluídas', 'Failed / cancelled': 'Falhadas / canceladas', 'Search filename or path …': 'Pesquisar nome ou caminho do ficheiro…', 'Cancel download': 'Cancelar transferência', 'Open file': 'Abrir ficheiro', 'Open folder': 'Abrir pasta', 'Remove entry': 'Remover entrada', 'Clear completed': 'Limpar concluídas', 'Clear history': 'Limpar histórico', 'Change master password': 'Alterar palavra-passe principal', 'Current master password:': 'Palavra-passe principal atual:', 'New master password': 'Nova palavra-passe principal', 'New master password (at least 10 characters):': 'Nova palavra-passe principal (pelo menos 10 caracteres):', 'Confirm master password': 'Confirmar palavra-passe principal', 'Enter the new master password again:': 'Introduza novamente a nova palavra-passe principal:', 'Export password': 'Palavra-passe de exportação', 'Choose a password for this export file (at least 10 characters):': 'Escolha uma palavra-passe para este ficheiro de exportação (pelo menos 10 caracteres):', 'Confirm export password': 'Confirmar palavra-passe de exportação', 'Enter the export password again:': 'Introduza novamente a palavra-passe de exportação:', 'Enter the password used to encrypt this export file:': 'Introduza a palavra-passe utilizada para encriptar este ficheiro de exportação:', 'Passwords deleted': 'Palavras-passe eliminadas', 'All saved website passwords have been deleted. The master password remains.': 'Todas as palavras-passe de sites guardadas foram eliminadas. A palavra-passe principal foi mantida.', 'Login details': 'Dados de início de sessão', 'Website (matched automatically)': 'Site (correspondência automática)', 'Username': 'Nome de utilizador', 'Password': 'Palavra-passe', 'Show password': 'Mostrar palavra-passe', 'Generate secure password': 'Gerar palavra-passe segura', 'LunaSurfer – Password manager': 'LunaSurfer – Gestor de palavras-passe', 'Passwords are encrypted locally. The master password cannot be recovered.': 'As palavras-passe são encriptadas localmente. Não é possível recuperar a palavra-passe principal.', 'Add': 'Adicionar', 'Edit': 'Editar', 'Export encrypted…': 'Exportar encriptado…', 'Import encrypted…': 'Importar encriptado…', 'Change master password…': 'Alterar palavra-passe principal…', 'Lock now': 'Bloquear agora', 'Update password?': 'Atualizar palavra-passe?', 'Save password?': 'Guardar palavra-passe?', 'Login details saved securely.': 'Dados de início de sessão guardados em segurança.', 'LunaSurfer – User guide': 'LunaSurfer – Manual do utilizador', 'Open homepage': 'Abrir página inicial', 'Restore last session': 'Restaurar última sessão', 'Open blank page': 'Abrir página em branco', 'Google Translate (whole webpage)': 'Google Translate (página Web completa)', 'MyMemory (no API key)': 'MyMemory (sem chave API)', 'Google translates the whole webpage. MyMemory translates visible text sections and has a free daily limit.': 'O Google traduz a página Web completa. O MyMemory traduz secções de texto visíveis e tem um limite diário gratuito.', 'Dark': 'Escuro', 'Light': 'Claro', 'Dark (Standard)': 'Escuro (padrão)', 'Light (Classic)': 'Claro (clássico)', 'Luna (Modern)': 'Luna (moderno)', 'Graphite Blue (Elegant)': 'Azul grafite (elegante)', 'Ocean (Teal Blue)': 'Oceano (azul-petróleo)', 'Show bookmarks bar below the address bar': 'Mostrar barra de marcadores por baixo da barra de endereços', 'Choose folder…': 'Escolher pasta…', 'Ask where to save each download': 'Perguntar onde guardar cada transferência', 'Show security warning for executable downloads': 'Mostrar aviso de segurança para transferências executáveis', 'Show popup when a download finishes': 'Mostrar aviso quando uma transferência terminar', 'Block pop-ups': 'Bloquear janelas de pop-up', 'Enable JavaScript': 'Ativar JavaScript', 'Send Do Not Track request': 'Enviar pedido Do Not Track', 'Ask when closing a tab': 'Perguntar ao fechar um separador', 'Automatically clear history on exit': 'Limpar automaticamente o histórico ao sair', 'Automatically clear cache on exit': 'Limpar automaticamente a cache ao sair', 'Automatically clear cookies on exit': 'Limpar automaticamente os cookies ao sair', 'Remember window size and position on exit': 'Memorizar tamanho e posição da janela ao sair', 'Use LunaSurfer as default browser': 'Utilizar o LunaSurfer como navegador predefinido', 'General': 'Geral', 'Language:': 'Idioma:', 'On startup:': 'Ao iniciar:', 'Homepage:': 'Página inicial:', 'Search engine:': 'Motor de pesquisa:', 'Translation provider:': 'Serviço de tradução:', 'Browser design:': 'Aspeto do navegador:', 'Website appearance:': 'Aspeto dos sites:', 'Download folder:': 'Pasta de transferências:', 'Default zoom:': 'Ampliação predefinida:', 'Default font size:': 'Tamanho de letra predefinido:', 'Website readability:': 'Legibilidade dos sites:', 'Website colors:': 'Cores dos sites:', 'Security and permissions': 'Segurança e permissões', 'Security:': 'Segurança:', 'User-Agent management': 'Gestão do User-Agent', 'Privacy default (reduced Chrome UA)': 'Predefinição de privacidade (User-Agent Chrome reduzido)', 'Native browser User-Agent': 'User-Agent nativo do navegador', 'Custom User-Agent': 'User-Agent personalizado', 'Enter a complete User-Agent string…': 'Introduza uma cadeia User-Agent completa…', 'Mode:': 'Modo:', 'Custom value:': 'Valor personalizado:', 'Current:': 'Atual:', 'Offer to save passwords after successful sign-in': 'Sugerir guardar palavras-passe após início de sessão bem-sucedido', 'Password manager must be unlocked before autofill': 'O gestor de palavras-passe tem de ser desbloqueado antes do preenchimento automático', 'Open password manager…': 'Abrir gestor de palavras-passe…', 'Manage encrypted saved website logins': 'Gerir credenciais de sites guardadas e encriptadas', 'Delete all passwords…': 'Eliminar todas as palavras-passe…', 'Passwords:': 'Palavras-passe:', 'Edit saved website permissions…': 'Editar permissões de sites guardadas…', 'Website permissions:': 'Permissões de sites:', 'Browser behavior:': 'Comportamento do navegador:', 'Clear cache': 'Limpar cache', 'Clear cookies': 'Limpar cookies', 'Clear everything': 'Limpar tudo', 'Privacy and browser data': 'Privacidade e dados do navegador', 'Cookie mode:': 'Modo de cookies:', 'Browser data:': 'Dados do navegador:', 'Permission request': 'Pedido de permissão', 'Remember this decision for this website': 'Memorizar esta decisão para este site', 'Allow': 'Permitir', 'Block': 'Bloquear', 'Yes': 'Sim', 'No': 'Não', 'Close tab': 'Fechar separador', 'Do you really want to close this tab?': 'Pretende mesmo fechar este separador?', 'Stop loading': 'Parar carregamento', 'Translation': 'Tradução', 'Open a regular webpage first.': 'Abra primeiro uma página Web normal.', 'Original page': 'Página original', 'No original page URL is saved for this tab.': 'Não está guardado nenhum URL da página original para este separador.', 'More bookmarks': 'Mais marcadores', 'Show more bookmarks': 'Mostrar mais marcadores', 'Name': 'Nome', 'Address': 'Endereço', 'Export bookmarks': 'Exportar marcadores', 'Import bookmarks': 'Importar marcadores', 'Website': 'Site', 'Permission': 'Permissão', 'Decision': 'Decisão', 'Action': 'Ação', 'Blocking strength:': 'Intensidade do bloqueio:', 'Protection level:': 'Nível de proteção:', 'File no longer present': 'O ficheiro já não existe', 'Cancelled': 'Cancelado', 'Failed': 'Falhou', 'Interrupted': 'Interrompido', 'Ⅱ Pause': 'Ⅱ Pausar', 'Download security warning': 'Aviso de segurança da transferência', 'This file may be dangerous': 'Este ficheiro pode ser perigoso', 'Do not show this security warning again': 'Não voltar a mostrar este aviso de segurança', 'Download anyway': 'Transferir mesmo assim', 'History cleared': 'Histórico limpo', 'The browsing history has been cleared.': 'O histórico de navegação foi limpo.', 'Unlock password manager': 'Desbloquear gestor de palavras-passe', 'Master password:': 'Palavra-passe principal:', 'Set up password manager': 'Configurar gestor de palavras-passe', 'Enter master password again:': 'Introduza novamente a palavra-passe principal:', 'Look in:': 'Procurar em:', 'File name:': 'Nome do ficheiro:', 'File type:': 'Tipo de ficheiro:', 'Too short': 'Demasiado curta', 'Please use at least 10 characters.': 'Utilize pelo menos 10 caracteres.', 'Passwords do not match': 'As palavras-passe não coincidem', 'The passwords do not match.': 'As palavras-passe não coincidem.', 'Master password changed': 'Palavra-passe principal alterada', 'Use at least 10 characters.': 'Utilize pelo menos 10 caracteres.', 'Export complete': 'Exportação concluída', 'Import complete': 'Importação concluída', 'No passwords stored': 'Não existem palavras-passe guardadas', 'There are no saved passwords to delete.': 'Não existem palavras-passe guardadas para eliminar.', 'Delete all passwords': 'Eliminar todas as palavras-passe', 'Invalid input': 'Entrada inválida', 'Ask': 'Perguntar', 'User-Agent missing': 'User-Agent em falta', 'Cache cleared': 'Cache limpa', 'Cookies cleared': 'Cookies limpos', 'Folder': 'Pasta', 'Delete folder': 'Eliminar pasta', 'Bookmarks exported': 'Marcadores exportados', 'Export': 'Exportar', 'Bookmarks imported': 'Marcadores importados', 'Import': 'Importar', 'Remove': 'Remover', 'Clear all permissions': 'Limpar todas as permissões', 'Total': 'Total', 'Download cancelled.': 'Transferência cancelada.', 'Download failed or cancelled.': 'A transferência falhou ou foi cancelada.', 'Incorrect password': 'Palavra-passe incorreta', 'Change failed': 'A alteração falhou', 'Export failed': 'A exportação falhou', 'Nothing to import': 'Nada para importar', 'Import passwords': 'Importar palavras-passe', 'Import failed': 'A importação falhou', 'Delete password': 'Eliminar palavra-passe', 'Really delete this saved login?': 'Pretende mesmo eliminar estas credenciais guardadas?', 'Folder deleted': 'Pasta eliminada', '▶ Resume': '▶ Retomar', 'Download': 'Transferir', 'Unknown': 'Desconhecido', 'Download complete': 'Transferência concluída', 'Error': 'Erro', 'Active': 'Ativo', 'Saved in:': 'Guardado em:', 'Clipboard': 'Área de transferência', 'Allow all cookies': 'Permitir todos os cookies', 'Block third-party cookies': 'Bloquear cookies de terceiros', 'Block all cookies': 'Bloquear todos os cookies', 'Allow session cookies only': 'Permitir apenas cookies de sessão', 'Strong': 'Forte', 'Very strong': 'Muito forte', 'Super strong': 'Super forte', 'Mega strong': 'Extremamente forte', 'Ultra strong': 'Ultra forte', 'Maximum': 'Máximo', 'Standard': 'Padrão', 'Small': 'Pequeno', 'Medium': 'Médio', 'Large': 'Grande', 'Very large': 'Muito grande', 'Export encrypted vault': 'Exportar cofre encriptado', 'Import encrypted vault': 'Importar cofre encriptado', 'New': 'Novo', 'Updated': 'Atualizado', 'Save image as': 'Guardar imagem como', 'Save page as': 'Guardar página como', 'All files (*.*)': 'Todos os ficheiros (*.*)', 'Web page (*.mhtml)': 'Página Web (*.mhtml)', 'Do you really want to clear all browser data?\n\nHistory, cache, cookies, sign-in sessions, Local Storage, IndexedDB and other website data will be removed. You will be signed out of websites.\n\nBookmarks and saved passwords will be kept. The full cleanup will finish the next time LunaSurfer starts.': 'Pretende mesmo limpar todos os dados do navegador?\n\nO histórico, a cache, os cookies, as sessões iniciadas e outros dados dos sites serão removidos. A sessão será terminada nos sites.\n\nOs marcadores e as palavras-passe guardadas serão mantidos. A limpeza completa terminará no próximo arranque do LunaSurfer.', 'Standard: canvas, audio and basic hardware protection. Strong: additionally masks WebGL identifiers. Maximum: additional hardware and browser client-hint protection. Changes apply immediately; no restart is required.': 'Padrão: proteção de canvas, áudio e dados básicos do hardware. Forte: oculta também identificadores WebGL. Máximo: proteção adicional dos dados de hardware e Client Hints do navegador. As alterações são aplicadas imediatamente, sem reiniciar.', 'Do you really want to delete the entire browsing history?': 'Pretende mesmo eliminar todo o histórico de navegação?', 'LunaSurfer vault (*.lsv);;All files (*)': 'Cofre LunaSurfer (*.lsv);;Todos os ficheiros (*)', 'Normal – leave websites unchanged': 'Normal – manter os sites inalterados', 'Gentle contrast': 'Contraste suave', 'Softer contrast': 'Contraste mais suave', 'Relaxed contrast': 'Contraste moderado', 'Original – keep website colors': 'Original – manter as cores dos sites', 'Black mode – black backgrounds': 'Modo preto – fundos pretos', 'The User-Agent changes the browser identification, not the browser engine or its capabilities. With fingerprint protection enabled, Client Hints are reduced to match the Chromium version.': 'O User-Agent altera a identificação do navegador, não o motor nem as suas capacidades. Com a proteção contra impressão digital ativa, os Client Hints são reduzidos para corresponder à versão do Chromium.', 'When disabled, LunaSurfer asks for the master password only when you focus a login field.': 'Quando desativado, o LunaSurfer só pede a palavra-passe principal quando seleciona um campo de início de sessão.', 'Delete all saved website logins; the master password remains': 'Eliminar todas as credenciais guardadas dos sites; a palavra-passe principal será mantida', 'Manage saved permission decisions for individual websites': 'Gerir decisões de permissões guardadas para cada site', 'Do you really want to clear the browser cache?': 'Pretende mesmo limpar a cache do navegador?', 'Browser data cleared; full cleanup will finish after restart.': 'Dados do navegador limpos; a limpeza completa terminará após reiniciar.', 'Browser data is being cleared. Please restart LunaSurfer to remove all stored website data completely. Bookmarks and saved passwords will be kept.': 'Os dados do navegador estão a ser limpos. Reinicie o LunaSurfer para remover completamente os dados guardados dos sites. Os marcadores e as palavras-passe serão mantidos.', 'Do you really want to delete all stored cookies?': 'Pretende mesmo eliminar todos os cookies guardados?', 'Provider: MyMemory – starting translation …': 'Serviço: MyMemory – a iniciar tradução…', 'Provider: Google Translate – loading whole webpage …': 'Serviço: Google Translate – a carregar a página Web completa…', 'Custom block patterns (separate with semicolons):': 'Padrões de bloqueio personalizados (separados por ponto e vírgula):', 'Whitelist domains (separate with semicolons):': 'Domínios na lista de permissões (separados por ponto e vírgula):', 'This file can run programs or scripts. Only download it if you trust the source.': 'Este ficheiro pode executar programas ou scripts. Transfira-o apenas se confiar na origem.', 'The vault has been re-encrypted with the new master password. Keep it safe; it cannot be recovered.': 'O cofre foi novamente encriptado com a nova palavra-passe principal. Guarde-a em segurança; não pode ser recuperada.', 'The vault was exported in encrypted form. Keep the export file and export password separately.': 'O cofre foi exportado em formato encriptado. Guarde o ficheiro exportado e a respetiva palavra-passe separadamente.', 'Do you really want to permanently delete ALL saved website logins? The master password will remain.': 'Pretende mesmo eliminar PERMANENTEMENTE TODAS as credenciais guardadas dos sites? A palavra-passe principal será mantida.', 'Enter a valid website address, username and password.': 'Introduza um endereço de site, nome de utilizador e palavra-passe válidos.', 'Enter a complete User-Agent or select another mode.': 'Introduza um User-Agent completo ou selecione outro modo.', 'The browser cache has been cleared.': 'A cache do navegador foi limpa.', 'All stored cookies have been cleared.': 'Todos os cookies guardados foram eliminados.', 'MyMemory could not translate the page. Check connection or daily quota.': 'O MyMemory não conseguiu traduzir a página. Verifique a ligação ou o limite diário.', 'Really delete this folder and all bookmarks inside it?': 'Pretende mesmo eliminar esta pasta e todos os marcadores que contém?', 'Bookmarks were exported, including their folder structure.': 'Os marcadores foram exportados, incluindo a estrutura de pastas.', 'Do you really want to clear all saved website permissions?': 'Pretende mesmo limpar todas as permissões de sites guardadas?', 'Download source: ': 'Origem da transferência: ', 'The current master password is incorrect or the vault is damaged.': 'A palavra-passe principal atual está incorreta ou o cofre está danificado.', 'The export contains no valid logins.': 'A exportação não contém credenciais válidas.', 'Translation provider applied immediately: ': 'Serviço de tradução aplicado imediatamente: ', 'Qt 6 + QtWebEngine with selectable light/dark website appearance and optional Widevine CDM integration.': 'Qt 6 + QtWebEngine com aspeto claro/escuro dos sites selecionável e integração opcional do Widevine CDM.', ' text sections translated.': ' secções de texto traduzidas.', 'No bookmarks found in the selected file.': 'Não foram encontrados marcadores no ficheiro selecionado.', 'The master password is incorrect or the vault is damaged.': 'A palavra-passe principal está incorreta ou o cofre está danificado.', 'Incorrect export password or damaged export file.': 'Palavra-passe de exportação incorreta ou ficheiro de exportação danificado.', 'No custom User-Agent entered yet': 'Ainda não foi introduzido um User-Agent personalizado', 'Could not refresh translation menu: ': 'Não foi possível atualizar o menu de tradução: ', 'MyMemory: ': 'MyMemory: ', 'The folder could not be deleted.': 'Não foi possível eliminar a pasta.', 'The download has finished:': 'A transferência terminou:', ' items': ' itens', ' matches': ' correspondências'}

# Spanish interface catalogue.
SPANISH_UI = {'Manage bookmarks': 'Administrar marcadores', '» More': '» Más', 'Clear all browser data': 'Borrar todos los datos del navegador', 'Find on this page': 'Buscar en esta página', 'Matches 0 of 0': 'Coincidencias: 0 de 0', 'Previous match': 'Coincidencia anterior', 'Next match': 'Coincidencia siguiente', 'Close find bar': 'Cerrar barra de búsqueda', 'Developer tools': 'Herramientas para desarrolladores', 'Back': 'Atrás', 'Forward': 'Adelante', 'Reload': 'Recargar', 'Home': 'Inicio', 'Enter address or search': 'Introducir dirección o buscar', 'Translate webpage': 'Traducir página web', 'Show original page': 'Mostrar página original', 'Add current page to bookmarks': 'Añadir página actual a marcadores', 'Unlock password manager – autofill saved logins (Ctrl+Shift+L)': 'Desbloquear el gestor de contraseñas – autocompletar inicios de sesión guardados (Ctrl+Mayús+L)', 'Download manager': 'Gestor de descargas', 'Protection & privacy': 'Protección y privacidad', 'New tab': 'Nueva pestaña', 'Menu': 'Menú', 'Bookmarks': 'Marcadores', 'History': 'Historial', 'Open downloads folder': 'Abrir carpeta de descargas', 'Settings': 'Configuración', 'User guide': 'Manual de usuario', 'Developer tools (F12)': 'Herramientas para desarrolladores (F12)', 'About LunaSurfer': 'Acerca de LunaSurfer', 'Quit': 'Salir', 'Bookmarks bar': 'Barra de marcadores', 'Ad blocker': 'Bloqueador de anuncios', 'Ready': 'Listo', 'Loading translated webpage …': 'Cargando página web traducida…', 'View and manage bookmarks': 'Ver y administrar marcadores', 'Open': 'Abrir', 'Edit bookmark…': 'Editar marcador…', 'Delete bookmark': 'Eliminar marcador', 'Edit bookmark': 'Editar marcador', 'Name:': 'Nombre:', 'Address:': 'Dirección:', 'Bookmark changed': 'Marcador modificado', 'Really delete this bookmark?': '¿Realmente desea eliminar este marcador?', 'Bookmark deleted': 'Marcador eliminado', 'Your bookmarks': 'Sus marcadores', 'Expand folders, search entries and manage them directly.': 'Despliegue carpetas, busque entradas y adminístrelas directamente.', 'Search bookmarks or addresses …': 'Buscar marcadores o direcciones…', 'Edit…': 'Editar…', 'Delete': 'Eliminar', 'Import…': 'Importar…', 'Export…': 'Exportar…', 'Close': 'Cerrar', 'Protection settings: ad blocker and fingerprint': 'Configuración de protección: bloqueador de anuncios y huella digital', 'Saved website permissions': 'Permisos guardados de sitios web', 'Change or remove remembered decisions for each website. Changes are saved immediately.': 'Cambie o elimine las decisiones guardadas para cada sitio web. Los cambios se guardan inmediatamente.', 'Camera': 'Cámara', 'Microphone': 'Micrófono', 'Location': 'Ubicación', 'Notifications': 'Notificaciones', 'Clear all saved permissions': 'Borrar todos los permisos guardados', 'Enable ad blocker': 'Activar bloqueador de anuncios', 'The ad blocker filters known advertising and tracking domains. Higher levels block more, but may affect some websites.': 'El bloqueador filtra dominios conocidos de publicidad y seguimiento. Los niveles más altos bloquean más contenido, pero pueden afectar a algunos sitios web.', 'Enable fingerprint protection': 'Activar protección contra huellas digitales', 'Fingerprint protection': 'Protección contra huellas digitales', 'Save': 'Guardar', 'Cancel': 'Cancelar', 'Download Manager': 'Gestor de descargas', 'Downloads': 'Descargas', 'All active and completed files in one place.': 'Todos los archivos activos y completados en un solo lugar.', 'All downloads': 'Todas las descargas', 'In progress': 'En curso', 'Paused': 'En pausa', 'Completed': 'Completadas', 'Failed / cancelled': 'Fallidas / canceladas', 'Search filename or path …': 'Buscar nombre de archivo o ruta…', 'Cancel download': 'Cancelar descarga', 'Open file': 'Abrir archivo', 'Open folder': 'Abrir carpeta', 'Remove entry': 'Eliminar entrada', 'Clear completed': 'Borrar completadas', 'Clear history': 'Borrar historial', 'Change master password': 'Cambiar contraseña maestra', 'Current master password:': 'Contraseña maestra actual:', 'New master password': 'Nueva contraseña maestra', 'New master password (at least 10 characters):': 'Nueva contraseña maestra (mínimo 10 caracteres):', 'Confirm master password': 'Confirmar contraseña maestra', 'Enter the new master password again:': 'Vuelva a introducir la nueva contraseña maestra:', 'Export password': 'Contraseña de exportación', 'Choose a password for this export file (at least 10 characters):': 'Elija una contraseña para este archivo de exportación (mínimo 10 caracteres):', 'Confirm export password': 'Confirmar contraseña de exportación', 'Enter the export password again:': 'Vuelva a introducir la contraseña de exportación:', 'Enter the password used to encrypt this export file:': 'Introduzca la contraseña utilizada para cifrar este archivo de exportación:', 'Passwords deleted': 'Contraseñas eliminadas', 'All saved website passwords have been deleted. The master password remains.': 'Se han eliminado todas las contraseñas de sitios web guardadas. La contraseña maestra se conserva.', 'Login details': 'Datos de inicio de sesión', 'Website (matched automatically)': 'Sitio web (detectado automáticamente)', 'Username': 'Nombre de usuario', 'Password': 'Contraseña', 'Show password': 'Mostrar contraseña', 'Generate secure password': 'Generar contraseña segura', 'LunaSurfer – Password manager': 'LunaSurfer – Gestor de contraseñas', 'Passwords are encrypted locally. The master password cannot be recovered.': 'Las contraseñas se cifran localmente. La contraseña maestra no se puede recuperar.', 'Add': 'Añadir', 'Edit': 'Editar', 'Export encrypted…': 'Exportar cifrado…', 'Import encrypted…': 'Importar cifrado…', 'Change master password…': 'Cambiar contraseña maestra…', 'Lock now': 'Bloquear ahora', 'Update password?': '¿Actualizar contraseña?', 'Save password?': '¿Guardar contraseña?', 'Login details saved securely.': 'Los datos de inicio de sesión se han guardado de forma segura.', 'LunaSurfer – User guide': 'LunaSurfer – Manual de usuario', 'Open homepage': 'Abrir página de inicio', 'Restore last session': 'Restaurar última sesión', 'Open blank page': 'Abrir página en blanco', 'Google Translate (whole webpage)': 'Google Translate (página web completa)', 'MyMemory (no API key)': 'MyMemory (sin clave API)', 'Google translates the whole webpage. MyMemory translates visible text sections and has a free daily limit.': 'Google traduce la página web completa. MyMemory traduce las secciones de texto visibles y tiene un límite diario gratuito.', 'Dark': 'Oscuro', 'Light': 'Claro', 'Dark (Standard)': 'Oscuro (estándar)', 'Light (Classic)': 'Claro (clásico)', 'Luna (Modern)': 'Luna (moderno)', 'Graphite Blue (Elegant)': 'Azul grafito (elegante)', 'Ocean (Teal Blue)': 'Océano (azul turquesa)', 'Show bookmarks bar below the address bar': 'Mostrar barra de marcadores debajo de la barra de direcciones', 'Choose folder…': 'Elegir carpeta…', 'Ask where to save each download': 'Preguntar dónde guardar cada descarga', 'Show security warning for executable downloads': 'Mostrar advertencia de seguridad para descargas ejecutables', 'Show popup when a download finishes': 'Mostrar aviso al finalizar una descarga', 'Block pop-ups': 'Bloquear ventanas emergentes', 'Enable JavaScript': 'Activar JavaScript', 'Send Do Not Track request': 'Enviar solicitud Do Not Track', 'Ask when closing a tab': 'Preguntar al cerrar una pestaña', 'Automatically clear history on exit': 'Borrar automáticamente el historial al salir', 'Automatically clear cache on exit': 'Borrar automáticamente la caché al salir', 'Automatically clear cookies on exit': 'Borrar automáticamente las cookies al salir', 'Remember window size and position on exit': 'Recordar el tamaño y la posición de la ventana al salir', 'Use LunaSurfer as default browser': 'Usar LunaSurfer como navegador predeterminado', 'General': 'General', 'Language:': 'Idioma:', 'On startup:': 'Al iniciar:', 'Homepage:': 'Página de inicio:', 'Search engine:': 'Motor de búsqueda:', 'Translation provider:': 'Proveedor de traducción:', 'Browser design:': 'Diseño del navegador:', 'Website appearance:': 'Apariencia de los sitios web:', 'Download folder:': 'Carpeta de descargas:', 'Default zoom:': 'Zoom predeterminado:', 'Default font size:': 'Tamaño de fuente predeterminado:', 'Website readability:': 'Legibilidad de los sitios web:', 'Website colors:': 'Colores de los sitios web:', 'Security and permissions': 'Seguridad y permisos', 'Security:': 'Seguridad:', 'User-Agent management': 'Administración del User-Agent', 'Privacy default (reduced Chrome UA)': 'Privacidad predeterminada (User-Agent de Chrome reducido)', 'Native browser User-Agent': 'User-Agent nativo del navegador', 'Custom User-Agent': 'User-Agent personalizado', 'Enter a complete User-Agent string…': 'Introduzca una cadena User-Agent completa…', 'Mode:': 'Modo:', 'Custom value:': 'Valor personalizado:', 'Current:': 'Actual:', 'Offer to save passwords after successful sign-in': 'Ofrecer guardar contraseñas después de iniciar sesión correctamente', 'Password manager must be unlocked before autofill': 'El gestor de contraseñas debe estar desbloqueado antes del autocompletado', 'Open password manager…': 'Abrir gestor de contraseñas…', 'Manage encrypted saved website logins': 'Administrar inicios de sesión cifrados guardados', 'Delete all passwords…': 'Eliminar todas las contraseñas…', 'Passwords:': 'Contraseñas:', 'Edit saved website permissions…': 'Editar permisos guardados de sitios web…', 'Website permissions:': 'Permisos de sitios web:', 'Browser behavior:': 'Comportamiento del navegador:', 'Clear cache': 'Borrar caché', 'Clear cookies': 'Borrar cookies', 'Clear everything': 'Borrar todo', 'Privacy and browser data': 'Privacidad y datos del navegador', 'Cookie mode:': 'Modo de cookies:', 'Browser data:': 'Datos del navegador:', 'Permission request': 'Solicitud de permiso', 'Remember this decision for this website': 'Recordar esta decisión para este sitio web', 'Allow': 'Permitir', 'Block': 'Bloquear', 'Yes': 'Sí', 'No': 'No', 'Close tab': 'Cerrar pestaña', 'Do you really want to close this tab?': '¿Realmente desea cerrar esta pestaña?', 'Stop loading': 'Detener carga', 'Translation': 'Traducción', 'Open a regular webpage first.': 'Primero abra una página web normal.', 'Original page': 'Página original', 'No original page URL is saved for this tab.': 'No hay guardada ninguna URL de página original para esta pestaña.', 'More bookmarks': 'Más marcadores', 'Show more bookmarks': 'Mostrar más marcadores', 'Name': 'Nombre', 'Address': 'Dirección', 'Export bookmarks': 'Exportar marcadores', 'Import bookmarks': 'Importar marcadores', 'Website': 'Sitio web', 'Permission': 'Permiso', 'Decision': 'Decisión', 'Action': 'Acción', 'Blocking strength:': 'Intensidad del bloqueo:', 'Protection level:': 'Nivel de protección:', 'File no longer present': 'El archivo ya no está disponible', 'Cancelled': 'Cancelado', 'Failed': 'Error', 'Interrupted': 'Interrumpido', 'Ⅱ Pause': 'Ⅱ Pausar', 'Download security warning': 'Advertencia de seguridad de descarga', 'This file may be dangerous': 'Este archivo puede ser peligroso', 'Do not show this security warning again': 'No volver a mostrar esta advertencia de seguridad', 'Download anyway': 'Descargar de todos modos', 'History cleared': 'Historial borrado', 'The browsing history has been cleared.': 'Se ha borrado el historial de navegación.', 'Unlock password manager': 'Desbloquear gestor de contraseñas', 'Master password:': 'Contraseña maestra:', 'Set up password manager': 'Configurar gestor de contraseñas', 'Enter master password again:': 'Vuelva a introducir la contraseña maestra:', 'Look in:': 'Buscar en:', 'File name:': 'Nombre de archivo:', 'File type:': 'Tipo de archivo:', 'Too short': 'Demasiado corta', 'Please use at least 10 characters.': 'Utilice al menos 10 caracteres.', 'Passwords do not match': 'Las contraseñas no coinciden', 'The passwords do not match.': 'Las contraseñas no coinciden.', 'Master password changed': 'Contraseña maestra cambiada', 'Use at least 10 characters.': 'Utilice al menos 10 caracteres.', 'Export complete': 'Exportación completada', 'Import complete': 'Importación completada', 'No passwords stored': 'No hay contraseñas guardadas', 'There are no saved passwords to delete.': 'No hay contraseñas guardadas que eliminar.', 'Delete all passwords': 'Eliminar todas las contraseñas', 'Invalid input': 'Entrada no válida', 'Ask': 'Preguntar', 'User-Agent missing': 'Falta el User-Agent', 'Cache cleared': 'Caché borrada', 'Cookies cleared': 'Cookies borradas', 'Folder': 'Carpeta', 'Delete folder': 'Eliminar carpeta', 'Bookmarks exported': 'Marcadores exportados', 'Export': 'Exportar', 'Bookmarks imported': 'Marcadores importados', 'Import': 'Importar', 'Remove': 'Eliminar', 'Clear all permissions': 'Borrar todos los permisos', 'Total': 'Total', 'Download cancelled.': 'Descarga cancelada.', 'Download failed or cancelled.': 'La descarga ha fallado o se ha cancelado.', 'Incorrect password': 'Contraseña incorrecta', 'Change failed': 'Error al cambiar', 'Export failed': 'Error al exportar', 'Nothing to import': 'Nada que importar', 'Import passwords': 'Importar contraseñas', 'Import failed': 'Error al importar', 'Delete password': 'Eliminar contraseña', 'Really delete this saved login?': '¿Realmente desea eliminar este inicio de sesión guardado?', 'Folder deleted': 'Carpeta eliminada', '▶ Resume': '▶ Reanudar', 'Download': 'Descargar', 'Unknown': 'Desconocido', 'Download complete': 'Descarga completada', 'Error': 'Error', 'Active': 'Activo', 'Saved in:': 'Guardado en:', 'Clipboard': 'Portapapeles', 'Allow all cookies': 'Permitir todas las cookies', 'Block third-party cookies': 'Bloquear cookies de terceros', 'Block all cookies': 'Bloquear todas las cookies', 'Allow session cookies only': 'Permitir solo cookies de sesión', 'Strong': 'Fuerte', 'Very strong': 'Muy fuerte', 'Super strong': 'Súper fuerte', 'Mega strong': 'Muy potente', 'Ultra strong': 'Ultrapotente', 'Maximum': 'Máximo', 'Standard': 'Estándar', 'Small': 'Pequeño', 'Medium': 'Mediano', 'Large': 'Grande', 'Very large': 'Muy grande', 'Export encrypted vault': 'Exportar bóveda cifrada', 'Import encrypted vault': 'Importar bóveda cifrada', 'New': 'Nuevo', 'Updated': 'Actualizado', 'Save image as': 'Guardar imagen como', 'Save page as': 'Guardar página como', 'All files (*.*)': 'Todos los archivos (*.*)', 'Web page (*.mhtml)': 'Página web (*.mhtml)', 'Do you really want to clear all browser data?\n\nHistory, cache, cookies, sign-in sessions, Local Storage, IndexedDB and other website data will be removed. You will be signed out of websites.\n\nBookmarks and saved passwords will be kept. The full cleanup will finish the next time LunaSurfer starts.': '¿Realmente desea borrar todos los datos del navegador?\n\nSe eliminarán el historial, la caché, las cookies, las sesiones de inicio de sesión, Local Storage, IndexedDB y otros datos de los sitios web. Se cerrará su sesión en los sitios web.\n\nLos marcadores y las contraseñas guardadas se conservarán. La limpieza completa finalizará la próxima vez que se inicie LunaSurfer.', 'Standard: canvas, audio and basic hardware protection. Strong: additionally masks WebGL identifiers. Maximum: additional hardware and browser client-hint protection. Changes apply immediately; no restart is required.': 'Estándar: protección de Canvas, audio e información básica del hardware. Fuerte: también oculta los identificadores WebGL. Máxima: protección adicional del hardware y de los Client Hints del navegador. Los cambios se aplican inmediatamente; no es necesario reiniciar.', 'Do you really want to delete the entire browsing history?': '¿Realmente desea eliminar todo el historial de navegación?', 'LunaSurfer vault (*.lsv);;All files (*)': 'Bóveda de LunaSurfer (*.lsv);;Todos los archivos (*)', 'Normal – leave websites unchanged': 'Normal – no modificar los sitios web', 'Gentle contrast': 'Contraste suave', 'Softer contrast': 'Contraste más suave', 'Relaxed contrast': 'Contraste relajado', 'Original – keep website colors': 'Original – mantener los colores del sitio web', 'Black mode – black backgrounds': 'Modo negro – fondos negros', 'The User-Agent changes the browser identification, not the browser engine or its capabilities. With fingerprint protection enabled, Client Hints are reduced to match the Chromium version.': 'El User-Agent cambia la identificación del navegador, no el motor ni sus capacidades. Con la protección contra huellas digitales activada, los Client Hints se reducen para coincidir con la versión de Chromium.', 'When disabled, LunaSurfer asks for the master password only when you focus a login field.': 'Cuando está desactivado, LunaSurfer solo solicita la contraseña maestra al seleccionar un campo de inicio de sesión.', 'Delete all saved website logins; the master password remains': 'Eliminar todos los inicios de sesión guardados; la contraseña maestra se conserva', 'Manage saved permission decisions for individual websites': 'Administrar las decisiones de permisos guardadas para cada sitio web', 'Do you really want to clear the browser cache?': '¿Realmente desea borrar la caché del navegador?', 'Browser data cleared; full cleanup will finish after restart.': 'Datos del navegador borrados; la limpieza completa finalizará después de reiniciar.', 'Browser data is being cleared. Please restart LunaSurfer to remove all stored website data completely. Bookmarks and saved passwords will be kept.': 'Se están borrando los datos del navegador. Reinicie LunaSurfer para eliminar por completo todos los datos almacenados de los sitios web. Los marcadores y las contraseñas guardadas se conservarán.', 'Do you really want to delete all stored cookies?': '¿Realmente desea eliminar todas las cookies guardadas?', 'Provider: MyMemory – starting translation …': 'Proveedor: MyMemory – iniciando traducción…', 'Provider: Google Translate – loading whole webpage …': 'Proveedor: Google Translate – cargando la página web completa…', 'Custom block patterns (separate with semicolons):': 'Patrones de bloqueo personalizados (separados por punto y coma):', 'Whitelist domains (separate with semicolons):': 'Dominios permitidos (separados por punto y coma):', 'This file can run programs or scripts. Only download it if you trust the source.': 'Este archivo puede ejecutar programas o scripts. Descárguelo solo si confía en el origen.', 'The vault has been re-encrypted with the new master password. Keep it safe; it cannot be recovered.': 'La bóveda se ha vuelto a cifrar con la nueva contraseña maestra. Guárdela en un lugar seguro; no se puede recuperar.', 'The vault was exported in encrypted form. Keep the export file and export password separately.': 'La bóveda se ha exportado cifrada. Guarde por separado el archivo exportado y la contraseña de exportación.', 'Do you really want to permanently delete ALL saved website logins? The master password will remain.': '¿Realmente desea eliminar PERMANENTEMENTE TODOS los inicios de sesión guardados? La contraseña maestra se conservará.', 'Enter a valid website address, username and password.': 'Introduzca una dirección web, un nombre de usuario y una contraseña válidos.', 'Enter a complete User-Agent or select another mode.': 'Introduzca un User-Agent completo o seleccione otro modo.', 'The browser cache has been cleared.': 'Se ha borrado la caché del navegador.', 'All stored cookies have been cleared.': 'Se han borrado todas las cookies guardadas.', 'MyMemory could not translate the page. Check connection or daily quota.': 'MyMemory no pudo traducir la página. Compruebe la conexión o el límite diario.', 'Really delete this folder and all bookmarks inside it?': '¿Realmente desea eliminar esta carpeta y todos los marcadores que contiene?', 'Bookmarks were exported, including their folder structure.': 'Los marcadores se han exportado, incluida la estructura de carpetas.', 'Do you really want to clear all saved website permissions?': '¿Realmente desea borrar todos los permisos guardados de los sitios web?', 'Download source: ': 'Origen de la descarga: ', 'The current master password is incorrect or the vault is damaged.': 'La contraseña maestra actual es incorrecta o la bóveda está dañada.', 'The export contains no valid logins.': 'La exportación no contiene inicios de sesión válidos.', 'Translation provider applied immediately: ': 'Proveedor de traducción aplicado inmediatamente: ', 'Qt 6 + QtWebEngine with selectable light/dark website appearance and optional Widevine CDM integration.': 'Qt 6 + QtWebEngine con apariencia clara u oscura seleccionable para los sitios web e integración opcional de Widevine CDM.', ' text sections translated.': ' secciones de texto traducidas.', 'No bookmarks found in the selected file.': 'No se encontraron marcadores en el archivo seleccionado.', 'The master password is incorrect or the vault is damaged.': 'La contraseña maestra es incorrecta o la bóveda está dañada.', 'Incorrect export password or damaged export file.': 'La contraseña de exportación es incorrecta o el archivo está dañado.', 'No custom User-Agent entered yet': 'Todavía no se ha introducido ningún User-Agent personalizado', 'Could not refresh translation menu: ': 'No se pudo actualizar el menú de traducción: ', 'MyMemory: ': 'MyMemory: ', 'The folder could not be deleted.': 'No se pudo eliminar la carpeta.', 'The download has finished:': 'La descarga ha finalizado:', ' items': ' elementos', ' matches': ' coincidencias'}

SPANISH_QT_BUTTON_TRANSLATIONS = {
    'OK':'OK','Cancel':'Cancelar','Yes':'Sí','No':'No','Apply':'Aplicar','Save':'Guardar','Open':'Abrir','Close':'Cerrar',
    'Discard':'Descartar','Retry':'Reintentar','Ignore':'Ignorar','Abort':'Abortar','Help':'Ayuda',
    '&Yes':'&Sí','&No':'&No','&Open':'&Abrir','&Save':'&Guardar','&Cancel':'&Cancelar',
}

# Italian interface catalogue (0.3.49).
TURKISH_UI = {'Manage bookmarks': 'Yer imlerini yönet', '» More': '» Daha fazla', 'Clear all browser data': 'Tüm tarayıcı verilerini temizle', 'Find on this page': 'Bu sayfada bul', 'Matches 0 of 0': 'Eşleşme: 0 / 0', 'Previous match': 'Önceki eşleşme', 'Next match': 'Sonraki eşleşme', 'Close find bar': 'Bul çubuğunu kapat', 'Developer tools': 'Geliştirici araçları', 'Back': 'Geri', 'Forward': 'İleri', 'Reload': 'Yenile', 'Home': 'Ana sayfa', 'Enter address or search': 'Adres girin veya arayın', 'Translate webpage': 'Web sayfasını çevir', 'Show original page': 'Orijinal sayfayı göster', 'Add current page to bookmarks': 'Geçerli sayfayı yer imlerine ekle', 'Unlock password manager – autofill saved logins (Ctrl+Shift+L)': 'Parola yöneticisinin kilidini aç – kayıtlı girişleri otomatik doldur (Ctrl+Shift+L)', 'Download manager': 'İndirme yöneticisi', 'Protection & privacy': 'Koruma ve gizlilik', 'New tab': 'Yeni sekme', 'Menu': 'Menü', 'Bookmarks': 'Yer imleri', 'History': 'Geçmiş', 'Open downloads folder': 'İndirilenler klasörünü aç', 'Settings': 'Ayarlar', 'User guide': 'Kullanım kılavuzu', 'Developer tools (F12)': 'Geliştirici araçları (F12)', 'About LunaSurfer': 'LunaSurfer hakkında', 'Quit': 'Çıkış', 'Bookmarks bar': 'Yer imi çubuğu', 'Ad blocker': 'Reklam engelleyici', 'Ready': 'Hazır', 'Loading translated webpage …': 'Çevrilmiş web sayfası yükleniyor…', 'View and manage bookmarks': 'Yer imlerini görüntüleyin ve yönetin', 'Open': 'Aç', 'Edit bookmark…': 'Yer imini düzenle…', 'Delete bookmark': 'Yer imini sil', 'Edit bookmark': 'Yer imini düzenle', 'Name:': 'Ad:', 'Address:': 'Adres:', 'Bookmark changed': 'Yer imi değiştirildi', 'Really delete this bookmark?': 'Bu yer imi gerçekten silinsin mi?', 'Bookmark deleted': 'Yer imi silindi', 'Your bookmarks': 'Yer imleriniz', 'Expand folders, search entries and manage them directly.': 'Klasörleri genişletin, kayıtları arayın ve doğrudan yönetin.', 'Search bookmarks or addresses …': 'Yer imlerinde veya adreslerde ara…', 'Edit…': 'Düzenle…', 'Delete': 'Sil', 'Import…': 'İçe aktar…', 'Export…': 'Dışa aktar…', 'Close': 'Kapat', 'Protection settings: ad blocker and fingerprint': 'Koruma ayarları: reklam engelleyici ve parmak izi koruması', 'Saved website permissions': 'Kaydedilmiş site izinleri', 'Change or remove remembered decisions for each website. Changes are saved immediately.': 'Her web sitesi için hatırlanan kararları değiştirin veya kaldırın. Değişiklikler hemen kaydedilir.', 'Camera': 'Kamera', 'Microphone': 'Mikrofon', 'Location': 'Konum', 'Notifications': 'Bildirimler', 'Clear all saved permissions': 'Kaydedilmiş tüm izinleri temizle', 'Enable ad blocker': 'Reklam engelleyiciyi etkinleştir', 'Enable fingerprint protection': 'Parmak izi korumasını etkinleştir', 'Fingerprint protection': 'Parmak izi koruması', 'Save': 'Kaydet', 'Cancel': 'İptal', 'Download Manager': 'İndirme Yöneticisi', 'Downloads': 'İndirilenler', 'All active and completed files in one place.': 'Tüm etkin ve tamamlanmış dosyalar tek bir yerde.', 'All downloads': 'Tüm indirmeler', 'In progress': 'Devam ediyor', 'Paused': 'Duraklatıldı', 'Completed': 'Tamamlandı', 'Failed / cancelled': 'Başarısız / iptal edildi', 'Search filename or path …': 'Dosya adı veya yol ara…', 'Cancel download': 'İndirmeyi iptal et', 'Open file': 'Dosyayı aç', 'Open folder': 'Klasörü aç', 'Remove entry': 'Kaydı kaldır', 'Clear completed': 'Tamamlananları temizle', 'Clear history': 'Geçmişi temizle', 'Change master password': 'Ana parolayı değiştir', 'Current master password:': 'Geçerli ana parola:', 'New master password': 'Yeni ana parola', 'New master password (at least 10 characters):': 'Yeni ana parola (en az 10 karakter):', 'Confirm master password': 'Ana parolayı onayla', 'Enter the new master password again:': 'Yeni ana parolayı tekrar girin:', 'Export password': 'Dışa aktarma parolası', 'Choose a password for this export file (at least 10 characters):': 'Bu dışa aktarma dosyası için bir parola seçin (en az 10 karakter):', 'Confirm export password': 'Dışa aktarma parolasını onayla', 'Enter the export password again:': 'Dışa aktarma parolasını tekrar girin:', 'Enter the password used to encrypt this export file:': 'Bu dışa aktarma dosyasını şifrelemek için kullanılan parolayı girin:', 'Passwords deleted': 'Parolalar silindi', 'All saved website passwords have been deleted. The master password remains.': 'Kaydedilmiş tüm web sitesi parolaları silindi. Ana parola korunur.', 'Login details': 'Giriş bilgileri', 'Website (matched automatically)': 'Web sitesi (otomatik eşleştirildi)', 'Username': 'Kullanıcı adı', 'Password': 'Parola', 'Show password': 'Parolayı göster', 'Generate secure password': 'Güvenli parola oluştur', 'LunaSurfer – Password manager': 'LunaSurfer – Parola yöneticisi', 'Passwords are encrypted locally. The master password cannot be recovered.': 'Parolalar yerel olarak şifrelenir. Ana parola kurtarılamaz.', 'Add': 'Ekle', 'Edit': 'Düzenle', 'Export encrypted…': 'Şifreli olarak dışa aktar…', 'Import encrypted…': 'Şifreli olarak içe aktar…', 'Change master password…': 'Ana parolayı değiştir…', 'Lock now': 'Şimdi kilitle', 'Update password?': 'Parola güncellensin mi?', 'Save password?': 'Parola kaydedilsin mi?', 'Login details saved securely.': 'Giriş bilgileri güvenli şekilde kaydedildi.', 'LunaSurfer – User guide': 'LunaSurfer – Kullanım kılavuzu', 'Open homepage': 'Ana sayfayı aç', 'Restore last session': 'Son oturumu geri yükle', 'Open blank page': 'Boş sayfa aç', 'Google Translate (whole webpage)': 'Google Translate (tüm web sayfası)', 'MyMemory (no API key)': 'MyMemory (API anahtarı gerekmez)', 'Dark': 'Koyu', 'Light': 'Açık', 'Dark (Standard)': 'Koyu (Standart)', 'Light (Classic)': 'Açık (Klasik)', 'Luna (Modern)': 'Luna (Modern)', 'Graphite Blue (Elegant)': 'Grafit Mavisi (Zarif)', 'Ocean (Teal Blue)': 'Okyanus (Turkuaz)', 'Show bookmarks bar below the address bar': 'Adres çubuğunun altında yer imi çubuğunu göster', 'Choose folder…': 'Klasör seç…', 'Ask where to save each download': 'Her indirme için kaydetme konumunu sor', 'Show security warning for executable downloads': 'Çalıştırılabilir indirmeler için güvenlik uyarısı göster', 'Show popup when a download finishes': 'İndirme tamamlandığında açılır bildirim göster', 'Block pop-ups': 'Açılır pencereleri engelle', 'Enable JavaScript': 'JavaScript’i etkinleştir', 'Send Do Not Track request': 'Do Not Track isteği gönder', 'Ask when closing a tab': 'Sekmeyi kapatırken sor', 'Automatically clear history on exit': 'Çıkışta geçmişi otomatik temizle', 'Automatically clear cache on exit': 'Çıkışta önbelleği otomatik temizle', 'Automatically clear cookies on exit': 'Çıkışta çerezleri otomatik temizle', 'Remember window size and position on exit': 'Çıkışta pencere boyutunu ve konumunu hatırla', 'Use LunaSurfer as default browser': 'LunaSurfer’ı varsayılan tarayıcı olarak kullan', 'General': 'Genel', 'Language:': 'Dil:', 'On startup:': 'Başlangıçta:', 'Homepage:': 'Ana sayfa:', 'Search engine:': 'Arama motoru:', 'Translation provider:': 'Çeviri sağlayıcısı:', 'Browser design:': 'Tarayıcı görünümü:', 'Website appearance:': 'Web sitesi görünümü:', 'Download folder:': 'İndirme klasörü:', 'Default zoom:': 'Varsayılan yakınlaştırma:', 'Default font size:': 'Varsayılan yazı tipi boyutu:', 'Website readability:': 'Web sitesi okunabilirliği:', 'Website colors:': 'Web sitesi renkleri:', 'Security and permissions': 'Güvenlik ve izinler', 'Security:': 'Güvenlik:', 'User-Agent management': 'User-Agent yönetimi', 'Privacy default (reduced Chrome UA)': 'Gizlilik varsayılanı (azaltılmış Chrome UA)', 'Native browser User-Agent': 'Tarayıcının yerel User-Agent değeri', 'Custom User-Agent': 'Özel User-Agent', 'Enter a complete User-Agent string…': 'Tam bir User-Agent dizgesi girin…', 'Mode:': 'Mod:', 'Custom value:': 'Özel değer:', 'Current:': 'Geçerli:', 'Offer to save passwords after successful sign-in': 'Başarılı oturum açma işleminden sonra parolaları kaydetmeyi öner', 'Password manager must be unlocked before autofill': 'Otomatik doldurmadan önce parola yöneticisinin kilidi açılmalı', 'Open password manager…': 'Parola yöneticisini aç…', 'Manage encrypted saved website logins': 'Şifrelenmiş kayıtlı web sitesi girişlerini yönet', 'Delete all passwords…': 'Tüm parolaları sil…', 'Passwords:': 'Parolalar:', 'Edit saved website permissions…': 'Kaydedilmiş web sitesi izinlerini düzenle…', 'Website permissions:': 'Web sitesi izinleri:', 'Browser behavior:': 'Tarayıcı davranışı:', 'Clear cache': 'Önbelleği temizle', 'Clear cookies': 'Çerezleri temizle', 'Clear everything': 'Her şeyi temizle', 'Privacy and browser data': 'Gizlilik ve tarayıcı verileri', 'Cookie mode:': 'Çerez modu:', 'Browser data:': 'Tarayıcı verileri:', 'Permission request': 'İzin isteği', 'Remember this decision for this website': 'Bu kararı bu web sitesi için hatırla', 'Allow': 'İzin ver', 'Block': 'Engelle', 'Yes': 'Evet', 'No': 'Hayır', 'Close tab': 'Sekmeyi kapat', 'Do you really want to close this tab?': 'Bu sekmeyi gerçekten kapatmak istiyor musunuz?', 'Stop loading': 'Yüklemeyi durdur', 'Translation': 'Çeviri', 'Open a regular webpage first.': 'Önce normal bir web sayfası açın.', 'Original page': 'Orijinal sayfa', 'No original page URL is saved for this tab.': 'Bu sekme için orijinal sayfa URL’si kaydedilmemiş.', 'More bookmarks': 'Daha fazla yer imi', 'Show more bookmarks': 'Daha fazla yer imi göster', 'Name': 'Ad', 'Address': 'Adres', 'Export bookmarks': 'Yer imlerini dışa aktar', 'Import bookmarks': 'Yer imlerini içe aktar', 'Website': 'Web sitesi', 'Permission': 'İzin', 'Decision': 'Karar', 'Action': 'İşlem', 'Blocking strength:': 'Engelleme gücü:', 'Protection level:': 'Koruma düzeyi:', 'File no longer present': 'Dosya artık mevcut değil', 'Cancelled': 'İptal edildi', 'Failed': 'Başarısız', 'Interrupted': 'Kesintiye uğradı', 'Ⅱ Pause': 'Ⅱ Duraklat', 'Download security warning': 'İndirme güvenlik uyarısı', 'This file may be dangerous': 'Bu dosya tehlikeli olabilir', 'Do not show this security warning again': 'Bu güvenlik uyarısını tekrar gösterme', 'Download anyway': 'Yine de indir', 'History cleared': 'Geçmiş temizlendi', 'The browsing history has been cleared.': 'Tarama geçmişi temizlendi.', 'Unlock password manager': 'Parola yöneticisinin kilidini aç', 'Master password:': 'Ana parola:', 'Set up password manager': 'Parola yöneticisini kur', 'Enter master password again:': 'Ana parolayı tekrar girin:', 'Look in:': 'Şurada ara:', 'File name:': 'Dosya adı:', 'File type:': 'Dosya türü:', 'Too short': 'Çok kısa', 'Please use at least 10 characters.': 'Lütfen en az 10 karakter kullanın.', 'Passwords do not match': 'Parolalar eşleşmiyor', 'The passwords do not match.': 'Parolalar eşleşmiyor.', 'Master password changed': 'Ana parola değiştirildi', 'Use at least 10 characters.': 'En az 10 karakter kullanın.', 'Export complete': 'Dışa aktarma tamamlandı', 'Import complete': 'İçe aktarma tamamlandı', 'No passwords stored': 'Kayıtlı parola yok', 'There are no saved passwords to delete.': 'Silinecek kayıtlı parola yok.', 'Delete all passwords': 'Tüm parolaları sil', 'Invalid input': 'Geçersiz giriş', 'Ask': 'Sor', 'User-Agent missing': 'User-Agent eksik', 'Cache cleared': 'Önbellek temizlendi', 'Cookies cleared': 'Çerezler temizlendi', 'Folder': 'Klasör', 'Delete folder': 'Klasörü sil', 'Bookmarks exported': 'Yer imleri dışa aktarıldı', 'Export': 'Dışa aktar', 'Bookmarks imported': 'Yer imleri içe aktarıldı', 'Import': 'İçe aktar', 'Remove': 'Kaldır', 'Clear all permissions': 'Tüm izinleri temizle', 'Total': 'Toplam', 'Download cancelled.': 'İndirme iptal edildi.', 'Download failed or cancelled.': 'İndirme başarısız oldu veya iptal edildi.', 'Incorrect password': 'Yanlış parola', 'Change failed': 'Değişiklik başarısız oldu', 'Export failed': 'Dışa aktarma başarısız oldu', 'Nothing to import': 'İçe aktarılacak bir şey yok', 'Import passwords': 'Parolaları içe aktar', 'Import failed': 'İçe aktarma başarısız oldu', 'Delete password': 'Parolayı sil', 'Really delete this saved login?': 'Bu kayıtlı giriş gerçekten silinsin mi?', 'Folder deleted': 'Klasör silindi', '▶ Resume': '▶ Devam et', 'Download': 'İndir', 'Unknown': 'Bilinmiyor', 'Download complete': 'İndirme tamamlandı', 'Error': 'Hata', 'Active': 'Etkin', 'Saved in:': 'Kaydedildiği yer:', 'Clipboard': 'Pano', 'Allow all cookies': 'Tüm çerezlere izin ver', 'Block third-party cookies': 'Üçüncü taraf çerezlerini engelle', 'Block all cookies': 'Tüm çerezleri engelle', 'Allow session cookies only': 'Yalnızca oturum çerezlerine izin ver', 'Strong': 'Güçlü', 'Very strong': 'Çok güçlü', 'Super strong': 'Süper güçlü', 'Mega strong': 'Son derece güçlü', 'Ultra strong': 'Ultra güçlü', 'Maximum': 'Maksimum', 'Standard': 'Standart', 'Small': 'Küçük', 'Medium': 'Orta', 'Large': 'Büyük', 'Very large': 'Çok büyük', 'Export encrypted vault': 'Şifreli kasayı dışa aktar', 'Import encrypted vault': 'Şifreli kasayı içe aktar', 'New': 'Yeni', 'Updated': 'Güncellendi', 'Save image as': 'Resmi farklı kaydet', 'Save page as': 'Sayfayı farklı kaydet', 'All files (*.*)': 'Tüm dosyalar (*.*)', 'Web page (*.mhtml)': 'Web sayfası (*.mhtml)', 'Do you really want to delete the entire browsing history?': 'Tüm tarama geçmişini gerçekten silmek istiyor musunuz?', 'Normal – leave websites unchanged': 'Normal – web sitelerini değiştirme', 'Gentle contrast': 'Hafif kontrast', 'Softer contrast': 'Daha yumuşak kontrast', 'Relaxed contrast': 'Rahat kontrast', 'Original – keep website colors': 'Orijinal – web sitesi renklerini koru', 'Black mode – black backgrounds': 'Siyah mod – siyah arka planlar', 'Custom block patterns (separate with semicolons):': 'Özel engelleme kalıpları (noktalı virgülle ayırın):', 'Whitelist domains (separate with semicolons):': 'İzin verilen alan adları (noktalı virgülle ayırın):', 'The download has finished:': 'İndirme tamamlandı:', ' items': ' öğe', ' matches': ' eşleşme'}

TURKISH_UI.update({'The ad blocker filters known advertising and tracking domains. Higher levels block more, but may affect some websites.': 'Reklam engelleyici, bilinen reklam ve izleme alan adlarını filtreler. Daha yüksek düzeyler daha fazlasını engeller ancak bazı web sitelerini etkileyebilir.', 'Google translates the whole webpage. MyMemory translates visible text sections and has a free daily limit.': 'Google tüm web sayfasını çevirir. MyMemory görünür metin bölümlerini çevirir ve günlük ücretsiz kullanım sınırı vardır.', 'LunaSurfer vault (*.lsv);;All files (*)': 'LunaSurfer kasası (*.lsv);;Tüm dosyalar (*)', 'Do you really want to clear all browser data?\n\nHistory, cache, cookies, sign-in sessions, Local Storage, IndexedDB and other website data will be removed. You will be signed out of websites.\n\nBookmarks and saved passwords will be kept. The full cleanup will finish the next time LunaSurfer starts.': 'Tüm tarayıcı verilerini gerçekten temizlemek istiyor musunuz?\n\nGeçmiş, önbellek, çerezler, oturum açma oturumları, Local Storage, IndexedDB ve diğer web sitesi verileri kaldırılacaktır. Web sitelerinden çıkış yapacaksınız.\n\nYer imleri ve kayıtlı parolalar korunacaktır. Temizlik, LunaSurfer bir sonraki başlatıldığında tamamlanacaktır.', 'Standard: canvas, audio and basic hardware protection. Strong: additionally masks WebGL identifiers. Maximum: additional hardware and browser client-hint protection. Changes apply immediately; no restart is required.': 'Standart: canvas, ses ve temel donanım koruması. Güçlü: ayrıca WebGL tanımlayıcılarını maskeler. Maksimum: ek donanım ve tarayıcı Client Hints koruması sağlar. Değişiklikler hemen uygulanır; yeniden başlatma gerekmez.', 'The User-Agent changes the browser identification, not the browser engine or its capabilities. With fingerprint protection enabled, Client Hints are reduced to match the Chromium version.': 'User-Agent, tarayıcı motorunu veya yeteneklerini değil, tarayıcı tanımlamasını değiştirir. Parmak izi koruması açıkken Client Hints, Chromium sürümüyle eşleşecek şekilde azaltılır.', 'When disabled, LunaSurfer asks for the master password only when you focus a login field.': 'Devre dışı bırakıldığında LunaSurfer ana parolayı yalnızca bir giriş alanına odaklandığınızda ister.', 'Delete all saved website logins; the master password remains': 'Kaydedilmiş tüm web sitesi girişlerini sil; ana parola korunur', 'Manage saved permission decisions for individual websites': 'Her web sitesi için kaydedilmiş izin kararlarını yönet', 'Do you really want to clear the browser cache?': 'Tarayıcı önbelleğini gerçekten temizlemek istiyor musunuz?', 'Browser data cleared; full cleanup will finish after restart.': 'Tarayıcı verileri temizlendi; tam temizlik yeniden başlatmadan sonra tamamlanacak.', 'Browser data is being cleared. Please restart LunaSurfer to remove all stored website data completely. Bookmarks and saved passwords will be kept.': 'Tarayıcı verileri temizleniyor. Kaydedilmiş tüm web sitesi verilerini tamamen kaldırmak için lütfen LunaSurfer’ı yeniden başlatın. Yer imleri ve kayıtlı parolalar korunacaktır.', 'Do you really want to delete all stored cookies?': 'Kaydedilmiş tüm çerezleri gerçekten silmek istiyor musunuz?', 'Provider: MyMemory – starting translation …': 'Sağlayıcı: MyMemory – çeviri başlatılıyor…', 'Provider: Google Translate – loading whole webpage …': 'Sağlayıcı: Google Translate – tüm web sayfası yükleniyor…', 'This file can run programs or scripts. Only download it if you trust the source.': 'Bu dosya program veya betik çalıştırabilir. Yalnızca kaynağa güveniyorsanız indirin.', 'The vault has been re-encrypted with the new master password. Keep it safe; it cannot be recovered.': 'Kasa yeni ana parola ile yeniden şifrelendi. Parolayı güvenli tutun; kaybolursa kurtarılamaz.', 'The vault was exported in encrypted form. Keep the export file and export password separately.': 'Kasa şifrelenmiş biçimde dışa aktarıldı. Dışa aktarma dosyasını ve parolasını ayrı yerlerde saklayın.', 'Do you really want to permanently delete ALL saved website logins? The master password will remain.': 'KAYITLI TÜM web sitesi girişlerini kalıcı olarak silmek istiyor musunuz? Ana parola korunacaktır.', 'Enter a valid website address, username and password.': 'Geçerli bir web sitesi adresi, kullanıcı adı ve parola girin.', 'Enter a complete User-Agent or select another mode.': 'Tam bir User-Agent girin veya başka bir mod seçin.', 'The browser cache has been cleared.': 'Tarayıcı önbelleği temizlendi.', 'All stored cookies have been cleared.': 'Kaydedilmiş tüm çerezler temizlendi.', 'MyMemory could not translate the page. Check connection or daily quota.': 'MyMemory sayfayı çeviremedi. Bağlantınızı veya günlük kotayı kontrol edin.', 'Really delete this folder and all bookmarks inside it?': 'Bu klasör ve içindeki tüm yer imleri gerçekten silinsin mi?', 'Bookmarks were exported, including their folder structure.': 'Yer imleri klasör yapılarıyla birlikte dışa aktarıldı.', 'Do you really want to clear all saved website permissions?': 'Kaydedilmiş tüm web sitesi izinlerini gerçekten temizlemek istiyor musunuz?', 'Download source: ': 'İndirme kaynağı: ', 'The current master password is incorrect or the vault is damaged.': 'Geçerli ana parola yanlış veya kasa hasarlı.', 'The export contains no valid logins.': 'Dışa aktarma dosyasında geçerli giriş bilgisi yok.', 'Translation provider applied immediately: ': 'Çeviri sağlayıcısı hemen uygulandı: ', 'Qt 6 + QtWebEngine with selectable light/dark website appearance and optional Widevine CDM integration.': 'Seçilebilir açık/koyu web sitesi görünümüne ve isteğe bağlı Widevine CDM entegrasyonuna sahip Qt 6 + QtWebEngine.', ' text sections translated.': ' metin bölümü çevrildi.', 'No bookmarks found in the selected file.': 'Seçilen dosyada yer imi bulunamadı.', 'The master password is incorrect or the vault is damaged.': 'Ana parola yanlış veya kasa hasarlı.', 'Incorrect export password or damaged export file.': 'Dışa aktarma parolası yanlış veya dışa aktarma dosyası hasarlı.', 'No custom User-Agent entered yet': 'Henüz özel User-Agent girilmedi', 'Could not refresh translation menu: ': 'Çeviri menüsü yenilenemedi: ', 'MyMemory: ': 'MyMemory: ', 'The folder could not be deleted.': 'Klasör silinemedi.'})

POLISH_UI = {'Manage bookmarks': 'Zarządzaj zakładkami', '» More': '» Więcej', 'Clear all browser data': 'Wyczyść wszystkie dane przeglądarki', 'Find on this page': 'Znajdź na tej stronie', 'Matches 0 of 0': 'Wyniki: 0 z 0', 'Previous match': 'Poprzedni wynik', 'Next match': 'Następny wynik', 'Close find bar': 'Zamknij pasek wyszukiwania', 'Developer tools': 'Narzędzia deweloperskie', 'Back': 'Wstecz', 'Forward': 'Dalej', 'Reload': 'Odśwież', 'Home': 'Strona główna', 'Enter address or search': 'Wpisz adres lub wyszukaj', 'Translate webpage': 'Przetłumacz stronę', 'Show original page': 'Pokaż oryginalną stronę', 'Add current page to bookmarks': 'Dodaj bieżącą stronę do zakładek', 'Unlock password manager – autofill saved logins (Ctrl+Shift+L)': 'Odblokuj menedżer haseł – automatycznie wypełnij zapisane loginy (Ctrl+Shift+L)', 'Download manager': 'Menedżer pobierania', 'Protection & privacy': 'Ochrona i prywatność', 'New tab': 'Nowa karta', 'Menu': 'Menu', 'Bookmarks': 'Zakładki', 'History': 'Historia', 'Open downloads folder': 'Otwórz folder pobierania', 'Settings': 'Ustawienia', 'User guide': 'Podręcznik użytkownika', 'Developer tools (F12)': 'Narzędzia deweloperskie (F12)', 'About LunaSurfer': 'O programie LunaSurfer', 'Quit': 'Zakończ', 'Bookmarks bar': 'Pasek zakładek', 'Ad blocker': 'Blokowanie reklam', 'Ready': 'Gotowe', 'Loading translated webpage …': 'Ładowanie przetłumaczonej strony…', 'View and manage bookmarks': 'Wyświetlaj i zarządzaj zakładkami', 'Open': 'Otwórz', 'Edit bookmark…': 'Edytuj zakładkę…', 'Delete bookmark': 'Usuń zakładkę', 'Edit bookmark': 'Edytuj zakładkę', 'Name:': 'Nazwa:', 'Address:': 'Adres:', 'Bookmark changed': 'Zakładka została zmieniona', 'Really delete this bookmark?': 'Czy na pewno usunąć tę zakładkę?', 'Bookmark deleted': 'Zakładka została usunięta', 'Your bookmarks': 'Twoje zakładki', 'Expand folders, search entries and manage them directly.': 'Rozwijaj foldery, wyszukuj wpisy i zarządzaj nimi bezpośrednio.', 'Search bookmarks or addresses …': 'Szukaj zakładek lub adresów…', 'Edit…': 'Edytuj…', 'Delete': 'Usuń', 'Import…': 'Importuj…', 'Export…': 'Eksportuj…', 'Close': 'Zamknij', 'Protection settings: ad blocker and fingerprint': 'Ustawienia ochrony: blokowanie reklam i ochrona przed fingerprintingiem', 'Saved website permissions': 'Zapisane uprawnienia witryn', 'Change or remove remembered decisions for each website. Changes are saved immediately.': 'Zmieniaj lub usuwaj zapamiętane decyzje dla poszczególnych witryn. Zmiany są zapisywane natychmiast.', 'Camera': 'Aparat', 'Microphone': 'Mikrofon', 'Location': 'Lokalizacja', 'Notifications': 'Powiadomienia', 'Clear all saved permissions': 'Wyczyść wszystkie zapisane uprawnienia', 'Enable ad blocker': 'Włącz blokowanie reklam', 'The ad blocker filters known advertising and tracking domains. Higher levels block more, but may affect some websites.': 'Blokowanie reklam filtruje znane domeny reklamowe i śledzące. Wyższe poziomy blokują więcej, ale mogą wpływać na działanie niektórych witryn.', 'Enable fingerprint protection': 'Włącz ochronę przed fingerprintingiem', 'Fingerprint protection': 'Ochrona przed fingerprintingiem', 'Save': 'Zapisz', 'Cancel': 'Anuluj', 'Download Manager': 'Menedżer pobierania', 'Downloads': 'Pobrane pliki', 'All active and completed files in one place.': 'Wszystkie aktywne i zakończone pobrania w jednym miejscu.', 'All downloads': 'Wszystkie pobrania', 'In progress': 'W trakcie', 'Paused': 'Wstrzymane', 'Completed': 'Zakończone', 'Failed / cancelled': 'Nieudane / anulowane', 'Search filename or path …': 'Szukaj nazwy pliku lub ścieżki…', 'Cancel download': 'Anuluj pobieranie', 'Open file': 'Otwórz plik', 'Open folder': 'Otwórz folder', 'Remove entry': 'Usuń wpis', 'Clear completed': 'Wyczyść zakończone', 'Clear history': 'Wyczyść historię', 'Change master password': 'Zmień hasło główne', 'Current master password:': 'Obecne hasło główne:', 'New master password': 'Nowe hasło główne', 'New master password (at least 10 characters):': 'Nowe hasło główne (co najmniej 10 znaków):', 'Confirm master password': 'Potwierdź hasło główne', 'Enter the new master password again:': 'Wpisz ponownie nowe hasło główne:', 'Export password': 'Hasło eksportu', 'Choose a password for this export file (at least 10 characters):': 'Wybierz hasło do tego pliku eksportu (co najmniej 10 znaków):', 'Confirm export password': 'Potwierdź hasło eksportu', 'Enter the export password again:': 'Wpisz ponownie hasło eksportu:', 'Enter the password used to encrypt this export file:': 'Wpisz hasło użyte do zaszyfrowania tego pliku eksportu:', 'Passwords deleted': 'Hasła usunięte', 'All saved website passwords have been deleted. The master password remains.': 'Wszystkie zapisane hasła do witryn zostały usunięte. Hasło główne pozostało.', 'Login details': 'Dane logowania', 'Website (matched automatically)': 'Witryna (dopasowana automatycznie)', 'Username': 'Nazwa użytkownika', 'Password': 'Hasło', 'Show password': 'Pokaż hasło', 'Generate secure password': 'Wygeneruj bezpieczne hasło', 'LunaSurfer – Password manager': 'LunaSurfer – Menedżer haseł', 'Passwords are encrypted locally. The master password cannot be recovered.': 'Hasła są szyfrowane lokalnie. Nie można odzyskać hasła głównego.', 'Add': 'Dodaj', 'Edit': 'Edytuj', 'Export encrypted…': 'Eksportuj zaszyfrowane…', 'Import encrypted…': 'Importuj zaszyfrowane…', 'Change master password…': 'Zmień hasło główne…', 'Lock now': 'Zablokuj teraz', 'Update password?': 'Zaktualizować hasło?', 'Save password?': 'Zapisać hasło?', 'Login details saved securely.': 'Dane logowania zostały bezpiecznie zapisane.', 'LunaSurfer – User guide': 'LunaSurfer – Podręcznik użytkownika', 'Open homepage': 'Otwórz stronę startową', 'Restore last session': 'Przywróć ostatnią sesję', 'Open blank page': 'Otwórz pustą stronę', 'Google Translate (whole webpage)': 'Google Translate (cała strona)', 'MyMemory (no API key)': 'MyMemory (bez klucza API)', 'Google translates the whole webpage. MyMemory translates visible text sections and has a free daily limit.': 'Google tłumaczy całą stronę. MyMemory tłumaczy widoczne fragmenty tekstu i ma dzienny bezpłatny limit.', 'Dark': 'Ciemny', 'Light': 'Jasny', 'Dark (Standard)': 'Ciemny (standardowy)', 'Light (Classic)': 'Jasny (klasyczny)', 'Luna (Modern)': 'Luna (nowoczesny)', 'Graphite Blue (Elegant)': 'Grafitowy niebieski (elegancki)', 'Ocean (Teal Blue)': 'Ocean (turkusowy)', 'Show bookmarks bar below the address bar': 'Pokaż pasek zakładek pod paskiem adresu', 'Choose folder…': 'Wybierz folder…', 'Ask where to save each download': 'Pytaj, gdzie zapisać każde pobranie', 'Show security warning for executable downloads': 'Pokazuj ostrzeżenie dla pobieranych plików wykonywalnych', 'Show popup when a download finishes': 'Pokaż powiadomienie po zakończeniu pobierania', 'Block pop-ups': 'Blokuj wyskakujące okna', 'Enable JavaScript': 'Włącz JavaScript', 'Send Do Not Track request': 'Wysyłaj żądanie Do Not Track', 'Ask when closing a tab': 'Pytaj przed zamknięciem karty', 'Automatically clear history on exit': 'Automatycznie czyść historię przy zamykaniu', 'Automatically clear cache on exit': 'Automatycznie czyść pamięć podręczną przy zamykaniu', 'Automatically clear cookies on exit': 'Automatycznie usuwaj pliki cookie przy zamykaniu', 'Remember window size and position on exit': 'Zapamiętaj rozmiar i położenie okna przy zamykaniu', 'Use LunaSurfer as default browser': 'Używaj LunaSurfer jako domyślnej przeglądarki', 'General': 'Ogólne', 'Language:': 'Język:', 'On startup:': 'Przy uruchomieniu:', 'Homepage:': 'Strona startowa:', 'Search engine:': 'Wyszukiwarka:', 'Translation provider:': 'Usługa tłumaczenia:', 'Browser design:': 'Wygląd przeglądarki:', 'Website appearance:': 'Wygląd witryn:', 'Download folder:': 'Folder pobierania:', 'Default zoom:': 'Domyślne powiększenie:', 'Default font size:': 'Domyślny rozmiar czcionki:', 'Website readability:': 'Czytelność witryn:', 'Website colors:': 'Kolory witryn:', 'Security and permissions': 'Bezpieczeństwo i uprawnienia', 'Security:': 'Bezpieczeństwo:', 'User-Agent management': 'Zarządzanie User-Agent', 'Privacy default (reduced Chrome UA)': 'Domyślne ustawienie prywatności (skrócony Chrome UA)', 'Native browser User-Agent': 'Natywny User-Agent przeglądarki', 'Custom User-Agent': 'Niestandardowy User-Agent', 'Enter a complete User-Agent string…': 'Wpisz pełny ciąg User-Agent…', 'Mode:': 'Tryb:', 'Custom value:': 'Własna wartość:', 'Current:': 'Obecnie:', 'Offer to save passwords after successful sign-in': 'Proponuj zapisanie haseł po pomyślnym zalogowaniu', 'Password manager must be unlocked before autofill': 'Menedżer haseł musi być odblokowany przed automatycznym wypełnianiem', 'Open password manager…': 'Otwórz menedżer haseł…', 'Manage encrypted saved website logins': 'Zarządzaj zaszyfrowanymi zapisanymi danymi logowania', 'Delete all passwords…': 'Usuń wszystkie hasła…', 'Passwords:': 'Hasła:', 'Edit saved website permissions…': 'Edytuj zapisane uprawnienia witryn…', 'Website permissions:': 'Uprawnienia witryn:', 'Browser behavior:': 'Zachowanie przeglądarki:', 'Clear cache': 'Wyczyść pamięć podręczną', 'Clear cookies': 'Usuń pliki cookie', 'Clear everything': 'Wyczyść wszystko', 'Privacy and browser data': 'Prywatność i dane przeglądarki', 'Cookie mode:': 'Tryb plików cookie:', 'Browser data:': 'Dane przeglądarki:', 'Permission request': 'Żądanie uprawnienia', 'Remember this decision for this website': 'Zapamiętaj tę decyzję dla tej witryny', 'Allow': 'Zezwól', 'Block': 'Zablokuj', 'Yes': 'Tak', 'No': 'Nie', 'Close tab': 'Zamknij kartę', 'Do you really want to close this tab?': 'Czy na pewno chcesz zamknąć tę kartę?', 'Stop loading': 'Zatrzymaj ładowanie', 'Translation': 'Tłumaczenie', 'Open a regular webpage first.': 'Najpierw otwórz zwykłą stronę internetową.', 'Original page': 'Oryginalna strona', 'No original page URL is saved for this tab.': 'Dla tej karty nie zapisano adresu URL oryginalnej strony.', 'More bookmarks': 'Więcej zakładek', 'Show more bookmarks': 'Pokaż więcej zakładek', 'Name': 'Nazwa', 'Address': 'Adres', 'Export bookmarks': 'Eksportuj zakładki', 'Import bookmarks': 'Importuj zakładki', 'Website': 'Witryna', 'Permission': 'Uprawnienie', 'Decision': 'Decyzja', 'Action': 'Działanie', 'Blocking strength:': 'Poziom blokowania:', 'Protection level:': 'Poziom ochrony:', 'File no longer present': 'Plik już nie istnieje', 'Cancelled': 'Anulowano', 'Failed': 'Niepowodzenie', 'Interrupted': 'Przerwano', 'Ⅱ Pause': 'Ⅱ Wstrzymaj', 'Download security warning': 'Ostrzeżenie dotyczące bezpieczeństwa pobierania', 'This file may be dangerous': 'Ten plik może być niebezpieczny', 'Do not show this security warning again': 'Nie pokazuj ponownie tego ostrzeżenia', 'Download anyway': 'Pobierz mimo to', 'History cleared': 'Historia została wyczyszczona', 'The browsing history has been cleared.': 'Historia przeglądania została wyczyszczona.', 'Unlock password manager': 'Odblokuj menedżer haseł', 'Master password:': 'Hasło główne:', 'Set up password manager': 'Skonfiguruj menedżer haseł', 'Enter master password again:': 'Wpisz ponownie hasło główne:', 'Look in:': 'Szukaj w:', 'File name:': 'Nazwa pliku:', 'File type:': 'Typ pliku:', 'Too short': 'Zbyt krótkie', 'Please use at least 10 characters.': 'Użyj co najmniej 10 znaków.', 'Passwords do not match': 'Hasła nie są zgodne', 'The passwords do not match.': 'Hasła nie są zgodne.', 'Master password changed': 'Hasło główne zostało zmienione', 'Use at least 10 characters.': 'Użyj co najmniej 10 znaków.', 'Export complete': 'Eksport zakończony', 'Import complete': 'Import zakończony', 'No passwords stored': 'Brak zapisanych haseł', 'There are no saved passwords to delete.': 'Nie ma zapisanych haseł do usunięcia.', 'Delete all passwords': 'Usuń wszystkie hasła', 'Invalid input': 'Nieprawidłowe dane wejściowe', 'Ask': 'Pytaj', 'User-Agent missing': 'Brak User-Agent', 'Cache cleared': 'Pamięć podręczna została wyczyszczona', 'Cookies cleared': 'Pliki cookie zostały usunięte', 'Folder': 'Folder', 'Delete folder': 'Usuń folder', 'Bookmarks exported': 'Zakładki wyeksportowane', 'Export': 'Eksportuj', 'Bookmarks imported': 'Zakładki zaimportowane', 'Import': 'Importuj', 'Remove': 'Usuń', 'Clear all permissions': 'Wyczyść wszystkie uprawnienia', 'Total': 'Łącznie', 'Download cancelled.': 'Pobieranie anulowane.', 'Download failed or cancelled.': 'Pobieranie nie powiodło się lub zostało anulowane.', 'Incorrect password': 'Nieprawidłowe hasło', 'Change failed': 'Zmiana nie powiodła się', 'Export failed': 'Eksport nie powiódł się', 'Nothing to import': 'Brak danych do zaimportowania', 'Import passwords': 'Importuj hasła', 'Import failed': 'Import nie powiódł się', 'Delete password': 'Usuń hasło', 'Really delete this saved login?': 'Czy na pewno usunąć te zapisane dane logowania?', 'Folder deleted': 'Folder został usunięty', '▶ Resume': '▶ Wznów', 'Download': 'Pobierz', 'Unknown': 'Nieznany', 'Download complete': 'Pobieranie zakończone', 'Error': 'Błąd', 'Active': 'Aktywne', 'Saved in:': 'Zapisano w:', 'Clipboard': 'Schowek', 'Allow all cookies': 'Zezwalaj na wszystkie pliki cookie', 'Block third-party cookies': 'Blokuj pliki cookie innych firm', 'Block all cookies': 'Blokuj wszystkie pliki cookie', 'Allow session cookies only': 'Zezwalaj tylko na sesyjne pliki cookie', 'Strong': 'Silny', 'Very strong': 'Bardzo silny', 'Super strong': 'Bardzo mocny', 'Mega strong': 'Mega mocny', 'Ultra strong': 'Ultra mocny', 'Maximum': 'Maksymalny', 'Standard': 'Standardowy', 'Small': 'Mały', 'Medium': 'Średni', 'Large': 'Duży', 'Very large': 'Bardzo duży', 'Export encrypted vault': 'Eksportuj zaszyfrowany sejf', 'Import encrypted vault': 'Importuj zaszyfrowany sejf', 'New': 'Nowy', 'Updated': 'Zaktualizowano', 'Save image as': 'Zapisz obraz jako', 'Save page as': 'Zapisz stronę jako', 'All files (*.*)': 'Wszystkie pliki (*.*)', 'Web page (*.mhtml)': 'Strona internetowa (*.mhtml)', 'Do you really want to delete the entire browsing history?': 'Czy na pewno chcesz usunąć całą historię przeglądania?', 'LunaSurfer vault (*.lsv);;All files (*)': 'Sejf LunaSurfer (*.lsv);;Wszystkie pliki (*)', 'Normal – leave websites unchanged': 'Normalny – bez zmian na stronach', 'Gentle contrast': 'Delikatny kontrast', 'Softer contrast': 'Łagodniejszy kontrast', 'Relaxed contrast': 'Umiarkowany kontrast', 'Original – keep website colors': 'Oryginalny – zachowaj kolory witryny', 'Black mode – black backgrounds': 'Tryb czarny – czarne tła', 'Custom block patterns (separate with semicolons):': 'Niestandardowe wzorce blokowania (oddziel średnikami):', 'Whitelist domains (separate with semicolons):': 'Domeny na białej liście (oddziel średnikami):', 'The download has finished:': 'Pobieranie zostało zakończone:', ' items': ' elementów', ' matches': ' wyników', 'Do you really want to clear all browser data?\n\nHistory, cache, cookies, sign-in sessions, Local Storage, IndexedDB and other website data will be removed. You will be signed out of websites.\n\nBookmarks and saved passwords will be kept. The full cleanup will finish the next time LunaSurfer starts.': 'Czy na pewno chcesz wyczyścić wszystkie dane przeglądarki?\n\nHistoria, pamięć podręczna, pliki cookie, sesje logowania, Local Storage, IndexedDB i inne dane witryn zostaną usunięte. Nastąpi wylogowanie z witryn.\n\nZakładki i zapisane hasła zostaną zachowane. Pełne czyszczenie zakończy się przy następnym uruchomieniu LunaSurfer.', 'Standard: canvas, audio and basic hardware protection. Strong: additionally masks WebGL identifiers. Maximum: additional hardware and browser client-hint protection. Changes apply immediately; no restart is required.': 'Standardowy: ochrona canvas, audio i podstawowych danych sprzętowych. Silny: dodatkowo maskuje identyfikatory WebGL. Maksymalny: dodatkowa ochrona danych sprzętowych i Client Hints przeglądarki. Zmiany są stosowane natychmiast; ponowne uruchomienie nie jest wymagane.', 'The User-Agent changes the browser identification, not the browser engine or its capabilities. With fingerprint protection enabled, Client Hints are reduced to match the Chromium version.': 'User-Agent zmienia identyfikację przeglądarki, a nie silnik przeglądarki ani jego możliwości. Po włączeniu ochrony przed fingerprintingiem Client Hints są ograniczane tak, aby odpowiadały wersji Chromium.', 'When disabled, LunaSurfer asks for the master password only when you focus a login field.': 'Gdy ta opcja jest wyłączona, LunaSurfer pyta o hasło główne dopiero po wybraniu pola logowania.', 'Delete all saved website logins; the master password remains': 'Usuń wszystkie zapisane loginy do witryn; hasło główne pozostanie', 'Manage saved permission decisions for individual websites': 'Zarządzaj zapisanymi decyzjami o uprawnieniach dla poszczególnych witryn', 'Do you really want to clear the browser cache?': 'Czy na pewno chcesz wyczyścić pamięć podręczną przeglądarki?', 'Browser data cleared; full cleanup will finish after restart.': 'Dane przeglądarki wyczyszczono; pełne czyszczenie zakończy się po ponownym uruchomieniu.', 'Browser data is being cleared. Please restart LunaSurfer to remove all stored website data completely. Bookmarks and saved passwords will be kept.': 'Trwa czyszczenie danych przeglądarki. Uruchom ponownie LunaSurfer, aby całkowicie usunąć wszystkie zapisane dane witryn. Zakładki i zapisane hasła zostaną zachowane.', 'Do you really want to delete all stored cookies?': 'Czy na pewno chcesz usunąć wszystkie zapisane pliki cookie?', 'Provider: MyMemory – starting translation …': 'Usługa: MyMemory – rozpoczynanie tłumaczenia…', 'Provider: Google Translate – loading whole webpage …': 'Usługa: Google Translate – ładowanie całej strony…', 'This file can run programs or scripts. Only download it if you trust the source.': 'Ten plik może uruchamiać programy lub skrypty. Pobieraj go tylko wtedy, gdy ufasz źródłu.', 'The vault has been re-encrypted with the new master password. Keep it safe; it cannot be recovered.': 'Sejf został ponownie zaszyfrowany nowym hasłem głównym. Przechowuj je bezpiecznie; nie można go odzyskać.', 'The vault was exported in encrypted form. Keep the export file and export password separately.': 'Sejf wyeksportowano w postaci zaszyfrowanej. Przechowuj plik eksportu i hasło do eksportu oddzielnie.', 'Do you really want to permanently delete ALL saved website logins? The master password will remain.': 'Czy na pewno chcesz trwale usunąć WSZYSTKIE zapisane loginy do witryn? Hasło główne pozostanie.', 'Enter a valid website address, username and password.': 'Wpisz prawidłowy adres witryny, nazwę użytkownika i hasło.', 'Enter a complete User-Agent or select another mode.': 'Wpisz pełny User-Agent lub wybierz inny tryb.', 'The browser cache has been cleared.': 'Pamięć podręczna przeglądarki została wyczyszczona.', 'All stored cookies have been cleared.': 'Wszystkie zapisane pliki cookie zostały usunięte.', 'MyMemory could not translate the page. Check connection or daily quota.': 'MyMemory nie może przetłumaczyć strony. Sprawdź połączenie lub dzienny limit.', 'Really delete this folder and all bookmarks inside it?': 'Czy na pewno usunąć ten folder i wszystkie znajdujące się w nim zakładki?', 'Bookmarks were exported, including their folder structure.': 'Zakładki zostały wyeksportowane wraz ze strukturą folderów.', 'Do you really want to clear all saved website permissions?': 'Czy na pewno chcesz wyczyścić wszystkie zapisane uprawnienia witryn?', 'Download source: ': 'Źródło pobierania: ', 'The current master password is incorrect or the vault is damaged.': 'Obecne hasło główne jest nieprawidłowe lub sejf jest uszkodzony.', 'The export contains no valid logins.': 'Eksport nie zawiera prawidłowych danych logowania.', 'Translation provider applied immediately: ': 'Usługa tłumaczenia zastosowana natychmiast: ', 'Qt 6 + QtWebEngine with selectable light/dark website appearance and optional Widevine CDM integration.': 'Qt 6 + QtWebEngine z możliwością wyboru jasnego lub ciemnego wyglądu witryn i opcjonalną integracją Widevine CDM.', ' text sections translated.': ' przetłumaczonych fragmentów tekstu.', 'No bookmarks found in the selected file.': 'W wybranym pliku nie znaleziono zakładek.', 'The master password is incorrect or the vault is damaged.': 'Hasło główne jest nieprawidłowe lub sejf jest uszkodzony.', 'Incorrect export password or damaged export file.': 'Nieprawidłowe hasło eksportu lub uszkodzony plik eksportu.', 'No custom User-Agent entered yet': 'Nie wpisano jeszcze niestandardowego User-Agent', 'Could not refresh translation menu: ': 'Nie można odświeżyć menu tłumaczenia: ', 'MyMemory: ': 'MyMemory: ', 'The folder could not be deleted.': 'Nie można usunąć folderu.'}

POLISH_QT_BUTTON_TRANSLATIONS = {'OK': 'OK', 'Cancel': 'Anuluj', 'Yes': 'Tak', 'No': 'Nie', 'Apply': 'Zastosuj', 'Save': 'Zapisz', 'Open': 'Otwórz', 'Close': 'Zamknij', 'Discard': 'Odrzuć', 'Retry': 'Ponów próbę', 'Ignore': 'Ignoruj', 'Abort': 'Przerwij', 'Help': 'Pomoc', '&Yes': '&Tak', '&No': '&Nie', '&Open': '&Otwórz', '&Save': '&Zapisz', '&Cancel': '&Anuluj'}

ITALIAN_UI = {'Manage bookmarks': 'Gestisci segnalibri', '» More': '» Altro', 'Clear all browser data': 'Cancella tutti i dati del browser', 'Do you really want to clear all browser data?\n\nHistory, cache, cookies, sign-in sessions, Local Storage, IndexedDB and other website data will be removed. You will be signed out of websites.\n\nBookmarks and saved passwords will be kept. The full cleanup will finish the next time LunaSurfer starts.': 'Vuoi davvero cancellare tutti i dati del browser?\n\nLa cronologia, la cache, i cookie, le sessioni di accesso, il Local Storage, l’IndexedDB e gli altri dati dei siti web verranno rimossi. Verrai disconnesso dai siti web.\n\nI segnalibri e le password salvate verranno conservati. La pulizia completa terminerà al prossimo avvio di LunaSurfer.', 'Find on this page': 'Trova nella pagina', 'Matches 0 of 0': 'Corrispondenze: 0 di 0', 'Previous match': 'Risultato precedente', 'Next match': 'Risultato successivo', 'Close find bar': 'Chiudi barra di ricerca', 'Developer tools': 'Strumenti per sviluppatori', 'Back': 'Indietro', 'Forward': 'Avanti', 'Reload': 'Ricarica', 'Home': 'Home', 'Enter address or search': 'Inserisci un indirizzo o cerca', 'Translate webpage': 'Traduci pagina web', 'Show original page': 'Mostra pagina originale', 'Add current page to bookmarks': 'Aggiungi la pagina corrente ai segnalibri', 'Unlock password manager – autofill saved logins (Ctrl+Shift+L)': 'Sblocca il gestore password – compila automaticamente gli accessi salvati (Ctrl+Shift+L)', 'Download manager': 'Gestione download', 'Protection & privacy': 'Protezione e privacy', 'New tab': 'Nuova scheda', 'Menu': 'Menu', 'Bookmarks': 'Segnalibri', 'History': 'Cronologia', 'Open downloads folder': 'Apri cartella dei download', 'Settings': 'Impostazioni', 'User guide': 'Guida utente', 'Developer tools (F12)': 'Strumenti per sviluppatori (F12)', 'About LunaSurfer': 'Informazioni su LunaSurfer', 'Quit': 'Esci', 'Bookmarks bar': 'Barra dei segnalibri', 'Ad blocker': 'Blocco pubblicità', 'Ready': 'Pronto', 'Loading translated webpage …': 'Caricamento della pagina web tradotta…', 'View and manage bookmarks': 'Visualizza e gestisci i segnalibri', 'Open': 'Apri', 'Edit bookmark…': 'Modifica segnalibro…', 'Delete bookmark': 'Elimina segnalibro', 'Edit bookmark': 'Modifica segnalibro', 'Name:': 'Nome:', 'Address:': 'Indirizzo:', 'Bookmark changed': 'Segnalibro modificato', 'Really delete this bookmark?': 'Vuoi davvero eliminare questo segnalibro?', 'Bookmark deleted': 'Segnalibro eliminato', 'Your bookmarks': 'I tuoi segnalibri', 'Expand folders, search entries and manage them directly.': 'Espandi le cartelle, cerca le voci e gestiscile direttamente.', 'Search bookmarks or addresses …': 'Cerca segnalibri o indirizzi…', 'Edit…': 'Modifica…', 'Delete': 'Elimina', 'Import…': 'Importa…', 'Export…': 'Esporta…', 'Close': 'Chiudi', 'Protection settings: ad blocker and fingerprint': 'Impostazioni di protezione: blocco pubblicità e impronta digitale', 'Saved website permissions': 'Autorizzazioni dei siti web salvate', 'Change or remove remembered decisions for each website. Changes are saved immediately.': 'Modifica o rimuovi le decisioni memorizzate per ogni sito web. Le modifiche vengono salvate immediatamente.', 'Camera': 'Fotocamera', 'Microphone': 'Microfono', 'Location': 'Posizione', 'Notifications': 'Notifiche', 'Clear all saved permissions': 'Cancella tutte le autorizzazioni salvate', 'Enable ad blocker': 'Attiva il blocco pubblicità', 'The ad blocker filters known advertising and tracking domains. Higher levels block more, but may affect some websites.': 'Il blocco pubblicità filtra i domini noti per pubblicità e tracciamento. I livelli più elevati bloccano di più, ma possono influire su alcuni siti web.', 'Enable fingerprint protection': 'Attiva la protezione dell’impronta digitale', 'Standard: canvas, audio and basic hardware protection. Strong: additionally masks WebGL identifiers. Maximum: additional hardware and browser client-hint protection. Changes apply immediately; no restart is required.': 'Standard: protezione di canvas, audio e hardware di base. Forte: maschera anche gli identificatori WebGL. Massima: aggiunge la protezione dell’hardware e dei Client Hints del browser. Le modifiche vengono applicate subito; non è necessario riavviare.', 'Fingerprint protection': 'Protezione dell’impronta digitale', 'Save': 'Salva', 'Cancel': 'Annulla', 'Download Manager': 'Gestione download', 'Downloads': 'Download', 'All active and completed files in one place.': 'Tutti i file attivi e completati in un unico posto.', 'All downloads': 'Tutti i download', 'In progress': 'In corso', 'Paused': 'In pausa', 'Completed': 'Completati', 'Failed / cancelled': 'Non riusciti / annullati', 'Search filename or path …': 'Cerca nome file o percorso…', 'Cancel download': 'Annulla download', 'Open file': 'Apri file', 'Open folder': 'Apri cartella', 'Remove entry': 'Rimuovi voce', 'Clear completed': 'Cancella completati', 'Clear history': 'Cancella cronologia', 'Do you really want to delete the entire browsing history?': 'Vuoi davvero eliminare tutta la cronologia di navigazione?', 'LunaSurfer vault (*.lsv);;All files (*)': 'Archivio LunaSurfer (*.lsv);;Tutti i file (*)', 'Change master password': 'Cambia password principale', 'Current master password:': 'Password principale attuale:', 'New master password': 'Nuova password principale', 'New master password (at least 10 characters):': 'Nuova password principale (almeno 10 caratteri):', 'Confirm master password': 'Conferma password principale', 'Enter the new master password again:': 'Inserisci nuovamente la nuova password principale:', 'Export password': 'Password di esportazione', 'Choose a password for this export file (at least 10 characters):': 'Scegli una password per questo file di esportazione (almeno 10 caratteri):', 'Confirm export password': 'Conferma password di esportazione', 'Enter the export password again:': 'Inserisci nuovamente la password di esportazione:', 'Enter the password used to encrypt this export file:': 'Inserisci la password usata per crittografare questo file di esportazione:', 'Passwords deleted': 'Password eliminate', 'All saved website passwords have been deleted. The master password remains.': 'Tutte le password dei siti web salvate sono state eliminate. La password principale è rimasta invariata.', 'Login details': 'Dati di accesso', 'Website (matched automatically)': 'Sito web (rilevato automaticamente)', 'Username': 'Nome utente', 'Password': 'Password', 'Show password': 'Mostra password', 'Generate secure password': 'Genera password sicura', 'LunaSurfer – Password manager': 'LunaSurfer – Gestore password', 'Passwords are encrypted locally. The master password cannot be recovered.': 'Le password vengono crittografate localmente. La password principale non può essere recuperata.', 'Add': 'Aggiungi', 'Edit': 'Modifica', 'Export encrypted…': 'Esporta in forma crittografata…', 'Import encrypted…': 'Importa in forma crittografata…', 'Change master password…': 'Cambia password principale…', 'Lock now': 'Blocca ora', 'Update password?': 'Aggiornare la password?', 'Save password?': 'Salvare la password?', 'Login details saved securely.': 'Dati di accesso salvati in modo sicuro.', 'LunaSurfer – User guide': 'LunaSurfer – Guida utente', 'Open homepage': 'Apri pagina iniziale', 'Restore last session': 'Ripristina ultima sessione', 'Open blank page': 'Apri pagina vuota', 'Google Translate (whole webpage)': 'Google Translate (intera pagina web)', 'MyMemory (no API key)': 'MyMemory (senza chiave API)', 'Google translates the whole webpage. MyMemory translates visible text sections and has a free daily limit.': 'Google traduce l’intera pagina web. MyMemory traduce le sezioni di testo visibili e ha un limite giornaliero gratuito.', 'Dark': 'Scuro', 'Light': 'Chiaro', 'Dark (Standard)': 'Scuro (standard)', 'Light (Classic)': 'Chiaro (classico)', 'Luna (Modern)': 'Luna (moderno)', 'Graphite Blue (Elegant)': 'Grafite blu (elegante)', 'Ocean (Teal Blue)': 'Oceano (blu petrolio)', 'Show bookmarks bar below the address bar': 'Mostra la barra dei segnalibri sotto la barra degli indirizzi', 'Choose folder…': 'Scegli cartella…', 'Ask where to save each download': 'Chiedi dove salvare ogni download', 'Show security warning for executable downloads': 'Mostra un avviso di sicurezza per i download eseguibili', 'Show popup when a download finishes': 'Mostra una notifica al termine di un download', 'Normal – leave websites unchanged': 'Normale – lascia invariati i siti web', 'Gentle contrast': 'Contrasto delicato', 'Softer contrast': 'Contrasto più morbido', 'Relaxed contrast': 'Contrasto rilassato', 'Original – keep website colors': 'Originale – mantieni i colori dei siti web', 'Black mode – black backgrounds': 'Modalità nera – sfondi neri', 'Block pop-ups': 'Blocca finestre pop-up', 'Enable JavaScript': 'Attiva JavaScript', 'Send Do Not Track request': 'Invia richiesta Do Not Track', 'Ask when closing a tab': 'Chiedi prima di chiudere una scheda', 'Automatically clear history on exit': 'Cancella automaticamente la cronologia all’uscita', 'Automatically clear cache on exit': 'Cancella automaticamente la cache all’uscita', 'Automatically clear cookies on exit': 'Cancella automaticamente i cookie all’uscita', 'Remember window size and position on exit': 'Ricorda dimensioni e posizione della finestra all’uscita', 'Use LunaSurfer as default browser': 'Usa LunaSurfer come browser predefinito', 'General': 'Generale', 'Language:': 'Lingua:', 'On startup:': 'All’avvio:', 'Homepage:': 'Pagina iniziale:', 'Search engine:': 'Motore di ricerca:', 'Translation provider:': 'Servizio di traduzione:', 'Browser design:': 'Aspetto del browser:', 'Website appearance:': 'Aspetto dei siti web:', 'Download folder:': 'Cartella dei download:', 'Default zoom:': 'Zoom predefinito:', 'Default font size:': 'Dimensione carattere predefinita:', 'Website readability:': 'Leggibilità dei siti web:', 'Website colors:': 'Colori dei siti web:', 'Security and permissions': 'Sicurezza e autorizzazioni', 'Security:': 'Sicurezza:', 'User-Agent management': 'Gestione User-Agent', 'Privacy default (reduced Chrome UA)': 'Predefinito privacy (User-Agent Chrome ridotto)', 'Native browser User-Agent': 'User-Agent nativo del browser', 'Custom User-Agent': 'User-Agent personalizzato', 'Enter a complete User-Agent string…': 'Inserisci una stringa User-Agent completa…', 'The User-Agent changes the browser identification, not the browser engine or its capabilities. With fingerprint protection enabled, Client Hints are reduced to match the Chromium version.': 'Lo User-Agent modifica l’identificazione del browser, non il motore né le sue funzionalità. Con la protezione dell’impronta digitale attiva, i Client Hints vengono ridotti per corrispondere alla versione di Chromium.', 'Mode:': 'Modalità:', 'Custom value:': 'Valore personalizzato:', 'Current:': 'Attuale:', 'Offer to save passwords after successful sign-in': 'Proponi di salvare le password dopo un accesso riuscito', 'Password manager must be unlocked before autofill': 'Il gestore password deve essere sbloccato prima della compilazione automatica', 'When disabled, LunaSurfer asks for the master password only when you focus a login field.': 'Se disattivato, LunaSurfer chiede la password principale solo quando selezioni un campo di accesso.', 'Open password manager…': 'Apri gestore password…', 'Manage encrypted saved website logins': 'Gestisci gli accessi ai siti web salvati e crittografati', 'Delete all passwords…': 'Elimina tutte le password…', 'Delete all saved website logins; the master password remains': 'Elimina tutti gli accessi salvati ai siti web; la password principale rimane', 'Passwords:': 'Password:', 'Edit saved website permissions…': 'Modifica autorizzazioni dei siti web salvate…', 'Manage saved permission decisions for individual websites': 'Gestisci le decisioni di autorizzazione salvate per i singoli siti web', 'Website permissions:': 'Autorizzazioni dei siti web:', 'Browser behavior:': 'Comportamento del browser:', 'Clear cache': 'Cancella cache', 'Clear cookies': 'Cancella cookie', 'Clear everything': 'Cancella tutto', 'Privacy and browser data': 'Privacy e dati del browser', 'Cookie mode:': 'Modalità cookie:', 'Browser data:': 'Dati del browser:', 'Do you really want to clear the browser cache?': 'Vuoi davvero cancellare la cache del browser?', 'Browser data cleared; full cleanup will finish after restart.': 'Dati del browser cancellati; la pulizia completa terminerà dopo il riavvio.', 'Browser data is being cleared. Please restart LunaSurfer to remove all stored website data completely. Bookmarks and saved passwords will be kept.': 'I dati del browser vengono cancellati. Riavvia LunaSurfer per rimuovere completamente tutti i dati dei siti web memorizzati. I segnalibri e le password salvate verranno conservati.', 'Do you really want to delete all stored cookies?': 'Vuoi davvero eliminare tutti i cookie memorizzati?', 'Permission request': 'Richiesta di autorizzazione', 'Remember this decision for this website': 'Ricorda questa decisione per questo sito web', 'Allow': 'Consenti', 'Block': 'Blocca', 'Yes': 'Sì', 'No': 'No', 'Close tab': 'Chiudi scheda', 'Do you really want to close this tab?': 'Vuoi davvero chiudere questa scheda?', 'Stop loading': 'Interrompi caricamento', 'Provider: MyMemory – starting translation …': 'Servizio: MyMemory – avvio traduzione…', 'Provider: Google Translate – loading whole webpage …': 'Servizio: Google Translate – caricamento dell’intera pagina web…', 'Translation': 'Traduzione', 'Open a regular webpage first.': 'Apri prima una normale pagina web.', 'Original page': 'Pagina originale', 'No original page URL is saved for this tab.': 'Nessun URL della pagina originale è salvato per questa scheda.', 'More bookmarks': 'Altri segnalibri', 'Show more bookmarks': 'Mostra altri segnalibri', 'Name': 'Nome', 'Address': 'Indirizzo', 'Export bookmarks': 'Esporta segnalibri', 'Import bookmarks': 'Importa segnalibri', 'Website': 'Sito web', 'Permission': 'Autorizzazione', 'Decision': 'Decisione', 'Action': 'Azione', 'Blocking strength:': 'Intensità del blocco:', 'Custom block patterns (separate with semicolons):': 'Regole di blocco personalizzate (separate da punto e virgola):', 'Whitelist domains (separate with semicolons):': 'Domini consentiti (separati da punto e virgola):', 'Protection level:': 'Livello di protezione:', 'File no longer present': 'File non più presente', 'Cancelled': 'Annullato', 'Failed': 'Non riuscito', 'Interrupted': 'Interrotto', 'Ⅱ Pause': 'Ⅱ Pausa', 'Download security warning': 'Avviso di sicurezza del download', 'This file may be dangerous': 'Questo file potrebbe essere pericoloso', 'This file can run programs or scripts. Only download it if you trust the source.': 'Questo file può eseguire programmi o script. Scaricalo solo se ti fidi della fonte.', 'Do not show this security warning again': 'Non mostrare più questo avviso di sicurezza', 'Download anyway': 'Scarica comunque', 'History cleared': 'Cronologia cancellata', 'The browsing history has been cleared.': 'La cronologia di navigazione è stata cancellata.', 'Unlock password manager': 'Sblocca gestore password', 'Master password:': 'Password principale:', 'Set up password manager': 'Configura gestore password', 'Enter master password again:': 'Inserisci nuovamente la password principale:', 'Look in:': 'Cerca in:', 'File name:': 'Nome file:', 'File type:': 'Tipo di file:', 'Too short': 'Troppo corta', 'Please use at least 10 characters.': 'Usa almeno 10 caratteri.', 'Passwords do not match': 'Le password non corrispondono', 'The passwords do not match.': 'Le password non corrispondono.', 'Master password changed': 'Password principale modificata', 'The vault has been re-encrypted with the new master password. Keep it safe; it cannot be recovered.': 'L’archivio è stato nuovamente crittografato con la nuova password principale. Conservala con cura: non può essere recuperata.', 'Use at least 10 characters.': 'Usa almeno 10 caratteri.', 'Export complete': 'Esportazione completata', 'The vault was exported in encrypted form. Keep the export file and export password separately.': 'L’archivio è stato esportato in forma crittografata. Conserva separatamente il file esportato e la relativa password.', 'Import complete': 'Importazione completata', 'No passwords stored': 'Nessuna password memorizzata', 'There are no saved passwords to delete.': 'Non ci sono password salvate da eliminare.', 'Delete all passwords': 'Elimina tutte le password', 'Do you really want to permanently delete ALL saved website logins? The master password will remain.': 'Vuoi davvero eliminare definitivamente TUTTI gli accessi salvati ai siti web? La password principale rimarrà.', 'Invalid input': 'Input non valido', 'Enter a valid website address, username and password.': 'Inserisci un indirizzo web, un nome utente e una password validi.', 'Ask': 'Chiedi', 'User-Agent missing': 'User-Agent mancante', 'Enter a complete User-Agent or select another mode.': 'Inserisci uno User-Agent completo o seleziona un’altra modalità.', 'Cache cleared': 'Cache cancellata', 'The browser cache has been cleared.': 'La cache del browser è stata cancellata.', 'Cookies cleared': 'Cookie cancellati', 'All stored cookies have been cleared.': 'Tutti i cookie memorizzati sono stati cancellati.', 'Folder': 'Cartella', 'MyMemory could not translate the page. Check connection or daily quota.': 'MyMemory non è riuscito a tradurre la pagina. Controlla la connessione o il limite giornaliero.', 'Delete folder': 'Elimina cartella', 'Really delete this folder and all bookmarks inside it?': 'Vuoi davvero eliminare questa cartella e tutti i segnalibri al suo interno?', 'Bookmarks exported': 'Segnalibri esportati', 'Export': 'Esporta', 'Bookmarks were exported, including their folder structure.': 'I segnalibri sono stati esportati, inclusa la struttura delle cartelle.', 'Bookmarks imported': 'Segnalibri importati', 'Import': 'Importa', 'Remove': 'Rimuovi', 'Clear all permissions': 'Cancella tutte le autorizzazioni', 'Do you really want to clear all saved website permissions?': 'Vuoi davvero cancellare tutte le autorizzazioni dei siti web salvate?', 'Total': 'Totale', 'Download source: ': 'Origine del download: ', 'Download cancelled.': 'Download annullato.', 'Download failed or cancelled.': 'Download non riuscito o annullato.', 'Incorrect password': 'Password errata', 'The current master password is incorrect or the vault is damaged.': 'La password principale attuale non è corretta oppure l’archivio è danneggiato.', 'Change failed': 'Modifica non riuscita', 'Export failed': 'Esportazione non riuscita', 'Nothing to import': 'Nessun elemento da importare', 'The export contains no valid logins.': 'Il file di esportazione non contiene accessi validi.', 'Import passwords': 'Importa password', 'Import failed': 'Importazione non riuscita', 'Delete password': 'Elimina password', 'Really delete this saved login?': 'Vuoi davvero eliminare questo accesso salvato?', 'Translation provider applied immediately: ': 'Servizio di traduzione applicato immediatamente: ', 'Qt 6 + QtWebEngine with selectable light/dark website appearance and optional Widevine CDM integration.': 'Qt 6 + QtWebEngine con aspetto chiaro/scuro dei siti web selezionabile e integrazione opzionale di Widevine CDM.', ' text sections translated.': ' sezioni di testo tradotte.', 'Folder deleted': 'Cartella eliminata', 'No bookmarks found in the selected file.': 'Nessun segnalibro trovato nel file selezionato.', '▶ Resume': '▶ Riprendi', 'Download': 'Download', 'Unknown': 'Sconosciuto', 'Download complete': 'Download completato', 'The master password is incorrect or the vault is damaged.': 'La password principale non è corretta oppure l’archivio è danneggiato.', 'Incorrect export password or damaged export file.': 'Password di esportazione errata o file di esportazione danneggiato.', 'No custom User-Agent entered yet': 'Non è stato ancora inserito uno User-Agent personalizzato', 'Could not refresh translation menu: ': 'Impossibile aggiornare il menu di traduzione: ', 'MyMemory: ': 'MyMemory: ', 'Error': 'Errore', 'The folder could not be deleted.': 'Impossibile eliminare la cartella.', 'Active': 'Attivo', 'Saved in:': 'Salvato in:', 'Clipboard': 'Appunti', 'The download has finished:': 'Il download è terminato:', 'Allow all cookies': 'Consenti tutti i cookie', 'Block third-party cookies': 'Blocca i cookie di terze parti', 'Block all cookies': 'Blocca tutti i cookie', 'Allow session cookies only': 'Consenti solo i cookie di sessione'}



# French interface catalogue (0.3.49).
FRENCH_UI = {'Manage bookmarks': 'Gérer les favoris', '» More': '» Plus', 'Clear all browser data': 'Effacer toutes les données du navigateur', 'Do you really want to clear all browser data?\n\nHistory, cache, cookies, sign-in sessions, Local Storage, IndexedDB and other website data will be removed. You will be signed out of websites.\n\nBookmarks and saved passwords will be kept. The full cleanup will finish the next time LunaSurfer starts.': 'Voulez-vous vraiment effacer toutes les données du navigateur ?\n\nL’historique, le cache, les cookies, les sessions de connexion, le Local Storage, IndexedDB et les autres données des sites seront supprimés. Vous serez déconnecté des sites web.\n\nLes favoris et les mots de passe enregistrés seront conservés. Le nettoyage complet sera terminé au prochain démarrage de LunaSurfer.', 'Find on this page': 'Rechercher dans la page', 'Matches 0 of 0': 'Résultats : 0 sur 0', 'Previous match': 'Résultat précédent', 'Next match': 'Résultat suivant', 'Close find bar': 'Fermer la barre de recherche', 'Developer tools': 'Outils de développement', 'Back': 'Précédent', 'Forward': 'Suivant', 'Reload': 'Actualiser', 'Home': 'Accueil', 'Enter address or search': 'Saisir une adresse ou rechercher', 'Translate webpage': 'Traduire la page web', 'Show original page': 'Afficher la page d’origine', 'Add current page to bookmarks': 'Ajouter la page actuelle aux favoris', 'Unlock password manager – autofill saved logins (Ctrl+Shift+L)': 'Déverrouiller le gestionnaire de mots de passe – remplir les identifiants enregistrés (Ctrl+Maj+L)', 'Download manager': 'Gestionnaire de téléchargements', 'Protection & privacy': 'Protection et confidentialité', 'New tab': 'Nouvel onglet', 'Menu': 'Menu', 'Bookmarks': 'Favoris', 'History': 'Historique', 'Open downloads folder': 'Ouvrir le dossier des téléchargements', 'Settings': 'Paramètres', 'User guide': 'Guide d’utilisation', 'Developer tools (F12)': 'Outils de développement (F12)', 'About LunaSurfer': 'À propos de LunaSurfer', 'Quit': 'Quitter', 'Bookmarks bar': 'Barre des favoris', 'Ad blocker': 'Bloqueur de publicités', 'Ready': 'Prêt', 'Loading translated webpage …': 'Chargement de la page traduite…', 'View and manage bookmarks': 'Afficher et gérer les favoris', 'Open': 'Ouvrir', 'Edit bookmark…': 'Modifier le favori…', 'Delete bookmark': 'Supprimer le favori', 'Edit bookmark': 'Modifier le favori', 'Name:': 'Nom :', 'Address:': 'Adresse :', 'Bookmark changed': 'Favori modifié', 'Really delete this bookmark?': 'Voulez-vous vraiment supprimer ce favori ?', 'Bookmark deleted': 'Favori supprimé', 'Your bookmarks': 'Vos favoris', 'Expand folders, search entries and manage them directly.': 'Développez les dossiers, recherchez des éléments et gérez-les directement.', 'Search bookmarks or addresses …': 'Rechercher des favoris ou des adresses…', 'Edit…': 'Modifier…', 'Delete': 'Supprimer', 'Import…': 'Importer…', 'Export…': 'Exporter…', 'Close': 'Fermer', 'Protection settings: ad blocker and fingerprint': 'Paramètres de protection : bloqueur de publicités et empreinte numérique', 'Saved website permissions': 'Autorisations des sites web enregistrées', 'Change or remove remembered decisions for each website. Changes are saved immediately.': 'Modifiez ou supprimez les décisions mémorisées pour chaque site web. Les modifications sont enregistrées immédiatement.', 'Camera': 'Caméra', 'Microphone': 'Microphone', 'Location': 'Localisation', 'Notifications': 'Notifications', 'Clear all saved permissions': 'Effacer toutes les autorisations enregistrées', 'Enable ad blocker': 'Activer le bloqueur de publicités', 'The ad blocker filters known advertising and tracking domains. Higher levels block more, but may affect some websites.': 'Le bloqueur filtre les domaines connus pour la publicité et le suivi. Les niveaux supérieurs bloquent davantage de contenus, mais peuvent affecter certains sites web.', 'Enable fingerprint protection': 'Activer la protection contre l’empreinte numérique', 'Standard: canvas, audio and basic hardware protection. Strong: additionally masks WebGL identifiers. Maximum: additional hardware and browser client-hint protection. Changes apply immediately; no restart is required.': 'Standard : protection de Canvas, de l’audio et des informations matérielles de base. Renforcée : masque également les identifiants WebGL. Maximale : protège davantage les informations matérielles et les Client Hints du navigateur. Les modifications sont appliquées immédiatement, sans redémarrage.', 'Fingerprint protection': 'Protection contre l’empreinte numérique', 'Save': 'Enregistrer', 'Cancel': 'Annuler', 'Download Manager': 'Gestionnaire de téléchargements', 'Downloads': 'Téléchargements', 'All active and completed files in one place.': 'Tous les fichiers en cours et terminés au même endroit.', 'All downloads': 'Tous les téléchargements', 'In progress': 'En cours', 'Paused': 'En pause', 'Completed': 'Terminés', 'Failed / cancelled': 'Échoués / annulés', 'Search filename or path …': 'Rechercher un nom de fichier ou un chemin…', 'Cancel download': 'Annuler le téléchargement', 'Open file': 'Ouvrir le fichier', 'Open folder': 'Ouvrir le dossier', 'Remove entry': 'Supprimer l’entrée', 'Clear completed': 'Effacer les téléchargements terminés', 'Clear history': 'Effacer l’historique', 'Do you really want to delete the entire browsing history?': 'Voulez-vous vraiment supprimer tout l’historique de navigation ?', 'LunaSurfer vault (*.lsv);;All files (*)': 'Coffre LunaSurfer (*.lsv);;Tous les fichiers (*)', 'Change master password': 'Modifier le mot de passe principal', 'Current master password:': 'Mot de passe principal actuel :', 'New master password': 'Nouveau mot de passe principal', 'New master password (at least 10 characters):': 'Nouveau mot de passe principal (10 caractères minimum) :', 'Confirm master password': 'Confirmer le mot de passe principal', 'Enter the new master password again:': 'Saisissez à nouveau le nouveau mot de passe principal :', 'Export password': 'Mot de passe d’exportation', 'Choose a password for this export file (at least 10 characters):': 'Choisissez un mot de passe pour ce fichier d’exportation (10 caractères minimum) :', 'Confirm export password': 'Confirmer le mot de passe d’exportation', 'Enter the export password again:': 'Saisissez à nouveau le mot de passe d’exportation :', 'Enter the password used to encrypt this export file:': 'Saisissez le mot de passe utilisé pour chiffrer ce fichier d’exportation :', 'Passwords deleted': 'Mots de passe supprimés', 'All saved website passwords have been deleted. The master password remains.': 'Tous les mots de passe des sites web enregistrés ont été supprimés. Le mot de passe principal est conservé.', 'Login details': 'Identifiants de connexion', 'Website (matched automatically)': 'Site web (détecté automatiquement)', 'Username': 'Nom d’utilisateur', 'Password': 'Mot de passe', 'Show password': 'Afficher le mot de passe', 'Generate secure password': 'Générer un mot de passe sécurisé', 'LunaSurfer – Password manager': 'LunaSurfer – Gestionnaire de mots de passe', 'Passwords are encrypted locally. The master password cannot be recovered.': 'Les mots de passe sont chiffrés localement. Le mot de passe principal ne peut pas être récupéré.', 'Add': 'Ajouter', 'Edit': 'Modifier', 'Export encrypted…': 'Exporter de manière chiffrée…', 'Import encrypted…': 'Importer de manière chiffrée…', 'Change master password…': 'Modifier le mot de passe principal…', 'Lock now': 'Verrouiller maintenant', 'Update password?': 'Mettre à jour le mot de passe ?', 'Save password?': 'Enregistrer le mot de passe ?', 'Login details saved securely.': 'Les identifiants ont été enregistrés de manière sécurisée.', 'LunaSurfer – User guide': 'LunaSurfer – Guide d’utilisation', 'Open homepage': 'Ouvrir la page d’accueil', 'Restore last session': 'Restaurer la dernière session', 'Open blank page': 'Ouvrir une page vierge', 'Google Translate (whole webpage)': 'Google Traduction (page web entière)', 'MyMemory (no API key)': 'MyMemory (sans clé API)', 'Google translates the whole webpage. MyMemory translates visible text sections and has a free daily limit.': 'Google traduit la page web entière. MyMemory traduit les sections de texte visibles et dispose d’une limite quotidienne gratuite.', 'Dark': 'Sombre', 'Light': 'Clair', 'Dark (Standard)': 'Sombre (standard)', 'Light (Classic)': 'Clair (classique)', 'Luna (Modern)': 'Luna (moderne)', 'Graphite Blue (Elegant)': 'Bleu graphite (élégant)', 'Ocean (Teal Blue)': 'Océan (bleu sarcelle)', 'Show bookmarks bar below the address bar': 'Afficher la barre des favoris sous la barre d’adresse', 'Choose folder…': 'Choisir un dossier…', 'Ask where to save each download': 'Demander où enregistrer chaque téléchargement', 'Show security warning for executable downloads': 'Afficher un avertissement de sécurité pour les téléchargements exécutables', 'Show popup when a download finishes': 'Afficher une notification à la fin d’un téléchargement', 'Normal – leave websites unchanged': 'Normal – ne pas modifier les sites web', 'Gentle contrast': 'Contraste doux', 'Softer contrast': 'Contraste plus léger', 'Relaxed contrast': 'Contraste atténué', 'Original – keep website colors': 'Original – conserver les couleurs du site', 'Black mode – black backgrounds': 'Mode noir – arrière-plans noirs', 'Block pop-ups': 'Bloquer les fenêtres pop-up', 'Enable JavaScript': 'Activer JavaScript', 'Send Do Not Track request': 'Envoyer une demande Do Not Track', 'Ask when closing a tab': 'Demander confirmation à la fermeture d’un onglet', 'Automatically clear history on exit': 'Effacer automatiquement l’historique à la fermeture', 'Automatically clear cache on exit': 'Effacer automatiquement le cache à la fermeture', 'Automatically clear cookies on exit': 'Effacer automatiquement les cookies à la fermeture', 'Remember window size and position on exit': 'Mémoriser la taille et la position de la fenêtre à la fermeture', 'Use LunaSurfer as default browser': 'Utiliser LunaSurfer comme navigateur par défaut', 'General': 'Général', 'Language:': 'Langue :', 'On startup:': 'Au démarrage :', 'Homepage:': 'Page d’accueil :', 'Search engine:': 'Moteur de recherche :', 'Translation provider:': 'Service de traduction :', 'Browser design:': 'Apparence du navigateur :', 'Website appearance:': 'Apparence des sites web :', 'Download folder:': 'Dossier de téléchargement :', 'Default zoom:': 'Zoom par défaut :', 'Default font size:': 'Taille de police par défaut :', 'Website readability:': 'Lisibilité des sites web :', 'Website colors:': 'Couleurs des sites web :', 'Security and permissions': 'Sécurité et autorisations', 'Security:': 'Sécurité :', 'User-Agent management': 'Gestion du User-Agent', 'Privacy default (reduced Chrome UA)': 'Paramètre de confidentialité par défaut (User-Agent Chrome réduit)', 'Native browser User-Agent': 'User-Agent natif du navigateur', 'Custom User-Agent': 'User-Agent personnalisé', 'Enter a complete User-Agent string…': 'Saisissez une chaîne User-Agent complète…', 'The User-Agent changes the browser identification, not the browser engine or its capabilities. With fingerprint protection enabled, Client Hints are reduced to match the Chromium version.': 'Le User-Agent modifie l’identification du navigateur, pas son moteur ni ses fonctionnalités. Lorsque la protection contre l’empreinte numérique est activée, les Client Hints sont réduits pour correspondre à la version de Chromium.', 'Mode:': 'Mode :', 'Custom value:': 'Valeur personnalisée :', 'Current:': 'Actuel :', 'Offer to save passwords after successful sign-in': 'Proposer d’enregistrer les mots de passe après une connexion réussie', 'Password manager must be unlocked before autofill': 'Le gestionnaire de mots de passe doit être déverrouillé avant le remplissage automatique', 'When disabled, LunaSurfer asks for the master password only when you focus a login field.': 'Lorsque cette option est désactivée, LunaSurfer demande le mot de passe principal uniquement lorsque vous sélectionnez un champ de connexion.', 'Open password manager…': 'Ouvrir le gestionnaire de mots de passe…', 'Manage encrypted saved website logins': 'Gérer les identifiants de sites web enregistrés et chiffrés', 'Delete all passwords…': 'Supprimer tous les mots de passe…', 'Delete all saved website logins; the master password remains': 'Supprimer tous les identifiants enregistrés ; le mot de passe principal est conservé', 'Passwords:': 'Mots de passe :', 'Edit saved website permissions…': 'Modifier les autorisations enregistrées des sites web…', 'Manage saved permission decisions for individual websites': 'Gérer les décisions d’autorisation mémorisées pour chaque site web', 'Website permissions:': 'Autorisations des sites web :', 'Browser behavior:': 'Comportement du navigateur :', 'Clear cache': 'Effacer le cache', 'Clear cookies': 'Effacer les cookies', 'Clear everything': 'Tout effacer', 'Privacy and browser data': 'Confidentialité et données du navigateur', 'Cookie mode:': 'Mode des cookies :', 'Browser data:': 'Données du navigateur :', 'Do you really want to clear the browser cache?': 'Voulez-vous vraiment effacer le cache du navigateur ?', 'Browser data cleared; full cleanup will finish after restart.': 'Les données du navigateur ont été effacées ; le nettoyage complet sera terminé après le redémarrage.', 'Browser data is being cleared. Please restart LunaSurfer to remove all stored website data completely. Bookmarks and saved passwords will be kept.': 'Les données du navigateur sont en cours d’effacement. Veuillez redémarrer LunaSurfer pour supprimer complètement toutes les données des sites web. Les favoris et les mots de passe enregistrés seront conservés.', 'Do you really want to delete all stored cookies?': 'Voulez-vous vraiment supprimer tous les cookies enregistrés ?', 'Permission request': 'Demande d’autorisation', 'Remember this decision for this website': 'Mémoriser cette décision pour ce site web', 'Allow': 'Autoriser', 'Block': 'Bloquer', 'Yes': 'Oui', 'No': 'Non', 'Close tab': 'Fermer l’onglet', 'Do you really want to close this tab?': 'Voulez-vous vraiment fermer cet onglet ?', 'Stop loading': 'Arrêter le chargement', 'Provider: MyMemory – starting translation …': 'Service : MyMemory – démarrage de la traduction…', 'Provider: Google Translate – loading whole webpage …': 'Service : Google Traduction – chargement de la page web entière…', 'Translation': 'Traduction', 'Open a regular webpage first.': 'Ouvrez d’abord une page web classique.', 'Original page': 'Page d’origine', 'No original page URL is saved for this tab.': 'Aucune adresse de page d’origine n’est enregistrée pour cet onglet.', 'More bookmarks': 'Plus de favoris', 'Show more bookmarks': 'Afficher plus de favoris', 'Name': 'Nom', 'Address': 'Adresse', 'Export bookmarks': 'Exporter les favoris', 'Import bookmarks': 'Importer les favoris', 'Website': 'Site web', 'Permission': 'Autorisation', 'Decision': 'Décision', 'Action': 'Action', 'Blocking strength:': 'Intensité du blocage :', 'Custom block patterns (separate with semicolons):': 'Règles de blocage personnalisées (séparées par des points-virgules) :', 'Whitelist domains (separate with semicolons):': 'Domaines autorisés (séparés par des points-virgules) :', 'Protection level:': 'Niveau de protection :', 'File no longer present': 'Fichier introuvable', 'Cancelled': 'Annulé', 'Failed': 'Échec', 'Interrupted': 'Interrompu', 'Ⅱ Pause': 'Ⅱ Pause', 'Download security warning': 'Avertissement de sécurité du téléchargement', 'This file may be dangerous': 'Ce fichier peut être dangereux', 'This file can run programs or scripts. Only download it if you trust the source.': 'Ce fichier peut exécuter des programmes ou des scripts. Ne le téléchargez que si vous faites confiance à la source.', 'Do not show this security warning again': 'Ne plus afficher cet avertissement de sécurité', 'Download anyway': 'Télécharger quand même', 'History cleared': 'Historique effacé', 'The browsing history has been cleared.': 'L’historique de navigation a été effacé.', 'Unlock password manager': 'Déverrouiller le gestionnaire de mots de passe', 'Master password:': 'Mot de passe principal :', 'Set up password manager': 'Configurer le gestionnaire de mots de passe', 'Enter master password again:': 'Saisissez à nouveau le mot de passe principal :', 'Look in:': 'Regarder dans :', 'File name:': 'Nom du fichier :', 'File type:': 'Type de fichier :', 'Too short': 'Trop court', 'Please use at least 10 characters.': 'Veuillez utiliser au moins 10 caractères.', 'Passwords do not match': 'Les mots de passe ne correspondent pas', 'The passwords do not match.': 'Les mots de passe ne correspondent pas.', 'Master password changed': 'Mot de passe principal modifié', 'The vault has been re-encrypted with the new master password. Keep it safe; it cannot be recovered.': 'Le coffre a été rechiffré avec le nouveau mot de passe principal. Conservez-le précieusement : il ne peut pas être récupéré.', 'Use at least 10 characters.': 'Utilisez au moins 10 caractères.', 'Export complete': 'Exportation terminée', 'The vault was exported in encrypted form. Keep the export file and export password separately.': 'Le coffre a été exporté sous forme chiffrée. Conservez séparément le fichier exporté et son mot de passe.', 'Import complete': 'Importation terminée', 'No passwords stored': 'Aucun mot de passe enregistré', 'There are no saved passwords to delete.': 'Il n’y a aucun mot de passe enregistré à supprimer.', 'Delete all passwords': 'Supprimer tous les mots de passe', 'Do you really want to permanently delete ALL saved website logins? The master password will remain.': 'Voulez-vous vraiment supprimer définitivement TOUS les identifiants enregistrés des sites web ? Le mot de passe principal sera conservé.', 'Invalid input': 'Saisie invalide', 'Enter a valid website address, username and password.': 'Saisissez une adresse de site web, un nom d’utilisateur et un mot de passe valides.', 'Ask': 'Demander', 'User-Agent missing': 'User-Agent manquant', 'Enter a complete User-Agent or select another mode.': 'Saisissez un User-Agent complet ou sélectionnez un autre mode.', 'Cache cleared': 'Cache effacé', 'The browser cache has been cleared.': 'Le cache du navigateur a été effacé.', 'Cookies cleared': 'Cookies effacés', 'All stored cookies have been cleared.': 'Tous les cookies enregistrés ont été effacés.', 'Folder': 'Dossier', 'MyMemory could not translate the page. Check connection or daily quota.': 'MyMemory n’a pas pu traduire la page. Vérifiez la connexion ou le quota quotidien.', 'Delete folder': 'Supprimer le dossier', 'Really delete this folder and all bookmarks inside it?': 'Voulez-vous vraiment supprimer ce dossier et tous les favoris qu’il contient ?', 'Bookmarks exported': 'Favoris exportés', 'Export': 'Exporter', 'Bookmarks were exported, including their folder structure.': 'Les favoris ont été exportés, y compris leur structure de dossiers.', 'Bookmarks imported': 'Favoris importés', 'Import': 'Importer', 'Remove': 'Supprimer', 'Clear all permissions': 'Effacer toutes les autorisations', 'Do you really want to clear all saved website permissions?': 'Voulez-vous vraiment effacer toutes les autorisations enregistrées des sites web ?', 'Total': 'Total', 'Download source: ': 'Source du téléchargement : ', 'Download cancelled.': 'Téléchargement annulé.', 'Download failed or cancelled.': 'Téléchargement échoué ou annulé.', 'Incorrect password': 'Mot de passe incorrect', 'The current master password is incorrect or the vault is damaged.': 'Le mot de passe principal actuel est incorrect ou le coffre est endommagé.', 'Change failed': 'Échec de la modification', 'Export failed': 'Échec de l’exportation', 'Nothing to import': 'Rien à importer', 'The export contains no valid logins.': 'L’exportation ne contient aucun identifiant valide.', 'Import passwords': 'Importer des mots de passe', 'Import failed': 'Échec de l’importation', 'Delete password': 'Supprimer le mot de passe', 'Really delete this saved login?': 'Voulez-vous vraiment supprimer cet identifiant enregistré ?', 'Translation provider applied immediately: ': 'Service de traduction appliqué immédiatement : ', 'Qt 6 + QtWebEngine with selectable light/dark website appearance and optional Widevine CDM integration.': 'Qt 6 + QtWebEngine avec apparence claire ou sombre des sites web et intégration facultative de Widevine CDM.', ' text sections translated.': ' sections de texte traduites.', 'Folder deleted': 'Dossier supprimé', 'No bookmarks found in the selected file.': 'Aucun favori trouvé dans le fichier sélectionné.', '▶ Resume': '▶ Reprendre', 'Download': 'Téléchargement', 'Unknown': 'Inconnu', 'Download complete': 'Téléchargement terminé', 'The master password is incorrect or the vault is damaged.': 'Le mot de passe principal est incorrect ou le coffre est endommagé.', 'Incorrect export password or damaged export file.': 'Mot de passe d’exportation incorrect ou fichier d’exportation endommagé.', 'No custom User-Agent entered yet': 'Aucun User-Agent personnalisé n’a encore été saisi', 'Could not refresh translation menu: ': 'Impossible d’actualiser le menu de traduction : ', 'MyMemory: ': 'MyMemory : ', 'Error': 'Erreur', 'The folder could not be deleted.': 'Impossible de supprimer le dossier.', 'Active': 'Actif', 'Saved in:': 'Enregistré dans :', 'Clipboard': 'Presse-papiers', 'The download has finished:': 'Le téléchargement est terminé :', 'Allow all cookies': 'Autoriser tous les cookies', 'Block third-party cookies': 'Bloquer les cookies tiers', 'Block all cookies': 'Bloquer tous les cookies', 'Allow session cookies only': 'Autoriser uniquement les cookies de session', 'Strong': 'Renforcée', 'Very strong': 'Très renforcée', 'Super strong': 'Super renforcée', 'Mega strong': 'Méga renforcée', 'Ultra strong': 'Ultra renforcée', 'Maximum': 'Maximale', 'Standard': 'Standard', 'Small': 'Petite', 'Medium': 'Moyenne', 'Large': 'Grande', 'Very large': 'Très grande', 'Export encrypted vault': 'Exporter le coffre chiffré', 'Import encrypted vault': 'Importer le coffre chiffré', ' items': ' éléments', ' matches': ' résultats', 'New': 'Nouveau', 'Updated': 'Mis à jour'}

DUTCH_UI = {'Manage bookmarks': 'Bladwijzers beheren', '» More': '» Meer', 'Clear all browser data': 'Alle browsergegevens wissen', 'Do you really want to clear all browser data?\n\nHistory, cache, cookies, sign-in sessions, Local Storage, IndexedDB and other website data will be removed. You will be signed out of websites.\n\nBookmarks and saved passwords will be kept. The full cleanup will finish the next time LunaSurfer starts.': 'Wilt u echt alle browsergegevens wissen?\n\nDe geschiedenis, cache, cookies, aanmeldsessies, Local Storage, IndexedDB en andere websitegegevens worden verwijderd. U wordt afgemeld bij websites.\n\nBladwijzers en opgeslagen wachtwoorden blijven behouden. Het volledig opschonen wordt voltooid wanneer LunaSurfer opnieuw wordt gestart.', 'Find on this page': 'Zoeken op deze pagina', 'Matches 0 of 0': 'Resultaten 0 van 0', 'Previous match': 'Vorige resultaat', 'Next match': 'Volgende resultaat', 'Close find bar': 'Zoekbalk sluiten', 'Developer tools': 'Ontwikkelaarstools', 'Back': 'Terug', 'Forward': 'Verder', 'Reload': 'Herladen', 'Home': 'Startpagina', 'Enter address or search': 'Adres invoeren of zoeken', 'Translate webpage': 'Webpagina vertalen', 'Show original page': 'Originele pagina weergeven', 'Add current page to bookmarks': 'Huidige pagina aan bladwijzers toevoegen', 'Unlock password manager – autofill saved logins (Ctrl+Shift+L)': 'Wachtwoordbeheerder ontgrendelen – opgeslagen aanmeldgegevens automatisch invullen (Ctrl+Shift+L)', 'Download manager': 'Downloadbeheer', 'Protection & privacy': 'Bescherming en privacy', 'New tab': 'Nieuw tabblad', 'Menu': 'Menu', 'Bookmarks': 'Bladwijzers', 'History': 'Geschiedenis', 'Open downloads folder': 'Downloadmap openen', 'Settings': 'Instellingen', 'User guide': 'Gebruikershandleiding', 'Developer tools (F12)': 'Ontwikkelaarstools (F12)', 'About LunaSurfer': 'Over LunaSurfer', 'Quit': 'Afsluiten', 'Bookmarks bar': 'Bladwijzerbalk', 'Ad blocker': 'Advertentieblokkering', 'Ready': 'Gereed', 'Loading translated webpage …': 'Vertaalde webpagina laden …', 'View and manage bookmarks': 'Bladwijzers bekijken en beheren', 'Open': 'Openen', 'Edit bookmark…': 'Bladwijzer bewerken…', 'Delete bookmark': 'Bladwijzer verwijderen', 'Edit bookmark': 'Bladwijzer bewerken', 'Name:': 'Naam:', 'Address:': 'Adres:', 'Bookmark changed': 'Bladwijzer gewijzigd', 'Really delete this bookmark?': 'Deze bladwijzer echt verwijderen?', 'Bookmark deleted': 'Bladwijzer verwijderd', 'Your bookmarks': 'Uw bladwijzers', 'Expand folders, search entries and manage them directly.': 'Vouw mappen uit, zoek items en beheer ze direct.', 'Search bookmarks or addresses …': 'Zoek bladwijzers of adressen …', 'Edit…': 'Bewerken…', 'Delete': 'Verwijderen', 'Import…': 'Importeren…', 'Export…': 'Exporteren…', 'Close': 'Sluiten', 'Protection settings: ad blocker and fingerprint': 'Beschermingsinstellingen: advertentieblokkering en digitale vingerafdruk', 'Saved website permissions': 'Opgeslagen websitemachtigingen', 'Change or remove remembered decisions for each website. Changes are saved immediately.': 'Wijzig of verwijder onthouden keuzes per website. Wijzigingen worden direct opgeslagen.', 'Camera': 'Camera', 'Microphone': 'Microfoon', 'Location': 'Locatie', 'Notifications': 'Meldingen', 'Clear all saved permissions': 'Alle opgeslagen machtigingen wissen', 'Enable ad blocker': 'Advertentieblokkering inschakelen', 'The ad blocker filters known advertising and tracking domains. Higher levels block more, but may affect some websites.': 'De advertentieblokkering filtert bekende advertentie- en trackingdomeinen. Hogere niveaus blokkeren meer, maar kunnen sommige websites beïnvloeden.', 'Enable fingerprint protection': 'Bescherming tegen digitale vingerafdruk inschakelen', 'Standard: canvas, audio and basic hardware protection. Strong: additionally masks WebGL identifiers. Maximum: additional hardware and browser client-hint protection. Changes apply immediately; no restart is required.': 'Standaard: bescherming van canvas, audio en basis-hardwaregegevens. Sterk: maskeert ook WebGL-identificaties. Maximaal: extra bescherming van hardwaregegevens en browser-Client Hints. Wijzigingen worden direct toegepast; opnieuw starten is niet nodig.', 'Fingerprint protection': 'Bescherming tegen digitale vingerafdruk', 'Save': 'Opslaan', 'Cancel': 'Annuleren', 'Download Manager': 'Downloadbeheer', 'Downloads': 'Downloads', 'All active and completed files in one place.': 'Alle actieve en voltooide bestanden op één plek.', 'All downloads': 'Alle downloads', 'In progress': 'Bezig', 'Paused': 'Gepauzeerd', 'Completed': 'Voltooid', 'Failed / cancelled': 'Mislukt / geannuleerd', 'Search filename or path …': 'Zoek bestandsnaam of pad …', 'Cancel download': 'Download annuleren', 'Open file': 'Bestand openen', 'Open folder': 'Map openen', 'Remove entry': 'Item verwijderen', 'Clear completed': 'Voltooide downloads wissen', 'Clear history': 'Geschiedenis wissen', 'Do you really want to delete the entire browsing history?': 'Wilt u de volledige browsegeschiedenis echt verwijderen?', 'LunaSurfer vault (*.lsv);;All files (*)': 'LunaSurfer-kluis (*.lsv);;Alle bestanden (*)', 'Change master password': 'Hoofdwachtwoord wijzigen', 'Current master password:': 'Huidig hoofdwachtwoord:', 'New master password': 'Nieuw hoofdwachtwoord', 'New master password (at least 10 characters):': 'Nieuw hoofdwachtwoord (minimaal 10 tekens):', 'Confirm master password': 'Hoofdwachtwoord bevestigen', 'Enter the new master password again:': 'Voer het nieuwe hoofdwachtwoord opnieuw in:', 'Export password': 'Exportwachtwoord', 'Choose a password for this export file (at least 10 characters):': 'Kies een wachtwoord voor dit exportbestand (minimaal 10 tekens):', 'Confirm export password': 'Exportwachtwoord bevestigen', 'Enter the export password again:': 'Voer het exportwachtwoord opnieuw in:', 'Enter the password used to encrypt this export file:': 'Voer het wachtwoord in waarmee dit exportbestand is versleuteld:', 'Passwords deleted': 'Wachtwoorden verwijderd', 'All saved website passwords have been deleted. The master password remains.': 'Alle opgeslagen websitewachtwoorden zijn verwijderd. Het hoofdwachtwoord blijft behouden.', 'Login details': 'Aanmeldgegevens', 'Website (matched automatically)': 'Website (automatisch herkend)', 'Username': 'Gebruikersnaam', 'Password': 'Wachtwoord', 'Show password': 'Wachtwoord tonen', 'Generate secure password': 'Veilig wachtwoord genereren', 'LunaSurfer – Password manager': 'LunaSurfer – Wachtwoordbeheerder', 'Passwords are encrypted locally. The master password cannot be recovered.': 'Wachtwoorden worden lokaal versleuteld. Het hoofdwachtwoord kan niet worden hersteld.', 'Add': 'Toevoegen', 'Edit': 'Bewerken', 'Export encrypted…': 'Versleuteld exporteren…', 'Import encrypted…': 'Versleuteld importeren…', 'Change master password…': 'Hoofdwachtwoord wijzigen…', 'Lock now': 'Nu vergrendelen', 'Update password?': 'Wachtwoord bijwerken?', 'Save password?': 'Wachtwoord opslaan?', 'Login details saved securely.': 'Aanmeldgegevens zijn veilig opgeslagen.', 'LunaSurfer – User guide': 'LunaSurfer – Gebruikershandleiding', 'Open homepage': 'Startpagina openen', 'Restore last session': 'Vorige sessie herstellen', 'Open blank page': 'Lege pagina openen', 'Google Translate (whole webpage)': 'Google Translate (hele webpagina)', 'MyMemory (no API key)': 'MyMemory (geen API-sleutel)', 'Google translates the whole webpage. MyMemory translates visible text sections and has a free daily limit.': 'Google vertaalt de hele webpagina. MyMemory vertaalt zichtbare tekstdelen en heeft een dagelijkse gratis limiet.', 'Dark': 'Donker', 'Light': 'Licht', 'Dark (Standard)': 'Donker (standaard)', 'Light (Classic)': 'Licht (klassiek)', 'Luna (Modern)': 'Luna (modern)', 'Graphite Blue (Elegant)': 'Grafietblauw (elegant)', 'Ocean (Teal Blue)': 'Oceaan (blauwgroen)', 'Show bookmarks bar below the address bar': 'Bladwijzerbalk onder de adresbalk tonen', 'Choose folder…': 'Map kiezen…', 'Ask where to save each download': 'Bij elke download vragen waar deze moet worden opgeslagen', 'Show security warning for executable downloads': 'Beveiligingswaarschuwing tonen voor uitvoerbare downloads', 'Show popup when a download finishes': 'Melding tonen wanneer een download is voltooid', 'Normal – leave websites unchanged': 'Normaal – websites ongewijzigd laten', 'Gentle contrast': 'Zacht contrast', 'Softer contrast': 'Lichter contrast', 'Relaxed contrast': 'Rustig contrast', 'Original – keep website colors': 'Origineel – websitekleuren behouden', 'Black mode – black backgrounds': 'Zwarte modus – zwarte achtergronden', 'Block pop-ups': 'Pop-ups blokkeren', 'Enable JavaScript': 'JavaScript inschakelen', 'Send Do Not Track request': 'Do Not Track-verzoek verzenden', 'Ask when closing a tab': 'Bevestiging vragen bij het sluiten van een tabblad', 'Automatically clear history on exit': 'Geschiedenis automatisch wissen bij afsluiten', 'Automatically clear cache on exit': 'Cache automatisch wissen bij afsluiten', 'Automatically clear cookies on exit': 'Cookies automatisch wissen bij afsluiten', 'Remember window size and position on exit': 'Venstergrootte en -positie onthouden bij afsluiten', 'Use LunaSurfer as default browser': 'LunaSurfer als standaardbrowser gebruiken', 'General': 'Algemeen', 'Language:': 'Taal:', 'On startup:': 'Bij opstarten:', 'Homepage:': 'Startpagina:', 'Search engine:': 'Zoekmachine:', 'Translation provider:': 'Vertaalservice:', 'Browser design:': 'Browserweergave:', 'Website appearance:': 'Weergave van websites:', 'Download folder:': 'Downloadmap:', 'Default zoom:': 'Standaardzoom:', 'Default font size:': 'Standaardlettergrootte:', 'Website readability:': 'Leesbaarheid van websites:', 'Website colors:': 'Websitekleuren:', 'Security and permissions': 'Beveiliging en machtigingen', 'Security:': 'Beveiliging:', 'User-Agent management': 'User-Agent-beheer', 'Privacy default (reduced Chrome UA)': 'Privacystandaard (verkorte Chrome-User-Agent)', 'Native browser User-Agent': 'Native browser-User-Agent', 'Custom User-Agent': 'Aangepaste User-Agent', 'Enter a complete User-Agent string…': 'Voer een volledige User-Agent-tekenreeks in…', 'The User-Agent changes the browser identification, not the browser engine or its capabilities. With fingerprint protection enabled, Client Hints are reduced to match the Chromium version.': 'De User-Agent wijzigt de browseridentificatie, niet de browserengine of de mogelijkheden ervan. Wanneer bescherming tegen digitale vingerafdrukken is ingeschakeld, worden Client Hints beperkt zodat ze overeenkomen met de Chromium-versie.', 'Mode:': 'Modus:', 'Custom value:': 'Aangepaste waarde:', 'Current:': 'Huidig:', 'Offer to save passwords after successful sign-in': 'Aanbieden wachtwoorden op te slaan na geslaagde aanmelding', 'Password manager must be unlocked before autofill': 'Wachtwoordbeheerder moet ontgrendeld zijn vóór automatisch invullen', 'When disabled, LunaSurfer asks for the master password only when you focus a login field.': 'Als dit is uitgeschakeld, vraagt LunaSurfer alleen om het hoofdwachtwoord wanneer u een aanmeldveld selecteert.', 'Open password manager…': 'Wachtwoordbeheerder openen…', 'Manage encrypted saved website logins': 'Versleutelde opgeslagen website-aanmeldingen beheren', 'Delete all passwords…': 'Alle wachtwoorden verwijderen…', 'Delete all saved website logins; the master password remains': 'Alle opgeslagen website-aanmeldingen verwijderen; het hoofdwachtwoord blijft behouden', 'Passwords:': 'Wachtwoorden:', 'Edit saved website permissions…': 'Opgeslagen websitemachtigingen bewerken…', 'Manage saved permission decisions for individual websites': 'Opgeslagen machtigingskeuzes voor afzonderlijke websites beheren', 'Website permissions:': 'Websitemachtigingen:', 'Browser behavior:': 'Browsergedrag:', 'Clear cache': 'Cache wissen', 'Clear cookies': 'Cookies wissen', 'Clear everything': 'Alles wissen', 'Privacy and browser data': 'Privacy en browsergegevens', 'Cookie mode:': 'Cookiemodus:', 'Browser data:': 'Browsergegevens:', 'Do you really want to clear the browser cache?': 'Wilt u de browsercache echt wissen?', 'Browser data cleared; full cleanup will finish after restart.': 'Browsergegevens gewist; het volledig opschonen wordt na opnieuw starten voltooid.', 'Browser data is being cleared. Please restart LunaSurfer to remove all stored website data completely. Bookmarks and saved passwords will be kept.': 'Browsergegevens worden gewist. Start LunaSurfer opnieuw om alle opgeslagen websitegegevens volledig te verwijderen. Bladwijzers en opgeslagen wachtwoorden blijven behouden.', 'Do you really want to delete all stored cookies?': 'Wilt u alle opgeslagen cookies echt verwijderen?', 'Permission request': 'Toestemmingsverzoek', 'Remember this decision for this website': 'Deze keuze voor deze website onthouden', 'Allow': 'Toestaan', 'Block': 'Blokkeren', 'Yes': 'Ja', 'No': 'Nee', 'Close tab': 'Tabblad sluiten', 'Do you really want to close this tab?': 'Wilt u dit tabblad echt sluiten?', 'Stop loading': 'Laden stoppen', 'Provider: MyMemory – starting translation …': 'Service: MyMemory – vertaling starten …', 'Provider: Google Translate – loading whole webpage …': 'Service: Google Translate – volledige webpagina laden …', 'Translation': 'Vertaling', 'Open a regular webpage first.': 'Open eerst een gewone webpagina.', 'Original page': 'Originele pagina', 'No original page URL is saved for this tab.': 'Voor dit tabblad is geen URL van de originele pagina opgeslagen.', 'More bookmarks': 'Meer bladwijzers', 'Show more bookmarks': 'Meer bladwijzers tonen', 'Name': 'Naam', 'Address': 'Adres', 'Export bookmarks': 'Bladwijzers exporteren', 'Import bookmarks': 'Bladwijzers importeren', 'Website': 'Website', 'Permission': 'Machtiging', 'Decision': 'Beslissing', 'Action': 'Actie', 'Blocking strength:': 'Blokkeersterkte:', 'Custom block patterns (separate with semicolons):': "Aangepaste blokkeerregels (scheiden met puntkomma's):", 'Whitelist domains (separate with semicolons):': "Domeinen op de toelatingslijst (scheiden met puntkomma's):", 'Protection level:': 'Beschermingsniveau:', 'File no longer present': 'Bestand niet meer aanwezig', 'Cancelled': 'Geannuleerd', 'Failed': 'Mislukt', 'Interrupted': 'Onderbroken', 'Ⅱ Pause': 'Ⅱ Pauzeren', 'Download security warning': 'Beveiligingswaarschuwing download', 'This file may be dangerous': 'Dit bestand kan gevaarlijk zijn', 'This file can run programs or scripts. Only download it if you trust the source.': "Dit bestand kan programma's of scripts uitvoeren. Download het alleen als u de bron vertrouwt.", 'Do not show this security warning again': 'Deze beveiligingswaarschuwing niet meer tonen', 'Download anyway': 'Toch downloaden', 'History cleared': 'Geschiedenis gewist', 'The browsing history has been cleared.': 'De browsegeschiedenis is gewist.', 'Unlock password manager': 'Wachtwoordbeheerder ontgrendelen', 'Master password:': 'Hoofdwachtwoord:', 'Set up password manager': 'Wachtwoordbeheerder instellen', 'Enter master password again:': 'Voer het hoofdwachtwoord opnieuw in:', 'Look in:': 'Zoeken in:', 'File name:': 'Bestandsnaam:', 'File type:': 'Bestandstype:', 'Too short': 'Te kort', 'Please use at least 10 characters.': 'Gebruik minimaal 10 tekens.', 'Passwords do not match': 'Wachtwoorden komen niet overeen', 'The passwords do not match.': 'De wachtwoorden komen niet overeen.', 'Master password changed': 'Hoofdwachtwoord gewijzigd', 'The vault has been re-encrypted with the new master password. Keep it safe; it cannot be recovered.': 'De kluis is opnieuw versleuteld met het nieuwe hoofdwachtwoord. Bewaar het goed; het kan niet worden hersteld.', 'Use at least 10 characters.': 'Gebruik minimaal 10 tekens.', 'Export complete': 'Export voltooid', 'The vault was exported in encrypted form. Keep the export file and export password separately.': 'De kluis is versleuteld geëxporteerd. Bewaar het exportbestand en het exportwachtwoord afzonderlijk.', 'Import complete': 'Import voltooid', 'No passwords stored': 'Geen wachtwoorden opgeslagen', 'There are no saved passwords to delete.': 'Er zijn geen opgeslagen wachtwoorden om te verwijderen.', 'Delete all passwords': 'Alle wachtwoorden verwijderen', 'Do you really want to permanently delete ALL saved website logins? The master password will remain.': 'Wilt u echt ALLE opgeslagen website-aanmeldingen permanent verwijderen? Het hoofdwachtwoord blijft behouden.', 'Invalid input': 'Ongeldige invoer', 'Enter a valid website address, username and password.': 'Voer een geldig websiteadres, een gebruikersnaam en een wachtwoord in.', 'Ask': 'Vragen', 'User-Agent missing': 'User-Agent ontbreekt', 'Enter a complete User-Agent or select another mode.': 'Voer een volledige User-Agent in of kies een andere modus.', 'Cache cleared': 'Cache gewist', 'The browser cache has been cleared.': 'De browsercache is gewist.', 'Cookies cleared': 'Cookies gewist', 'All stored cookies have been cleared.': 'Alle opgeslagen cookies zijn gewist.', 'Folder': 'Map', 'MyMemory could not translate the page. Check connection or daily quota.': 'MyMemory kon de pagina niet vertalen. Controleer de verbinding of het dagelijkse quotum.', 'Delete folder': 'Map verwijderen', 'Really delete this folder and all bookmarks inside it?': 'Deze map en alle bladwijzers erin echt verwijderen?', 'Bookmarks exported': 'Bladwijzers geëxporteerd', 'Export': 'Exporteren', 'Bookmarks were exported, including their folder structure.': 'De bladwijzers zijn geëxporteerd, inclusief de mappenstructuur.', 'Bookmarks imported': 'Bladwijzers geïmporteerd', 'Import': 'Importeren', 'Remove': 'Verwijderen', 'Clear all permissions': 'Alle machtigingen wissen', 'Do you really want to clear all saved website permissions?': 'Wilt u alle opgeslagen websitemachtigingen echt wissen?', 'Total': 'Totaal', 'Download source: ': 'Downloadbron: ', 'Download cancelled.': 'Download geannuleerd.', 'Download failed or cancelled.': 'Download mislukt of geannuleerd.', 'Incorrect password': 'Onjuist wachtwoord', 'The current master password is incorrect or the vault is damaged.': 'Het huidige hoofdwachtwoord is onjuist of de kluis is beschadigd.', 'Change failed': 'Wijzigen mislukt', 'Export failed': 'Export mislukt', 'Nothing to import': 'Niets om te importeren', 'The export contains no valid logins.': 'De export bevat geen geldige aanmeldgegevens.', 'Import passwords': 'Wachtwoorden importeren', 'Import failed': 'Import mislukt', 'Delete password': 'Wachtwoord verwijderen', 'Really delete this saved login?': 'Deze opgeslagen aanmelding echt verwijderen?', 'Translation provider applied immediately: ': 'Vertaalservice direct toegepast: ', 'Qt 6 + QtWebEngine with selectable light/dark website appearance and optional Widevine CDM integration.': 'Qt 6 + QtWebEngine met instelbare lichte/donkere websiteweergave en optionele Widevine CDM-integratie.', ' text sections translated.': ' tekstdelen vertaald.', 'Folder deleted': 'Map verwijderd', 'No bookmarks found in the selected file.': 'Geen bladwijzers gevonden in het geselecteerde bestand.', '▶ Resume': '▶ Hervatten', 'Download': 'Download', 'Unknown': 'Onbekend', 'Download complete': 'Download voltooid', 'The master password is incorrect or the vault is damaged.': 'Het hoofdwachtwoord is onjuist of de kluis is beschadigd.', 'Incorrect export password or damaged export file.': 'Onjuist exportwachtwoord of beschadigd exportbestand.', 'No custom User-Agent entered yet': 'Er is nog geen aangepaste User-Agent ingevoerd', 'Could not refresh translation menu: ': 'Kan het vertaalmenu niet vernieuwen: ', 'MyMemory: ': 'MyMemory: ', 'Error': 'Fout', 'The folder could not be deleted.': 'De map kon niet worden verwijderd.', 'Active': 'Actief', 'Saved in:': 'Opgeslagen in:', 'Clipboard': 'Klembord', 'The download has finished:': 'De download is voltooid:', 'Allow all cookies': 'Alle cookies toestaan', 'Block third-party cookies': 'Cookies van derden blokkeren', 'Block all cookies': 'Alle cookies blokkeren', 'Allow session cookies only': 'Alleen sessiecookies toestaan', 'Strong': 'Sterk', 'Very strong': 'Zeer sterk', 'Super strong': 'Supersterk', 'Mega strong': 'Megasterk', 'Ultra strong': 'Ultrasterk', 'Maximum': 'Maximaal', 'Standard': 'Standaard', 'Small': 'Klein', 'Medium': 'Gemiddeld', 'Large': 'Groot', 'Very large': 'Zeer groot', 'Export encrypted vault': 'Versleutelde kluis exporteren', 'Import encrypted vault': 'Versleutelde kluis importeren', ' items': ' items', ' matches': ' resultaten', 'New': 'Nieuw', 'Updated': 'Bijgewerkt'}

# Italian translations for standard Qt dialog buttons.
QT_BUTTON_TRANSLATIONS = {
    "OK": "OK", "Cancel": "Annulla", "Yes": "Sì", "No": "No",
    "Apply": "Applica", "Save": "Salva", "Open": "Apri", "Close": "Chiudi",
    "Discard": "Scarta", "Retry": "Riprova", "Ignore": "Ignora",
    "Abort": "Interrompi", "Help": "Aiuto",
    "&Yes": "&Sì", "&No": "&No", "&Open": "&Apri",
    "&Save": "&Salva", "&Cancel": "&Annulla",
}


FRENCH_QT_BUTTON_TRANSLATIONS = {
    "OK": "OK", "Cancel": "Annuler", "Yes": "Oui", "No": "Non",
    "Apply": "Appliquer", "Save": "Enregistrer", "Open": "Ouvrir",
    "Close": "Fermer", "Discard": "Abandonner", "Retry": "Réessayer",
    "Ignore": "Ignorer", "Abort": "Abandonner", "Help": "Aide",
    "&Yes": "&Oui", "&No": "&Non", "&Open": "&Ouvrir",
    "&Save": "&Enregistrer", "&Cancel": "&Annuler",
}

class LunaFrenchQtTranslator(QTranslator):
    def translate(self, context, sourceText, disambiguation=None, n=-1):
        return FRENCH_QT_BUTTON_TRANSLATIONS.get(sourceText, "")

DUTCH_QT_BUTTON_TRANSLATIONS = {
    "OK": "OK", "Cancel": "Annuleren", "Yes": "Ja", "No": "Nee",
    "Apply": "Toepassen", "Save": "Opslaan", "Open": "Openen",
    "Close": "Sluiten", "Discard": "Verwerpen", "Retry": "Opnieuw proberen",
    "Ignore": "Negeren", "Abort": "Afbreken", "Help": "Help",
    "&Yes": "&Ja", "&No": "&Nee", "&Open": "&Openen",
    "&Save": "&Opslaan", "&Cancel": "&Annuleren",
}

class LunaDutchQtTranslator(QTranslator):
    def translate(self, context, sourceText, disambiguation=None, n=-1):
        return DUTCH_QT_BUTTON_TRANSLATIONS.get(sourceText, "")



class LunaItalianQtTranslator(QTranslator):
    def translate(self, context, sourceText, disambiguation=None, n=-1):
        return QT_BUTTON_TRANSLATIONS.get(sourceText, "")


TURKISH_QT_BUTTON_TRANSLATIONS = {
    "OK": "Tamam", "Cancel": "İptal", "Yes": "Evet", "No": "Hayır",
    "Apply": "Uygula", "Save": "Kaydet", "Open": "Aç", "Close": "Kapat",
    "Discard": "At", "Retry": "Yeniden dene", "Ignore": "Yoksay",
    "Abort": "Durdur", "Help": "Yardım", "&Yes": "&Evet", "&No": "&Hayır",
    "&Open": "&Aç", "&Save": "&Kaydet", "&Cancel": "&İptal",
}


PORTUGUESE_QT_BUTTON_TRANSLATIONS = {
    "OK": "OK", "Cancel": "Cancelar", "Yes": "Sim", "No": "Não",
    "Apply": "Aplicar", "Save": "Guardar", "Open": "Abrir", "Close": "Fechar",
    "Discard": "Descartar", "Retry": "Tentar novamente", "Ignore": "Ignorar",
    "Abort": "Anular", "Help": "Ajuda", "&Yes": "&Sim", "&No": "&Não",
    "&Open": "&Abrir", "&Save": "&Guardar", "&Cancel": "&Cancelar",
}

RUSSIAN_QT_BUTTON_TRANSLATIONS = {
    "OK": "ОК", "Cancel": "Отмена", "Yes": "Да", "No": "Нет",
    "Apply": "Применить", "Save": "Сохранить", "Open": "Открыть", "Close": "Закрыть",
    "Discard": "Отбросить", "Retry": "Повторить", "Ignore": "Игнорировать",
    "Abort": "Прервать", "Help": "Справка", "&Yes": "&Да", "&No": "&Нет",
    "&Open": "&Открыть", "&Save": "&Сохранить", "&Cancel": "&Отмена",
}
CHINESE_QT_BUTTON_TRANSLATIONS = {
    "OK": "确定", "Cancel": "取消", "Yes": "是", "No": "否",
    "Apply": "应用", "Save": "保存", "Open": "打开", "Close": "关闭",
    "Discard": "放弃", "Retry": "重试", "Ignore": "忽略", "Abort": "中止", "Help": "帮助",
    "&Yes": "是(&Y)", "&No": "否(&N)", "&Open": "打开(&O)", "&Save": "保存(&S)", "&Cancel": "取消(&C)",
}
JAPANESE_QT_BUTTON_TRANSLATIONS = {
    "OK": "OK", "Cancel": "キャンセル", "Yes": "はい", "No": "いいえ",
    "Apply": "適用", "Save": "保存", "Open": "開く", "Close": "閉じる",
    "Discard": "破棄", "Retry": "再試行", "Ignore": "無視",
    "Abort": "中止", "Help": "ヘルプ",
    "&Yes": "はい(&Y)", "&No": "いいえ(&N)", "&Open": "開く(&O)",
    "&Save": "保存(&S)", "&Cancel": "キャンセル(&C)",
}

GERMAN_QT_BUTTON_TRANSLATIONS = {
    "OK": "OK", "Cancel": "Abbrechen", "Yes": "Ja", "No": "Nein",
    "Apply": "Anwenden", "Save": "Speichern", "Open": "Öffnen", "Close": "Schließen",
    "Discard": "Verwerfen", "Retry": "Wiederholen", "Ignore": "Ignorieren",
    "Abort": "Abbrechen", "Help": "Hilfe",
    "&Yes": "&Ja", "&No": "&Nein", "&Open": "&Öffnen",
    "&Save": "&Speichern", "&Cancel": "&Abbrechen",
}

ENGLISH_QT_BUTTON_TRANSLATIONS = {
    "OK": "OK", "Cancel": "Cancel", "Yes": "Yes", "No": "No",
    "Apply": "Apply", "Save": "Save", "Open": "Open", "Close": "Close",
    "Discard": "Discard", "Retry": "Retry", "Ignore": "Ignore",
    "Abort": "Abort", "Help": "Help",
    "&Yes": "&Yes", "&No": "&No", "&Open": "&Open",
    "&Save": "&Save", "&Cancel": "&Cancel",
}


class LunaQtButtonTranslator(QTranslator):
    """Application-owned Qt button translations, refreshed when UI language changes."""
    def __init__(self, language, parent=None):
        super().__init__(parent)
        self.language = language

    def translate(self, context, sourceText, disambiguation=None, n=-1):
        catalogs = {
            "de": GERMAN_QT_BUTTON_TRANSLATIONS,
            "en": ENGLISH_QT_BUTTON_TRANSLATIONS,
            "fr": FRENCH_QT_BUTTON_TRANSLATIONS,
            "nl": DUTCH_QT_BUTTON_TRANSLATIONS,
            "it": QT_BUTTON_TRANSLATIONS,
            "es": SPANISH_QT_BUTTON_TRANSLATIONS,
            "pt": PORTUGUESE_QT_BUTTON_TRANSLATIONS,
            "pl": POLISH_QT_BUTTON_TRANSLATIONS,
            "tr": TURKISH_QT_BUTTON_TRANSLATIONS,
            "ru": RUSSIAN_QT_BUTTON_TRANSLATIONS,
            "ja": JAPANESE_QT_BUTTON_TRANSLATIONS,
            "zh-CN": CHINESE_QT_BUTTON_TRANSLATIONS,
        }
        return catalogs.get(self.language, {}).get(sourceText, "")


def refresh_qt_dialog_language(language):
    """Replace stale Qt translators so dialogs follow the currently selected language."""
    app = QApplication.instance()
    if app is None:
        return
    language = language if language in ("de", "en", "fr", "it", "nl", "es", "pt", "pl", "tr", "ru", "ja", "zh-CN") else "de"
    for attr in ("_luna_qt_base_translator", "_luna_qt_button_translator"):
        old = getattr(app, attr, None)
        if old is not None:
            app.removeTranslator(old)
            setattr(app, attr, None)
    qt_language = ("zh_CN" if language == "zh-CN" else language) if language in ("fr", "it", "nl", "es", "pt", "pl", "tr", "ru", "ja", "zh-CN") else ("en" if language == "en" else "de")
    base = QTranslator(app)
    translations_path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    if base.load(f"qtbase_{qt_language}", translations_path):
        app.installTranslator(base)
        app._luna_qt_base_translator = base
    buttons = LunaQtButtonTranslator(language, app)
    app.installTranslator(buttons)
    app._luna_qt_button_translator = buttons
    QLocale.setDefault(QLocale(qt_language))


class StoredDownload:
    """Read-only completed download restored from the persistent history."""
    def __init__(self, record):
        self._received = int(record.get("received", 0) or 0)
        self._total = int(record.get("total", self._received) or self._received)
    def isFinished(self): return True
    def receivedBytes(self): return self._received
    def totalBytes(self): return self._total
    def cancel(self): return None


class DownloadHistoryLoader(QThread):
    """Read the existing download-history file without blocking the GUI."""
    records_loaded = Signal(object)

    def __init__(self, path, parent=None):
        super().__init__(parent)
        self.path = pathlib.Path(path)
        self.records = []

    def run(self):
        records = read_json(self.path, [])
        self.records = records if isinstance(records, list) else []
        self.records_loaded.emit(self.records)


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
        language = self.window_ref.settings_data.get("language", "de")
        if language == "zh-CN":
            labels = ("撤销", "重做", "剪切", "复制", "粘贴", "删除", "全选")
        elif language == "ja":
            labels = ("元に戻す", "やり直す", "切り取り", "コピー", "貼り付け", "削除", "すべて選択")
        elif language == "ru":
            labels = ("Отменить", "Повторить", "Вырезать", "Копировать", "Вставить", "Удалить", "Выделить всё")
        elif language == "tr":
            labels = ("Geri al", "Yinele", "Kes", "Kopyala", "Yapıştır", "Sil", "Tümünü seç")
        elif language == "pl":
            labels = ("Cofnij", "Ponów", "Wytnij", "Kopiuj", "Wklej", "Usuń", "Zaznacz wszystko")
        elif language == "nl":
            labels = ("Ongedaan maken", "Opnieuw", "Knippen", "Kopiëren", "Plakken", "Verwijderen", "Alles selecteren")
        elif language == "fr":
            labels = ("Annuler", "Rétablir", "Couper", "Copier", "Coller", "Supprimer", "Tout sélectionner")
        elif language == "it":
            labels = ("Annulla", "Ripeti", "Taglia", "Copia", "Incolla", "Elimina", "Seleziona tutto")
        elif language == "pt":
            labels = ("Anular", "Refazer", "Cortar", "Copiar", "Colar", "Eliminar", "Selecionar tudo")
        elif language == "es":
            labels = ("Deshacer", "Rehacer", "Cortar", "Copiar", "Pegar", "Eliminar", "Seleccionar todo")
        elif language == "en":
            labels = ("Undo", "Redo", "Cut", "Copy", "Paste", "Delete", "Select All")
        else:
            labels = ("Rückgängig", "Wiederholen", "Ausschneiden", "Kopieren", "Einfügen", "Löschen", "Alles auswählen")
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




class PageFindLineEdit(QLineEdit):
    """Find-bar input: Enter/down = next match, Shift+Enter/up = previous."""
    def __init__(self, window):
        super().__init__()
        self.window_ref = window

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Up or (
            event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
            and event.modifiers() & Qt.KeyboardModifier.ShiftModifier
        ):
            self.window_ref.find_page_previous()
            event.accept()
            return
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Down):
            self.window_ref.find_page_next()
            event.accept()
            return
        super().keyPressEvent(event)


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
        mega_strong += [
            # Gaps identified by the Adblock Tester run: Adobe, Mixpanel,
            # Lucky Orange, Heap, Plausible/WordPress stats, Meta and Index Exchange.
            "adobedtm.com", "sstats.adobe.com", "mxpnl.com", "luckyorange.net",
            "heapanalytics.com", "plausible.io", "stats.wp.com", "an.facebook.com",
            "graph.facebook.com", "indexww.com"
        ]
        mega_url_patterns = [
            "facebook.com/tr", "/collect?", "/collect/", "/analytics", "/analytics/",
            "/tracking", "/tracking/", "/tracker", "/tracker/", "/telemetry", "/telemetry/",
            "/beacon", "/beacon/", "/pixel", "/pixel/", "/pageview", "/page-view",
            "/event?", "/events?", "/conversion", "/conversions", "/remarketing",
            "/adservice", "/adserver", "/ads/", "/ads?", "/advert/", "/advertising/",
            "utm_source=", "utm_medium=", "gclid=", "fbclid=", "msclkid=",
            "advice-ads.s3.amazonaws.com", "adtago.s3.amazonaws.com",
            "c.bing.com", "ads.microsoft.com", "adsdk.microsoft.com",
            "msadsscale.microsoft.com", "udcm.yahoo.com", "udc.yahoo.com",
            "adtech.yahooinc.com", "log.fc.yahoo.com", "partnerads.ysm.yahoo.com",
            "beap-bc.yahoo.com", "an.facebook.com",
            "graph.facebook.com", "js-sec.indexww.com", "upload.luckyorange.net",
            "cs.luckyorange.net", "settings.luckyorange.net", "cdn.mxpnl.com",
            "cdn.heapanalytics.com", "sstats.adobe.com",
            "pagead.js", "/widget/ads."
        ]
        # Ultra strong adds the complete host set used by the supplied Turtlecute
        # Ad Blocker Test report. Entries are exact hostnames (including subdomains),
        # not broad parent domains, to limit collateral breakage.
        ultra_strong = mega_strong + [
            "ad.doubleclick.net",
            "adc3-launch.adcolony.com",
            "adfox.yandex.ru",
            "adfstat.yandex.ru",
            "adm.hotjar.com",
            "ads-api.tiktok.com",
            "ads-api.twitter.com",
            "ads-sg.tiktok.com",
            "ads.linkedin.com",
            "ads.pinterest.com",
            "ads.tiktok.com",
            "ads.yahoo.com",
            "ads.youtube.com",
            "ads30.adcolony.com",
            "adserver.unityads.unity3d.com",
            "adservice.google.com",
            "adsfs.oppomobile.com",
            "adtago.s3.amazonaws.com",
            "adtech.yahooinc.com",
            "advice-ads.s3.amazonaws.com",
            "adx.ads.oppomobile.com",
            "afs.googlesyndication.com",
            "an.facebook.com",
            "analytics-api.samsunghealthcn.com",
            "analytics-sg.tiktok.com",
            "analytics.google.com",
            "analytics.pointdrive.linkedin.com",
            "analytics.query.yahoo.com",
            "analytics.s3.amazonaws.com",
            "analytics.tiktok.com",
            "analytics.yahoo.com",
            "analyticsengine.s3.amazonaws.com",
            "api-adservices.apple.com",
            "api.ad.xiaomi.com",
            "api.bugsnag.com",
            "api.luckyorange.com",
            "api.mouseflow.com",
            "app.bugsnag.com",
            "app.getsentry.com",
            "appmetrica.yandex.ru",
            "auction.unityads.unity3d.com",
            "bdapi-ads.realmemobile.com",
            "bdapi-in-ads.realmemobile.com",
            "books-analytics-events.apple.com",
            "browser.sentry-cdn.com",
            "business-api.tiktok.com",
            "careers.hotjar.com",
            "cdn-test.mouseflow.com",
            "cdn.luckyorange.com",
            "cdn.mouseflow.com",
            "ck.ads.oppomobile.com",
            "claritybt.freshmarketer.com",
            "click.googleanalytics.com",
            "click.oneplus.cn",
            "config.unityads.unity3d.com",
            "cs.luckyorange.net",
            "data.ads.oppomobile.com",
            "data.mistat.india.xiaomi.com",
            "data.mistat.rus.xiaomi.com",
            "data.mistat.xiaomi.com",
            "events.reddit.com",
            "events.redditmedia.com",
            "events3alt.adcolony.com",
            "extmaps-api.yandex.net",
            "freshmarketer.com",
            "fwtracks.freshmarketer.com",
            "gemini.yahoo.com",
            "geo.yahoo.com",
            "google-analytics.com",
            "grs.hicloud.com",
            "gtm.mouseflow.com",
            "iadsdk.apple.com",
            "identify.hotjar.com",
            "insights.hotjar.com",
            "iot-eu-logser.realme.com",
            "iot-logser.realme.com",
            "log.byteoversea.com",
            "log.fc.yahoo.com",
            "log.pinterest.com",
            "logbak.hicloud.com",
            "logservice.hicloud.com",
            "logservice1.hicloud.com",
            "luckyorange.com",
            "m.doubleclick.net",
            "mediavisor.doubleclick.net",
            "metrics.data.hicloud.com",
            "metrics.icloud.com",
            "metrics.mzstatic.com",
            "metrics2.data.hicloud.com",
            "metrika.yandex.ru",
            "mouseflow.com",
            "nmetrics.samsung.com",
            "notes-analytics-events.apple.com",
            "notify.bugsnag.com",
            "o2.mouseflow.com",
            "offerwall.yandex.net",
            "pagead2.googleadservices.com",
            "pagead2.googlesyndication.com",
            "partnerads.ysm.yahoo.com",
            "pixel.facebook.com",
            "realtime.luckyorange.com",
            "samsung-com.112.2o7.net",
            "samsungads.com",
            "script.hotjar.com",
            "sdkconfig.ad.intl.xiaomi.com",
            "sdkconfig.ad.xiaomi.com",
            "sessions.bugsnag.com",
            "settings.luckyorange.net",
            "smetrics.samsung.com",
            "ssl.google-analytics.com",
            "static.ads-twitter.com",
            "static.doubleclick.net",
            "static.media.net",
            "stats.g.doubleclick.net",
            "stats.wp.com",
            "surveys.hotjar.com",
            "tools.mouseflow.com",
            "tracking.rus.miui.com",
            "trk.pinterest.com",
            "udcm.yahoo.com",
            "upload.luckyorange.net",
            "w1.luckyorange.com",
            "wd.adcolony.com",
            "weather-analytics-events.apple.com",
            "webview.unityads.unity3d.com",
        ]
        # Ultra-only additions based on the weak categories in the 357-domain
        # report: video advertising, affiliate redirects, browser miners and
        # additional fingerprinting/telemetry endpoints. Exact hosts only.
        ultra_strong += [
            # Video advertising and ad delivery
            "pubads.g.doubleclick.net", "securepubads.g.doubleclick.net",
            "googleads.g.doubleclick.net", "video-ad-stats.googlesyndication.com",
            "tpc.googlesyndication.com", "s0.2mdn.net", "c.amazon-adsystem.com",
            "fls-na.amazon.com", "ads.stickyadstv.com", "video.unrulymedia.com",
            "ads.vidoomy.com", "ads.servebom.com", "ads.yieldmo.com",
            "adserver.adtech.de", "vast.yieldmo.com", "imasdk.googleapis.com",
            "imasdk.g.doubleclick.net", "pubads4kads.com", "adsafeprotected.com",
            # Affiliate and conversion redirect networks
            "click.linksynergy.com", "linksynergy.com", "track.adform.net",
            "clk.tradedoubler.com", "tradedoubler.com", "redirect.viglink.com",
            "api.viglink.com", "viglink.com", "skimlinks.com", "go.skimresources.com",
            "prf.hn", "t.cfjump.com", "track.flexlinks.com", "shareasale.com",
            "www.awin1.com", "www.affiliatewindow.com", "track.impact.com",
            "app.partnerize.com", "clickbank.net", "rakutenadvertising.com",
            "cj.com", "anrdoezrs.net", "jdoqwsz.com",
            # Browser-based cryptocurrency mining / mining script delivery
            "coinhive.com", "coin-hive.com", "authedmine.com", "crypto-loot.com",
            "cryptoloot.pro", "coinimp.com", "jsecoin.com", "webminepool.com",
            "webmine.cz", "minero.cc", "miner.pr0gramm.com",
            # Additional fingerprinting, session replay and telemetry hosts
            "api.fpjs.io", "fpjscdn.net", "fpcdn.io", "cdn.usefathom.com",
            "api-js.mixpanel.com", "api2.amplitude.com", "api.segment.io",
            "cdn.segment.com", "events.launchdarkly.com", "clientstream.launchdarkly.com",
            "o450.ingest.sentry.io", "browser-intake-datadoghq.com",
            "rum.browser-intake-datadoghq.com", "bam.nr-data.net",
            "collector.github.com", "telemetry.mozilla.org", "vortex.data.microsoft.com",
            "settings-win.data.microsoft.com", "watson.telemetry.microsoft.com",
            "self.events.data.microsoft.com", "umeng.com", "alog.umeng.com",
            "apm.umeng.com", "sdk.open.talk.getui.net",
        ]
        # Local/script-based test resources are same-origin and cannot be caught
        # by a domain list. Match only known ad/tracker script filenames.
        mega_script_names = {"ads.js", "pagead.js", "advertisement.js", "analytics.js"}
        strength = self.window_ref.settings_data.get("adblock_strength", "standard")
        builtins = (standard if strength == "standard" else
                    strong if strength == "strong" else
                    very_strong if strength == "very_strong" else
                    super_strong if strength == "super_strong" else
                    ultra_strong if strength == "ultra_strong" else mega_strong)
        custom = [str(x).lower() for x in self.window_ref.settings_data.get("adblock_custom_blocklist", [])]
        # Match domains precisely (including subdomains), while custom entries may
        # still be URL patterns. This avoids accidental partial hostname matches.
        domain_match = any(host == token or host.endswith("." + token) for token in builtins if "/" not in token)
        pattern_match = any(token in url for token in custom)
        mega_pattern_match = strength in ("mega_strong", "ultra_strong") and any(token in url for token in mega_url_patterns)
        path_name = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1].lower()
        mega_script_match = strength in ("mega_strong", "ultra_strong") and path_name in mega_script_names and host not in ("localhost", "127.0.0.1", "::1")
        ultra_url_patterns = (
            "/vast/", "/vmap/", "/prebid/", "/affiliate/redirect", "/outbound/track",
            "/clickthrough", "/click-through", "/pixel.gif", "/fingerprint/",
            "/fp/collect", "/deviceid", "/device-id", "/miner.js", "/coinhive.min.js",
        )
        ultra_pattern_match = strength == "ultra_strong" and any(token in url for token in ultra_url_patterns)
        if domain_match or pattern_match or mega_pattern_match or mega_script_match or ultra_pattern_match:
            info.block(True)


class LoginCaptureBridge(QObject):
    """Private-world bridge for the top-level document's password helper."""
    def __init__(self, window, view):
        super().__init__(view)
        self.window_ref = window
        self.view_ref = view

    def _request_is_current_top_level_origin(self, page_url):
        """Reject requests unless their origin is the page's actual top-level origin.

        The bridge is installed in Qt's ApplicationWorld and the helper script is
        restricted to the main frame. This server-side check is an additional
        fail-closed boundary; a URL supplied by JavaScript is never trusted alone.
        """
        try:
            requested = urllib.parse.urlparse(str(page_url or ""))
            current_url = self.view_ref.page().url().toString()
            current = urllib.parse.urlparse(current_url)

            def origin(parsed):
                scheme = (parsed.scheme or "").lower()
                if scheme not in ("http", "https") or not parsed.hostname:
                    return None
                if parsed.username is not None or parsed.password is not None:
                    return None
                host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
                port = parsed.port
                if port is None:
                    port = 443 if scheme == "https" else 80
                return scheme, host, port

            wanted = origin(requested)
            actual = origin(current)
            return bool(wanted and actual and wanted == actual)
        except (ValueError, UnicodeError, RuntimeError, AttributeError):
            return False

    @Slot(str, str)
    def diagnostic(self, event, details=""):
        try:
            self.window_ref._password_debug_log("js_" + str(event)[:64], str(details)[:240])
        except Exception:
            pass

    @Slot(str, str, str, result=str)
    def capture(self, page_url, username, password):
        try:
            if not self._request_is_current_top_level_origin(page_url):
                return "continue"
            return self.window_ref.capture_login_submission(self.view_ref, page_url, username, password)
        except Exception:
            return "continue"

    @Slot(str, bool, result=str)
    def suggestions(self, page_url, interactive):
        try:
            if not self._request_is_current_top_level_origin(page_url):
                return "[]"
            related_url = getattr(self.view_ref, "_password_flow_origin_url", "")
            raw = self.window_ref.password_suggestions(page_url, interactive, related_url)
            # Never serialize full vault records to the page helper. It receives
            # only the two values needed to fill the selected login form.
            entries = json.loads(raw or "[]")
            minimal = [
                {"username": str(item.get("username", "")),
                 "password": str(item.get("password", ""))}
                for item in entries
                if isinstance(item, dict) and item.get("username") and item.get("password")
            ]
            return json.dumps(minimal, ensure_ascii=False)
        except Exception:
            return "[]"

    @Slot(str, str)
    def bindCredentialToRelyingParty(self, page_url, username):
        try:
            if not self._request_is_current_top_level_origin(page_url):
                return
            related_url = getattr(self.view_ref, "_password_flow_origin_url", "")
            self.window_ref.bind_password_entry_to_relying_party(page_url, username, related_url)
        except Exception:
            pass

    @Slot(str, str, str, result=str)
    def confirmSave(self, page_url, username, password):
        try:
            if not self._request_is_current_top_level_origin(page_url):
                return "no"
            related_url = getattr(self.view_ref, "_password_flow_origin_url", "")
            return self.window_ref.confirm_login_save(page_url, username, password, related_url)
        except Exception:
            return "no"


class BookmarkEntryButton(QToolButton):
    """Bookmark row button that handles right-click before popup menus can consume it."""
    def __init__(self, parent=None, context_callback=None):
        super().__init__(parent)
        self._bookmark_context_callback = context_callback

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.RightButton and self._bookmark_context_callback:
            self._bookmark_context_callback(self.mapToGlobal(event.pos()))
            event.accept()
            return
        super().mousePressEvent(event)


class BookmarkOverflowMenu(QMenu):
    """Overflow menu that supports right-click actions on bookmark entries."""
    def __init__(self, title, parent, window_ref):
        super().__init__(title, parent)
        self.window_ref = window_ref
        self.setStyleSheet("""
            QMenu {
                background: #1d2430; color: #e8edf5;
                border: 1px solid #354155; border-radius: 8px;
                padding: 6px;
            }
            QMenu::item { min-height: 30px; padding: 6px 28px 6px 12px; border-radius: 5px; }
            QMenu::item:selected { background: #303b4c; color: #ffffff; }
            QMenu::separator { height: 1px; background: #354155; margin: 5px 8px; }
            QMenu::indicator { width: 14px; height: 14px; }
        """)

    def wheelEvent(self, event):
        """Use Qt's native menu scrolling so the visible bookmark list moves."""
        # Do not emulate scrolling by changing the active action: that only
        # moves the selection and leaves the menu's scrollable viewport still.
        super().wheelEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.RightButton:
            action = self.actionAt(event.pos())
            if action is not None:
                url = action.data()
                if url:
                    self.window_ref.show_bookmark_context_menu(str(url), event.globalPos())
                    event.accept()
                    self.close()
                    return
        super().mousePressEvent(event)


class BrowserView(QWebEngineView):
    def __init__(self, window):
        super().__init__()
        self.window_ref = window
        self.titleChanged.connect(self.on_title)
        self.urlChanged.connect(self.on_url)
        self._is_loading = False
        self.loadStarted.connect(self.on_load_started)
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
        # Allow clipboard writes from web pages after an explicit user action.
        # GitHub and other HTTPS sites use navigator.clipboard.writeText() for
        # their Copy buttons; disabling this setting makes the UI report a copy
        # even though the system clipboard is not updated.
        clipboard_attr = getattr(QWebEngineSettings.WebAttribute, "JavascriptCanAccessClipboard", None)
        if clipboard_attr is not None:
            settings.setAttribute(clipboard_attr, True)
        # Explicitly deny risky cross-boundary content capabilities. These are
        # normally disabled by Qt, but setting them here protects against future
        # defaults or profile-level changes.
        for attribute_name in (
            "LocalContentCanAccessFileUrls",
            "LocalContentCanAccessRemoteUrls",
            "AllowRunningInsecureContent",
            "HyperlinkAuditingEnabled",
            "PluginsEnabled",
        ):
            attribute = getattr(QWebEngineSettings.WebAttribute, attribute_name, None)
            if attribute is not None:
                settings.setAttribute(attribute, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)
        page.fullScreenRequested.connect(self.handle_fullscreen)
        # Handle camera, microphone, location and notification permissions in LunaSurfer.
        page.permissionRequested.connect(self.window_ref.handle_permission_request)
        self.login_channel = QWebChannel(page)
        self.login_bridge = LoginCaptureBridge(self.window_ref, self)
        self.login_channel.registerObject('lunaLoginBridge', self.login_bridge)
        # Keep the privileged bridge out of the website's MainWorld. Page scripts
        # cannot inspect or invoke objects installed in ApplicationWorld.
        page.setWebChannel(self.login_channel, QWebEngineScript.ScriptWorldId.ApplicationWorld)

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
                    let link = '';
                    let image = '';
                    for (const node of nodes) {
                        if (!node) continue;
                        if (!image) {
                            const img = node.matches && node.matches('img')
                                ? node : (node.closest ? node.closest('img') : null);
                            if (img) image = img.currentSrc || img.src || '';
                        }
                        if (!link) {
                            let el = node;
                            while (el) {
                                if (el.matches && el.matches('a[href]')) {
                                    link = el.href;
                                    break;
                                }
                                el = el.parentElement;
                            }
                        }
                        if (link && image) break;
                    }
                    return JSON.stringify({link: link, image: image});
                })(%d, %d)
            """ % (local_pos.x(), local_pos.y())
            fallback_url = link_url.toString()
            self.page().runJavaScript(
                js,
                lambda result, gp=global_pos, fallback=fallback_url:
                    self._show_context_menu_from_hit_test(gp, result, fallback)
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

    def _show_context_menu_from_hit_test(self, global_pos, result, fallback_link=""):
        try:
            hit = json.loads(result) if isinstance(result, str) else {}
        except (TypeError, ValueError):
            hit = {}
        if not isinstance(hit, dict):
            hit = {}
        self._show_context_menu_at(
            global_pos,
            hit.get("link") or fallback_link,
            hit.get("image") or ""
        )

    def _show_context_menu_at(self, global_pos, clicked_link="", clicked_image=""):
        """Build a lightweight, icon-free menu using only ordinary QMenu actions."""
        menu = QMenu(self)
        language = self.window_ref.settings_data.get("language", "de")
        is_english = language == "en"
        if language == "zh-CN":
            labels = {
                "back": "后退", "forward": "前进", "reload": "重新加载",
                "open_link": "在新标签页中打开链接", "open_page": "在新标签页中打开页面",
                "copy_link": "复制链接地址", "copy_page": "复制页面地址",
                "save_link_as": "链接另存为…",
                "save_page": "网页另存为…", "view_source": "查看网页源代码",
                "reload_cache": "忽略缓存并重新加载", "devtools": "打开开发者工具 (F12)",
                "copy_selection": "复制所选内容", "cut": "剪切", "copy": "复制", "paste": "粘贴",
                "find_page": "在页面中查找…", "view_image": "查看图片",
                "copy_image": "复制图片地址", "save_image": "保存图片", "save_image_as": "图片另存为…",
            }
        elif language == "ja":
            labels = {
                "back": "戻る", "forward": "進む", "reload": "再読み込み",
                "open_link": "リンクを新しいタブで開く", "open_page": "ページを新しいタブで開く",
                "copy_link": "リンクアドレスをコピー", "copy_page": "ページアドレスをコピー",
                "save_link_as": "リンク先を名前を付けて保存…",
                "save_page": "ページを名前を付けて保存…", "view_source": "ページのソースを表示",
                "reload_cache": "キャッシュを使わずに再読み込み", "devtools": "開発者ツールを開く (F12)",
                "copy_selection": "選択範囲をコピー", "cut": "切り取り", "copy": "コピー", "paste": "貼り付け",
                "find_page": "ページ内を検索…", "view_image": "画像を表示",
                "copy_image": "画像アドレスをコピー", "save_image": "画像を保存",
                "save_image_as": "画像を名前を付けて保存…",
            }
        elif language == "ru":
            labels = {
                "back": "Назад", "forward": "Вперёд", "reload": "Обновить",
                "open_link": "Открыть ссылку в новой вкладке", "open_page": "Открыть страницу в новой вкладке",
                "copy_link": "Копировать адрес ссылки", "copy_page": "Копировать адрес страницы",
                "save_link_as": "Сохранить ссылку как…",
                "save_page": "Сохранить страницу как…", "view_source": "Просмотреть исходный код страницы",
                "reload_cache": "Обновить без использования кэша", "devtools": "Открыть инструменты разработчика (F12)",
                "copy_selection": "Копировать выделенное", "cut": "Вырезать", "copy": "Копировать", "paste": "Вставить",
                "find_page": "Найти на странице…", "view_image": "Открыть изображение",
                "copy_image": "Копировать адрес изображения", "save_image": "Сохранить изображение",
                "save_image_as": "Сохранить изображение как…",
            }
        elif language == "nl":
            labels = {
                "back": "Terug", "forward": "Verder", "reload": "Herladen",
                "open_link": "Link openen in nieuw tabblad", "open_page": "Pagina openen in nieuw tabblad",
                "copy_link": "Linkadres kopiëren", "copy_page": "Pagina-adres kopiëren",
                "save_link_as": "Link opslaan als…",
                "save_page": "Pagina opslaan als…", "view_source": "Paginabron weergeven",
                "reload_cache": "Herladen (cache negeren)", "devtools": "Ontwikkelaarstools openen (F12)",
                "copy_selection": "Selectie kopiëren", "cut": "Knippen", "copy": "Kopiëren", "paste": "Plakken",
                "find_page": "Zoeken op pagina…", "view_image": "Afbeelding weergeven",
                "copy_image": "Afbeeldingsadres kopiëren", "save_image": "Afbeelding opslaan",
                "save_image_as": "Afbeelding opslaan als…",
            }
        elif language == "fr":
            labels = {
                "back": "Précédent", "forward": "Suivant", "reload": "Actualiser",
                "open_link": "Ouvrir le lien dans un nouvel onglet", "open_page": "Ouvrir la page dans un nouvel onglet",
                "copy_link": "Copier l’adresse du lien", "copy_page": "Copier l’adresse de la page",
                "save_link_as": "Enregistrer le lien sous…",
                "save_page": "Enregistrer la page sous…", "view_source": "Afficher le code source",
                "reload_cache": "Actualiser (sans utiliser le cache)", "devtools": "Ouvrir les outils de développement (F12)",
                "copy_selection": "Copier la sélection", "cut": "Couper", "copy": "Copier", "paste": "Coller",
                "find_page": "Rechercher dans la page…", "view_image": "Afficher l’image",
                "copy_image": "Copier l’adresse de l’image", "save_image": "Enregistrer l’image",
                "save_image_as": "Enregistrer l’image sous…",
            }
        elif language == "it":
            labels = {
                "back": "Indietro", "forward": "Avanti", "reload": "Ricarica",
                "open_link": "Apri link in una nuova scheda", "open_page": "Apri pagina in una nuova scheda",
                "copy_link": "Copia indirizzo del link", "copy_page": "Copia indirizzo della pagina",
                "save_link_as": "Salva link con nome…",
                "save_page": "Salva pagina con nome…", "view_source": "Visualizza sorgente pagina",
                "reload_cache": "Ricarica (ignora cache)", "devtools": "Apri strumenti per sviluppatori (F12)",
                "copy_selection": "Copia selezione", "cut": "Taglia", "copy": "Copia", "paste": "Incolla",
                "find_page": "Trova nella pagina…", "view_image": "Visualizza immagine",
                "copy_image": "Copia indirizzo immagine", "save_image": "Salva immagine",
                "save_image_as": "Salva immagine con nome…",
            }
        elif language == "es":
            labels = {
                "back": "Atrás", "forward": "Adelante", "reload": "Recargar",
                "open_link": "Abrir enlace en una pestaña nueva", "open_page": "Abrir página en una pestaña nueva",
                "copy_link": "Copiar dirección del enlace", "copy_page": "Copiar dirección de la página",
                "save_link_as": "Guardar enlace como…",
                "save_page": "Guardar página como…", "view_source": "Ver código fuente de la página",
                "reload_cache": "Recargar (sin caché)", "devtools": "Abrir herramientas para desarrolladores (F12)",
                "copy_selection": "Copiar selección", "cut": "Cortar", "copy": "Copiar", "paste": "Pegar",
                "find_page": "Buscar en la página…", "view_image": "Ver imagen",
                "copy_image": "Copiar dirección de la imagen", "save_image": "Guardar imagen",
                "save_image_as": "Guardar imagen como…",
            }
        elif language == "pt":
            labels = {
                "back": "Anterior", "forward": "Seguinte", "reload": "Recarregar",
                "open_link": "Abrir ligação num novo separador", "open_page": "Abrir página num novo separador",
                "copy_link": "Copiar endereço da ligação", "copy_page": "Copiar endereço da página",
                "save_link_as": "Guardar ligação como…",
                "save_page": "Guardar página como…", "view_source": "Ver código-fonte da página",
                "reload_cache": "Recarregar (ignorar cache)", "devtools": "Abrir ferramentas de programador (F12)",
                "copy_selection": "Copiar seleção", "cut": "Cortar", "copy": "Copiar", "paste": "Colar",
                "find_page": "Localizar nesta página…", "view_image": "Ver imagem",
                "copy_image": "Copiar endereço da imagem", "save_image": "Guardar imagem",
                "save_image_as": "Guardar imagem como…",
            }
        elif language == "tr":
            labels = {
                "back": "Geri", "forward": "İleri", "reload": "Yenile",
                "open_link": "Bağlantıyı yeni sekmede aç", "open_page": "Sayfayı yeni sekmede aç",
                "copy_link": "Bağlantı adresini kopyala", "copy_page": "Sayfa adresini kopyala",
                "save_link_as": "Bağlantıyı farklı kaydet…",
                "save_page": "Sayfayı farklı kaydet…", "view_source": "Sayfa kaynağını görüntüle",
                "reload_cache": "Yenile (önbelleği yok say)", "devtools": "Geliştirici araçlarını aç (F12)",
                "copy_selection": "Seçimi kopyala", "cut": "Kes", "copy": "Kopyala", "paste": "Yapıştır",
                "find_page": "Sayfada bul…", "view_image": "Resmi görüntüle",
                "copy_image": "Resim adresini kopyala", "save_image": "Resmi kaydet",
                "save_image_as": "Resmi farklı kaydet…",
            }
        elif language == "pl":
            labels = {
                "back": "Wstecz", "forward": "Dalej", "reload": "Odśwież",
                "open_link": "Otwórz link w nowej karcie", "open_page": "Otwórz stronę w nowej karcie",
                "copy_link": "Kopiuj adres linku", "copy_page": "Kopiuj adres strony",
                "save_link_as": "Zapisz link jako…",
                "save_page": "Zapisz stronę jako…", "view_source": "Wyświetl źródło strony",
                "reload_cache": "Odśwież (z pominięciem pamięci podręcznej)", "devtools": "Otwórz narzędzia deweloperskie (F12)",
                "copy_selection": "Kopiuj zaznaczenie", "cut": "Wytnij", "copy": "Kopiuj", "paste": "Wklej",
                "find_page": "Znajdź na tej stronie…", "view_image": "Wyświetl obraz",
                "copy_image": "Kopiuj adres obrazu", "save_image": "Zapisz obraz",
                "save_image_as": "Zapisz obraz jako…",
            }
        else:
            labels = {
                "back": "Back" if is_english else "Zurück",
                "forward": "Forward" if is_english else "Vorwärts",
                "reload": "Reload" if is_english else "Neu laden",
                "open_link": "Open link in new tab" if is_english else "Link in neuem Tab öffnen",
                "open_page": "Open page in new tab" if is_english else "Seite in neuem Tab öffnen",
                "copy_link": "Copy link address" if is_english else "Link-Adresse kopieren",
                "save_link_as": "Save link as…" if is_english else "Link speichern unter…",
                "copy_page": "Copy page address" if is_english else "Seitenadresse kopieren",
                "save_page": "Save page as…" if is_english else "Seite speichern unter…",
                "view_source": "View page source" if is_english else "Quelltext anzeigen",
                "reload_cache": "Reload (bypass cache)" if is_english else "Neu laden (Cache umgehen)",
                "devtools": "Open developer tools (F12)" if is_english else "Entwicklerwerkzeuge öffnen (F12)",
                "copy_selection": "Copy selection" if is_english else "Auswahl kopieren",
                "cut": "Cut" if is_english else "Ausschneiden",
                "copy": "Copy" if is_english else "Kopieren",
                "paste": "Paste" if is_english else "Einfügen",
                "find_page": "Find on this page…" if is_english else "Diese Seite durchsuchen…",
                "view_image": "View image" if is_english else "Bild anzeigen",
                "copy_image": "Copy image address" if is_english else "Bild-Adresse kopieren",
                "save_image": "Save image" if is_english else "Bild speichern",
                "save_image_as": "Save image as…" if is_english else "Bild speichern unter …",
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
            menu.addAction(
                labels["save_link_as"],
                lambda u=clicked_link: self.save_link_as(u)
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

        if clicked_image:
            menu.addSeparator()
            menu.addAction(
                labels["view_image"],
                lambda u=clicked_image: self.window_ref.add_tab(u, switch=True)
            )
            menu.addAction(
                labels["copy_image"],
                lambda u=clicked_image: QApplication.clipboard().setText(u)
            )
            menu.addAction(
                labels["save_image"],
                lambda u=clicked_image: self.download_image(u, save_as=False)
            )
            menu.addAction(
                labels["save_image_as"],
                lambda u=clicked_image: self.download_image(u, save_as=True)
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
        menu.addAction(labels["find_page"], self.window_ref.find_in_page)
        menu.addAction(labels["save_page"], self.save_page_as)
        # Use the explicit WebEngine ViewSource action, not the native context menu.
        menu.addAction(
            labels["view_source"],
            lambda: self.page().triggerAction(QWebEnginePage.WebAction.ViewSource)
        )
        menu.addAction(labels["reload_cache"], self.reload_bypass_cache)
        menu.addAction(labels["devtools"], self.window_ref.show_devtools)
        menu.exec(global_pos)

    def save_link_as(self, link_url):
        """Download the linked resource to a user-selected destination."""
        link_qurl = QUrl(str(link_url))
        if not link_qurl.isValid() or link_qurl.isEmpty():
            return
        parsed_path = urllib.parse.urlparse(str(link_url)).path
        link_name = pathlib.PurePosixPath(urllib.parse.unquote(parsed_path)).name or "download"
        suggested = self.window_ref.download_dir / safe_download_filename(link_name)
        language = self.window_ref.settings_data.get("language", "de")
        titles = {
            "de": "Link speichern unter", "en": "Save link as", "fr": "Enregistrer le lien sous",
            "nl": "Link opslaan als", "it": "Salva link con nome", "es": "Guardar enlace como",
            "pt": "Guardar ligação como", "pl": "Zapisz link jako", "tr": "Bağlantıyı farklı kaydet",
            "ru": "Сохранить ссылку как", "ja": "リンク先を名前を付けて保存", "zh-CN": "链接另存为",
        }
        filters = {
            "de": "Alle Dateien (*.*)", "en": "All files (*.*)", "fr": "Tous les fichiers (*.*)",
            "nl": "Alle bestanden (*.*)", "it": "Tutti i file (*.*)", "es": "Todos los archivos (*.*)",
            "pt": "Todos os ficheiros (*.*)", "pl": "Wszystkie pliki (*.*)", "tr": "Tüm dosyalar (*.*)",
            "ru": "Все файлы (*.*)", "ja": "すべてのファイル (*.*)", "zh-CN": "所有文件 (*.*)",
        }
        selected, _ = QFileDialog.getSaveFileName(
            self.window_ref, titles.get(language, titles["de"]), str(suggested),
            filters.get(language, filters["de"])
        )
        if not selected:
            return
        self.window_ref._next_download_path = pathlib.Path(selected).expanduser()
        self.page().download(link_qurl)

    def download_image(self, image_url, save_as=False):
        """Download the image under its original name or a user-selected path."""
        image_qurl = QUrl(str(image_url))
        if not image_qurl.isValid() or image_qurl.isEmpty():
            return
        if save_as:
            image_name = pathlib.PurePosixPath(
                urllib.parse.urlparse(str(image_url)).path
            ).name or "image"
            suggested = self.window_ref.download_dir / safe_download_filename(image_name)
            language = self.window_ref.settings_data.get("language", "de")
            image_dialog_titles = {
                "de": "Bild speichern unter", "en": "Save image as", "fr": "Enregistrer l’image sous",
                "nl": "Afbeelding opslaan als", "it": "Salva immagine con nome", "es": "Guardar imagen como",
                "pt": "Guardar imagem como", "pl": "Zapisz obraz jako", "tr": "Resmi farklı kaydet",
                "ru": "Сохранить изображение как", "ja": "画像を名前を付けて保存", "zh-CN": "图片另存为",
            }
            image_file_filters = {
                "de": "Alle Dateien (*.*)", "en": "All files (*.*)", "fr": "Tous les fichiers (*.*)",
                "nl": "Alle bestanden (*.*)", "it": "Tutti i file (*.*)", "es": "Todos los archivos (*.*)",
                "pt": "Todos os ficheiros (*.*)", "pl": "Wszystkie pliki (*.*)", "tr": "Tüm dosyalar (*.*)",
                "ru": "Все файлы (*.*)", "ja": "すべてのファイル (*.*)", "zh-CN": "所有文件 (*.*)",
            }
            title = image_dialog_titles.get(language, image_dialog_titles["de"])
            file_filter = image_file_filters.get(language, image_file_filters["de"])
            selected, _ = QFileDialog.getSaveFileName(self.window_ref, title, str(suggested), file_filter)
            if not selected:
                return
            self.window_ref._next_download_path = pathlib.Path(selected).expanduser()
        self.page().download(image_qurl)

    def save_page_as(self):
        """Ask for the exact destination before triggering QtWebEngine's Save Page."""
        title = (self.title() or "Webseite").strip()
        safe_title = "".join(ch for ch in title if ch not in '<>:"/\\\\|?*').strip() or "Webseite"
        suggested = self.window_ref.download_dir / (safe_title[:100] + ".mhtml")
        language = self.window_ref.settings_data.get("language", "de")
        is_english = language == "en"
        is_dutch = language == "nl"
        is_french = language == "fr"
        is_italian = language == "it"
        is_spanish = language == "es"
        is_portuguese = language == "pt"
        is_russian = language == "ru"
        dialog = QFileDialog(self.window_ref)
        dialog_titles = {
            "de": "Seite speichern unter", "en": "Save page as", "fr": "Enregistrer la page sous",
            "nl": "Pagina opslaan als", "it": "Salva pagina con nome", "es": "Guardar página como",
            "pt": "Guardar página como", "pl": "Zapisz stronę jako", "tr": "Sayfayı farklı kaydet",
            "ru": "Сохранить страницу как", "ja": "ページを名前を付けて保存", "zh-CN": "网页另存为",
        }
        dialog.setWindowTitle(dialog_titles.get(language, "Seite speichern unter"))
        dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        dialog.setFileMode(QFileDialog.FileMode.AnyFile)
        page_filters = {
            "de": ["Webseite (*.mhtml)", "Alle Dateien (*.*)"],
            "en": ["Web page (*.mhtml)", "All files (*.*)"],
            "fr": ["Page web (*.mhtml)", "Tous les fichiers (*.*)"],
            "nl": ["Webpagina (*.mhtml)", "Alle bestanden (*.*)"],
            "it": ["Pagina web (*.mhtml)", "Tutti i file (*.*)"],
            "es": ["Página web (*.mhtml)", "Todos los archivos (*.*)"],
            "pt": ["Página Web (*.mhtml)", "Todos os ficheiros (*.*)"],
            "pl": ["Strona internetowa (*.mhtml)", "Wszystkie pliki (*.*)"],
            "tr": ["Web sayfası (*.mhtml)", "Tüm dosyalar (*.*)"],
            "ru": ["Веб-страница (*.mhtml)", "Все файлы (*.*)"],
            "ja": ["ウェブページ (*.mhtml)", "すべてのファイル (*.*)"],
            "zh-CN": ["网页 (*.mhtml)", "所有文件 (*.*)"],
        }
        dialog.setNameFilters(page_filters.get(language, page_filters["de"]))
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
                accept_labels = {"zh-CN": "保存", "ja": "保存", "ru": "Сохранить", "en": "Save", "es": "Guardar", "pt": "Guardar", "nl": "Opslaan", "fr": "Enregistrer", "it": "Salva", "pl": "Zapisz", "tr": "Kaydet"}
                accept_button.setText(accept_labels.get(language, "Speichern"))
            if cancel_button is not None:
                cancel_labels = {"zh-CN": "取消", "ja": "キャンセル", "ru": "Отмена", "en": "Cancel", "es": "Cancelar", "pt": "Cancelar", "nl": "Annuleren", "fr": "Annuler", "it": "Annulla", "pl": "Anuluj", "tr": "İptal"}
                cancel_button.setText(cancel_labels.get(language, "Abbrechen"))
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
        """Offer translation when a loaded page differs from the selected UI language."""
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
                target_language = self.window_ref._get_translation_target_language()
                normalized_target = target_language.lower()
                if not language or language == normalized_target or language.startswith(normalized_target + "-"):
                    return
                if self.window_ref._translation_notice_url == url:
                    return
                self.window_ref._translation_notice_url = url
                self.window_ref.offer_page_translation(url, language)
            except RuntimeError:
                pass
        self.page().runJavaScript(js, language_ready)

    def on_load_started(self):
        self._is_loading = True
        self.window_ref.update_reload_stop_button()

    def on_load_finished(self, ok):
        self._is_loading = False
        self.window_ref.update_reload_stop_button()
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
        # Keep the "Weitere" membership stable when an item is edited.
        self._bookmark_overflow_keys = None
        self._preserve_bookmark_overflow_once = False
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
            "cookie_mode": "third",
            "ask_download_location": False,
            "warn_executable_downloads": True,
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
        self._download_history_loaded = False
        self._download_history_loading = False
        self._download_history_ready_callbacks = []
        self._download_history_loader = None
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
        self.central_container = QWidget(self)
        self.central_layout = QVBoxLayout(self.central_container)
        self.central_layout.setContentsMargins(0, 0, 0, 0)
        self.central_layout.setSpacing(0)
        self.central_layout.addWidget(self.tabs, 1)
        self.find_bar = QWidget(self.central_container)
        self.find_bar.setObjectName("pageFindBar")
        find_layout = QHBoxLayout(self.find_bar)
        find_layout.setContentsMargins(10, 6, 10, 6)
        find_layout.setSpacing(8)
        self.find_input = PageFindLineEdit(self)
        self.find_input.setPlaceholderText(self.tr("Auf dieser Seite suchen", "Find on this page"))
        self.find_input.setMinimumWidth(260)
        self.find_input.textChanged.connect(self._update_page_find)
        find_layout.addWidget(self.find_input, 1)
        self.find_count = QLabel(self.tr("Treffer 0 von 0", "Matches 0 of 0"), self.find_bar)
        self.find_count.setMinimumWidth(150)
        self.find_count.setFixedHeight(32)
        self.find_count.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.find_count.setStyleSheet(
            "QLabel { color: #ffffff; background: #31577f; "
            "border: 1px solid #6b9dcc; border-radius: 5px; "
            "padding: 3px 9px; font-size: 14px; font-weight: bold; }"
        )
        find_layout.addWidget(self.find_count)
        self.find_prev_button = QToolButton(self.find_bar)
        self.find_prev_button.setText("↑")
        self.find_prev_button.setToolTip(self.tr("Vorheriger Treffer", "Previous match"))
        self.find_prev_button.clicked.connect(self.find_page_previous)
        find_layout.addWidget(self.find_prev_button)
        self.find_next_button = QToolButton(self.find_bar)
        self.find_next_button.setText("↓")
        self.find_next_button.setToolTip(self.tr("Nächster Treffer", "Next match"))
        self.find_next_button.clicked.connect(self.find_page_next)
        find_layout.addWidget(self.find_next_button)
        self.find_close_button = QToolButton(self.find_bar)
        self.find_close_button.setText("✕")
        self.find_close_button.setToolTip(self.tr("Suchleiste schließen", "Close find bar"))
        self.find_close_button.clicked.connect(self.close_find_bar)
        find_layout.addWidget(self.find_close_button)
        self.find_bar.setStyleSheet("#pageFindBar { background: #202b3a; border-top: 1px solid #40516a; } #pageFindBar QLineEdit { padding: 7px; border: 1px solid #52657e; border-radius: 5px; } #pageFindBar QToolButton { min-width: 30px; min-height: 28px; font-size: 16px; }")
        self.central_layout.addWidget(self.find_bar)
        self.find_bar.hide()
        self._find_match_count = 0
        self._find_active_match = 0
        self.setCentralWidget(self.central_container)
        self.find_action = QAction(self.tr("Diese Seite durchsuchen", "Find on this page"), self)
        self.find_action.setShortcut(QKeySequence("Ctrl+F"))
        self.find_action.triggered.connect(self.find_in_page)
        self.addAction(self.find_action)
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
        self.reload_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload), "", self)
        self.reload_action.setToolTip(self.tr("Neu laden", "Reload"))
        self.reload_action.triggered.connect(self.reload_or_stop_current_page)
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
        # Read the existing download history after startup without blocking the UI.
        self._start_download_history_load()

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
        language = self.settings_data.get("language", "de")
        # Explicit translations for the bookmark destination dialog.  These
        # strings are application-owned (not Qt native dialog labels), so
        # they must be translated independently of Qt's system catalogs.
        bookmark_folder_labels = {
            "de": {"New folder…": "Neuer Ordner…", "New folder": "Neuer Ordner", "Folder name:": "Ordnername:", "Add bookmark": "Lesezeichen hinzufügen", "Save in:": "Speichern in:"},
            "en": {"New folder…": "New folder…", "New folder": "New folder", "Folder name:": "Folder name:", "Add bookmark": "Add bookmark", "Save in:": "Save in:"},
            "fr": {"New folder…": "Nouveau dossier…", "New folder": "Nouveau dossier", "Folder name:": "Nom du dossier :", "Add bookmark": "Ajouter un favori", "Save in:": "Enregistrer dans :"},
            "it": {"New folder…": "Nuova cartella…", "New folder": "Nuova cartella", "Folder name:": "Nome della cartella:", "Add bookmark": "Aggiungi segnalibro", "Save in:": "Salva in:"},
            "nl": {"New folder…": "Nieuwe map…", "New folder": "Nieuwe map", "Folder name:": "Mapnaam:", "Add bookmark": "Bladwijzer toevoegen", "Save in:": "Opslaan in:"},
            "es": {"New folder…": "Nueva carpeta…", "New folder": "Nueva carpeta", "Folder name:": "Nombre de la carpeta:", "Add bookmark": "Añadir marcador", "Save in:": "Guardar en:"},
            "pt": {"New folder…": "Nova pasta…", "New folder": "Nova pasta", "Folder name:": "Nome da pasta:", "Add bookmark": "Adicionar favorito", "Save in:": "Salvar em:"},
            "pl": {"New folder…": "Nowy folder…", "New folder": "Nowy folder", "Folder name:": "Nazwa folderu:", "Add bookmark": "Dodaj zakładkę", "Save in:": "Zapisz w:"},
            "ru": {"New folder…": "Новая папка…", "New folder": "Новая папка", "Folder name:": "Имя папки:", "Add bookmark": "Добавить закладку", "Save in:": "Сохранить в:"},
            "tr": {"New folder…": "Yeni klasör…", "New folder": "Yeni klasör", "Folder name:": "Klasör adı:", "Add bookmark": "Yer işareti ekle", "Save in:": "Şuraya kaydet:"},
            "ja": {"New folder…": "新しいフォルダー…", "New folder": "新しいフォルダー", "Folder name:": "フォルダー名:", "Add bookmark": "ブックマークを追加", "Save in:": "保存先:"},
            "zh-CN": {"New folder…": "新建文件夹…", "New folder": "新建文件夹", "Folder name:": "文件夹名称：", "Add bookmark": "添加书签", "Save in:": "保存到："},
        }
        if en in bookmark_folder_labels.get(language, {}):
            return bookmark_folder_labels[language][en]
        if language == "nl":
            translated = DUTCH_UI.get(en)
            if translated is not None:
                return translated
            match = re.fullmatch(r"(\\d+) items", en)
            if match:
                return f"{match.group(1)} items"
            match = re.fullmatch(r"(\\d+) matches", en)
            if match:
                return f"{match.group(1)} resultaten"
            match = re.fullmatch(r"(\\d+) bookmarks found\\.\\n\\nYes: replace existing bookmarks\\nNo: add to existing bookmarks", en)
            if match:
                return f"{match.group(1)} bladwijzers gevonden.\\n\\nJa: bestaande bladwijzers vervangen\\nNee: toevoegen aan bestaande bladwijzers"
            match = re.fullmatch(r"(\\d+) bookmark folders/items were imported\\.", en)
            if match:
                return f"{match.group(1)} bladwijzermappen/-items geïmporteerd."
            match = re.fullmatch(r"(\\d+) new, (\\d+) updated\\.", en)
            if match:
                return f"{match.group(1)} nieuw, {match.group(2)} bijgewerkt."
            match = re.fullmatch(r"Found (\\d+) login\\(s\\)\\. Entries for the same website and username will be updated; all others will be kept\\.", en)
            if match:
                return f"{match.group(1)} aanmeldgegevens gevonden. Items voor dezelfde website en gebruikersnaam worden bijgewerkt; alle andere blijven behouden."
            match = re.fullmatch(r"(Update|Save) the password for (.+) on (.+)\\?", en)
            if match:
                verb = "Werk" if match.group(1) == "Update" else "Sla"
                tail = "bij" if match.group(1) == "Update" else "op"
                return f"{verb} het wachtwoord voor {match.group(2)} op {match.group(3)} {tail}?"
            return en
        if language == "fr":
            translated = FRENCH_UI.get(en)
            if translated is not None:
                return translated
            # Dynamic text used by counters and confirmation dialogs is translated
            # here as well; keep the English source strings intact for English users.
            match = re.fullmatch(r"(\d+) items", en)
            if match:
                return f"{match.group(1)} éléments"
            match = re.fullmatch(r"(\d+) matches", en)
            if match:
                return f"{match.group(1)} résultats"
            match = re.fullmatch(r"(\d+) bookmarks found\.\n\nYes: replace existing bookmarks\nNo: add to existing bookmarks", en)
            if match:
                return f"{match.group(1)} favoris trouvés.\n\nOui : remplacer les favoris existants\nNon : ajouter aux favoris existants"
            match = re.fullmatch(r"(\d+) bookmark folders/items were imported\.", en)
            if match:
                return f"{match.group(1)} dossiers/éléments de favoris ont été importés."
            match = re.fullmatch(r"(\d+) new, (\d+) updated\.", en)
            if match:
                return f"{match.group(1)} nouveaux, {match.group(2)} mis à jour."
            match = re.fullmatch(r"Found (\d+) login\(s\)\. Entries for the same website and username will be updated; all others will be kept\.", en)
            if match:
                return f"{match.group(1)} identifiant(s) trouvé(s). Les entrées du même site web et du même nom d’utilisateur seront mises à jour ; les autres seront conservées."
            match = re.fullmatch(r"(Update|Save) the password for (.+) on (.+)\?", en)
            if match:
                verb = "Mettre à jour" if match.group(1) == "Update" else "Enregistrer"
                return f"{verb} le mot de passe de {match.group(2)} sur {match.group(3)} ?"
            return en
        if language == "zh-CN":
            match = re.fullmatch(r"(\d+) items", en)
            if match: return f"{match.group(1)} 项"
            match = re.fullmatch(r"(\d+) matches", en)
            if match: return f"{match.group(1)} 个匹配项"
            return CHINESE_UI.get(en, en)
        if language == "ja":
            match = re.fullmatch(r"(\d+) items", en)
            if match: return f"{match.group(1)} 件"
            match = re.fullmatch(r"(\d+) matches", en)
            if match: return f"{match.group(1)} 件一致"
            return JAPANESE_UI.get(en, en)
        if language == "ru":
            match = re.fullmatch(r"(\d+) items", en)
            if match: return f"{match.group(1)} элементов"
            match = re.fullmatch(r"(\d+) matches", en)
            if match: return f"{match.group(1)} совпадений"
            return RUSSIAN_UI.get(en, en)
        if language == "pt":
            return PORTUGUESE_UI.get(en, en)
        if language == "tr":
            translated = TURKISH_UI.get(en)
            if translated is not None:
                return translated
            match = re.fullmatch(r"(\d+) items", en)
            if match:
                return f"{match.group(1)} öğe"
            match = re.fullmatch(r"(\d+) matches", en)
            if match:
                return f"{match.group(1)} eşleşme"
            return en
        if language == "pl":
            return POLISH_UI.get(en, en)
        if language == "it":
            return ITALIAN_UI.get(en, en)
        if language == "es":
            translated = SPANISH_UI.get(en)
            if translated is not None:
                return translated
            match = re.fullmatch(r"(\d+) items", en)
            if match:
                return f"{match.group(1)} elementos"
            match = re.fullmatch(r"(\d+) matches", en)
            if match:
                return f"{match.group(1)} coincidencias"
            match = re.fullmatch(r"(\d+) bookmarks found\.\n\nYes: replace existing bookmarks\nNo: add to existing bookmarks", en)
            if match:
                return f"{match.group(1)} marcadores encontrados.\n\nSí: reemplazar los marcadores existentes\nNo: añadir a los marcadores existentes"
            match = re.fullmatch(r"(\d+) bookmark folders/items were imported\.", en)
            if match:
                return f"Se han importado {match.group(1)} carpetas/elementos de marcadores."
            match = re.fullmatch(r"(\d+) new, (\d+) updated\.", en)
            if match:
                return f"{match.group(1)} nuevos, {match.group(2)} actualizados."
            match = re.fullmatch(r"(Update|Save) the password for (.+) on (.+)\?", en)
            if match:
                verb = "¿Actualizar" if match.group(1) == "Update" else "¿Guardar"
                return f"{verb} la contraseña de {match.group(2)} en {match.group(3)}?"
            return en
        return en if language == "en" else de

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
            elif "clipboardreadwrite" in raw_type:
                key, label = "permission_clipboard", self.tr("Zwischenablage", "Clipboard")
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
        refresh_qt_dialog_language(self.settings_data.get("language", "de"))
        self.back_action.setToolTip(self.tr("Zurück", "Back"))
        self.forward_action.setToolTip(self.tr("Vorwärts", "Forward"))
        self.update_reload_stop_button()
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
        self.install_adblock_cosmetic_script(page)
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
            self.update_reload_stop_button()
        elif index >= 0:
            self.address.setText("lunasurfer://settings")
            self.back_action.setEnabled(False)
            self.forward_action.setEnabled(False)
            self.update_reload_stop_button()

    def reload_or_stop_current_page(self):
        view = self.current_view()
        if not view:
            return
        if getattr(view, "_is_loading", False):
            view.stop()
            view._is_loading = False
            self.update_reload_stop_button()
        else:
            view.reload()

    def update_reload_stop_button(self):
        view = self.current_view()
        loading = bool(view and getattr(view, "_is_loading", False))
        style = QApplication.style()
        if loading:
            self.reload_action.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_BrowserStop))
            self.reload_action.setToolTip(self.tr("Laden abbrechen", "Stop loading"))
        else:
            self.reload_action.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
            self.reload_action.setToolTip(self.tr("Neu laden", "Reload"))

    def update_navigation(self):
        view = self.current_view()
        if view:
            self.back_action.setEnabled(view.history().canGoBack())
            self.forward_action.setEnabled(view.history().canGoForward())

    def _get_translation_target_language(self):
        """Return the translation target matching the currently selected UI language."""
        language = str(self.settings_data.get("language", "de") or "de")
        supported = {"de", "en", "fr", "it", "nl", "es", "pt", "pl", "ru", "tr", "ja", "zh-CN"}
        return language if language in supported else "de"

    def offer_page_translation(self, url, detected_language):
        """Show a localized prompt to translate a page into the selected UI language."""
        language = self.settings_data.get("language", "de")
        target = self._get_translation_target_language()
        target_names = {
            "de": "Deutsch", "en": "English", "fr": "français", "it": "italiano",
            "nl": "Nederlands", "es": "español", "pt": "português", "pl": "polski",
            "tr": "Türkçe", "ru": "русский", "ja": "日本語", "zh-CN": "中文",
        }
        target_name = target_names.get(target, "Deutsch")
        notices = {
            "de": (f"Diese Seite scheint nicht auf {target_name} zu sein. Übersetzen?", "Übersetzen"),
            "en": (f"This page does not appear to be in {target_name}. Translate it?", "Translate"),
            "fr": (f"Cette page ne semble pas être en {target_name}. Voulez-vous la traduire ?", "Traduire"),
            "nl": (f"Deze pagina lijkt niet in het {target_name} te zijn. Wilt u deze vertalen?", "Vertalen"),
            "it": (f"Questa pagina non sembra essere in {target_name}. Vuoi tradurla?", "Traduci"),
            "es": (f"Esta página no parece estar en {target_name}. ¿Desea traducirla?", "Traducir"),
            "pt": (f"Esta página não parece estar em {target_name}. Pretende traduzi-la?", "Traduzir"),
            "pl": (f"Ta strona nie wygląda na {target_name}. Czy chcesz ją przetłumaczyć?", "Przetłumacz"),
            "tr": (f"Bu sayfa {target_name} görünmüyor. Çevirmek ister misiniz?", "Çevir"),
            "ru": (f"Похоже, эта страница не на языке {target_name}. Перевести?", "Перевести"),
            "ja": (f"このページは{target_name}ではないようです。翻訳しますか？", "翻訳"),
            "zh-CN": (f"此页面似乎不是{target_name}。要翻译吗？", "翻译"),
        }
        message, action_text = notices.get(language, notices["de"])
        try:
            if self._translation_notice_button is not None:
                self.statusBar().removeWidget(self._translation_notice_button)
                self._translation_notice_button.deleteLater()
            button = QToolButton(self)
            button.setText(action_text)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setStyleSheet(
                "QToolButton { background-color: #c7a6ff; color: #11151d; "
                "border: 1px solid #e0ccff; border-radius: 5px; "
                "font-weight: 700; padding: 5px 12px; min-height: 24px; }"
                "QToolButton:hover { background-color: #d8c0ff; border-color: #ffffff; }"
                "QToolButton:pressed { background-color: #a879f5; color: #11151d; }"
            )
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
        self.translate_current_page_selected(self._get_translation_target_language())

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

    def find_in_page(self):
        """Open the persistent in-page find bar; this is not a web search."""
        if self.current_view() is None:
            return
        self.find_bar.show()
        self.find_input.setFocus()
        self.find_input.selectAll()

    def _update_page_find(self, text):
        view = self.current_view()
        self._find_match_count = 0
        self._find_active_match = 0
        if view is None or not text:
            if view:
                view.page().findText("")
            self.find_count.setText(self.tr("Treffer 0 von 0", "Matches 0 of 0"))
            return
        self._run_page_find(text, False)

    def _run_page_find(self, text, backwards=False):
        view = self.current_view()
        if view is None or not text:
            return
        flags = QWebEnginePage.FindFlag.FindBackward if backwards else QWebEnginePage.FindFlag(0)
        def finished(result):
            try:
                self._find_match_count = int(result.numberOfMatches())
                self._find_active_match = int(result.activeMatch())
                self.find_count.setText(
                    self.tr(
                        f"Treffer {self._find_active_match} von {self._find_match_count}",
                        f"Match {self._find_active_match} of {self._find_match_count}"
                    ) if self._find_match_count else self.tr("Treffer 0 von 0", "Matches 0 of 0")
                )
            except Exception:
                self.find_count.setText(self.tr("Treffer 0 von 0", "Matches 0 of 0"))
        view.page().findText(text, flags, finished)

    def find_page_next(self):
        self._run_page_find(self.find_input.text().strip(), False)

    def find_page_previous(self):
        self._run_page_find(self.find_input.text().strip(), True)

    def close_find_bar(self):
        view = self.current_view()
        if view:
            view.page().findText("")
            view.setFocus()
        self.find_input.clear()
        self.find_bar.hide()

    def add_bookmark(self):
        """Ask for a destination folder whenever the bookmark star is used."""
        view = self.current_view()
        if not view:
            return
        url = view.url().toString()
        if not url:
            return
        items = read_json(BOOKMARKS_FILE, [])
        title = view.title() or url
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("Lesezeichen hinzufügen", "Add bookmark"))
        dialog.resize(520, 470)
        layout = QVBoxLayout(dialog)
        form = QFormLayout()
        name_edit = QLineEdit(title)
        address_edit = QLineEdit(url)
        form.addRow(self.tr("Name:", "Name:"), name_edit)
        form.addRow(self.tr("Adresse:", "Address:"), address_edit)
        layout.addLayout(form)
        layout.addWidget(QLabel(self.tr("Speichern in:", "Save in:")))
        tree = QTreeWidget()
        tree.setHeaderHidden(True)
        tree.setMinimumHeight(230)
        tree.setStyleSheet("QTreeWidget { background:#1d2430; color:#e8edf5; border:1px solid #354155; border-radius:8px; padding:5px; } QTreeWidget::item { padding:6px; }")
        def add_folders(parent, entries, path=()):
            for i, entry in enumerate(entries if isinstance(entries, list) else []):
                if not isinstance(entry, dict) or not (entry.get("type") == "folder" or "children" in entry):
                    continue
                node = QTreeWidgetItem(parent, [self.bookmark_display_title(entry, root=(len(path) == 0))])
                node.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
                node.setData(0, Qt.ItemDataRole.UserRole, tuple(path) + (i,))
                add_folders(node, entry.get("children", []), tuple(path) + (i,))
        add_folders(tree, items)
        if tree.topLevelItemCount():
            tree.setCurrentItem(tree.topLevelItem(0))
        layout.addWidget(tree, 1)
        row = QHBoxLayout()
        new_folder_btn = QPushButton(self.tr("Neuer Ordner…", "New folder…"))
        row.addWidget(new_folder_btn)
        row.addStretch(1)
        layout.addLayout(row)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText(self.tr("Speichern", "Save"))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(self.tr("Abbrechen", "Cancel"))
        layout.addWidget(buttons)
        def selected_folder_path():
            node = tree.currentItem()
            return node.data(0, Qt.ItemDataRole.UserRole) if node else None
        def new_folder():
            folder_name, ok = QInputDialog.getText(dialog, self.tr("Neuer Ordner", "New folder"), self.tr("Ordnername:", "Folder name:"))
            if not ok or not folder_name.strip():
                return
            data = read_json(BOOKMARKS_FILE, [])
            path = selected_folder_path()
            target = data
            if path is not None:
                for index in path:
                    target = target[index].setdefault("children", [])
            target.append({"type": "folder", "title": folder_name.strip(), "children": []})
            write_json(BOOKMARKS_FILE, data)
            self.refresh_bookmarks_bar()
            tree.clear()
            add_folders(tree, data)
            # Select the newly created folder.
            parent = tree.invisibleRootItem()
            for index in (path or ()):
                parent = parent.child(index)
            parent.child(parent.childCount() - 1).setSelected(True)
            parent.child(parent.childCount() - 1).setExpanded(True)
        def save_bookmark():
            name = name_edit.text().strip() or address_edit.text().strip()
            address = address_edit.text().strip()
            if not address:
                QMessageBox.warning(dialog, self.tr("Lesezeichen", "Bookmark"), self.tr("Bitte eine gültige Adresse eingeben.", "Please enter an address."))
                return
            data = read_json(BOOKMARKS_FILE, [])
            path = selected_folder_path()
            target = data
            if path is not None:
                try:
                    for index in path:
                        target = target[index].setdefault("children", [])
                except (IndexError, KeyError, TypeError):
                    target = data
            # Update an existing URL rather than creating duplicates.
            def find(entries):
                for entry in entries:
                    if entry.get("url") == address:
                        return entry
                    found = find(entry.get("children", [])) if isinstance(entry.get("children"), list) else None
                    if found:
                        return found
                return None
            existing = find(data)
            if existing:
                existing["title"] = name
            else:
                target.append({"title": name, "url": address})
            write_json(BOOKMARKS_FILE, data)
            self.refresh_bookmarks_bar()
            self.statusBar().showMessage(self.tr("Lesezeichen gespeichert", "Bookmark saved"), 3000)
            dialog.accept()
        new_folder_btn.clicked.connect(new_folder)
        buttons.accepted.connect(save_bookmark)
        buttons.rejected.connect(dialog.reject)
        dialog.exec()

    def refresh_bookmarks_bar(self):
        """Build a responsive bookmarks bar with a clean overflow menu."""
        if not hasattr(self, "bookmarks_bar"):
            return
        self.bookmarks_bar.clear()
        items = read_json(BOOKMARKS_FILE, [])
        style = QApplication.style()

        # Work from the actual toolbar width (not the main-window width).
        # The overflow button must be budgeted BEFORE deciding which bookmark
        # fits; otherwise the last visible entry and "Weitere" get squeezed.
        toolbar_width = max(0, self.bookmarks_bar.width())
        manage_label = self.tr("Lesezeichen verwalten", "Manage bookmarks")
        more_label = self.tr("» Weitere", "» More")
        manage_width = max(150, self.fontMetrics().horizontalAdvance(manage_label) + 48)
        more_width = max(104, self.fontMetrics().horizontalAdvance(more_label) + 42)
        toolbar_margins = 36
        available_without_more = max(0, toolbar_width - manage_width - toolbar_margins)
        used = 0
        visible, overflow = [], []

        def entry_width(item):
            title = self.bookmark_display_title(item, root=True)
            return max(88, min(220, self.fontMetrics().horizontalAdvance(title) + 42))

        def bookmark_layout_key(item):
            # URLs uniquely identify ordinary bookmarks. Folder keys also
            # include their child URLs so renaming a folder does not move it
            # between the toolbar and the "More" popup.
            url = str(item.get("url", "")).strip()
            if url:
                return ("url", url)
            child_urls = []
            def collect_urls(entries):
                for child in entries if isinstance(entries, list) else []:
                    child_url = str(child.get("url", "")).strip()
                    if child_url:
                        child_urls.append(child_url)
                    collect_urls(child.get("children", []))
            collect_urls(item.get("children", []))
            return ("folder", tuple(sorted(child_urls)) if child_urls else str(item.get("title", "")).casefold())

        # Determine whether an overflow button is needed using the full
        # natural width. If yes, reserve its complete width before placing
        # any bookmark. This keeps the button from being squeezed at the end.
        natural_total = sum(entry_width(item) for item in items)
        needs_overflow = (
            natural_total > available_without_more
            or bool(self._preserve_bookmark_overflow_once and self._bookmark_overflow_keys)
        )
        available = max(0, available_without_more - (more_width + 8 if needs_overflow else 0))

        # Preserve the membership only for the single refresh immediately
        # following an edit; normal additions/resizes are laid out afresh.
        if self._preserve_bookmark_overflow_once and self._bookmark_overflow_keys is not None:
            pinned_overflow = set(self._bookmark_overflow_keys)
        else:
            pinned_overflow = set()
        self._preserve_bookmark_overflow_once = False

        for item in items:
            key = bookmark_layout_key(item)
            width = entry_width(item)
            if key in pinned_overflow:
                overflow.append(item)
            elif used + width <= available or not visible:
                visible.append(item)
                used += width
            else:
                overflow.append(item)
                pinned_overflow.add(key)

        self._bookmark_overflow_keys = pinned_overflow

        def add_menu_entries(menu, entries):
            """Build a genuinely scrollable bookmark popup with a visible scrollbar."""
            screen = self.screen() if hasattr(self, "screen") else QApplication.primaryScreen()
            screen_geometry = screen.availableGeometry() if screen else None
            screen_width = screen_geometry.width() if screen_geometry else 1280
            screen_height = screen_geometry.height() if screen_geometry else 800
            menu_width = min(380, max(220, int(screen_width * 0.32)))
            menu.setMinimumWidth(menu_width)
            menu.setMaximumWidth(menu_width)
            menu.setToolTipsVisible(True)

            scroll = QScrollArea(menu)
            scroll.setObjectName("bookmarkPopupScroll")
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QScrollArea.Shape.NoFrame)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            scroll.setMaximumHeight(max(180, screen_height - 130))
            scroll.setMinimumWidth(menu_width - 12)
            scroll.setStyleSheet("""
                QScrollArea#bookmarkPopupScroll, QScrollArea#bookmarkPopupScroll QWidget#qt_scrollarea_viewport { background-color: #1d2430; border: 0; }
                QScrollBar:vertical { width: 13px; background: #202a38; margin: 2px; }
                QScrollBar::handle:vertical { background: #687991; min-height: 28px; border-radius: 5px; }
                QScrollBar::handle:vertical:hover { background: #9270c8; }
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
                QWidget#bookmarkPopupContent { background-color: #1d2430; color: #e8edf5; }
            """)
            content = QWidget()
            content.setObjectName("bookmarkPopupContent")
            content.setAutoFillBackground(True)
            content.setStyleSheet("QWidget#bookmarkPopupContent { background-color: #1d2430; color: #e8edf5; }")
            scroll.viewport().setStyleSheet("background-color: #1d2430;")
            rows = QVBoxLayout(content)
            rows.setContentsMargins(5, 5, 5, 5)
            rows.setSpacing(2)

            def fit_menu_text(value):
                return menu.fontMetrics().elidedText(
                    str(value), Qt.TextElideMode.ElideRight, menu_width - 55
                )

            for item in entries:
                is_folder = item.get("type") == "folder" or "children" in item
                full_title = (item.get("title") or ("Ordner" if is_folder else item.get("url", ""))).strip()
                row = BookmarkEntryButton(content)
                row.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
                row.setText(("▸  " if is_folder else "     ") + fit_menu_text(full_title))
                row.setToolTip(full_title if is_folder else f"{full_title}\n{item.get('url', '')}")
                row.setMinimumHeight(34)
                row.setMaximumWidth(menu_width - 28)
                row.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                row.setStyleSheet("""
                    QToolButton { text-align: left; padding: 6px 9px; border: 0;
                                  border-radius: 5px; color: #e8edf5; background: transparent; }
                    QToolButton:hover { background: #303b4c; color: white; }
                """)
                if is_folder:
                    child_menu = BookmarkOverflowMenu(fit_menu_text(full_title), menu, self)
                    add_menu_entries(child_menu, item.get("children", []))
                    row.clicked.connect(
                        lambda checked=False, b=row, m=child_menu:
                            m.popup(b.mapToGlobal(QPoint(b.width(), 0)))
                    )
                else:
                    url = item.get("url", "").strip()
                    if url:
                        row.clicked.connect(lambda checked=False, u=url: (menu.close(), self.open_bookmark(u)))
                        # The scroll-area rows are real widgets, not QMenu
                        # actions.  Route their right-clicks to the same
                        # Open / Edit / Delete menu used by the toolbar.
                        row._bookmark_context_callback = (
                            lambda global_pos, u=url:
                                self.show_bookmark_context_menu(u, global_pos)
                        )
                    else:
                        row.setEnabled(False)
                rows.addWidget(row)

            rows.addStretch(1)
            scroll.setWidget(content)
            widget_action = QWidgetAction(menu)
            widget_action.setDefaultWidget(scroll)
            menu.addAction(widget_action)

        def create_bookmark_popup(title, entries):
            """Create the standard cascading, scrollable popup used by all bookmark buttons."""
            menu = BookmarkOverflowMenu(title, self, self)
            add_menu_entries(menu, entries)
            return menu

        def configure_bookmark_popup_button(button, title, menu, tooltip):
            """Give folder buttons and the 'More' button identical popup behavior."""
            button.setText(title)
            button.setToolTip(tooltip)
            button.setMenu(menu)
            button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
            button.setMinimumWidth(88)
            button.setMaximumWidth(220)

        def add_visible(item):
            if item.get("type") == "folder" or "children" in item:
                title = self.bookmark_display_title(item, root=True)
                # Use the same right-click capable menu as the overflow area,
                # so bookmarks inside folders on the visible bookmarks bar
                # also expose Open / Edit / Delete actions.
                menu = create_bookmark_popup(title, item.get("children", []))
                button = QToolButton(self.bookmarks_bar)
                configure_bookmark_popup_button(
                    button, title, menu, self.tr("Ordner öffnen", "Open folder")
                )
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
            more_title = more_label
            more_menu = create_bookmark_popup(
                self.tr("Weitere Lesezeichen", "More bookmarks"), overflow
            )
            more_button = QToolButton(self.bookmarks_bar)
            configure_bookmark_popup_button(
                more_button, more_title, more_menu,
                self.tr("Weitere Lesezeichen anzeigen", "Show more bookmarks")
            )
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
        # A wider/narrower window must always recalculate which bookmarks fit.
        self._bookmark_overflow_keys = None
        self._preserve_bookmark_overflow_once = False
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
        def locate(entries):
            for entry in entries:
                if entry.get("url") == old_url:
                    return entry
                found = locate(entry.get("children", [])) if isinstance(entry.get("children"), list) else None
                if found is not None:
                    return found
            return None
        item = locate(items)
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
        # If this bookmark belongs to "Weitere", keep it there even when
        # its URL is changed during editing.
        if self._bookmark_overflow_keys is not None:
            old_key = ("url", str(old_url).strip())
            if old_key in self._bookmark_overflow_keys:
                self._bookmark_overflow_keys.discard(old_key)
                self._bookmark_overflow_keys.add(("url", str(url).strip()))
        write_json(BOOKMARKS_FILE, items)
        self._preserve_bookmark_overflow_once = True
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
        def remove_url(entries):
            kept = []
            for entry in entries:
                if entry.get("url") == url:
                    continue
                if isinstance(entry.get("children"), list):
                    entry["children"] = remove_url(entry["children"])
                kept.append(entry)
            return kept
        items = remove_url(read_json(BOOKMARKS_FILE, []))
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
        bookmark_tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        bookmark_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        bookmark_tree.setEditTriggers(QTreeWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(bookmark_tree, 1)
        bookmark_clipboard = {"entries": [], "paths": [], "cut": False}

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

        def resolve_list(data, path):
            target = data
            for index in path:
                target = target[index].setdefault("children", [])
            return target

        def selected_paths():
            paths = [tuple(node.data(0, Qt.ItemDataRole.UserRole + 2)) for node in bookmark_tree.selectedItems()]
            # Do not process a child separately when its parent folder is selected.
            return [p for p in sorted(set(paths), key=lambda x: (len(x), x))
                    if not any(len(parent) < len(p) and p[:len(parent)] == parent for parent in paths)]

        def destination_list(data):
            node = selected_node()
            if node is None:
                return data
            path = tuple(node.data(0, Qt.ItemDataRole.UserRole + 2))
            if node.data(0, Qt.ItemDataRole.UserRole + 1) == "folder":
                folder = resolve_list(data, path[:-1])[path[-1]]
                return folder.setdefault("children", [])
            return resolve_list(data, path[:-1])

        def do_copy(cut=False):
            data = read_json(BOOKMARKS_FILE, [])
            paths = selected_paths()
            if not paths:
                return
            try:
                entries = [copy.deepcopy(resolve_list(data, path[:-1])[path[-1]]) for path in paths]
            except (IndexError, KeyError, TypeError):
                return
            bookmark_clipboard.update({"entries": entries, "paths": paths if cut else [], "cut": bool(cut)})

        def do_paste():
            if not bookmark_clipboard["entries"]:
                return
            data = read_json(BOOKMARKS_FILE, [])
            dest = destination_list(data)
            if bookmark_clipboard["cut"]:
                source_paths = bookmark_clipboard["paths"]
                # A folder cannot be moved into itself or one of its descendants.
                dest_path = tuple(selected_node().data(0, Qt.ItemDataRole.UserRole + 2)) if selected_node() else ()
                if any(dest_path[:len(src)] == src for src in source_paths):
                    QMessageBox.warning(dialog, self.tr("Verschieben nicht möglich", "Cannot move"), self.tr("Ein Ordner kann nicht in sich selbst oder einen seiner Unterordner verschoben werden.", "A folder cannot be moved into itself or one of its subfolders."))
                    return
                # The destination list is held by reference, so removing siblings does not invalidate it.
                for path in sorted(source_paths, key=lambda x: (x[:-1], x[-1]), reverse=True):
                    parent = resolve_list(data, path[:-1])
                    if path[-1] < len(parent):
                        del parent[path[-1]]
                dest.extend(copy.deepcopy(bookmark_clipboard["entries"]))
                bookmark_clipboard.update({"entries": [], "paths": [], "cut": False})
            else:
                dest.extend(copy.deepcopy(bookmark_clipboard["entries"]))
            write_json(BOOKMARKS_FILE, data)
            self.refresh_bookmarks_bar()
            populate()

        def do_new_folder():
            data = read_json(BOOKMARKS_FILE, [])
            target = destination_list(data)
            name, ok = QInputDialog.getText(dialog, self.tr("Neuer Ordner", "New folder"), self.tr("Ordnername:", "Folder name:"))
            if not ok or not name.strip():
                return
            target.append({"type": "folder", "title": name.strip(), "children": []})
            write_json(BOOKMARKS_FILE, data)
            self.refresh_bookmarks_bar(); populate()

        def show_manager_context_menu(pos):
            node = bookmark_tree.itemAt(pos)
            if node and node not in bookmark_tree.selectedItems():
                bookmark_tree.setCurrentItem(node)
            menu = QMenu(bookmark_tree)
            open_action = menu.addAction(self.tr("Öffnen", "Open"))
            menu.addSeparator()
            copy_action = menu.addAction(self.tr("Kopieren", "Copy"))
            cut_action = menu.addAction(self.tr("Ausschneiden", "Cut"))
            paste_action = menu.addAction(self.tr("Einfügen", "Paste"))
            menu.addSeparator()
            folder_action = menu.addAction(self.tr("Neuer Ordner…", "New folder…"))
            edit_action = menu.addAction(self.tr("Bearbeiten…", "Edit…"))
            delete_action = menu.addAction(self.tr("Löschen", "Delete"))
            open_action.setEnabled(bool(node and node.data(0, Qt.ItemDataRole.UserRole + 1) == "bookmark"))
            edit_action.setEnabled(bool(node and node.data(0, Qt.ItemDataRole.UserRole + 1) == "bookmark"))
            delete_action.setEnabled(bool(node))
            paste_action.setEnabled(bool(bookmark_clipboard["entries"]))
            chosen = menu.exec(bookmark_tree.viewport().mapToGlobal(pos))
            if chosen == open_action: do_open()
            elif chosen == copy_action: do_copy(False)
            elif chosen == cut_action: do_copy(True)
            elif chosen == paste_action: do_paste()
            elif chosen == folder_action: do_new_folder()
            elif chosen == edit_action: do_edit()
            elif chosen == delete_action: do_delete()

        bookmark_tree.customContextMenuRequested.connect(show_manager_context_menu)
        bookmark_tree.setToolTip(self.tr("Rechtsklick: Kopieren, Ausschneiden, Einfügen und weitere Aktionen", "Right-click for copy, cut, paste and more actions"))

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

    @staticmethod
    def adblock_cosmetic_script():
        """Hide common ad slots and remove known local ad-script decoys in the strongest ad-blocking modes."""
        return r"""(() => {
          'use strict';
          if (window.__lunaMegaAdblockInstalled) return;
          window.__lunaMegaAdblockInstalled = true;
          const selectors = [
            '.adsbox', '.ad-banner', '#ad-container', '.adsbygoogle', '.google-ad',
            '[id^="google_ads"]', '[id^="div-gpt-ad"]', '[class*="advert"]',
            '[id*="advert"]', '[class*="sponsor"]', '[id*="sponsor"]',
            'iframe[src*="doubleclick.net"]', 'iframe[src*="googlesyndication.com"]',
            'iframe[src*="amazon-adsystem.com"]', 'iframe[src*="taboola.com"]',
            'iframe[src*="outbrain.com"]'
          ];
          if (location.hostname === 'adblock.turtlecute.org') {
            selectors.push('.adbox.banner_ads.adsbox', '.textads');
          }
          const style = document.createElement('style');
          style.id = 'luna-mega-adblock-cosmetic';
          style.textContent = selectors.join(',') + '{display:none!important;visibility:hidden!important;'
            + 'width:0!important;height:0!important;min-width:0!important;min-height:0!important;'
            + 'pointer-events:none!important;overflow:hidden!important}';
          const addStyle = () => {
            if (document.documentElement && !document.getElementById(style.id))
              document.documentElement.appendChild(style);
          };
          addStyle();
          if (!document.documentElement) document.addEventListener('DOMContentLoaded', addStyle, {once:true});
          const scriptNames = new Set(['ads.js','pagead.js','advertisement.js','analytics.js']);
          const removeDecoyScripts = root => {
            try {
              (root.querySelectorAll ? root.querySelectorAll('script[src]') : []).forEach(script => {
                try {
                  const url = new URL(script.src, location.href);
                  if (url.origin === location.origin && scriptNames.has(url.pathname.split('/').pop().toLowerCase()))
                    script.remove();
                } catch (_) {}
              });
            } catch (_) {}
          };
          removeDecoyScripts(document);
          try {
            const observe = () => { window.__lunaMegaAdblockObserver = new MutationObserver(records => records.forEach(record =>
              record.addedNodes.forEach(node => {
                if (node.nodeType !== 1) return;
                if (node.matches && node.matches('script[src]')) {
                  try {
                    const url = new URL(node.src, location.href);
                    if (url.origin === location.origin && scriptNames.has(url.pathname.split('/').pop().toLowerCase())) node.remove();
                  } catch (_) {}
                }
                removeDecoyScripts(node);
              })
            ));
              window.__lunaMegaAdblockObserver.observe(document.documentElement, {childList:true, subtree:true});
            };
            if (document.documentElement) observe();
            else document.addEventListener('DOMContentLoaded', observe, {once:true});
          } catch (_) {}
        })();"""

    def install_adblock_cosmetic_script(self, page, run_now=False):
        scripts = page.scripts()
        for old_script in scripts.find("LunaSurferMegaAdblockCosmetic"):
            scripts.remove(old_script)
        if (self.settings_data.get("adblock_enabled", True)
                and self.settings_data.get("adblock_strength", "standard") in ("mega_strong", "ultra_strong")):
            script = QWebEngineScript()
            script.setName("LunaSurferMegaAdblockCosmetic")
            script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
            script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
            script.setRunsOnSubFrames(True)
            script.setSourceCode(self.adblock_cosmetic_script())
            scripts.insert(script)
            if run_now:
                page.runJavaScript(self.adblock_cosmetic_script())
        elif run_now:
            page.runJavaScript("""(() => {
              const style = document.getElementById('luna-mega-adblock-cosmetic');
              if (style) style.remove();
              if (window.__lunaMegaAdblockObserver) window.__lunaMegaAdblockObserver.disconnect();
              window.__lunaMegaAdblockObserver = null;
              window.__lunaMegaAdblockInstalled = false;
            })();""")

    def apply_adblock_cosmetic_live(self):
        """Apply or remove high-strength cosmetic rules in all open tabs immediately."""
        for index in range(self.tabs.count()):
            view = self.tabs.widget(index)
            if isinstance(view, BrowserView):
                self.install_adblock_cosmetic_script(view.page(), run_now=True)

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
            ("Ultra stark", "Ultra strong", "ultra_strong"),
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
            self.apply_adblock_cosmetic_live()
            self.apply_fingerprint_protection_live()
            dialog.accept()

        save.clicked.connect(do_save)
        cancel.clicked.connect(dialog.reject)
        dialog.exec()

    def _restore_download_history_records(self, records):
        """Restore persistent download records on the GUI thread."""
        if not isinstance(records, list):
            records = []
        for record in records:
            if not isinstance(record, dict) or not record.get("target"):
                continue
            target = pathlib.Path(record["target"]).expanduser()
            stored = dict(record)
            # The transfer result is independent from whether the user still
            # keeps the downloaded file. Repair old stale failure records only
            # when the persisted byte counters prove the full transfer arrived.
            try:
                expected_size = int(stored.get("total", 0) or 0)
                received_size = int(stored.get("received", 0) or 0)
            except (TypeError, ValueError):
                expected_size = received_size = 0
            status = stored.get("status")
            if not status:
                status = "completed" if target.is_file() else "failed"
            if (status in ("failed", "interrupted")
                    and expected_size > 0 and received_size >= expected_size):
                status = "completed"
            self.download_items.append({
                "id": stored.get("id") or secrets.token_hex(12),
                "download": StoredDownload(stored), "target": target,
                "last_bytes": int(stored.get("received", 0) or 0),
                "last_time": time.monotonic(), "speed": 0, "stored": True,
                "status": status,
                "downloaded_at": stored.get("downloaded_at", "")
            })

    def _start_download_history_load(self, on_ready=None):
        """Start one background read; callers may register a UI refresh callback."""
        if on_ready is not None:
            self._download_history_ready_callbacks.append(on_ready)
        if self._download_history_loaded:
            callbacks = self._download_history_ready_callbacks
            self._download_history_ready_callbacks = []
            for callback in callbacks:
                try:
                    callback()
                except Exception:
                    pass
            return
        if self._download_history_loading:
            return
        self._download_history_loading = True
        loader = DownloadHistoryLoader(DOWNLOADS_FILE, self)
        self._download_history_loader = loader
        loader.records_loaded.connect(self._on_download_history_loaded)
        loader.finished.connect(self._on_download_history_loader_finished)
        loader.start()

    def _on_download_history_loaded(self, records):
        """Apply records read in the background and notify waiting UI callbacks."""
        if self._download_history_loaded:
            return
        self._restore_download_history_records(records)
        self._download_history_loaded = True
        self._download_history_loading = False
        callbacks = self._download_history_ready_callbacks
        self._download_history_ready_callbacks = []
        for callback in callbacks:
            try:
                callback()
            except Exception:
                pass

    def _on_download_history_loader_finished(self):
        loader = self._download_history_loader
        if loader is not None and not self._download_history_loaded:
            # Normally records_loaded arrives first. This fallback also covers
            # a thread finishing while the window is closing.
            self._on_download_history_loaded(loader.records)
        self._download_history_loader = None


    @staticmethod
    def _download_status(item):
        """Return the transfer outcome; file deletion never means transfer failure."""
        download = item.get("download")
        if item.get("stored"):
            return item.get("status", "completed")
        if not download:
            return "failed"
        try:
            state = str(download.state()).casefold()
        except Exception:
            state = ""

        # Explicit Qt terminal states take precedence over filesystem checks.
        if "cancel" in state:
            return "cancelled"
        if "interrupt" in state or "fail" in state:
            # Older Qt versions may briefly expose a stale state after all
            # bytes arrived. The full byte count is sufficient evidence.
            try:
                expected = int(getattr(download, "totalBytes", lambda: 0)() or 0)
                received = int(getattr(download, "receivedBytes", lambda: 0)() or 0)
            except (TypeError, ValueError):
                expected = received = 0
            if expected > 0 and received >= expected:
                return "completed"
            return "failed"
        if "complete" in state:
            return "completed"

        if download.isFinished():
            try:
                expected = int(getattr(download, "totalBytes", lambda: 0)() or 0)
                received = int(getattr(download, "receivedBytes", lambda: 0)() or 0)
            except (TypeError, ValueError):
                expected = received = 0
            if expected > 0 and received >= expected:
                return "completed"
            target = pathlib.Path(item["target"]) if item.get("target") else None
            return "completed" if target and target.is_file() else "failed"
        if bool(getattr(download, "isPaused", lambda: False)()):
            return "paused"
        return "active"

    def save_download_history(self):
        """Persist history and terminal outcomes; live Qt objects are never serialized."""
        records = []
        for item in self.download_items:
            download = item.get("download")
            if not download:
                continue
            status = self._download_status(item)
            if status not in ("completed", "cancelled", "failed", "interrupted"):
                continue
            target = item.get("target")
            if not target:
                continue
            received = int(getattr(download, "receivedBytes", lambda: item.get("last_bytes", 0))() or 0)
            total = int(getattr(download, "totalBytes", lambda: 0)() or 0)
            records.append({
                "id": item.get("id") or secrets.token_hex(12),
                "target": str(target), "received": received, "total": total,
                "status": status,
                "downloaded_at": item.get("downloaded_at", "")
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
        filter_box.addItem(self.tr("Pausiert", "Paused"), "paused")
        filter_box.addItem(self.tr("Abgeschlossen", "Completed"), "finished")
        filter_box.addItem(self.tr("Fehlgeschlagen / abgebrochen", "Failed / cancelled"), "failed")
        search = QLineEdit()
        search.setPlaceholderText(self.tr("Dateiname oder Pfad suchen …", "Search filename or path …"))
        search.setClearButtonEnabled(True)
        top.addWidget(filter_box)
        top.addWidget(search, 1)
        layout.addLayout(top)

        lst = QListWidget()
        lst.setSpacing(9)
        lst.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        lst.setStyleSheet("QListWidget { background:transparent; border:0; outline:0; }")
        layout.addWidget(lst, 1)

        def fmt(n):
            # Decimal units (1 MB = 1,000,000 bytes), matching common
            # download-speed displays and avoiding mislabeled 1024-based units.
            units = ["B", "KB", "MB", "GB", "TB"]
            n = float(max(0, n)); i = 0
            while n >= 1000 and i < len(units) - 1:
                n /= 1000; i += 1
            return f"{n:.1f} {units[i]}"

        def actual_selected():
            qitem = lst.currentItem()
            if qitem is None:
                return None, -1
            stable_id = qitem.data(Qt.ItemDataRole.UserRole)
            for index, entry in enumerate(self.download_items):
                if entry.get("id") == stable_id:
                    return entry, index
            return None, -1

        def update_row(item, now, status):
            """Update an existing download card without replacing its widget."""
            download = item["download"]
            received = getattr(download, "receivedBytes", lambda: 0)()
            total = getattr(download, "totalBytes", lambda: 0)()
            finished = status in ("completed", "cancelled", "failed", "interrupted")
            paused = status == "paused"
            if not finished and not paused:
                # Measure the real byte delta over a rolling time window.
                # Qt's receivedBytes() is cumulative; do not blend rates or
                # apply artificial decay factors, which distort the result.
                samples = item.setdefault("_speed_samples", [])
                if not samples:
                    samples.append((now, received))
                else:
                    last_sample_time, last_sample_bytes = samples[-1]
                    # A counter reset can occur after a restarted transfer.
                    if received < last_sample_bytes:
                        samples.clear()
                        samples.append((now, received))
                    elif now > last_sample_time:
                        samples.append((now, received))

                # Keep enough history for a stable ~2.4 s measurement.
                cutoff = now - 2.4
                while len(samples) > 2 and samples[1][0] < cutoff:
                    samples.pop(0)

                if len(samples) >= 2:
                    first_time, first_bytes = samples[0]
                    elapsed = now - first_time
                    speed = max(0, received - first_bytes) / elapsed if elapsed >= 0.8 else 0
                else:
                    speed = 0
                # If no bytes arrive for a full measurement window, show 0.
                if samples and now - samples[-1][0] >= 2.4:
                    speed = 0
                item["speed"] = speed
                item["last_bytes"] = received
                item["last_time"] = now
            else:
                speed = 0
                item["speed"] = 0

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
            # "missing" is a display-only state: the transfer succeeded,
            # but the file is no longer at its original path (deleted or moved).
            if status == "completed":
                file_check = item.get("_download_manager_file_check")
                if file_check is None or now - file_check[0] >= 2.4:
                    file_check = (now, pathlib.Path(item["target"]).is_file())
                    item["_download_manager_file_check"] = file_check
                display_status = "completed" if file_check[1] else "missing"
            else:
                item.pop("_download_manager_file_check", None)
                display_status = status
            state_labels = {
                "completed": self.tr("Fertig", "Completed"),
                "missing": self.tr("Datei nicht mehr vorhanden", "File no longer present"),
                "cancelled": self.tr("Abgebrochen", "Cancelled"),
                "failed": self.tr("Fehlgeschlagen", "Failed"),
                "interrupted": self.tr("Unterbrochen", "Interrupted"),
                "paused": self.tr("Pausiert", "Paused"),
            }
            state_text = state_labels.get(display_status, f"{percent} %")
            ui["state"].setText(state_text)
            state_color = {
                "completed": "background:#153d32; color:#5ce0a8;",
                "missing": "background:#51401f; color:#ffd27a;",
                "cancelled": "background:#49302d; color:#ffb3a8;",
                "failed": "background:#49302d; color:#ff8f86;",
                "interrupted": "background:#49302d; color:#ffb3a8;",
                "paused": "background:#51401f; color:#ffd27a;",
            }.get(display_status, "background:#173954; color:#73c7ff;")
            ui["state"].setStyleSheet(
                state_color
                + "border:0; border-radius:8px; padding:7px 9px; font-size:11px; font-weight:800;"
            )
            if ui.get("pause") is not None:
                ui["pause"].setText(self.tr("▶ Fortsetzen", "▶ Resume") if paused else self.tr("Ⅱ Pause", "Ⅱ Pause"))
                ui["pause"].setEnabled(not finished)
                ui["pause"].setStyleSheet("background:#254b3d; border:1px solid #398c6c; color:#9af0c7; border-radius:8px; padding:7px 9px; font-weight:700;" if paused else "background:#263f59; border:1px solid #47749c; color:#a8d9ff; border-radius:8px; padding:7px 9px; font-weight:700;")
        def toggle_download(download):
            if download.isFinished():
                return
            try:
                if bool(getattr(download, "isPaused", lambda: False)()):
                    download.resume()
                else:
                    download.pause()
            except Exception as exc:
                QMessageBox.warning(dialog, self.tr("Download", "Download"), str(exc))
            refresh()

        def make_row(item, now):
            target = item["target"]
            card = QWidget()
            card.setStyleSheet("QWidget#downloadCard { background:#202733; border:1px solid #303c4d; border-radius:12px; }")
            card.setObjectName("downloadCard")
            outer = QHBoxLayout(card)
            outer.setContentsMargins(10, 10, 10, 10)
            outer.setSpacing(8)
            card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

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
            name.setMinimumWidth(0)
            name.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            name.setStyleSheet("font-size:14px; font-weight:700; color:#f3f6fb; border:0;")
            name.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            path_label = QLabel(str(target.parent))
            path_label.setToolTip(str(target.parent))
            path_label.setMinimumWidth(0)
            path_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            path_label.setStyleSheet("font-size:11px; color:#8f9daf; border:0;")
            path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            text_col.addWidget(name)
            text_col.addWidget(path_label)
            outer.addLayout(text_col, 3)

            progress_col = QVBoxLayout()
            progress_col.setSpacing(7)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setTextVisible(False)
            details = QLabel()
            details.setMinimumWidth(0)
            details.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            details.setStyleSheet("font-size:11px; color:#aab6c5; border:0;")
            progress_col.addWidget(bar)
            progress_col.addWidget(details)
            outer.addLayout(progress_col, 2)

            pause_btn = QPushButton(self.tr("Ⅱ Pause", "Ⅱ Pause"))
            pause_btn.setMinimumWidth(92)
            pause_btn.setMaximumWidth(104)
            pause_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            pause_btn.clicked.connect(lambda checked=False, d=item["download"]: toggle_download(d))
            outer.addWidget(pause_btn)

            state = QLabel()
            state.setAlignment(Qt.AlignmentFlag.AlignCenter)
            # Reserve enough horizontal space for the full German status
            # "Datei nicht mehr vorhanden", including the label's padding.
            # The previous 116–132 px cap clipped the beginning/end of the text.
            state.setMinimumWidth(205)
            state.setMaximumWidth(205)
            state.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            outer.addWidget(state)
            item["_download_ui"] = {"bar": bar, "details": details, "state": state, "pause": pause_btn, "card": card}
            return card

        render_state = {"pending": []}
        render_timer = QTimer(dialog)
        render_timer.setSingleShot(True)

        def build_pending_rows():
            """Create a small batch of cards so the manager stays responsive."""
            pending = render_state["pending"]
            if not pending:
                return
            batch = pending[:8]
            del pending[:len(batch)]
            now = time.monotonic()
            current_items = {entry.get("id"): entry for entry in self.download_items}
            current_ids = {
                lst.item(row).data(Qt.ItemDataRole.UserRole)
                for row in range(lst.count())
            }
            for wanted_position, _index, queued_item, queued_status in batch:
                stable_id = queued_item.get("id")
                item = current_items.get(stable_id)
                if item is None:
                    continue
                # A refresh may already have inserted this row while a batch
                # was waiting in the event queue. Never create it twice.
                if stable_id in current_ids:
                    continue
                status = queued_status
                widget = make_row(item, now)
                qitem = QListWidgetItem()
                qitem.setData(Qt.ItemDataRole.UserRole, stable_id)
                qitem.setSizeHint(widget.sizeHint())
                insert_at = min(wanted_position, lst.count())
                lst.insertItem(insert_at, qitem)
                lst.setItemWidget(qitem, widget)
                current_ids.add(stable_id)
                update_row(item, now, status)
            if render_state["pending"]:
                render_timer.start(8)

        render_timer.timeout.connect(build_pending_rows)

        def refresh():
            query = search.text().strip().casefold()
            mode = filter_box.currentData()
            now = time.monotonic()
            # Resolve each status exactly once per refresh. The same result is
            # used for counters, filtering and the corresponding card update.
            statuses = [self._download_status(entry) for entry in self.download_items]
            active_count = statuses.count("active")
            paused_count = statuses.count("paused")
            finished_count = statuses.count("completed")
            stat_active.setText("●  " + self.tr("Aktiv", "Active") + f"  {active_count}   " + self.tr("Pausiert", "Paused") + f"  {paused_count}")
            stat_finished.setText("✓  " + self.tr("Fertig", "Completed") + f"  {finished_count}")
            stat_total.setText(self.tr("Gesamt", "Total") + f"  {len(self.download_items)}")

            visible = []
            for index, (item, status) in enumerate(zip(self.download_items, statuses)):
                target = item["target"]
                searchable = (target.name + " " + str(target.parent)).casefold()
                if query and query not in searchable:
                    continue
                if mode == "active" and status != "active":
                    continue
                if mode == "paused" and status != "paused":
                    continue
                if mode == "finished" and status != "completed":
                    continue
                if mode == "failed" and status not in ("failed", "cancelled", "interrupted"):
                    continue
                visible.append((index, item, status))

            # Newest downloads are stored at the end of download_items;
            # show them first without changing their stable backing indices.
            visible.reverse()

            wanted_by_id = {item.get("id"): item for _index, item, _status in visible}
            entries_by_id = {entry.get("id"): entry for entry in self.download_items}

            # Remove only rows that are no longer visible.
            for row in range(lst.count() - 1, -1, -1):
                qitem = lst.item(row)
                stable_id = qitem.data(Qt.ItemDataRole.UserRole)
                if stable_id not in wanted_by_id:
                    widget = lst.itemWidget(qitem)
                    removed = lst.takeItem(row)
                    if widget is not None:
                        entry = entries_by_id.get(stable_id)
                        if entry is not None:
                            ui = entry.get("_download_ui")
                            if ui is not None and ui.get("card") is widget:
                                entry["_download_ui"] = None
                        widget.deleteLater()
                    del removed

            current_by_id = {
                lst.item(row).data(Qt.ItemDataRole.UserRole): lst.item(row)
                for row in range(lst.count())
            }

            # Refresh existing cards immediately; missing cards are queued and
            # created in short batches after the dialog's event loop starts.
            for _index, item, status in visible:
                if item.get("id") in current_by_id and item.get("_download_ui") is not None:
                    update_row(item, now, status)

            render_state["pending"] = [
                (position, index, item, status)
                for position, (index, item, status) in enumerate(visible)
                if item.get("id") not in current_by_id
            ]
            if render_state["pending"] and not render_timer.isActive():
                render_timer.start(0)
            elif not render_state["pending"] and render_timer.isActive():
                render_timer.stop()

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
            self.download_items[:] = [entry for entry in self.download_items if self._download_status(entry) != "completed"]
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

        def refresh_after_history_loaded():
            try:
                if dialog.isVisible():
                    refresh()
            except RuntimeError:
                pass

        self._start_download_history_load(refresh_after_history_loaded)
        refresh()

        def update_selection_style(*_args):
            for row in range(lst.count()):
                qitem = lst.item(row)
                widget = lst.itemWidget(qitem)
                if widget is None:
                    continue
                chosen = qitem is lst.currentItem()
                widget.setStyleSheet(
                    "QWidget#downloadCard { background:#294968; border:3px solid #70c5ff; border-radius:12px; }" if chosen else
                    "QWidget#downloadCard { background:#202733; border:1px solid #303c4d; border-radius:12px; }"
                )
        lst.currentItemChanged.connect(update_selection_style)
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
        # Consume a path selected by "Link speichern unter…" immediately.
        # This prevents a cancelled security warning (or another early exit)
        # from leaking that path into the next, unrelated download.
        explicit_target = getattr(self, "_next_download_path", None)
        if explicit_target is not None:
            self._next_download_path = None

        suggested = safe_download_filename(download.suggestedFileName() or "download")
        risky_extensions = {
            ".appimage", ".apk", ".bat", ".bin", ".cmd", ".deb", ".dmg",
            ".dll", ".dylib", ".exe", ".jar", ".msi", ".pkg", ".ps1",
            ".py", ".pyz", ".rpm", ".run", ".sh", ".so", ".desktop",
        }
        if pathlib.Path(suggested).suffix.lower() in risky_extensions and self.settings_data.get("warn_executable_downloads", True):
            try:
                source_host = download.url().host() or download.url().toString()
            except Exception:
                source_host = ""

            # Eigener Sicherheitsdialog im LunaSurfer-Graphitdesign.
            warning = QDialog(self)
            warning.setWindowTitle(self.tr("Sicherheitswarnung beim Download", "Download security warning"))
            warning.setModal(True)
            warning.setMinimumWidth(490)
            warning.setStyleSheet("""
                QDialog { background: #171d28; color: #e8eef8; }
                QLabel { color: #e8eef8; }
                QLabel#warningIcon {
                    background: #3a2b18; color: #ffbd59; border: 1px solid #785326;
                    border-radius: 12px; font-size: 25px; font-weight: 700;
                    min-width: 48px; max-width: 48px; min-height: 48px; max-height: 48px;
                }
                QLabel#warningTitle { font-size: 17px; font-weight: 700; color: #f4f7fc; }
                QLabel#warningFile {
                    background: #202b3b; border: 1px solid #344b69; border-radius: 7px;
                    padding: 9px 11px; color: #9dccff; font-weight: 600;
                }
                QLabel#warningSource { color: #9eacc0; }
                QCheckBox { color: #cbd6e5; spacing: 9px; padding: 5px 0; }
                QCheckBox::indicator {
                    width: 17px; height: 17px; border-radius: 4px;
                    border: 1px solid #60738d; background: #202b3b;
                }
                QCheckBox::indicator:checked { background: #2684e8; border-color: #55a5ff; }
                QPushButton {
                    background: #26364c; color: #eaf2fc; border: 1px solid #405a7b;
                    border-radius: 7px; padding: 9px 17px; min-width: 112px;
                    font-weight: 600;
                }
                QPushButton:hover { background: #324a68; border-color: #6ca8ed; }
                QPushButton#acceptDownload {
                    background: #176fc5; border-color: #318fe8; color: white;
                }
                QPushButton#acceptDownload:hover { background: #2385e2; }
            """)

            layout = QVBoxLayout(warning)
            layout.setContentsMargins(22, 20, 22, 18)
            layout.setSpacing(13)

            header = QHBoxLayout()
            header.setSpacing(13)
            icon_label = QLabel("!")
            icon_label.setObjectName("warningIcon")
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            header.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)

            heading_column = QVBoxLayout()
            heading_column.setSpacing(4)
            heading = QLabel(self.tr("Diese Datei kann gefährlich sein", "This file may be dangerous"))
            heading.setObjectName("warningTitle")
            heading_column.addWidget(heading)
            intro = QLabel(self.tr(
                "Die Datei kann Programme oder Skripte ausführen. Lade sie nur herunter, wenn du der Quelle vertraust.",
                "This file can run programs or scripts. Only download it if you trust the source."
            ))
            intro.setWordWrap(True)
            intro.setMinimumWidth(365)
            heading_column.addWidget(intro)
            header.addLayout(heading_column, 1)
            layout.addLayout(header)

            file_label = QLabel(suggested)
            file_label.setObjectName("warningFile")
            file_label.setWordWrap(True)
            file_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(file_label)

            source_label = QLabel(self.tr("Download-Quelle: ", "Download source: ") + (source_host or self.tr("Unbekannt", "Unknown")))
            source_label.setObjectName("warningSource")
            source_label.setWordWrap(True)
            layout.addWidget(source_label)

            disable_warning = QCheckBox(self.tr(
                "Diese Sicherheitswarnung künftig nicht mehr anzeigen",
                "Do not show this security warning again"
            ))
            layout.addWidget(disable_warning)

            buttons = QHBoxLayout()
            buttons.addStretch(1)
            cancel_button = QPushButton(self.tr("Abbrechen", "Cancel"))
            accept_button = QPushButton(self.tr("Trotzdem herunterladen", "Download anyway"))
            accept_button.setObjectName("acceptDownload")
            cancel_button.clicked.connect(warning.reject)
            accept_button.clicked.connect(warning.accept)
            buttons.addWidget(cancel_button)
            buttons.addWidget(accept_button)
            layout.addLayout(buttons)

            answer = warning.exec()
            if answer != QDialog.DialogCode.Accepted:
                download.cancel()
                self.statusBar().showMessage(self.tr("Download abgebrochen.", "Download cancelled."), 5000)
                return
            if disable_warning.isChecked():
                self.settings_data["warn_executable_downloads"] = False
                write_json(CONFIG_FILE, self.settings_data)
        if explicit_target is not None:
            target = pathlib.Path(explicit_target)
            target = target.parent / safe_download_filename(target.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            download.setDownloadDirectory(str(target.parent))
            download.setDownloadFileName(target.name)
            download.accept()
            self.download_items.append({"id": secrets.token_hex(12), "download": download, "target": target, "last_bytes": 0, "last_time": time.monotonic(), "speed": 0, "status": "active"})
            self.watch_download_finished(download, target)
            self.statusBar().showMessage(f"Download gestartet: {target.name}", 5000)
            return
        if self.settings_data.get("ask_download_location", False):
            selected, _ = QFileDialog.getSaveFileName(self, "Download speichern unter", str(self.download_dir / suggested))
            if not selected:
                download.cancel()
                return
            target = pathlib.Path(selected)
            target = target.parent / safe_download_filename(target.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            download.setDownloadDirectory(str(target.parent))
            download.setDownloadFileName(target.name)
            download.accept()
            self.download_items.append({"id": secrets.token_hex(12), "download": download, "target": target, "last_bytes": 0, "last_time": time.monotonic(), "speed": 0, "status": "active"})
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
        self.download_items.append({"id": secrets.token_hex(12), "download": download, "target": target, "last_bytes": 0, "last_time": time.monotonic(), "speed": 0, "status": "active"})
        self.watch_download_finished(download, target)
        self.statusBar().showMessage(f"Download gestartet: {target.name}", 5000)

    def watch_download_finished(self, download, target):
        """Handle each terminal transition once and never label a failed transfer complete."""
        def check_finished():
            if not download.isFinished():
                return
            entry = next((entry for entry in self.download_items if entry.get("download") is download), None)
            if entry is None or entry.get("_finish_handled"):
                return
            entry["_finish_handled"] = True
            entry["downloaded_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            status = self._download_status(entry)
            self.save_download_history()
            if status == "completed":
                self.statusBar().showMessage(f"Download fertig: {target.name}", 8000)
                if self.settings_data.get("show_download_complete_popup", True):
                    QMessageBox.information(
                        self,
                        self.tr("Download fertig", "Download complete"),
                        self.tr("Der Download wurde abgeschlossen:", "The download has finished:")
                        + f"\\n{target.name}\\n\\n"
                        + self.tr("Gespeichert in:", "Saved in:")
                        + f"\\n{target.parent}"
                    )
            else:
                self.statusBar().showMessage(
                    self.tr("Download fehlgeschlagen oder abgebrochen.", "Download failed or cancelled."),
                    8000
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
        for entry in self.download_items:
            if self._download_status(entry) in ("active", "paused"):
                entry["status"] = "interrupted"
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

    # New vaults use Argon2id. Existing version-1 vaults without a KDF marker
    # remain readable as PBKDF2-HMAC-SHA256 and are migrated after successful unlock.
    PASSWORD_KDF = "argon2id"
    ARGON2_TIME_COST = 4
    ARGON2_MEMORY_COST = 131072  # KiB (128 MiB)
    ARGON2_PARALLELISM = 1

    def _password_key(self, master_password, salt, kdf_name="argon2id", params=None):
        params = params or {}
        if kdf_name == "pbkdf2-sha256":
            iterations = int(params.get("iterations", 600000))
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
            raw = kdf.derive(master_password.encode("utf-8"))
        elif kdf_name == "argon2id":
            raw = hash_secret_raw(
                secret=master_password.encode("utf-8"),
                salt=salt,
                time_cost=int(params.get("time_cost", self.ARGON2_TIME_COST)),
                memory_cost=int(params.get("memory_cost", self.ARGON2_MEMORY_COST)),
                parallelism=int(params.get("parallelism", self.ARGON2_PARALLELISM)),
                hash_len=32,
                type=Argon2Type.ID,
                version=19,
            )
        else:
            raise ValueError("Unsupported password KDF")
        return base64.urlsafe_b64encode(raw)

    def _password_kdf_metadata(self):
        return {
            "kdf": self.PASSWORD_KDF,
            "kdf_params": {
                "time_cost": self.ARGON2_TIME_COST,
                "memory_cost": self.ARGON2_MEMORY_COST,
                "parallelism": self.ARGON2_PARALLELISM,
            },
        }

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
                old_kdf = data.get("kdf", "pbkdf2-sha256")
                old_params = data.get("kdf_params") or ({"iterations": 600000} if old_kdf in ("pbkdf2-sha256", "PBKDF2-HMAC-SHA256") else {})
                if old_kdf == "PBKDF2-HMAC-SHA256":
                    old_kdf = "pbkdf2-sha256"
                fernet = Fernet(self._password_key(master, salt, old_kdf, old_params))
                payload = json.loads(fernet.decrypt(data["token"].encode()).decode("utf-8"))
            except (InvalidToken, ValueError, KeyError, TypeError, json.JSONDecodeError):
                QMessageBox.warning(self, self.tr("Falsches Passwort", "Incorrect password"), self.tr("Das Master-Passwort ist falsch oder die Passwortdatei beschädigt.", "The master password is incorrect or the vault is damaged."))
                return False
            self._password_fernet = fernet
            self._password_entries = payload if isinstance(payload, list) else []
            # Upgrade legacy KDFs and older Argon2id settings only after a
            # successful unlock, preserving the existing master password/entries.
            current_params = self._password_kdf_metadata()["kdf_params"]
            stored_params = data.get("kdf_params") or {}
            needs_upgrade = (
                old_kdf != self.PASSWORD_KDF
                or any(int(stored_params.get(key, -1)) != value
                       for key, value in current_params.items())
            )
            if needs_upgrade:
                new_salt = secrets.token_bytes(16)
                self._password_fernet = Fernet(self._password_key(master, new_salt))
                self._save_password_entries(new_salt)
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
        envelope = {"version": 2, "salt": base64.b64encode(salt).decode(), "token": token}
        envelope.update(self._password_kdf_metadata())
        write_json(PASSWORDS_FILE, envelope)
        self._secure_password_storage_permissions()

    def _password_export_key(self, export_password, salt):
        return self._password_key(export_password, salt, self.PASSWORD_KDF, self._password_kdf_metadata()["kdf_params"])

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
            old_kdf = data.get("kdf", "pbkdf2-sha256")
            old_params = data.get("kdf_params") or ({"iterations": 600000}
                if old_kdf in ("pbkdf2-sha256", "PBKDF2-HMAC-SHA256") else {})
            if old_kdf == "PBKDF2-HMAC-SHA256":
                old_kdf = "pbkdf2-sha256"
            old_cipher = Fernet(self._password_key(old_password, old_salt, old_kdf, old_params))
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
            envelope = {
                "version": 2,
                "salt": base64.b64encode(new_salt).decode("ascii"),
                "token": token
            }
            envelope.update(self._password_kdf_metadata())
            write_json(PASSWORDS_FILE, envelope)
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
                        **self._password_kdf_metadata(),
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
            export_kdf = envelope.get("kdf", "pbkdf2-sha256")
            export_params = envelope.get("kdf_params") or ({"iterations": int(envelope.get("iterations", 600000))} if export_kdf in ("pbkdf2-sha256", "PBKDF2-HMAC-SHA256") else {})
            if export_kdf == "PBKDF2-HMAC-SHA256":
                export_kdf = "pbkdf2-sha256"
            cipher = Fernet(self._password_key(export_password, salt, export_kdf, export_params))
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
            if not channel_source:
                self._password_debug_log("capture_script_disabled", "reason=qwebchannel_resource_unavailable")
                return
            capture_source = channel_source + "\n;\n" + script
            capture_script = QWebEngineScript()
            capture_script.setName("LunaSurferPasswordManagerCapture")
            capture_script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentReady)
            capture_script.setWorldId(QWebEngineScript.ScriptWorldId.ApplicationWorld)
            capture_script.setRunsOnSubFrames(False)
            capture_script.setSourceCode(capture_source)
            collection.insert(capture_script)
            self._password_debug_log(
                "capture_script_registered",
                "injection=document_ready world=application subframes=false qwebchannel_embedded=true"
            )
            # Also start on the already-loaded document; the persistent script
            # handles all subsequent navigations automatically.
            page.runJavaScript(capture_source, QWebEngineScript.ScriptWorldId.ApplicationWorld)
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
                "if (window.__lunaPasswordRescan) window.__lunaPasswordRescan();",
                QWebEngineScript.ScriptWorldId.ApplicationWorld
            )
        except Exception:
            pass


    def show_manual(self):
        """Display the built-in guide in the selected application language."""
        selected_language = self.settings_data.get("language", "de")
        en = selected_language == "en"
        dialog = QDialog(self)
        dialog.setWindowTitle(self.tr("LunaSurfer – Anleitung", "LunaSurfer – User guide"))
        dialog.resize(900, 760)
        dialog.setStyleSheet("QDialog{background:#11151d;color:#e8edf5} QTextBrowser{background:#171e29;color:#e8edf5;border:1px solid #344158;border-radius:10px;padding:18px} QPushButton{background:#293548;color:#edf2f8;border:1px solid #40516a;border-radius:8px;padding:9px 20px;min-width:90px} QPushButton:hover{border-color:#a879f5;background:#3b4b63}")
        layout = QVBoxLayout(dialog)
        browser = QTextBrowser(dialog)
        browser.setReadOnly(True)
        browser.setOpenExternalLinks(True)
        style = "<style>body{font-family:sans-serif;line-height:1.55;color:#e8edf5;font-size:14px}h1{color:#c7a6ff;font-size:27px}h2{color:#b99af0;font-size:19px;margin-top:26px;border-bottom:1px solid #39465b;padding-bottom:5px}p,li{color:#d5dbea}.tip{background:#222d3d;border-left:4px solid #9870d5;padding:10px 14px;border-radius:5px}</style>"
        if selected_language == "pt":
            content = """<h1>LunaSurfer – Manual do utilizador</h1>
<p>Este manual explica as principais funções do LunaSurfer e as opções disponíveis nas Definições.</p>
<h2>1. Geral</h2><ul><li><b>Idioma:</b> seleciona o idioma da interface, menus e caixas de diálogo.</li><li><b>Ao iniciar:</b> pode abrir a página inicial, restaurar a última sessão ou abrir uma página em branco.</li><li><b>Página inicial:</b> define o endereço aberto pelo botão Início.</li><li><b>Motor de pesquisa:</b> escolhe o serviço utilizado nas pesquisas da barra de endereços.</li><li><b>Serviço de tradução:</b> o Google traduz a página completa; o MyMemory traduz secções de texto visíveis e tem um limite diário gratuito.</li><li><b>Aspeto do navegador:</b> permite escolher os temas disponíveis.</li><li><b>Pasta de transferências:</b> define onde são guardados os ficheiros transferidos.</li></ul>
<h2>2. Segurança e privacidade</h2><ul><li><b>Bloquear pop-ups:</b> bloqueia janelas emergentes indesejadas.</li><li><b>JavaScript:</b> permite que os sites executem scripts; desativá-lo pode limitar algumas páginas.</li><li><b>User-Agent:</b> gere a identificação apresentada aos sites, sem alterar o motor do navegador.</li><li><b>Proteção contra impressão digital:</b> limita a exposição de identificadores do navegador e do hardware.</li></ul>
<h2>3. Gestor de palavras-passe</h2><ul><li>As credenciais guardadas são encriptadas localmente e protegidas pela palavra-passe principal.</li><li>Guarde a palavra-passe principal em segurança; não é possível recuperá-la.</li><li>O gestor pode ter de ser desbloqueado antes do preenchimento automático.</li></ul>
<h2>4. Permissões de sites</h2><p>Configure as permissões de câmara, microfone, localização e notificações. Permita apenas sites em que confia.</p>
<h2>5. Dados do navegador</h2><p>Pode limpar o histórico, a cache e os cookies. Os marcadores e as palavras-passe guardadas são mantidos.</p>"""
        elif selected_language == "tr":
            content = """<h1>LunaSurfer – Kullanım kılavuzu</h1>
<p>Bu kılavuz, LunaSurfer tarayıcısının temel işlevlerini ve Ayarlar bölümündeki seçenekleri açıklar.</p>
<h2>1. Genel</h2>
<ul>
<li><b>Dil:</b> Tarayıcı arayüzünün dilini seçer. Değişiklikler kaydedildikten sonra menüler ve iletişim kutuları seçilen dili kullanır.</li>
<li><b>Başlangıçta:</b> Ana sayfayı açabilir, son oturumu geri yükleyebilir veya boş bir sayfa başlatabilirsiniz.</li>
<li><b>Ana sayfa:</b> Ana sayfa düğmesiyle açılacak adresi belirler. Tam bir URL girin.</li>
<li><b>Arama motoru:</b> Adres çubuğuna yazılan aramalar için Google, DuckDuckGo veya Bing'i seçer.</li>
<li><b>Çeviri sağlayıcısı:</b> Google Translate tüm sayfayı çevirir. MyMemory görünür metin bölümlerini çevirir ve günlük ücretsiz kullanım sınırına sahiptir.</li>
<li><b>Tarayıcı görünümü:</b> Koyu, Açık, Luna, Grafit Mavisi veya Okyanus tasarımını seçer.</li>
<li><b>İndirme klasörü:</b> İndirilen dosyaların kaydedileceği klasörü belirler. Her indirme için ayrı konum sorulmasını da etkinleştirebilirsiniz.</li>
</ul>
<h2>2. Güvenlik ve gizlilik</h2>
<ul>
<li><b>Açılır pencereleri engelle:</b> İstenmeyen açılır pencereleri engeller.</li>
<li><b>JavaScript:</b> Web sitelerinin betik çalıştırmasına izin verir. Devre dışı bırakılması bazı sitelerin işlevlerini bozabilir.</li>
<li><b>User-Agent:</b> Tarayıcının web sitelerine sunduğu tanımlayıcıyı yönetir. Bu ayar tarayıcı motorunu veya gerçek yeteneklerini değiştirmez.</li>
<li><b>Parmak izi koruması:</b> Canvas, ses, WebGL ve donanım tanımlayıcılarının açığa çıkmasını sınırlar. Değişiklikler hemen uygulanır.</li>
</ul>
<h2>3. Parola yöneticisi</h2>
<ul>
<li>Kaydedilmiş giriş bilgileri yerel olarak şifrelenir ve ana parola ile korunur.</li>
<li>Ana parolanızı güvenli bir yerde saklayın. Kaybedilirse şifreli kasa kurtarılamayabilir.</li>
<li>Otomatik doldurma için parola yöneticisinin kilidini açmanız gerekebilir.</li>
</ul>
<h2>4. Web sitesi izinleri</h2>
<p>Kamera, mikrofon, konum ve bildirim izinleri için Sor, İzin ver veya Engelle seçeneklerini kullanın. Yalnızca güvendiğiniz sitelere izin verin.</p>
<h2>5. Tarayıcı verileri</h2>
<p>Geçmişi, önbelleği ve çerezleri ayrı ayrı veya birlikte temizleyebilirsiniz. Yer imleri ve kaydedilmiş parolalar tarayıcı verilerini temizleme işleminde korunur.</p>
<h2>6. Yer imleri ve indirmeler</h2>
<p>Yer imlerini klasörlerle düzenleyebilir, içe ve dışa aktarabilirsiniz. İndirme yöneticisi etkin ve tamamlanmış indirmeleri gösterir; dosyaları veya indirme klasörlerini buradan açabilirsiniz.</p>
"""
        elif en:
            content = """<h1>LunaSurfer – Complete user guide</h1>


<p>This guide describes the browser and every control currently shown on the Settings page, plus the separate Protection &amp; Privacy panel. The names below correspond to the English interface.</p>
<h2>1. General</h2>
<ul>
<li><b>Language:</b> switches the LunaSurfer interface between Deutsch, English, Français, Italiano, Nederlands, Español, Português, Polski and Türkçe. The guide follows this choice and opens in one language only.</li>
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
<li><b>Enable ad blocker:</b> turns filtering on or off.</li><li><b>Blocking strength:</b> Standard, Strong, Very strong, Super strong, Mega strong or Ultra strong. Higher levels filter more patterns but can break site features or hide content.</li>
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
        elif self.settings_data.get("language", "de") == "fr":
            content = """<h1>LunaSurfer – Guide complet</h1>
<p>Ce guide décrit le navigateur, les options de la page Paramètres et le panneau séparé Protection et confidentialité. Les noms correspondent à l’interface française.</p>
<h2>1. Général</h2>
<ul>
<li><b>Langue :</b> modifie la langue de l’interface LunaSurfer. Le guide suit ce choix et s’affiche dans une seule langue.</li>
<li><b>Au démarrage :</b> <i>Ouvrir la page d’accueil</i> charge la page d’accueil configurée ; <i>Restaurer la dernière session</i> rouvre la session précédente ; <i>Ouvrir une page vierge</i> démarre sans charger de site web.</li>
<li><b>Page d’accueil :</b> définit la page ouverte avec le bouton Accueil et, selon le comportement de démarrage, dans un nouvel onglet. Saisissez une adresse complète, y compris https://.</li>
<li><b>Moteur de recherche :</b> choisit Google, DuckDuckGo ou Bing pour les recherches saisies dans la barre d’adresse.</li>
<li><b>Service de traduction :</b> <i>Google Traduction (page web entière)</i> ouvre la page complète dans Google Traduction. <i>MyMemory</i> traduit les sections de texte visibles sans clé API et dispose d’un quota quotidien gratuit. La qualité et la disponibilité dépendent du service.</li>
<li><b>Apparence du navigateur :</b> choisit l’apparence de la fenêtre : Sombre (standard), Clair (classique), Luna (moderne), Bleu graphite (élégant) ou Océan (bleu sarcelle).</li>
<li><b>Apparence des sites web :</b> choisit le thème clair ou sombre des pages. Ce réglage est indépendant de l’apparence du navigateur et des couleurs propres aux sites.</li>
<li><b>Afficher la barre des favoris sous la barre d’adresse :</b> affiche ou masque la barre des favoris.</li>
<li><b>Dossier de téléchargement :</b> définit le dossier dans lequel les fichiers téléchargés sont enregistrés. Utilisez <i>Choisir un dossier…</i> pour sélectionner un autre emplacement.</li>
<li><b>Demander où enregistrer chaque téléchargement :</b> demande un emplacement à chaque nouveau téléchargement. Sinon, le dossier configuré est utilisé.</li>
<li><b>Zoom par défaut :</b> définit le zoom initial des pages. Chaque onglet peut ensuite utiliser son propre niveau de zoom.</li>
<li><b>Taille de police par défaut :</b> définit la taille initiale du texte des pages web.</li>
<li><b>Lisibilité des sites web :</b> <i>Normal</i> ne modifie pas les pages. Les options de contraste doux, plus léger et atténué appliquent des ajustements progressifs. Revenez à Normal si un site s’affiche incorrectement.</li>
<li><b>Couleurs des sites web :</b> <i>Original</i> conserve les couleurs du site ; <i>Mode noir</i> demande des arrière-plans noirs. Certains sites peuvent être affichés imparfaitement en mode sombre forcé.</li>
</ul>
<h2>2. Sécurité et autorisations</h2>
<ul>
<li><b>Bloquer les fenêtres pop-up :</b> bloque les fenêtres indésirables. Désactivez temporairement cette option uniquement si un site fiable en a besoin pour une connexion ou un paiement.</li>
<li><b>Activer JavaScript :</b> autorise l’exécution des scripts. De nombreux sites modernes en ont besoin ; sa désactivation peut empêcher les menus, connexions, vidéos et autres fonctions de fonctionner.</li>
<li><b>Envoyer une demande Do Not Track :</b> envoie le signal DNT facultatif. Les sites web ne sont pas obligés de le respecter.</li>
<li><b>Demander confirmation à la fermeture d’un onglet :</b> affiche une confirmation avant la fermeture pour éviter les fermetures accidentelles.</li>
</ul>
<h2>3. Gestion du User-Agent</h2>
<ul>
<li><b>Paramètre de confidentialité par défaut (User-Agent Chrome réduit) :</b> présente une identification de type Chrome avec moins de détails sur la version et la plateforme.</li>
<li><b>User-Agent natif du navigateur :</b> utilise la chaîne User-Agent normale du moteur du navigateur.</li>
<li><b>User-Agent personnalisé :</b> utilise exactement la chaîne saisie dans Valeur personnalisée. Saisissez une chaîne complète et valide ; une valeur vide ne peut pas être enregistrée.</li>
<li><b>Actuel :</b> affiche le User-Agent effectivement utilisé. Vous pouvez le sélectionner et le copier.</li>
<li><b>Important :</b> le User-Agent modifie l’identification du navigateur, pas son moteur ni ses capacités. Lorsque la protection contre l’empreinte numérique est active, les Client Hints peuvent également être réduits.</li>
</ul>
<h2>4. Gestionnaire de mots de passe</h2>
<ul>
<li><b>Ouvrir le gestionnaire de mots de passe… :</b> ouvre le coffre chiffré des identifiants de sites web. Déverrouillez-le avec le mot de passe principal pour gérer les entrées enregistrées.</li>
<li><b>Supprimer tous les mots de passe… :</b> supprime tous les identifiants enregistrés. Le mot de passe principal est conservé. Cette opération ne modifie pas les mots de passe stockés sur les sites web.</li>
<li><b>Proposer d’enregistrer les mots de passe après une connexion réussie :</b> détermine si LunaSurfer propose d’enregistrer un identifiant après une connexion détectée.</li>
<li><b>Le gestionnaire doit être déverrouillé avant le remplissage automatique :</b> si cette option est activée, déverrouillez le coffre avant le remplissage automatique. Sinon, LunaSurfer demande le mot de passe principal lorsque vous sélectionnez un champ de connexion.</li>
<li>Les identifiants sont associés au site web concerné, et pas seulement à une adresse e-mail. Une même adresse peut être utilisée sur plusieurs services : chacun doit avoir sa propre entrée. Vérifiez toujours le site et le compte avant d’accepter une proposition d’enregistrement ou de mise à jour.</li>
<li>Conservez soigneusement le mot de passe principal. S’il est perdu, le coffre chiffré peut être irrécupérable. Effectuez des sauvegardes sûres et ne partagez jamais ce mot de passe.</li>
</ul>
<h2>5. Autorisations des sites web</h2>
<p><b>Modifier les autorisations enregistrées des sites web…</b> ouvre la gestion des décisions mémorisées pour chaque site. Les réglages généraux s’appliquent lorsqu’un site demande un accès :</p>
<ul>
<li><b>Caméra, Microphone, Localisation, Notifications :</b> chaque autorisation peut être réglée sur <i>Demander</i>, <i>Autoriser</i> ou <i>Bloquer</i>. Demander affiche une invite ; Autoriser accorde l’accès ; Bloquer le refuse. N’accordez l’accès qu’aux sites fiables et lorsque la fonction est nécessaire.</li>
<li><b>Envoyer une demande Do Not Track :</b> transmet le signal DNT facultatif. Les sites ne sont pas tenus de le respecter.</li>
<li><b>Comportement du navigateur – Demander confirmation à la fermeture d’un onglet :</b> demande une confirmation avant de fermer un onglet.</li>
</ul>
<h2>6. Confidentialité et données du navigateur</h2>
<ul>
<li><b>Mode des cookies – Autoriser tous les cookies :</b> autorise les cookies internes et tiers. La compatibilité est meilleure, mais davantage de données peuvent être partagées entre les sites.</li>
<li><b>Bloquer les cookies tiers :</b> bloque les cookies provenant d’autres domaines que celui du site visité. Certains contenus intégrés ou processus de connexion peuvent être affectés.</li>
<li><b>Bloquer tous les cookies :</b> empêche les sites d’enregistrer des cookies et peut perturber les connexions, préférences et paniers d’achat.</li>
<li><b>Autoriser uniquement les cookies de session :</b> autorise les cookies temporaires de session, mais limite les cookies persistants.</li>
<li><b>Effacer l’historique :</b> supprime l’historique de navigation enregistré.</li>
<li><b>Effacer le cache :</b> supprime les ressources de pages mises en cache. Le prochain chargement peut être plus lent.</li>
<li><b>Effacer les cookies :</b> supprime les cookies des sites web et peut vous déconnecter ou réinitialiser les préférences des sites.</li>
<li><b>Tout effacer :</b> nettoie les données disponibles de l’historique, du cache et des cookies. Lisez attentivement la demande de confirmation.</li>
<li><b>Effacer automatiquement l’historique/le cache/les cookies à la fermeture :</b> chaque option efface séparément la catégorie correspondante lorsque LunaSurfer se ferme.</li>
<li><b>Mémoriser la taille et la position de la fenêtre à la fermeture :</b> restaure la géométrie de la fenêtre au prochain démarrage.</li>
<li><b>Utiliser LunaSurfer comme navigateur par défaut :</b> demande à l’environnement de bureau d’enregistrer LunaSurfer comme navigateur préféré pour les liens web.</li>
</ul>
<h2>7. Panneau Protection et confidentialité</h2>
<h3>Bloqueur de publicités</h3>
<ul>
<li><b>Activer le bloqueur de publicités :</b> active ou désactive le filtrage.</li>
<li><b>Intensité du blocage :</b> les niveaux plus élevés filtrent davantage de règles, mais peuvent perturber certaines fonctions ou masquer du contenu.</li>
<li><b>Règles de blocage personnalisées :</b> ajoutez des domaines ou règles séparés par des points-virgules.</li>
<li><b>Domaines autorisés :</b> liste les domaines exclus du blocage. Utilisez cette option pour les sites fiables qui ne fonctionnent pas correctement.</li>
</ul>
<h3>Protection contre l’empreinte numérique</h3>
<ul>
<li><b>Activer la protection :</b> réduit certains signaux d’identification du navigateur et de l’appareil.</li>
<li><b>Standard :</b> protection de Canvas, de l’audio et des informations matérielles de base.</li>
<li><b>Renforcée :</b> ajoute le masquage des identifiants WebGL.</li>
<li><b>Maximale :</b> protège davantage les détails matériels et les Client Hints du navigateur.</li>
<li>Les modifications sont appliquées immédiatement ; un redémarrage n’est normalement pas nécessaire. Une protection plus forte peut réduire la compatibilité et ne garantit pas l’anonymat.</li>
</ul>
<h2>8. Enregistrement et application des modifications</h2>
<p>Utilisez <b>Enregistrer</b> pour mémoriser les choix de la page Paramètres. Utilisez <b>Annuler</b> pour fermer sans enregistrer les modifications en attente. Certains réglages s’appliquent immédiatement ; d’autres prennent effet après le rechargement des pages ouvertes. Le panneau de protection possède ses propres boutons Enregistrer et Annuler.</p>
<h2>9. Autres fonctions du navigateur</h2>
<ul>
<li><b>Favoris :</b> utilisez l’étoile pour enregistrer une page. Le gestionnaire de favoris permet d’organiser les dossiers et d’importer ou d’exporter les favoris.</li>
<li><b>Téléchargements :</b> consultez les transferts en cours et terminés dans le gestionnaire de téléchargements. En cas d’échec, vérifiez le dossier de destination et l’espace disque disponible.</li>
<li><b>Traduction des sites web :</b> utilisez le bouton de traduction pour choisir une langue cible ou revenir à la page d’origine. La traduction dépend du service sélectionné et peut contenir des erreurs.</li>
<li><b>Onglets et raccourcis :</b> Ctrl+T ouvre un nouvel onglet ; Ctrl+W ferme l’onglet actuel ; Ctrl+L sélectionne la barre d’adresse ; Ctrl+R actualise la page ; Alt+Flèche gauche revient en arrière ; Alt+Flèche droite avance ; Ctrl+Maj+L ouvre le gestionnaire de mots de passe ; F12 affiche ou masque les outils de développement.</li>
</ul>
<h2>10. Référence des raccourcis clavier</h2>
<table border="1" cellpadding="7" cellspacing="0"><tr><th>Raccourci</th><th>Action</th></tr>
<tr><td><b>Ctrl+L</b></td><td>Active la barre d’adresse et sélectionne son contenu.</td></tr>
<tr><td><b>Ctrl+T</b></td><td>Ouvre un nouvel onglet avec la page d’accueil configurée.</td></tr>
<tr><td><b>Ctrl+W</b></td><td>Ferme l’onglet actif.</td></tr>
<tr><td><b>Ctrl+R</b></td><td>Actualise la page de l’onglet actif.</td></tr>
<tr><td><b>Alt+Flèche gauche</b></td><td>Revient à la page précédente de l’onglet actuel.</td></tr>
<tr><td><b>Alt+Flèche droite</b></td><td>Avance dans l’historique de l’onglet actuel.</td></tr>
<tr><td><b>Ctrl+Maj+L</b></td><td>Ouvre le gestionnaire de mots de passe.</td></tr>
<tr><td><b>F12</b></td><td>Affiche ou masque le panneau des outils de développement.</td></tr></table>
<p><b>Remarques :</b> la fenêtre LunaSurfer doit être active. Les raccourcis dépendent du contexte ; un site web ou un champ de saisie peut intercepter certaines combinaisons. Appuyez de nouveau sur F12 pour masquer les outils de développement.</p>
<h2>11. Dépannage et sécurité</h2>
<ul>
<li>Si un site ne fonctionne pas, vérifiez JavaScript, les cookies, le blocage des fenêtres pop-up, le bloqueur de publicités et la protection contre l’empreinte numérique. Ne modifiez qu’un réglage à la fois.</li>
<li>Si le remplissage automatique ne s’affiche pas, déverrouillez le coffre et vérifiez qu’une entrée existe pour l’adresse exacte du site.</li>
<li>Si les médias ne sont pas lus, vérifiez les codecs du système et la compatibilité du navigateur. Les contenus en streaming protégés peuvent nécessiter des composants DRM pris en charge.</li>
<li>Vérifiez le domaine avant de saisir vos identifiants. Maintenez LunaSurfer et Debian à jour à partir de sources fiables.</li>
</ul>
<p class='tip'><b>Confidentialité :</b> les protections réduisent certains signaux et certaines requêtes du navigateur, mais ne rendent pas anonyme. Les sites web, les fournisseurs réseau et le système d’exploitation peuvent toujours traiter des données d’activité.</p><p><i>Goldisoft · LunaSurfer 0.3.49</i></p>"""

        elif self.settings_data.get("language", "de") == "nl":
            content = """<h1>LunaSurfer – Volledige gebruikershandleiding</h1>
<p>Deze handleiding beschrijft de browser, de instellingen en het afzonderlijke paneel Bescherming en privacy. De benamingen komen overeen met de Nederlandse programma-interface.</p>
<h2>1. Algemeen</h2>
<ul>
<li><b>Taal:</b> wijzigt de taal van de LunaSurfer-interface. De handleiding volgt deze keuze.</li>
<li><b>Bij opstarten:</b> <i>Startpagina openen</i> laadt de ingestelde startpagina; <i>Vorige sessie herstellen</i> opent de vorige browsersessie opnieuw; <i>Lege pagina openen</i> start zonder website.</li>
<li><b>Startpagina:</b> bepaalt welke pagina met de startknop en eventueel in een nieuw tabblad wordt geopend. Voer een volledig adres in, inclusief https://.</li>
<li><b>Zoekmachine:</b> kiest Google, DuckDuckGo of Bing voor zoekopdrachten in de adresbalk.</li>
<li><b>Vertaalservice:</b> Google Translate vertaalt de volledige webpagina. MyMemory vertaalt zichtbare tekstgedeelten zonder API-sleutel en heeft een dagelijkse gratis limiet. Kwaliteit en beschikbaarheid zijn afhankelijk van de dienst.</li>
<li><b>Browserweergave:</b> kiest het uiterlijk van het browservenster: Donker (standaard), Licht (klassiek), Luna (modern), Grafietblauw (elegant) of Oceaan (blauwgroen).</li>
<li><b>Weergave van websites:</b> kiest een lichte of donkere weergave van webpagina's. Deze instelling staat los van het browserontwerp.</li>
<li><b>Bladwijzerbalk onder de adresbalk tonen:</b> toont of verbergt de bladwijzerbalk.</li>
<li><b>Downloadmap:</b> bepaalt waar gedownloade bestanden worden opgeslagen. Gebruik <i>Map kiezen…</i> om een andere map te selecteren.</li>
<li><b>Bij elke download vragen waar deze moet worden opgeslagen:</b> vraagt bij elke download om een doelmap; anders wordt de ingestelde downloadmap gebruikt.</li>
<li><b>Standaardzoom:</b> stelt de beginzoom van webpagina's in. Afzonderlijke tabbladen kunnen hun eigen zoomniveau hebben.</li>
<li><b>Standaardlettergrootte:</b> stelt de standaardgrootte van tekst op webpagina's in.</li>
<li><b>Leesbaarheid van websites:</b> Normaal laat pagina's ongewijzigd. De contrastopties passen het contrast stapsgewijs aan. Kies Normaal als een website niet goed wordt weergegeven.</li>
<li><b>Websitekleuren:</b> Origineel behoudt de kleuren van de website; Zwarte modus vraagt om zwarte achtergronden. Sommige websites kunnen in geforceerde donkere modus verkeerd worden weergegeven.</li>
</ul>
<h2>2. Beveiliging en machtigingen</h2>
<ul>
<li><b>Pop-ups blokkeren:</b> blokkeert ongewenste pop-upvensters. Schakel dit alleen tijdelijk uit voor een vertrouwde website die een pop-up nodig heeft.</li>
<li><b>JavaScript inschakelen:</b> staat scripts toe. Veel moderne websites hebben dit nodig; uitschakelen kan menu's, aanmeldingen, video's en andere functies verstoren.</li>
<li><b>Do Not Track-verzoek verzenden:</b> verzendt het optionele DNT-signaal. Websites hoeven dit niet te respecteren.</li>
<li><b>Bevestiging vragen bij het sluiten van een tabblad:</b> vraagt om bevestiging voordat een tabblad wordt gesloten.</li>
</ul>
<h2>3. User-Agent-beheer</h2>
<ul>
<li><b>Privacystandaard (verkorte Chrome-User-Agent):</b> gebruikt een Chrome-achtige browseridentificatie met minder details over versie en platform.</li>
<li><b>Native browser-User-Agent:</b> gebruikt de normale User-Agent-tekenreeks van de browserengine.</li>
<li><b>Aangepaste User-Agent:</b> gebruikt precies de ingevoerde tekenreeks. Voer een volledige geldige User-Agent in; een lege waarde kan niet worden opgeslagen.</li>
<li><b>Huidig:</b> toont de daadwerkelijk gebruikte User-Agent. De tekst kan worden geselecteerd en gekopieerd.</li>
<li><b>Belangrijk:</b> de User-Agent wijzigt de browseridentificatie, niet de browserengine of de mogelijkheden ervan. Bescherming tegen digitale vingerafdrukken kan ook Client Hints beperken.</li>
</ul>
<h2>4. Wachtwoordbeheerder</h2>
<ul>
<li><b>Wachtwoordbeheerder openen…:</b> opent de versleutelde kluis met website-aanmeldgegevens. Ontgrendel de kluis met het hoofdwachtwoord om opgeslagen items te beheren.</li>
<li><b>Alle wachtwoorden verwijderen…:</b> verwijdert alle opgeslagen websitewachtwoorden. Het hoofdwachtwoord blijft behouden. Wachtwoorden op de websites zelf worden niet gewijzigd.</li>
<li><b>Aanbieden wachtwoorden op te slaan na geslaagde aanmelding:</b> bepaalt of LunaSurfer na een herkende aanmelding voorstelt de gegevens op te slaan.</li>
<li><b>Wachtwoordbeheerder moet ontgrendeld zijn vóór automatisch invullen:</b> als dit is ingeschakeld, moet de kluis eerst worden ontgrendeld. Anders vraagt LunaSurfer om het hoofdwachtwoord wanneer u een aanmeldveld selecteert.</li>
<li>Aanmeldgegevens zijn gekoppeld aan de betreffende website, niet alleen aan het e-mailadres. Dezelfde e-mail kan bij verschillende diensten worden gebruikt; elke dienst heeft een eigen item nodig. Controleer website en account voordat u opslaan of bijwerken bevestigt.</li>
<li>Bewaar het hoofdwachtwoord zorgvuldig. Als u het verliest, kan de versleutelde kluis mogelijk niet worden hersteld. Maak veilige reservekopieën en deel het hoofdwachtwoord nooit.</li>
</ul>
<h2>5. Websitemachtigingen</h2>
<p><b>Opgeslagen websitemachtigingen bewerken…</b> opent de opgeslagen beslissingen per website. De algemene instellingen bepalen hoe verzoeken worden behandeld:</p>
<ul>
<li><b>Camera, Microfoon, Locatie en Meldingen:</b> elke machtiging kan worden ingesteld op Vragen, Toestaan of Blokkeren. Vragen toont een verzoek; Toestaan verleent toegang; Blokkeren weigert toegang. Sta alleen vertrouwde websites toegang toe wanneer dat nodig is.</li>
<li><b>Do Not Track-verzoek verzenden:</b> verzendt het optionele DNT-signaal. Websites zijn niet verplicht dit te volgen.</li>
<li><b>Browsergedrag – bevestiging vragen bij het sluiten van een tabblad:</b> vraagt om bevestiging om onbedoeld sluiten te voorkomen.</li>
</ul>
<h2>6. Privacy en browsergegevens</h2>
<ul>
<li><b>Cookiemodus – Alle cookies toestaan:</b> staat first-party- en third-party-cookies toe. Dit biedt de beste compatibiliteit, maar maakt meer opslag tussen websites mogelijk.</li>
<li><b>Cookies van derden blokkeren:</b> blokkeert cookies van andere domeinen dan de bezochte website. Ingesloten inhoud of aanmeldprocessen kunnen hierdoor worden beïnvloed.</li>
<li><b>Alle cookies blokkeren:</b> voorkomt dat websites cookies opslaan en kan aanmeldingen, voorkeuren en winkelmandjes verstoren.</li>
<li><b>Alleen sessiecookies toestaan:</b> staat tijdelijke sessiecookies toe, maar beperkt blijvende cookies.</li>
<li><b>Geschiedenis wissen:</b> verwijdert de opgeslagen browsegeschiedenis.</li>
<li><b>Cache wissen:</b> verwijdert opgeslagen paginabestanden. De volgende keer kan het laden langer duren.</li>
<li><b>Cookies wissen:</b> verwijdert websitecookies en kan u afmelden of websitevoorkeuren resetten.</li>
<li><b>Alles wissen:</b> wist de beschikbare geschiedenis-, cache- en cookiegegevens. Lees de bevestigingsvraag zorgvuldig.</li>
<li><b>Geschiedenis/cache/cookies automatisch wissen bij afsluiten:</b> elke optie wist de betreffende gegevenscategorie wanneer LunaSurfer wordt afgesloten.</li>
<li><b>Venstergrootte en -positie onthouden bij afsluiten:</b> herstelt de laatste vensterafmetingen en -positie bij de volgende start.</li>
<li><b>LunaSurfer als standaardbrowser gebruiken:</b> vraagt de desktopomgeving LunaSurfer als voorkeursbrowser voor webkoppelingen te registreren.</li>
</ul>
<h2>7. Paneel Bescherming en privacy</h2>
<h3>Advertentieblokkering</h3>
<ul>
<li><b>Advertentieblokkering inschakelen:</b> schakelt het filteren in of uit.</li>
<li><b>Blokkeersterkte:</b> hogere niveaus filteren meer regels, maar kunnen sommige functies verstoren of inhoud verbergen.</li>
<li><b>Aangepaste blokkeerregels:</b> voeg domeinen of regels toe, gescheiden door puntkomma's.</li>
<li><b>Domeinen op de toelatingslijst:</b> vermeld domeinen die van de blokkering worden uitgesloten. Gebruik dit voor vertrouwde websites die anders niet goed werken.</li>
</ul>
<h3>Bescherming tegen digitale vingerafdruk</h3>
<ul>
<li><b>Bescherming inschakelen:</b> vermindert bepaalde identificerende signalen van browser en apparaat.</li>
<li><b>Standaard:</b> basisbescherming voor Canvas, audio en hardwaregegevens.</li>
<li><b>Sterk:</b> maskeert ook WebGL-identificaties.</li>
<li><b>Maximaal:</b> biedt extra bescherming voor hardwaredetails en browser-Client Hints.</li>
<li>Wijzigingen worden direct toegepast; opnieuw starten is normaal niet nodig. Sterkere bescherming kan de compatibiliteit beïnvloeden en garandeert geen anonimiteit.</li>
</ul>
<h2>8. Instellingen opslaan en toepassen</h2>
<p>Gebruik <b>Opslaan</b> om de keuzes op de instellingenpagina te bewaren. Gebruik <b>Annuleren</b> om te sluiten zonder openstaande wijzigingen op te slaan. Sommige instellingen worden direct toegepast, andere pas nadat geopende pagina's opnieuw zijn geladen. Het beschermingspaneel heeft eigen knoppen Opslaan en Annuleren.</p>
<h2>9. Andere browserfuncties</h2>
<ul>
<li><b>Bladwijzers:</b> gebruik de ster om een pagina op te slaan. In het bladwijzerbeheer kunt u mappen ordenen en bladwijzers importeren of exporteren.</li>
<li><b>Downloads:</b> bekijk actieve en voltooide overdrachten in Downloadbeheer. Controleer bij fouten de doelmap en beschikbare schijfruimte.</li>
<li><b>Webpagina's vertalen:</b> gebruik de vertaalfunctie om een doeltaal te kiezen of terug te keren naar de originele pagina. De vertaling wordt door de geselecteerde dienst geleverd en kan fouten bevatten.</li>
<li><b>Tabbladen en sneltoetsen:</b> Ctrl+T opent een nieuw tabblad; Ctrl+W sluit het huidige tabblad; Ctrl+L selecteert de adresbalk; Ctrl+R laadt de pagina opnieuw; Alt+Pijl links gaat terug; Alt+Pijl rechts gaat vooruit; Ctrl+Shift+L opent de wachtwoordbeheerder; F12 toont of verbergt de ontwikkelaarstools.</li>
</ul>
<h2>10. Overzicht van sneltoetsen</h2>
<table border="1" cellpadding="7" cellspacing="0"><tr><th>Sneltoets</th><th>Actie</th></tr>
<tr><td><b>Ctrl+L</b></td><td>Activeert de adresbalk en selecteert de huidige tekst.</td></tr>
<tr><td><b>Ctrl+T</b></td><td>Opent een nieuw tabblad met de ingestelde startpagina.</td></tr>
<tr><td><b>Ctrl+W</b></td><td>Sluit het actieve tabblad.</td></tr>
<tr><td><b>Ctrl+R</b></td><td>Laadt de pagina in het actieve tabblad opnieuw.</td></tr>
<tr><td><b>Alt+Pijl links</b></td><td>Gaat naar de vorige pagina in de geschiedenis van het huidige tabblad.</td></tr>
<tr><td><b>Alt+Pijl rechts</b></td><td>Gaat vooruit in de geschiedenis van het huidige tabblad.</td></tr>
<tr><td><b>Ctrl+Shift+L</b></td><td>Opent de wachtwoordbeheerder.</td></tr>
<tr><td><b>F12</b></td><td>Toont of verbergt het paneel met ontwikkelaarstools.</td></tr></table>
<p><b>Opmerking:</b> het LunaSurfer-venster moet actief zijn. Een website of invoerveld kan sommige sneltoetsen onderscheppen. Druk opnieuw op F12 om de ontwikkelaarstools te verbergen.</p>
<h2>11. Problemen oplossen en beveiliging</h2>
<ul>
<li>Als een website niet werkt, controleer JavaScript, cookies, pop-upblokkering, advertentieblokkering en bescherming tegen digitale vingerafdrukken. Wijzig telkens één instelling.</li>
<li>Als automatisch invullen niet verschijnt, ontgrendel de kluis en controleer of er een item bestaat voor het exacte websiteadres.</li>
<li>Als media niet afspelen, controleer de systeemcodecs en browsercompatibiliteit. Beschermde streaminginhoud kan ondersteunde DRM-componenten vereisen.</li>
<li>Controleer het domein voordat u aanmeldgegevens invoert. Houd LunaSurfer en Debian bijgewerkt via vertrouwde bronnen.</li>
</ul>
<p class='tip'><b>Privacy:</b> privacybescherming vermindert bepaalde browsersignalen en verzoeken, maar maakt u niet anoniem. Websites, netwerkproviders en het besturingssysteem kunnen nog steeds activiteitsgegevens verwerken.</p><p><i>Goldisoft · LunaSurfer 0.3.49</i></p>"""
        elif self.settings_data.get("language", "de") == "es":
            content = """<h1>LunaSurfer – Guía de usuario</h1>
<p>Esta guía explica las funciones principales del navegador y las opciones de configuración. Los nombres corresponden a la interfaz en español.</p>
<h2>1. General</h2>
<ul>
<li><b>Idioma:</b> cambia el idioma de la interfaz de LunaSurfer.</li>
<li><b>Al iniciar:</b> puede abrir la página de inicio, restaurar la última sesión o abrir una página en blanco.</li>
<li><b>Página de inicio y motor de búsqueda:</b> configura la página que se abre al inicio y el proveedor utilizado para las búsquedas desde la barra de direcciones.</li>
<li><b>Diseño del navegador:</b> selecciona el aspecto visual de la ventana. La apariencia clara u oscura de los sitios web se configura por separado.</li>
<li><b>Barra de marcadores:</b> muestra u oculta los marcadores debajo de la barra de direcciones.</li>
<li><b>Descargas:</b> permite elegir la carpeta, preguntar dónde guardar cada archivo y mostrar avisos de seguridad para archivos ejecutables.</li>
</ul>
<h2>2. Marcadores e historial</h2>
<ul>
<li>Usa el icono de estrella para guardar la página actual en los marcadores.</li>
<li>Abre el administrador de marcadores para buscar, editar, eliminar, importar o exportar marcadores y carpetas.</li>
<li>El historial permite revisar las páginas visitadas y borrar los datos de navegación.</li>
</ul>
<h2>3. Descargas</h2>
<p>El gestor de descargas muestra transferencias activas y completadas. Puedes buscar archivos, cancelar una descarga, abrir un archivo o su carpeta y limpiar el historial.</p>
<h2>4. Protección y privacidad</h2>
<ul>
<li><b>Bloqueador de anuncios:</b> filtra dominios conocidos de publicidad y seguimiento. Los niveles más altos pueden afectar a algunos sitios web.</li>
<li><b>Protección contra huellas digitales:</b> reduce determinadas señales de identificación de Canvas, audio, WebGL y hardware. Una protección más fuerte puede afectar a la compatibilidad y no garantiza el anonimato.</li>
<li><b>Permisos de sitios web:</b> administra los permisos guardados para cámara, micrófono, ubicación y notificaciones.</li>
<li><b>Cookies y datos:</b> puedes ajustar el modo de cookies y borrar la caché, las cookies o el historial. Los marcadores y las contraseñas guardadas se conservan al limpiar los datos del navegador.</li>
</ul>
<h2>5. Gestor de contraseñas</h2>
<p>Las credenciales se cifran localmente. La contraseña maestra no se puede recuperar; guárdala de forma segura. Desbloquea el gestor para consultar o autocompletar los inicios de sesión guardados. También puedes importar y exportar una bóveda cifrada.</p>
<h2>6. Traducción de páginas</h2>
<p>El menú de traducción permite traducir la página completa con Google Translate o traducir secciones de texto visibles con MyMemory. También puedes volver a la página original.</p>
<h2>7. Guardar los cambios</h2>
<p>Usa <b>Guardar</b> para conservar los cambios de configuración. Algunas opciones se aplican inmediatamente; otras pueden requerir volver a cargar una página o reiniciar LunaSurfer.</p>
<p class='tip'><b>Privacidad:</b> las protecciones reducen determinados datos del navegador, pero no hacen que la navegación sea anónima.</p>
<p><i>Goldisoft · LunaSurfer 0.3.49</i></p>"""
        elif self.settings_data.get("language", "de") == "it":
            content = """<h1>LunaSurfer – Guida completa</h1>
<p>Questa guida descrive il browser e tutte le opzioni attualmente presenti nella pagina Impostazioni, oltre al pannello separato Protezione e privacy. Le denominazioni corrispondono all’interfaccia italiana.</p>
<h2>1. Generale</h2>
<ul>
<li><b>Lingua:</b> cambia la lingua dell’interfaccia di LunaSurfer. La guida segue questa scelta e viene visualizzata in una sola lingua.</li>
<li><b>All’avvio:</b> <i>Apri pagina iniziale</i> carica la pagina iniziale configurata; <i>Ripristina ultima sessione</i> riapre la precedente sessione del browser; <i>Apri pagina vuota</i> avvia il browser senza caricare un sito.</li>
<li><b>Pagina iniziale:</b> stabilisce quale pagina viene aperta con il pulsante Home e, in base al comportamento scelto all’avvio, in una nuova scheda. Inserisci un URL completo, incluso https://.</li>
<li><b>Motore di ricerca:</b> sceglie Google, DuckDuckGo o Bing per le ricerche digitate come testo semplice nella barra degli indirizzi.</li>
<li><b>Servizio di traduzione:</b> <i>Google Translate (intera pagina web)</i> invia la pagina a Google Translate per tradurla interamente. <i>MyMemory</i> traduce le sezioni di testo visibili senza una chiave API e dispone di un limite giornaliero gratuito. Qualità e disponibilità dipendono dal servizio.</li>
<li><b>Aspetto del browser:</b> seleziona l’aspetto della finestra del browser: Scuro (standard), Chiaro (classico), Luna (moderno), Grafite blu (elegante) oppure Oceano (blu petrolio).</li>
<li><b>Aspetto dei siti web:</b> seleziona il tema chiaro o scuro del browser. Questa opzione è indipendente dall’aspetto del browser e dai colori dei siti web.</li>
<li><b>Mostra la barra dei segnalibri sotto la barra degli indirizzi:</b> mostra o nasconde la barra dei segnalibri.</li>
<li><b>Cartella dei download:</b> indica la cartella in cui vengono salvati i file scaricati. Usa <i>Scegli cartella…</i> per selezionare un’altra directory.</li>
<li><b>Chiedi dove salvare ogni download:</b> se attivata, chiede una destinazione per ogni nuovo download; altrimenti viene usata la cartella dei download configurata.</li>
<li><b>Zoom predefinito:</b> imposta lo zoom iniziale delle pagine. I valori disponibili vanno dal 50% al 200%; le singole pagine possono comunque avere uno zoom separato.</li>
<li><b>Dimensione carattere predefinita:</b> imposta la dimensione predefinita del testo delle pagine web.</li>
<li><b>Leggibilità dei siti web:</b> <i>Normale</i> lascia invariate le pagine. Contrasto delicato, più morbido e rilassato applicano regolazioni progressive. Se una pagina appare in modo errato, torna a Normale. Immagini e video dovrebbero rimanere invariati.</li>
<li><b>Colori dei siti web:</b> <i>Originale</i> mantiene i colori del sito; <i>Modalità nera</i> richiede sfondi neri. Alcuni siti potrebbero non essere visualizzati perfettamente con la modalità scura forzata.</li>
</ul>
<h2>2. Sicurezza e autorizzazioni</h2>
<ul>
<li><b>Blocca finestre pop-up:</b> blocca le finestre pop-up indesiderate. Disattiva temporaneamente questa funzione solo se un sito attendibile richiede una finestra pop-up per l’accesso o il pagamento.</li>
<li><b>Attiva JavaScript:</b> consente ai siti web di eseguire script. Molti siti moderni ne hanno bisogno; disattivarlo può impedire il funzionamento di menu, accessi, video e altre funzioni.</li>
<li><b>Invia richiesta Do Not Track:</b> invia il segnale DNT facoltativo. I siti web non sono obbligati a rispettarlo.</li>
<li><b>Chiedi prima di chiudere una scheda:</b> richiede una conferma prima di chiudere le schede e aiuta a evitare chiusure accidentali.</li>
</ul>
<h2>3. Gestione User-Agent</h2>
<ul>
<li><b>Predefinito privacy (User-Agent Chrome ridotto):</b> presenta un’identificazione del browser in stile Chrome con meno dettagli sulla versione e sulla piattaforma.</li>
<li><b>User-Agent nativo del browser:</b> usa la normale stringa User-Agent del motore del browser.</li>
<li><b>User-Agent personalizzato:</b> usa esattamente la stringa inserita nel campo Valore personalizzato. Inserisci una stringa User-Agent completa e valida; un valore vuoto non può essere salvato.</li>
<li><b>Attuale:</b> mostra la stringa User-Agent effettivamente utilizzata. Il testo può essere selezionato e copiato.</li>
<li><b>Importante:</b> modificare lo User-Agent cambia l’identificazione del browser, non il motore né le sue funzionalità. Quando la protezione dell’impronta digitale è attiva, anche i Client Hints possono essere ridotti.</li>
</ul>
<h2>4. Gestore password</h2>
<ul>
<li><b>Apri gestore password…:</b> apre l’archivio crittografato degli accessi ai siti web. Sbloccalo con la password principale per gestire le voci salvate.</li>
<li><b>Elimina tutte le password…:</b> rimuove tutti gli accessi ai siti web salvati. La password principale rimane attiva. Questa operazione non modifica le password memorizzate sui siti web stessi.</li>
<li><b>Proponi di salvare le password dopo un accesso riuscito:</b> stabilisce se LunaSurfer deve proporre il salvataggio dopo aver rilevato un accesso riuscito.</li>
<li><b>Il gestore password deve essere sbloccato prima della compilazione automatica:</b> se attivato, l’archivio deve essere sbloccato prima della compilazione automatica. Se disattivato, LunaSurfer chiede la password principale quando selezioni un campo di accesso.</li>
<li>Le credenziali sono associate al rispettivo sito web, non soltanto all’indirizzo e-mail. La stessa e-mail può essere usata con servizi diversi: ogni servizio deve avere una propria voce. Controlla sempre sito e account prima di confermare il salvataggio o l’aggiornamento.</li>
<li>Conserva con cura la password principale. Se viene persa, l’archivio crittografato potrebbe non essere recuperabile. Crea copie di sicurezza e non condividere mai la password principale.</li>
</ul>
<h2>5. Autorizzazioni dei siti web</h2>
<p><b>Modifica autorizzazioni dei siti web salvate…</b> apre la gestione delle decisioni memorizzate per i singoli siti. Le impostazioni generali seguenti si applicano quando un sito richiede l’accesso:</p>
<ul>
<li><b>Fotocamera, Microfono, Posizione, Notifiche:</b> ciascuna autorizzazione può essere impostata su <i>Chiedi</i>, <i>Consenti</i> o <i>Blocca</i>. Chiedi mostra una richiesta; Consenti concede l’autorizzazione; Blocca nega l’accesso. Concedi l’accesso solo ai siti attendibili e quando la funzione è necessaria.</li>
<li><b>Invia richiesta Do Not Track:</b> invia il segnale DNT facoltativo. I siti web non sono tenuti a rispettarlo.</li>
<li><b>Comportamento del browser – Chiedi prima di chiudere una scheda:</b> richiede una conferma prima della chiusura per evitare operazioni accidentali.</li>
</ul>
<h2>6. Privacy e dati del browser</h2>
<ul>
<li><b>Modalità cookie – Consenti tutti i cookie:</b> permette i cookie di prima e terza parte. Offre la massima compatibilità, ma consente una maggiore memorizzazione tra siti diversi.</li>
<li><b>Blocca cookie di terze parti:</b> blocca i cookie provenienti da domini diversi dal sito visitato. Alcuni contenuti incorporati o procedure di accesso potrebbero risentirne.</li>
<li><b>Blocca tutti i cookie:</b> impedisce ai siti di memorizzare cookie e può compromettere accessi, preferenze e carrelli degli acquisti.</li>
<li><b>Consenti solo cookie di sessione:</b> permette i cookie temporanei di sessione, ma limita quelli persistenti. Il comportamento dei siti e la permanenza degli accessi potrebbero cambiare.</li>
<li><b>Cancella cronologia:</b> elimina la cronologia di navigazione registrata.</li>
<li><b>Cancella cache:</b> rimuove le risorse delle pagine memorizzate nella cache. Alla visita successiva il caricamento potrebbe essere più lento perché i file dovranno essere scaricati di nuovo.</li>
<li><b>Cancella cookie:</b> rimuove i cookie dei siti web e potrebbe disconnetterti o ripristinare le preferenze dei siti.</li>
<li><b>Cancella tutto:</b> esegue la pulizia dei dati disponibili relativi a cronologia, cache e cookie. Leggi attentamente la richiesta di conferma.</li>
<li><b>Cancella automaticamente cronologia/cache/cookie all’uscita:</b> ogni casella elimina indipendentemente la relativa categoria di dati quando LunaSurfer viene chiuso.</li>
<li><b>Ricorda dimensioni e posizione della finestra all’uscita:</b> ripristina al successivo avvio le dimensioni e la posizione dell’ultima finestra.</li>
<li><b>Usa LunaSurfer come browser predefinito:</b> chiede all’ambiente desktop di registrare LunaSurfer come browser preferito per i collegamenti web.</li>
</ul>
<h2>7. Pannello separato Protezione e privacy</h2>
<p>Apri questo pannello con il pulsante a forma di scudo nella barra degli strumenti. Contiene due schede:</p>
<h3>Blocco pubblicità</h3>
<ul>
<li><b>Attiva il blocco pubblicità:</b> attiva o disattiva il filtraggio.</li>
<li><b>Intensità del blocco:</b> Standard, Forte, Molto forte, Super forte, Mega forte o Ultra forte. I livelli più elevati filtrano più regole, ma possono compromettere alcune funzioni o nascondere contenuti.</li>
<li><b>Regole di blocco personalizzate:</b> aggiungi domini o regole separandoli con punti e virgola, ad esempio <code>example-ads.com; tracker.example</code>.</li>
<li><b>Domini consentiti:</b> elenca i domini esclusi dal blocco pubblicità, separandoli con punti e virgola. Usa questa opzione per i siti attendibili che non funzionano correttamente.</li>
</ul>
<h3>Protezione dell’impronta digitale</h3>
<ul>
<li><b>Attiva la protezione dell’impronta digitale:</b> attiva misure pensate per ridurre i segnali identificativi del browser e del dispositivo.</li>
<li><b>Livello di protezione – Standard:</b> protezione di Canvas, audio e hardware di base.</li>
<li><b>Forte:</b> aggiunge la mascheratura degli identificatori WebGL.</li>
<li><b>Massima:</b> aggiunge ulteriore protezione dei dettagli hardware e dei Client Hints del browser.</li>
<li>Le modifiche vengono applicate subito; normalmente non è necessario riavviare il browser. Una protezione più forte può influire sulla compatibilità e non garantisce l’anonimato.</li>
</ul>
<h2>8. Salvataggio e applicazione delle modifiche</h2>
<p>Usa <b>Salva</b> per memorizzare le scelte nella pagina Impostazioni. Usa <b>Annulla</b> per chiudere senza salvare le modifiche in sospeso. Alcune impostazioni vengono applicate subito, altre dopo aver ricaricato le pagine aperte. Il pannello di protezione dispone di propri pulsanti Salva e Annulla.</p>
<h2>9. Altre funzioni del browser</h2>
<ul>
<li><b>Segnalibri:</b> usa la stella per salvare una pagina; nella gestione dei segnalibri puoi organizzare le cartelle e importare o esportare i segnalibri.</li>
<li><b>Download:</b> controlla i trasferimenti in corso e completati nel gestore download. Se un download non riesce, verifica la cartella di destinazione e lo spazio disponibile.</li>
<li><b>Traduzione dei siti web:</b> usa il controllo di traduzione per scegliere una lingua di destinazione o tornare alla pagina originale. La traduzione è fornita dal servizio selezionato e può contenere errori.</li>
<li><b>Schede e scorciatoie:</b> Ctrl+T apre una nuova scheda; Ctrl+W chiude la scheda corrente; Ctrl+L attiva e seleziona la barra degli indirizzi; Ctrl+R ricarica la pagina; Alt+Freccia sinistra torna indietro; Alt+Freccia destra avanza; Ctrl+Shift+L apre il gestore password; F12 mostra o nasconde gli strumenti per sviluppatori. Le scorciatoie funzionano quando la finestra di LunaSurfer è attiva. In base al contesto, un sito o un campo di immissione può gestire alcuni tasti in modo diverso.</li>
</ul>
<h2>10. Elenco completo delle scorciatoie da tastiera</h2>
<table border="1" cellpadding="7" cellspacing="0"><tr><th>Scorciatoia</th><th>Azione</th></tr>
<tr><td><b>Ctrl+L</b></td><td>Attiva la barra degli indirizzi e seleziona il testo presente, pronto per inserire un URL o una ricerca.</td></tr>
<tr><td><b>Ctrl+T</b></td><td>Apre una nuova scheda con la pagina iniziale configurata.</td></tr>
<tr><td><b>Ctrl+W</b></td><td>Chiude la scheda attiva.</td></tr>
<tr><td><b>Ctrl+R</b></td><td>Ricarica la pagina nella scheda attiva.</td></tr>
<tr><td><b>Alt+Freccia sinistra</b></td><td>Torna alla pagina precedente nella cronologia della scheda corrente.</td></tr>
<tr><td><b>Alt+Freccia destra</b></td><td>Avanza nella cronologia della scheda corrente.</td></tr>
<tr><td><b>Ctrl+Shift+L</b></td><td>Apre il gestore password. Se l’archivio è bloccato, segui la richiesta di sblocco.</td></tr>
<tr><td><b>F12</b></td><td>Mostra o nasconde il pannello degli strumenti per sviluppatori, utile per la diagnostica e l’analisi avanzata dei siti. Il pannello può contenere informazioni tecniche sulla pagina, sulle richieste e sugli script.</td></tr></table>
<p><b>Note sull’uso:</b> la finestra di LunaSurfer deve essere attiva. Le scorciatoie dipendono dal contesto: mentre scrivi in un campo di un sito, il sito o il campo stesso potrebbe intercettare una combinazione di tasti. Premi nuovamente F12 per nascondere gli strumenti per sviluppatori. Questi strumenti sono destinati a utenti esperti; modificare il codice o l’archiviazione della pagina può influire sulla sessione corrente del sito.</p>
<h2>11. Risoluzione dei problemi e sicurezza</h2>
<ul>
<li>Se un sito non funziona, verifica se la causa è JavaScript, cookie, blocco dei pop-up, blocco pubblicità o protezione dell’impronta digitale. Modifica una sola impostazione alla volta.</li>
<li>Se la compilazione automatica non compare, sblocca l’archivio e controlla che esista una voce per l’indirizzo esatto del sito.</li>
<li>Se i contenuti multimediali non vengono riprodotti, controlla i codec di sistema e la compatibilità del browser. I contenuti in streaming protetti potrebbero richiedere componenti DRM supportati.</li>
<li>Controlla il dominio prima di inserire le credenziali. Mantieni LunaSurfer e Debian aggiornati tramite fonti attendibili.</li>
</ul>
<p class='tip'><b>Nota sulla privacy:</b> i controlli di privacy riducono determinati segnali e richieste del browser, ma non rendono anonimi. I siti web, i fornitori di rete e il sistema operativo possono continuare a elaborare dati sulle attività.</p><p><i>Goldisoft · LunaSurfer 0.3.49</i></p>"""
        elif self.settings_data.get("language", "de") == "pl":
            content = """<h1>LunaSurfer – Pełny podręcznik użytkownika</h1>
<p>Ten podręcznik opisuje przeglądarkę, ustawienia oraz oddzielny panel Ochrona i prywatność. Nazwy odpowiadają polskiemu interfejsowi programu.</p>
<h2>1. Ustawienia ogólne</h2>
<ul>
<li><b>Język:</b> zmienia język interfejsu LunaSurfer. Podręcznik jest wyświetlany w wybranym języku.</li>
<li><b>Przy uruchomieniu:</b> można otworzyć stronę startową, przywrócić ostatnią sesję lub otworzyć pustą stronę.</li>
<li><b>Strona startowa i wyszukiwarka:</b> określają stronę otwieraną po uruchomieniu oraz usługę używaną do wyszukiwania z paska adresu.</li>
<li><b>Wygląd przeglądarki:</b> wybiera motyw okna. Jasny lub ciemny wygląd witryn można ustawić niezależnie.</li>
<li><b>Pasek zakładek:</b> pokazuje lub ukrywa zakładki pod paskiem adresu.</li>
<li><b>Pobieranie:</b> pozwala wybrać folder pobierania, pytać o miejsce zapisu każdego pliku i wyświetlać ostrzeżenia dla plików wykonywalnych.</li>
</ul>
<h2>2. Zakładki i historia</h2>
<ul>
<li>Użyj ikony gwiazdki, aby zapisać bieżącą stronę w zakładkach.</li>
<li>Otwórz menedżer zakładek, aby wyszukiwać, edytować, usuwać, importować i eksportować zakładki oraz foldery.</li>
<li>Historia pokazuje odwiedzone strony. Możesz wyczyścić historię lub wszystkie dane przeglądarki.</li>
</ul>
<h2>3. Pobieranie</h2>
<p>Menedżer pobierania pokazuje aktywne i zakończone transfery. Możesz wyszukiwać pliki, anulować pobieranie, otwierać plik lub jego folder oraz czyścić historię.</p>
<h2>4. Ochrona i prywatność</h2>
<ul>
<li><b>Blokowanie reklam:</b> filtruje znane domeny reklamowe i śledzące. Wyższe poziomy mogą wpływać na działanie niektórych witryn.</li>
<li><b>Ochrona przed fingerprintingiem:</b> ogranicza wybrane sygnały identyfikacyjne Canvas, audio, WebGL i sprzętu. Silniejsza ochrona może wpływać na zgodność witryn.</li>
<li><b>Uprawnienia witryn:</b> zarządzaj zapisanymi uprawnieniami do aparatu, mikrofonu, lokalizacji i powiadomień.</li>
<li><b>Pliki cookie i dane:</b> wybierz tryb obsługi plików cookie oraz wyczyść pamięć podręczną, pliki cookie lub historię. Zakładki i zapisane hasła pozostają zachowane.</li>
</ul>
<h2>5. Menedżer haseł</h2>
<p>Dane logowania są szyfrowane lokalnie. Hasła głównego nie można odzyskać, dlatego przechowuj je bezpiecznie. Odblokuj menedżer, aby przeglądać zapisane dane lub używać automatycznego wypełniania.</p>
<h2>6. Tłumaczenie stron</h2>
<p>Menu tłumaczenia umożliwia przetłumaczenie całej strony za pomocą Google Translate lub widocznych fragmentów tekstu za pomocą MyMemory. Możesz także wrócić do oryginalnej strony.</p>
<h2>7. Zapisywanie ustawień</h2>
<p>Użyj przycisku <b>Zapisz</b>, aby zachować zmiany ustawień. Niektóre opcje są stosowane natychmiast; inne mogą wymagać ponownego załadowania strony lub restartu przeglądarki.</p>
<h2>8. Skróty klawiaturowe</h2>
<table border="1" cellpadding="7" cellspacing="0"><tr><th>Skrót</th><th>Działanie</th></tr>
<tr><td><b>Ctrl+L</b></td><td>Aktywuje pasek adresu i zaznacza jego zawartość.</td></tr>
<tr><td><b>Ctrl+T</b></td><td>Otwiera nową kartę.</td></tr><tr><td><b>Ctrl+W</b></td><td>Zamyka aktywną kartę.</td></tr>
<tr><td><b>Ctrl+R</b></td><td>Ponownie ładuje bieżącą stronę.</td></tr><tr><td><b>Alt+strzałka w lewo</b></td><td>Przechodzi do poprzedniej strony.</td></tr>
<tr><td><b>Alt+strzałka w prawo</b></td><td>Przechodzi do następnej strony.</td></tr><tr><td><b>Ctrl+Shift+L</b></td><td>Otwiera menedżer haseł.</td></tr>
<tr><td><b>F12</b></td><td>Pokazuje lub ukrywa narzędzia deweloperskie.</td></tr></table>
<h2>9. Rozwiązywanie problemów i bezpieczeństwo</h2>
<ul><li>Jeśli witryna nie działa prawidłowo, sprawdź JavaScript, pliki cookie, blokowanie wyskakujących okien, blokowanie reklam i ochronę przed fingerprintingiem. Zmieniaj jedną opcję naraz.</li>
<li>Jeśli automatyczne wypełnianie nie działa, odblokuj sejf i sprawdź, czy istnieje wpis dla dokładnego adresu witryny.</li>
<li>Przed wpisaniem danych logowania sprawdź domenę. Aktualizuj LunaSurfer i Debian z zaufanych źródeł.</li></ul>
<p class='tip'><b>Prywatność:</b> funkcje ochrony ograniczają wybrane sygnały przeglądarki, ale nie zapewniają anonimowości.</p>
<p><i>Goldisoft · LunaSurfer 0.3.49</i></p>"""
        elif selected_language == "ru":
            content = """<h1>LunaSurfer – Полное руководство пользователя</h1>
<p>Это руководство описывает основные функции браузера, параметры настроек и отдельное окно «Защита и конфиденциальность».</p>
<h2>1. Общие настройки</h2><ul>
<li><b>Язык:</b> выбирает язык интерфейса, меню и диалоговых окон. Руководство отображается на выбранном языке.</li>
<li><b>При запуске:</b> можно открыть домашнюю страницу, восстановить предыдущий сеанс или открыть пустую страницу.</li>
<li><b>Домашняя страница и поисковая система:</b> задают страницу запуска и службу поиска для запросов из адресной строки. Доступны Google, DuckDuckGo и Bing.</li>
<li><b>Служба перевода:</b> Google Translate переводит всю страницу; MyMemory переводит видимые фрагменты текста без ключа API и имеет дневной бесплатный лимит.</li>
<li><b>Оформление браузера:</b> выбирает тему окна. Светлый или тёмный вид веб-сайтов настраивается отдельно.</li>
<li><b>Панель закладок:</b> показывает или скрывает панель под адресной строкой.</li>
<li><b>Загрузки:</b> задаёт папку загрузок и позволяет спрашивать место сохранения каждого файла. Можно включить предупреждение о загружаемых исполняемых файлах.</li>
<li><b>Масштаб и размер шрифта:</b> задают начальный масштаб страницы (50–200 %) и стандартный размер текста.</li>
<li><b>Читаемость и цвета сайтов:</b> режим «Оригинал» сохраняет исходные цвета; принудительный тёмный режим может отображать некоторые сайты некорректно. При проблемах верните обычную читаемость.</li></ul>
<h2>2. Безопасность и разрешения</h2><ul>
<li><b>Блокировка всплывающих окон:</b> блокирует нежелательные окна. Отключайте её только временно для доверенных сайтов.</li>
<li><b>JavaScript:</b> разрешает выполнение сценариев. Многие современные сайты требуют его; отключение может нарушить меню, вход, видео и другие функции.</li>
<li><b>Разрешения сайтов:</b> для камеры, микрофона, местоположения и уведомлений доступны варианты «Спрашивать», «Разрешить» и «Блокировать». Предоставляйте доступ только доверенным сайтам.</li>
<li><b>Do Not Track:</b> отправляет необязательный сигнал запрета отслеживания; сайты не обязаны его соблюдать.</li></ul>
<h2>3. Управление User-Agent</h2><ul>
<li><b>Стандарт конфиденциальности:</b> использует сокращённую идентификацию браузера Chrome, уменьшая раскрытие сведений о версии и платформе.</li>
<li><b>Родной User-Agent:</b> использует обычную строку идентификации движка браузера.</li>
<li><b>Пользовательский User-Agent:</b> применяет введённую вами полную строку. Пустое значение сохранить нельзя.</li>
<li><b>Текущий:</b> показывает фактически используемую строку. User-Agent меняет идентификацию, но не движок и реальные возможности браузера.</li></ul>
<h2>4. Менеджер паролей</h2><ul>
<li>Данные входа шифруются локально и защищаются мастер-паролем. Откройте менеджер и разблокируйте хранилище для управления записями и автозаполнения.</li>
<li>Можно включить предложение сохранить пароль после успешного входа. Для автозаполнения может требоваться разблокировка хранилища.</li>
<li>Записи привязаны к адресу сайта. Проверяйте сайт и учётную запись перед сохранением или обновлением.</li>
<li>Удаление сохранённых паролей не меняет пароли на самих сайтах. Мастер-пароль нельзя восстановить: храните его в надёжном месте и делайте резервные копии хранилища.</li></ul>
<h2>5. Конфиденциальность и данные браузера</h2><ul>
<li><b>Режим cookie:</b> можно разрешить все cookie, блокировать сторонние или все cookie либо разрешить только сеансовые cookie. Строгие ограничения могут нарушить вход и работу сайтов.</li>
<li><b>Очистка данных:</b> отдельно или вместе можно удалить историю, кэш и cookie. После удаления cookie сайты могут выйти из учётной записи. Закладки и сохранённые пароли при обычной очистке этих данных сохраняются.</li>
<li><b>Автоматическая очистка:</b> позволяет очищать историю, кэш и cookie при выходе из LunaSurfer.</li>
<li><b>Размер и положение окна:</b> можно запоминать для следующего запуска. Параметр браузера по умолчанию просит рабочее окружение использовать LunaSurfer для веб-ссылок.</li></ul>
<h2>6. Окно «Защита и конфиденциальность»</h2><h3>Блокировщик рекламы</h3><ul>
<li>Включает или отключает фильтрацию рекламных и отслеживающих доменов. Уровни от стандартного до Ultra Strong фильтруют всё больше шаблонов, но могут нарушать работу некоторых сайтов.</li>
<li>Пользовательские блокирующие шаблоны и домены исключений вводятся через точку с запятой. Добавляйте исключения только для доверенных сайтов.</li></ul>
<h3>Защита от цифрового отпечатка</h3><ul>
<li>Снижает объём идентифицирующих сигналов Canvas, Audio, WebGL и оборудования. Более высокий уровень может повлиять на совместимость сайтов.</li>
<li>Изменения защиты применяются настройками браузера; защита не делает пользователя анонимным.</li></ul>
<h2>7. Закладки, история и загрузки</h2><ul>
<li>Нажмите значок звёздочки, чтобы добавить текущую страницу в закладки. В менеджере закладок можно искать, редактировать, удалять, импортировать и экспортировать записи и папки.</li>
<li>Менеджер загрузок показывает активные, завершённые, приостановленные и неудачные загрузки. Можно искать файлы, отменять загрузки, открывать файл или папку и очищать историю.</li></ul>
<h2>8. Перевод веб-страниц</h2><p>Используйте меню перевода для перевода всей страницы через Google Translate или видимых текстовых фрагментов через MyMemory. Команда возврата к оригиналу открывает исходную страницу. Качество перевода зависит от службы.</p>
<h2>9. Горячие клавиши</h2><table border="1" cellpadding="7" cellspacing="0"><tr><th>Клавиши</th><th>Действие</th></tr><tr><td>Ctrl+L</td><td>Выделить адресную строку</td></tr><tr><td>Ctrl+T</td><td>Открыть новую вкладку</td></tr><tr><td>Ctrl+W</td><td>Закрыть текущую вкладку</td></tr><tr><td>Ctrl+R</td><td>Перезагрузить страницу</td></tr><tr><td>Alt+Стрелка влево / вправо</td><td>Назад / вперёд</td></tr><tr><td>Ctrl+Shift+L</td><td>Открыть менеджер паролей</td></tr><tr><td>F12</td><td>Показать или скрыть инструменты разработчика</td></tr></table>
<h2>10. Устранение неполадок и безопасность</h2><ul><li>Если сайт работает неправильно, проверьте JavaScript, cookie, всплывающие окна, блокировщик рекламы и защиту от цифрового отпечатка. Меняйте только один параметр за раз.</li><li>Если автозаполнение не появляется, разблокируйте хранилище и проверьте наличие записи для точного адреса сайта.</li><li>Перед вводом учётных данных проверяйте домен. Обновляйте LunaSurfer и Debian из доверенных источников.</li></ul>
<p class='tip'><b>Конфиденциальность:</b> средства защиты уменьшают некоторые сигналы браузера, но не обеспечивают анонимность. Сайты, сетевые провайдеры и операционная система могут продолжать обрабатывать данные.</p><p><i>Goldisoft · LunaSurfer 0.3.49</i></p>"""
        elif selected_language == "ja":
            content = """<h1>LunaSurfer – 完全ユーザーガイド</h1>
<p>このガイドでは、ブラウザーの主な機能、設定項目、および独立した「保護とプライバシー」画面について説明します。</p>
<h2>1. 基本設定</h2><ul>
<li><b>言語：</b>インターフェース、メニュー、ダイアログの言語を選択します。ガイドも選択した言語で表示されます。</li>
<li><b>起動時：</b>ホームページを開く、前回のセッションを復元する、空白ページを開く、のいずれかを選べます。</li>
<li><b>ホームページと検索エンジン：</b>起動時のページと、アドレスバーから検索するときのサービスを設定します。Google、DuckDuckGo、Bingを利用できます。</li>
<li><b>翻訳サービス：</b>Google Translateはウェブページ全体を翻訳します。MyMemoryはAPIキーなしで表示中のテキスト部分を翻訳しますが、無料利用には1日の上限があります。</li>
<li><b>ブラウザーのデザイン：</b>ウィンドウのテーマを選びます。ウェブサイトのライト／ダーク表示は別に設定できます。</li>
<li><b>ブックマークバー：</b>アドレスバーの下にあるバーを表示または非表示にします。</li>
<li><b>ダウンロード：</b>保存先フォルダーを指定し、毎回保存場所を尋ねる設定にもできます。実行可能ファイルの安全警告も設定できます。</li>
<li><b>ズームと文字サイズ：</b>初期ズーム（50～200%）と標準の文字サイズを設定します。</li>
<li><b>読みやすさとウェブサイトの色：</b>「オリジナル」はサイト本来の色を維持します。強制ダーク表示では一部サイトが正しく表示されない場合があります。問題があれば通常の表示に戻してください。</li></ul>
<h2>2. セキュリティと権限</h2><ul>
<li><b>ポップアップをブロック：</b>不要なポップアップをブロックします。信頼できるサイトで必要な場合のみ一時的に無効にしてください。</li>
<li><b>JavaScript：</b>ウェブサイトのスクリプト実行を許可します。多くのサイトで必要なため、無効にするとメニュー、ログイン、動画などが動作しない場合があります。</li>
<li><b>サイトの権限：</b>カメラ、マイク、位置情報、通知ごとに「確認」「許可」「ブロック」を設定できます。信頼できるサイトに必要な場合だけ許可してください。</li>
<li><b>Do Not Track：</b>任意の追跡拒否信号を送信します。サイト側に対応義務はありません。</li></ul>
<h2>3. User-Agent の管理</h2><ul>
<li><b>プライバシー標準：</b>簡略化したChrome形式の識別情報を使用し、バージョンやプラットフォームの詳細公開を抑えます。</li>
<li><b>標準ブラウザー User-Agent：</b>ブラウザーエンジン標準の文字列を使用します。</li>
<li><b>カスタム User-Agent：</b>入力した完全な文字列を使用します。空欄のまま保存することはできません。</li>
<li><b>現在：</b>実際に使用されている文字列を表示します。User-Agentは識別情報を変えるもので、ブラウザーエンジンや実際の機能を変更するものではありません。</li></ul>
<h2>4. パスワードマネージャー</h2><ul>
<li>保存したログイン情報はローカルで暗号化され、マスターパスワードで保護されます。管理や自動入力の前に保管庫のロック解除が必要な場合があります。</li>
<li>ログイン成功後にパスワード保存を提案する設定や、自動入力前にロック解除を必須にする設定があります。</li>
<li>ログイン情報はメールアドレスだけでなくウェブサイトに紐付けられます。保存・更新の前にサイトとアカウントを確認してください。</li>
<li>保存済みパスワードを削除しても、ウェブサイト上のパスワードは変更されません。マスターパスワードは復元できません。安全に保管し、保管庫のバックアップを作成してください。</li></ul>
<h2>5. プライバシーとブラウザーデータ</h2><ul>
<li><b>Cookie モード：</b>すべて許可、サードパーティーをブロック、すべてブロック、セッションCookieのみ許可、から選択できます。制限を強くするとログインやサイト機能に影響する場合があります。</li>
<li><b>データの消去：</b>閲覧履歴、キャッシュ、Cookieを個別またはまとめて削除できます。Cookieを削除するとサイトからログアウトされる場合があります。通常の消去ではブックマークと保存済みパスワードは保持されます。</li>
<li><b>終了時の自動消去：</b>LunaSurfer終了時に履歴、キャッシュ、Cookieをそれぞれ消去できます。</li>
<li><b>ウィンドウサイズと位置：</b>次回起動時のために記憶できます。既定のブラウザー設定は、デスクトップ環境にWebリンクでLunaSurferを使用するよう要求します。</li></ul>
<h2>6. 「保護とプライバシー」画面</h2><h3>広告ブロッカー</h3><ul>
<li>広告およびトラッキングドメインのフィルターを有効／無効にします。標準からUltra Strongまで強度を選べます。強度を上げると多くをブロックできますが、一部サイトの機能に影響する場合があります。</li>
<li>独自のブロックパターンと除外ドメインはセミコロンで区切って入力します。除外は信頼できるサイトに限ってください。</li></ul>
<h3>フィンガープリント保護</h3><ul>
<li>Canvas、Audio、WebGL、ハードウェアなど、識別に使われるブラウザー信号の公開を抑えます。保護を強めるとサイトとの互換性に影響する場合があります。</li>
<li>この機能は匿名性を保証するものではありません。</li></ul>
<h2>7. ブックマーク、履歴、ダウンロード</h2><ul>
<li>星のアイコンで現在のページをブックマークに追加できます。管理画面では検索、編集、削除、インポート、エクスポート、フォルダー管理ができます。</li>
<li>ダウンロードマネージャーには進行中、完了、一時停止、失敗した項目が表示されます。ファイル検索、ダウンロードのキャンセル、ファイルやフォルダーを開く操作、履歴の消去ができます。</li></ul>
<h2>8. ウェブページの翻訳</h2><p>翻訳メニューからGoogle Translateによるページ全体の翻訳、またはMyMemoryによる表示テキスト部分の翻訳を選べます。「元のページを表示」で原文に戻れます。翻訳品質はサービスによって異なります。</p>
<h2>9. キーボードショートカット</h2><table border="1" cellpadding="7" cellspacing="0"><tr><th>キー</th><th>操作</th></tr><tr><td>Ctrl+L</td><td>アドレスバーを選択</td></tr><tr><td>Ctrl+T</td><td>新しいタブを開く</td></tr><tr><td>Ctrl+W</td><td>現在のタブを閉じる</td></tr><tr><td>Ctrl+R</td><td>ページを再読み込み</td></tr><tr><td>Alt+左／右矢印</td><td>戻る／進む</td></tr><tr><td>Ctrl+Shift+L</td><td>パスワードマネージャーを開く</td></tr><tr><td>F12</td><td>開発者ツールの表示／非表示</td></tr></table>
<h2>10. トラブルシューティングと安全</h2><ul><li>サイトが正しく動作しない場合は、JavaScript、Cookie、ポップアップブロック、広告ブロッカー、フィンガープリント保護を確認してください。一度に変更する設定は一つにしてください。</li><li>自動入力が表示されない場合は、保管庫のロックを解除し、その正確なサイトURLのログイン情報があるか確認してください。</li><li>ログイン情報を入力する前にドメインを確認してください。LunaSurferとDebianは信頼できる配布元から更新してください。</li></ul>
<p class='tip'><b>プライバシーに関する注意：</b>保護機能は一部のブラウザー信号を減らしますが、匿名性を保証しません。ウェブサイト、ネットワーク事業者、OSは引き続き利用データを処理する場合があります。</p><p><i>Goldisoft · LunaSurfer 0.3.49</i></p>"""
        elif selected_language == "zh-CN":
            content = """<h1>LunaSurfer – 完整用户指南</h1>
<p>本指南介绍浏览器的主要功能、设置选项，以及独立的“保护与隐私”窗口。</p>
<h2>1. 常规设置</h2><ul>
<li><b>语言：</b>选择界面、菜单和对话框的语言。此指南会随所选语言切换。</li>
<li><b>启动时：</b>可以打开主页、恢复上次会话，或打开空白页面。</li>
<li><b>主页和搜索引擎：</b>设置启动页面，以及在地址栏输入搜索内容时使用的服务。可选 Google、DuckDuckGo 或 Bing。</li>
<li><b>翻译服务：</b>Google Translate 翻译整个网页；MyMemory 无需 API 密钥即可翻译可见文本片段，但有每日免费额度限制。</li>
<li><b>浏览器外观：</b>选择浏览器窗口主题。网页的浅色或深色显示可单独设置。</li>
<li><b>书签栏：</b>显示或隐藏地址栏下方的书签工具栏。</li>
<li><b>下载：</b>设置下载文件夹，也可以选择每次下载时询问保存位置。还可以设置可执行文件下载安全警告。</li>
<li><b>缩放和字体：</b>设置网页初始缩放比例（50%–200%）和默认文字大小。</li>
<li><b>网页可读性与颜色：</b>“原始”保留网站原有颜色；强制深色模式可能导致个别网站显示异常。如有问题，请恢复普通显示。</li></ul>
<h2>2. 安全与权限</h2><ul>
<li><b>阻止弹出窗口：</b>拦截不需要的弹出窗口。只有可信网站确实需要时才临时关闭。</li>
<li><b>启用 JavaScript：</b>允许网站运行脚本。许多现代网站依赖 JavaScript；关闭后菜单、登录、视频等功能可能无法使用。</li>
<li><b>网站权限：</b>摄像头、麦克风、位置和通知分别支持“询问”“允许”“阻止”。只向可信网站授予必要权限。</li>
<li><b>Do Not Track 请求：</b>发送可选的禁止跟踪信号，但网站没有义务遵守。</li></ul>
<h2>3. User-Agent 管理</h2><ul>
<li><b>隐私默认设置：</b>使用精简的 Chrome 风格浏览器标识，减少暴露的版本和平台细节。</li>
<li><b>原生浏览器 User-Agent：</b>使用浏览器引擎默认的标识字符串。</li>
<li><b>自定义 User-Agent：</b>使用输入的完整字符串。自定义值不能为空。</li>
<li><b>当前值：</b>显示实际生效的 User-Agent。它只改变浏览器标识，不会改变浏览器引擎或实际功能。</li></ul>
<h2>4. 密码管理器</h2><ul>
<li>保存的登录信息在本地加密，并由主密码保护。管理记录或自动填充前，可能需要先解锁密码库。</li>
<li>可以设置在成功登录后提示保存密码，也可以要求自动填充前必须解锁密码库。</li>
<li>登录信息与具体网站关联，而不只是与电子邮件地址关联。保存或更新前请核对网站和账户。</li>
<li>删除已保存密码不会更改网站本身的密码。主密码无法恢复，请妥善保管，并为加密密码库创建安全备份。</li></ul>
<h2>5. 隐私和浏览器数据</h2><ul>
<li><b>Cookie 模式：</b>可以允许所有 Cookie、阻止第三方 Cookie、阻止所有 Cookie，或仅允许会话 Cookie。限制过严可能影响登录和网站功能。</li>
<li><b>清除数据：</b>可以分别或一起清除浏览历史、缓存和 Cookie。清除 Cookie 后，网站可能要求重新登录。常规清理不会删除书签和已保存密码。</li>
<li><b>退出时自动清除：</b>可分别设置退出 LunaSurfer 时清除历史、缓存和 Cookie。</li>
<li><b>记住窗口大小和位置：</b>下次启动时恢复窗口尺寸和位置。将 LunaSurfer 设为默认浏览器会请求桌面环境使用它打开网页链接。</li></ul>
<h2>6. “保护与隐私”窗口</h2><h3>广告拦截器</h3><ul>
<li>启用或关闭广告和跟踪域名过滤。强度从标准到 Ultra Strong 可选；级别越高，过滤越多，但可能影响部分网站功能。</li>
<li>自定义拦截规则和白名单域名使用分号分隔。只将可信网站加入白名单。</li></ul>
<h3>指纹保护</h3><ul>
<li>减少 Canvas、Audio、WebGL 和硬件等可用于识别浏览器的信号。更强的保护可能影响网站兼容性。</li>
<li>指纹保护不能保证匿名。</li></ul>
<h2>7. 书签、历史记录和下载</h2><ul>
<li>点击星形图标可将当前网页加入书签。书签管理器支持搜索、编辑、删除、导入、导出和文件夹管理。</li>
<li>下载管理器显示正在下载、已完成、已暂停和失败的项目。可以搜索文件、取消下载、打开文件或文件夹，以及清理下载历史。</li></ul>
<h2>8. 网页翻译</h2><p>通过翻译菜单，可以使用 Google Translate 翻译整个网页，或使用 MyMemory 翻译可见文本片段。选择“显示原始页面”可返回原网页。翻译质量取决于所选服务。</p>
<h2>9. 键盘快捷键</h2><table border="1" cellpadding="7" cellspacing="0"><tr><th>快捷键</th><th>操作</th></tr><tr><td>Ctrl+L</td><td>选中地址栏</td></tr><tr><td>Ctrl+T</td><td>打开新标签页</td></tr><tr><td>Ctrl+W</td><td>关闭当前标签页</td></tr><tr><td>Ctrl+R</td><td>重新加载页面</td></tr><tr><td>Alt+左／右方向键</td><td>后退／前进</td></tr><tr><td>Ctrl+Shift+L</td><td>打开密码管理器</td></tr><tr><td>F12</td><td>显示或隐藏开发者工具</td></tr></table>
<h2>10. 故障排除与安全</h2><ul><li>网站无法正常工作时，请检查 JavaScript、Cookie、弹出窗口拦截、广告拦截器和指纹保护。每次只更改一项设置。</li><li>自动填充没有出现时，请解锁密码库，并确认是否存在与该网站准确地址对应的登录记录。</li><li>输入登录信息前请核对域名。请从可信来源更新 LunaSurfer 和 Debian。</li></ul>
<p class='tip'><b>隐私提示：</b>隐私功能可以减少部分浏览器信号，但不能让用户匿名。网站、网络服务提供商和操作系统仍可能处理使用数据。</p><p><i>Goldisoft · LunaSurfer 0.3.49</i></p>"""
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
<li><b>Werbeblocker aktivieren:</b> schaltet die Filterung ein oder aus.</li><li><b>Blockierstärke:</b> Standard, Stark, Sehr stark, Super stark, Mega stark oder Ultra stark. Höhere Stufen filtern mehr Muster, können aber Funktionen stören oder Inhalte ausblenden.</li>
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
        language = QComboBox()
        language.addItem("Deutsch", "de")
        language.addItem("English", "en")
        language.addItem("Français", "fr")
        language.addItem("Italiano", "it")
        language.addItem("Nederlands", "nl")
        language.addItem("Español", "es")
        language.addItem("Português", "pt")
        language.addItem("Polski", "pl")
        language.addItem("Türkçe", "tr")
        language.addItem("Русский", "ru")
        language.addItem("日本語", "ja")
        language.addItem("中文（简体）", "zh-CN")
        language.setCurrentIndex(max(0, language.findData(self.settings_data.get("language", "de"))))
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
        warn_executable_downloads = QCheckBox(self.tr("Sicherheitswarnung bei ausführbaren Downloads anzeigen", "Show security warning for executable downloads"))
        warn_executable_downloads.setChecked(self.settings_data.get("warn_executable_downloads", True))
        show_download_complete_popup = QCheckBox(self.tr("Popup nach Abschluss eines Downloads anzeigen", "Show popup when a download finishes"))
        show_download_complete_popup.setChecked(self.settings_data.get("show_download_complete_popup", True))
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
        form.addRow(self.tr("Sprache:", "Language:"), language); form.addRow(self.tr("Beim Start:", "On startup:"),startup); form.addRow(self.tr("Startseite:", "Homepage:"),home); form.addRow(self.tr("Suchmaschine:", "Search engine:"),engine); form.addRow(self.tr("Übersetzungsanbieter:", "Translation provider:"), translation_provider); form.addRow("", translation_help); form.addRow(self.tr("Browser-Design:", "Browser design:"),browser_design); form.addRow(self.tr("Webseiten-Design:", "Website appearance:"),theme); form.addRow("",show_bookmarks_bar); add_section(self.tr("Downloads", "Downloads")); form.addRow(self.tr("Download-Ordner:", "Download folder:"),row); form.addRow("",ask_download); form.addRow("",warn_executable_downloads); form.addRow("",show_download_complete_popup); form.addRow(self.tr("Standard-Zoom:", "Default zoom:"),zoom); form.addRow(self.tr("Standard-Schriftgröße:", "Default font size:"),font_size); form.addRow(self.tr("Webseiten-Lesbarkeit:", "Website readability:"), readability); form.addRow(self.tr("Webseiten-Farbgebung:", "Website colors:"), website_color)
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
        save.clicked.connect(lambda:self.save_settings_v39(page,home.text(),engine.currentText(),engine.currentData(),theme.currentData(),show_bookmarks_bar.isChecked(),startup.currentData(),download_dir.text(),ask_download.isChecked(),zoom.currentData(),font_size.currentData(),block.isChecked(),dnt.isChecked(),confirm_tabs.isChecked(),{k:v.currentData() for k,v in permission_boxes.items()},clear_history_exit.isChecked(),clear_cache_exit.isChecked(),clear_cookies_exit.isChecked(),remember_window_size.isChecked(),language.currentData(),default_browser.isChecked(),browser_design.currentData(),javascript.isChecked(),cookie_mode.currentData(),password_auto_save.isChecked(),password_unlock_required.isChecked(),readability.currentData(),website_color.currentData(),ua_mode.currentData(),ua_custom.text(),translation_provider.currentData(),show_download_complete_popup.isChecked(),warn_executable_downloads.isChecked()))
        cancel.clicked.connect(lambda: self.close_settings_page(page))

    def close_settings_page(self, page):
        index = self.tabs.indexOf(page)
        if index >= 0:
            self.tabs.removeTab(index)
            page.deleteLater()
            if self.tabs.count() == 0:
                self.add_tab(self.settings_data.get("home"))
            QTimer.singleShot(0, self.update_new_tab_button_position)

    def save_settings_v39(self, dialog, home, engine_name, search_url, theme, bookmarks, startup_mode, download_dir, ask_download, zoom, font_size, block, dnt, confirm_tabs, permissions, ch, cc, ck, remember_window_size=True, language="de", default_browser=False, browser_design="dark", javascript_enabled=True, cookie_mode="all", password_auto_save=True, password_unlock_required=True, website_readability="normal", website_color_mode="normal", user_agent_mode="privacy", user_agent_custom="", translation_provider="google", show_download_complete_popup=True, warn_executable_downloads=True):
        if user_agent_mode == "custom" and not str(user_agent_custom).strip():
            QMessageBox.warning(self, self.tr("User-Agent fehlt", "User-Agent missing"), self.tr("Bitte einen vollständigen User-Agent eintragen oder einen anderen Modus auswählen.", "Enter a complete User-Agent or select another mode."))
            return
        chosen=pathlib.Path(download_dir.strip() or str(DOWNLOAD_DIR)).expanduser()
        previous_translation_provider = self.settings_data.get("translation_provider", "google")
        selected_translation_provider = translation_provider if translation_provider in ("google", "mymemory") else "google"
        self.settings_data.update({"home":home.strip() or "https://duckduckgo.com","search":search_url,"search_engine":engine_name,"theme":theme,"show_bookmarks_bar":bool(bookmarks),"startup_mode":startup_mode,"restore_session":startup_mode=="restore","download_dir":str(chosen),"default_zoom":int(zoom or 100),"font_size":font_size,"ask_download_location":bool(ask_download),"block_popups":bool(block),"javascript_enabled":bool(javascript_enabled),"send_dnt":bool(dnt),"confirm_close_multiple_tabs":bool(confirm_tabs),"clear_history_on_exit":bool(ch),"clear_cache_on_exit":bool(cc),"clear_cookies_on_exit":bool(ck),"cookie_mode":cookie_mode if cookie_mode in ("all","third","none","session") else "all","remember_window_size":bool(remember_window_size),"language":language or "de","default_browser":bool(default_browser),"browser_design":browser_design if browser_design in ("dark", "light", "luna", "graphite", "ocean") else "dark","password_auto_save":bool(password_auto_save),"password_unlock_required":bool(password_unlock_required),"website_readability": website_readability if website_readability in ("normal", "soft", "softer", "relaxed") else "normal", "website_color_mode": website_color_mode if website_color_mode in ("normal", "black") else "normal", "user_agent_mode": user_agent_mode if user_agent_mode in ("privacy", "native", "custom") else "privacy", "user_agent_custom": str(user_agent_custom).strip(), "translation_provider": selected_translation_provider,"show_download_complete_popup":bool(show_download_complete_popup),"warn_executable_downloads":bool(warn_executable_downloads),**permissions})
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
        mode = self.settings_data.get("cookie_mode", "third")
        if mode == "none":
            return False
        if mode == "third":
            return not bool(request.thirdParty)
        return True

    def apply_cookie_mode(self):
        """Apply persistence behavior; cookie filtering is handled by CookieStore."""
        mode = self.settings_data.get("cookie_mode", "third")
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
    # This same helper is called again whenever the user changes the UI language.
    try:
        saved_language = read_json(CONFIG_FILE, {}).get("language", "de")
    except Exception:
        saved_language = "de"
    refresh_qt_dialog_language(saved_language)
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
