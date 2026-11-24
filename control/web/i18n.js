// STATUS: DIAMANT VGT SUPREME
'use strict';

// V6.3.0 refactoring wave 2: the DE/EN/RU/zh-CN catalogue data lives in
// ./i18n/<language>.js; this module keeps the public translator API stable so
// every existing `import { t } from './i18n.js'` keeps working.
import { catalog as de } from './i18n/de.js';
import { catalog as en } from './i18n/en.js';
import { catalog as ru } from './i18n/ru.js';
import { catalog as zhCN } from './i18n/zh-CN.js';

export const SUPPORTED_LANGUAGES = Object.freeze(['de', 'en', 'ru', 'zh-CN']);
const SUPPORTED = new Set(SUPPORTED_LANGUAGES);
const LOCALES = Object.freeze({ de: 'de-DE', en: 'en-US', ru: 'ru-RU', 'zh-CN': 'zh-CN' });

export const catalogs = Object.freeze({ de, en, ru, 'zh-CN': zhCN });

let activeLanguage = 'de';
try {
  const saved = typeof localStorage !== 'undefined' ? localStorage.getItem('gedefense.language') : null;
  if (saved && SUPPORTED.has(saved)) activeLanguage = saved;
  if (typeof window !== 'undefined' && window.location && typeof window.location.search === 'string') {
    const queryLang = new URLSearchParams(window.location.search).get('lang');
    if (queryLang && SUPPORTED.has(queryLang)) {
      activeLanguage = queryLang;
      if (typeof localStorage !== 'undefined') localStorage.setItem('gedefense.language', queryLang);
    }
  }
} catch (_) {}

export function locale() {
  return LOCALES[activeLanguage] || 'de-DE';
}

export function currentLanguage() {
  return activeLanguage;
}

export function setLanguage(lang) {
  if (!SUPPORTED.has(lang) || lang === activeLanguage) return;
  activeLanguage = lang;
  try {
    if (typeof localStorage !== 'undefined') localStorage.setItem('gedefense.language', lang);
  } catch (_) {}
  applyTranslations();
  if (typeof document !== 'undefined') {
    document.dispatchEvent(new CustomEvent('gedefense:language', { detail: lang }));
  }
}

export function t(key, vars = {}) {
  const catalog = catalogs[activeLanguage] || catalogs.de || {};
  let text = catalog[key] || catalogs.de[key] || key;
  for (const [name, val] of Object.entries(vars)) {
    text = text.replaceAll('{' + name + '}', String(val));
  }
  return text;
}

export function applyTranslations(root = document) {
  if (typeof document !== 'undefined' && document.documentElement) {
    document.documentElement.lang = activeLanguage;
  }
  root.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (key) el.textContent = t(key);
  });
  root.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (key) el.setAttribute('placeholder', t(key));
  });
  root.querySelectorAll('[data-i18n-aria]').forEach(el => {
    const key = el.getAttribute('data-i18n-aria');
    if (key) el.setAttribute('aria-label', t(key));
  });
  root.querySelectorAll('[data-i18n-title]').forEach(el => {
    const key = el.getAttribute('data-i18n-title');
    if (key) el.setAttribute('title', t(key));
  });
  const langSelect = root.querySelector('#languageSelect');
  if (langSelect) langSelect.value = activeLanguage;
}

export function initializeI18n() {
  applyTranslations();
}
