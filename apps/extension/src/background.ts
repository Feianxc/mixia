/** 把 Controller 接到 chrome.* 上，不放判断。 */
import { Controller, type Browser } from './controller';
import { NativeClient } from './native';

const browser: Browser = {
  async frames(tabId) {
    const list = await chrome.webNavigation.getAllFrames({ tabId }).catch(() => null);
    return list?.map((f) => ({ frameId: f.frameId, parentFrameId: f.parentFrameId, url: f.url, documentId: f.documentId })) ?? null;
  },
  send: (tabId, documentId, msg) => chrome.tabs.sendMessage(tabId, msg, { documentId }),
  async activeTab() {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return tab?.id;
  },
  openPopup: () => chrome.action.openPopup().then(
    () => true,
    () => false,
  ),
  badge(tabId, text) {
    const set = (t: string) => void chrome.action.setBadgeText({ tabId, text: t }).catch(() => undefined); // 标签页可能已关
    set(text);
    setTimeout(() => set(''), 3000);
  },
};

const controller = new Controller(chrome.runtime.id, browser, new NativeClient());

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  void controller.handle(msg, sender).then(reply, () => reply({ error: 'failed' }));
  return true;
});
