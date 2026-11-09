import { createRoot } from 'react-dom/client';
import { Mixia } from '@mixia/core';
import { Root } from './Root';
import { devBridge, type Bridge } from './bridge';
import './styles.css';

declare global {
  interface Window {
    /** 由平台外壳在启动前注入。 */
    mixiaBridge?: () => Promise<Bridge>;
  }
}

async function start() {
  const bridge = window.mixiaBridge ? await window.mixiaBridge() : await loadShellBridge();
  const m = await Mixia.boot(bridge.env);
  if (import.meta.env.DEV) (window as unknown as { __m: Mixia }).__m = m;
  createRoot(document.getElementById('root')!).render(<Root m={m} bridge={bridge} />);
}

async function loadShellBridge(): Promise<Bridge> {
  const w = window as unknown as { mixiaDesktop?: unknown; Capacitor?: { isNativePlatform(): boolean } };
  if (w.mixiaDesktop) return (await import('./shell-desktop')).desktopBridge();
  if (w.Capacitor?.isNativePlatform()) return (await import('./shell-mobile')).mobileBridge();
  return devBridge();
}

void start();
