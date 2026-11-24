import { createRoot } from 'react-dom/client';
import { registerSW } from 'virtual:pwa-register';
import App from './App.tsx';
import './index.css';

try {
  registerSW({
    immediate: true,
    onOfflineReady() {
      // Service worker precache ready for offline shell availability
    },
  });
} catch {
  // Safe fallback if browser restricts service workers in an embedded frame
}

createRoot(document.getElementById('root')!).render(<App />);
