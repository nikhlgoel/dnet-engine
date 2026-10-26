import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';
import { defineConfig, type Plugin } from 'vite';

/**
 * ADR-0007 R4 / design-system §17: Content-Security-Policy `default-src 'self'`, no remote content, no
 * inline script. Added to the built page only: the dev server injects inline styles for hot reload.
 * No `{@html}` and no inline style attributes exist in the app, so nothing needs `unsafe-inline`.
 */
function contentSecurityPolicy(): Plugin {
  const policy = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self' ipc: http://ipc.localhost",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join('; ');
  return {
    name: 'dnet-csp',
    apply: 'build',
    transformIndexHtml: (html) =>
      html.replace('<!--csp-->', `<meta http-equiv="Content-Security-Policy" content="${policy}" />`),
  };
}

export default defineConfig({
  // The testing plugin resolves Svelte's browser build and cleans up after each test; it is not in the app.
  plugins: [svelte(), contentSecurityPolicy(), ...(process.env.VITEST ? [svelteTesting()] : [])],
  // The one stylesheet that defines a colour, a size or a duration lives under docs/design (R7).
  server: { fs: { allow: ['../..'] }, port: 5173, strictPort: true },
  build: { target: 'es2022', sourcemap: false, cssCodeSplit: false, assetsInlineLimit: 0 },
  test: {
    environment: 'jsdom',
    include: ['tests/**/*.test.ts'],
    css: false,
    setupFiles: ['tests/setup.ts'],
  },
});
