/**
 * Tailwind configuration for VibeShield AI frontend.
 *
 * Modern security operations design system inspired by shadcn/ui and Radix UI:
 * Deep obsidian surfaces, refined hairline borders, crisp typography, and
 * WCAG-compliant high-contrast status and severity indicators.
 */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: [
          '"Instrument Sans"',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          '"Helvetica Neue"',
          'Arial',
          'sans-serif',
        ],
        mono: [
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          '"Liberation Mono"',
          '"Courier New"',
          'monospace',
        ],
      },
      colors: {
        // High-contrast slate/zinc ramp mapped for compatibility with existing components
        slate: {
          50: '#141416', // elevated dark surface for cards and panels
          100: '#fafafa', // primary crisp white for headings
          200: '#f4f4f5', // secondary white
          300: '#d4d4d8', // primary body text (high contrast)
          400: '#a1a1aa', // muted captions and metadata (WCAG AA > 4.5:1)
          500: '#71717a', // subtle helper text
          600: '#52525b', // faint tags and borders
          700: '#3f3f46', // subtle hairline border
          800: '#27272a', // standard card border
          900: '#18181b', // card background
          950: '#09090b', // obsidian page background
        },
        // Real cyan & sky accents for links and focus indicators
        cyan: {
          50: '#083344',
          100: '#0e4e68',
          200: '#075985',
          300: '#0284c7',
          400: '#0ea5e9',
          500: '#38bdf8',
          600: '#7dd3fc',
          700: '#38bdf8', // crisp legible link on dark
          800: '#bae6fd',
          900: '#e0f2fe',
          950: '#f0f9ff',
        },
        sky: {
          50: '#082f49',
          100: '#0c4a6e',
          200: '#0369a1',
          300: '#0284c7',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#38bdf8',
          700: '#7dd3fc',
          800: '#bae6fd',
          900: '#e0f2fe',
          950: '#f0f9ff',
        },
        // AI explanation accent (warm violet / amethyst)
        violet: {
          100: '#2e1065',
          200: '#4c1d95',
          300: '#d8b4fe',
          400: '#c084fc',
          500: '#a855f7',
          600: '#9333ea',
          700: '#e9d5ff',
          800: '#f3e8ff',
          900: '#faf5ff',
          950: '#fcfaff',
        },
        // Success green
        emerald: {
          100: '#022c22',
          200: '#064e3b',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          600: '#059669',
          700: '#a7f3d0',
          800: '#d1fae5',
          900: '#ecfdf5',
          950: '#f0fdf4',
        },
        // Cybersecurity severity spectrum (WCAG AA legible on #09090b)
        severity: {
          critical: '#ef4444', // red-500
          high: '#f97316', // orange-500
          medium: '#f59e0b', // amber-500
          low: '#38bdf8', // sky-400
          info: '#94a3b8', // slate-400
        },
      },
      borderRadius: {
        lg: '0.625rem',
        md: '0.5rem',
        sm: '0.375rem',
      },
      boxShadow: {
        card: '0 4px 20px -2px rgba(0, 0, 0, 0.45), inset 0 1px 0 0 rgba(255, 255, 255, 0.05)',
        'card-hover': '0 8px 30px -4px rgba(0, 0, 0, 0.6), inset 0 1px 0 0 rgba(255, 255, 255, 0.08)',
        subtle: '0 1px 2px 0 rgba(0, 0, 0, 0.3)',
      },
    },
  },
  plugins: [],
}
