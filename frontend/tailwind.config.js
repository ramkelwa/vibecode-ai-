/**
 * Tailwind configuration for VibeShield AI frontend.
 *
 * Design language: editorial black-on-white, after Preymaker (DashDigital).
 * Two colours carry almost everything — paper #FFFFFF and ink #2A2A2A — with
 * hairline rules instead of cards, shadows or gradients. The ramps below are
 * inversion-compatible with the class names already used across the app, so
 * `text-slate-100` resolves to ink and `bg-slate-950` to the bone surface.
 */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          '"Instrument Sans"',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          '"Segoe UI"',
          'sans-serif',
        ],
      },
      colors: {
        slate: {
          50: '#f7f6f2', // bone wash
          100: '#2a2a2a', // primary ink (headings)
          200: '#232323',
          300: '#3d3d3a', // body copy
          400: '#6e6e68', // muted
          500: '#6e6e68',
          600: '#9a9992', // faint / captions
          700: '#b5b4ac',
          800: '#d8d7cf', // hairline (as a solid)
          900: '#2a2a2a', // ink, used at low opacity for rules
          950: '#f3f2ed', // bone surface (chips, code blocks)
        },
        /* Interaction accent: the ink itself, so links and focus read as type. */
        cyan: {
          50: '#f7f6f2',
          100: '#ecebe4',
          200: '#dcdbd3',
          300: '#b5b4ac',
          400: '#8a8981',
          500: '#5a5a54',
          600: '#3d3d3a',
          700: '#2a2a2a',
          800: '#1f1f1f',
          900: '#171717',
          950: '#0f0f0f',
        },
        sky: {
          50: '#f7f6f2',
          100: '#ecebe4',
          200: '#dcdbd3',
          300: '#b5b4ac',
          400: '#8a8981',
          500: '#5a5a54',
          600: '#3d3d3a',
          700: '#2a2a2a',
          800: '#1f1f1f',
          900: '#171717',
          950: '#0f0f0f',
        },
        /* Machine-written text (AI explanations) gets one warm stone accent so it
           can never be mistaken for scanner evidence. */
        violet: {
          100: '#efe8da',
          200: '#e0d5c1',
          300: '#c9b795',
          400: '#ad9a75',
          500: '#8f7c56',
          600: '#7a6844',
          700: '#665636',
          800: '#54462c',
          900: '#443a26',
          950: '#221d13',
        },
        /* Success keeps a quiet green: status is meaning, not decoration. */
        emerald: {
          100: '#e6f2e9',
          200: '#c9e4d2',
          300: '#9bcbb0',
          400: '#6fae8a',
          500: '#4c8f6c',
          600: '#3a7a59',
          700: '#2f6b4f',
          800: '#275842',
          900: '#204836',
          950: '#10241b',
        },
        /*
         * Severity keeps distinct hues: a risky finding must never read as the
         * black editorial accent. Only `info` stays neutral.
         */
        severity: {
          critical: '#a21caf',
          high: '#c02626',
          medium: '#b45309',
          low: '#1f5fa8',
          info: '#6e6e68',
        },
      },
    },
  },
  plugins: [],
}
