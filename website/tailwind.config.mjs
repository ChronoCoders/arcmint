/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        bg: {
          base:    '#05070a',
          surface: '#0d1117',
          raised:  '#131c2b',
          border:  '#1e2d3d',
        },
        orange: {
          DEFAULT: '#f7931a',
          dim:     'rgba(247,147,26,0.15)',
          glow:    'rgba(247,147,26,0.35)',
        },
        text: {
          primary:   '#e8edf4',
          secondary: '#7d8fa3',
          dim:       '#3d5066',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'float':         'float 6s ease-in-out infinite',
        'float-delay':   'float 6s ease-in-out 2s infinite',
        'float-slow':    'float 9s ease-in-out 1s infinite',
        'pulse-orange':  'pulse-orange 3s ease-in-out infinite',
        'grid-pan':      'grid-pan 25s linear infinite',
        'fade-up':       'fade-up 0.6s ease-out forwards',
        'glow-ring':     'glow-ring 3s ease-in-out infinite',
        'slide-right':   'slide-right 0.5s ease-out forwards',
        'count-up':      'count-up 0.8s ease-out forwards',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%':      { transform: 'translateY(-18px)' },
        },
        'pulse-orange': {
          '0%, 100%': { opacity: '0.6', transform: 'scale(1)' },
          '50%':      { opacity: '1',   transform: 'scale(1.05)' },
        },
        'grid-pan': {
          '0%':   { backgroundPosition: '0 0' },
          '100%': { backgroundPosition: '60px 60px' },
        },
        'fade-up': {
          '0%':   { opacity: '0', transform: 'translateY(24px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'glow-ring': {
          '0%, 100%': { opacity: '0.4', transform: 'scale(1)' },
          '50%':      { opacity: '0.8', transform: 'scale(1.12)' },
        },
        'slide-right': {
          '0%':   { opacity: '0', transform: 'translateX(-16px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
      },
      boxShadow: {
        'orange-sm':  '0 0 12px rgba(247,147,26,0.25)',
        'orange-md':  '0 0 28px rgba(247,147,26,0.35)',
        'orange-lg':  '0 0 60px rgba(247,147,26,0.2)',
        'card':       '0 1px 3px rgba(0,0,0,0.5), 0 0 0 1px rgba(30,45,61,0.6)',
        'card-hover': '0 4px 24px rgba(0,0,0,0.6), 0 0 0 1px rgba(247,147,26,0.25)',
      },
      backgroundImage: {
        'orange-gradient':  'linear-gradient(135deg, #f7931a, #e8650a)',
        'hero-radial':      'radial-gradient(ellipse 80% 60% at 60% 40%, rgba(247,147,26,0.08) 0%, transparent 70%)',
        'grid-pattern':     'linear-gradient(rgba(247,147,26,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(247,147,26,0.04) 1px, transparent 1px)',
        'card-gradient':    'linear-gradient(135deg, rgba(19,28,43,0.9), rgba(13,17,23,0.9))',
        'border-gradient':  'linear-gradient(135deg, rgba(247,147,26,0.4), rgba(247,147,26,0.1))',
      },
      backgroundSize: {
        'grid': '60px 60px',
      },
    },
  },
  plugins: [],
};
