import { CheckResult } from '../types';

interface TechSignature {
  name: string;
  category: 'framework' | 'hosting' | 'cdn' | 'cms' | 'analytics' | 'other';
  // Header-based detection
  headers?: { name: string; pattern: RegExp }[];
  // HTML/meta tag detection
  html?: RegExp[];
  // Cookie detection
  cookies?: RegExp[];
  // URL path detection
  paths?: string[];
}

const TECH_SIGNATURES: TechSignature[] = [
  // Frameworks
  {
    name: 'Next.js',
    category: 'framework',
    headers: [{ name: 'x-nextjs-cache', pattern: /.+/ }],
    html: [
      /_next\/static/,
      /__NEXT_DATA__/,
      /next\/dist/
    ],
    paths: ['/_next/']
  },
  {
    name: 'Nuxt.js',
    category: 'framework',
    html: [
      /_nuxt\//,
      /__NUXT__/,
      /nuxt\.js/i
    ]
  },
  {
    name: 'React',
    category: 'framework',
    html: [
      /react\.production\.min\.js/,
      /react-dom/,
      /__REACT_DEVTOOLS/,
      /data-reactroot/,
      /data-reactid/
    ]
  },
  {
    name: 'Vue.js',
    category: 'framework',
    html: [
      /vue\.runtime/,
      /vue\.min\.js/,
      /data-v-[a-f0-9]{8}/,
      /__VUE__/
    ]
  },
  {
    name: 'Angular',
    category: 'framework',
    html: [
      /ng-version/,
      /angular\.min\.js/,
      /ng-app/,
      /\[\(ngModel\)\]/
    ]
  },
  {
    name: 'Svelte',
    category: 'framework',
    html: [
      /svelte/i,
      /__svelte/
    ]
  },
  {
    name: 'Remix',
    category: 'framework',
    html: [
      /__remix/,
      /remix\.run/i
    ]
  },
  {
    name: 'Astro',
    category: 'framework',
    html: [
      /astro-/,
      /is:visible/,
      /client:load/
    ]
  },

  // Hosting
  {
    name: 'Vercel',
    category: 'hosting',
    headers: [
      { name: 'x-vercel-id', pattern: /.+/ },
      { name: 'server', pattern: /vercel/i }
    ]
  },
  {
    name: 'Netlify',
    category: 'hosting',
    headers: [
      { name: 'x-nf-request-id', pattern: /.+/ },
      { name: 'server', pattern: /netlify/i }
    ]
  },
  {
    name: 'AWS',
    category: 'hosting',
    headers: [
      { name: 'x-amz-request-id', pattern: /.+/ },
      { name: 'x-amzn-requestid', pattern: /.+/ },
      { name: 'server', pattern: /AmazonS3|CloudFront/i }
    ]
  },
  {
    name: 'Google Cloud',
    category: 'hosting',
    headers: [
      { name: 'x-cloud-trace-context', pattern: /.+/ },
      { name: 'server', pattern: /Google Frontend/i }
    ]
  },
  {
    name: 'Heroku',
    category: 'hosting',
    headers: [
      { name: 'via', pattern: /heroku/i }
    ]
  },
  {
    name: 'Railway',
    category: 'hosting',
    headers: [
      { name: 'x-railway-request-id', pattern: /.+/ }
    ]
  },
  {
    name: 'Render',
    category: 'hosting',
    headers: [
      { name: 'x-render-origin-server', pattern: /.+/ }
    ]
  },
  {
    name: 'Fly.io',
    category: 'hosting',
    headers: [
      { name: 'fly-request-id', pattern: /.+/ }
    ]
  },
  {
    name: 'DigitalOcean',
    category: 'hosting',
    headers: [
      { name: 'x-do-app-origin', pattern: /.+/ },
      { name: 'x-do-orig-status', pattern: /.+/ }
    ]
  },

  // CDN
  {
    name: 'Cloudflare',
    category: 'cdn',
    headers: [
      { name: 'cf-ray', pattern: /.+/ },
      { name: 'server', pattern: /cloudflare/i },
      { name: 'cf-cache-status', pattern: /.+/ }
    ]
  },
  {
    name: 'Fastly',
    category: 'cdn',
    headers: [
      { name: 'x-served-by', pattern: /cache-/i },
      { name: 'x-fastly-request-id', pattern: /.+/ }
    ]
  },
  {
    name: 'Akamai',
    category: 'cdn',
    headers: [
      { name: 'x-akamai-transformed', pattern: /.+/ }
    ]
  },

  // CMS
  {
    name: 'WordPress',
    category: 'cms',
    html: [
      /wp-content/,
      /wp-includes/,
      /wordpress/i
    ],
    paths: ['/wp-admin/', '/wp-content/', '/wp-includes/']
  },
  {
    name: 'Shopify',
    category: 'cms',
    headers: [
      { name: 'x-shopify-stage', pattern: /.+/ }
    ],
    html: [
      /cdn\.shopify\.com/,
      /Shopify\.theme/
    ]
  },
  {
    name: 'Webflow',
    category: 'cms',
    html: [
      /webflow/i,
      /assets\.website-files\.com/
    ]
  },
  {
    name: 'Wix',
    category: 'cms',
    html: [
      /wix\.com/,
      /wixstatic\.com/
    ]
  },
  {
    name: 'Squarespace',
    category: 'cms',
    html: [
      /squarespace/i,
      /sqsp\.net/
    ]
  },
  {
    name: 'Ghost',
    category: 'cms',
    headers: [
      { name: 'x-ghost-cache-status', pattern: /.+/ }
    ],
    html: [
      /ghost-/,
      /content\/themes/
    ]
  },

  // Analytics
  {
    name: 'Google Analytics',
    category: 'analytics',
    html: [
      /google-analytics\.com/,
      /googletagmanager\.com/,
      /gtag\(/
    ]
  },
  {
    name: 'Plausible',
    category: 'analytics',
    html: [
      /plausible\.io/
    ]
  },
  {
    name: 'Fathom',
    category: 'analytics',
    html: [
      /usefathom\.com/
    ]
  },
  {
    name: 'Mixpanel',
    category: 'analytics',
    html: [
      /mixpanel\.com/
    ]
  },
  {
    name: 'Amplitude',
    category: 'analytics',
    html: [
      /amplitude\.com/
    ]
  },

  // Auth providers (common for vibe coders)
  {
    name: 'Clerk',
    category: 'other',
    html: [
      /clerk\.com/,
      /clerk\.accounts/
    ]
  },
  {
    name: 'Auth0',
    category: 'other',
    html: [
      /auth0\.com/
    ]
  },
  {
    name: 'Supabase',
    category: 'other',
    html: [
      /supabase\.co/,
      /supabase\.io/
    ]
  },
  {
    name: 'Firebase',
    category: 'other',
    html: [
      /firebaseapp\.com/,
      /firebase\.google\.com/,
      /firebaseio\.com/
    ]
  },
  {
    name: 'Stripe',
    category: 'other',
    html: [
      /js\.stripe\.com/,
      /stripe\.com/
    ]
  }
];

interface DetectedTech {
  name: string;
  category: string;
  confidence: 'high' | 'medium';
}

export async function checkTechStack(url: string, headers: Headers, html: string): Promise<CheckResult> {
  const detected: DetectedTech[] = [];

  // Check headers
  for (const tech of TECH_SIGNATURES) {
    if (tech.headers) {
      for (const headerCheck of tech.headers) {
        const value = headers.get(headerCheck.name);
        if (value && headerCheck.pattern.test(value)) {
          if (!detected.some(d => d.name === tech.name)) {
            detected.push({
              name: tech.name,
              category: tech.category,
              confidence: 'high'
            });
          }
          break;
        }
      }
    }
  }

  // Check HTML patterns
  for (const tech of TECH_SIGNATURES) {
    if (tech.html && !detected.some(d => d.name === tech.name)) {
      for (const pattern of tech.html) {
        if (pattern.test(html)) {
          detected.push({
            name: tech.name,
            category: tech.category,
            confidence: 'medium'
          });
          break;
        }
      }
    }
  }

  // Group by category for nice output
  const byCategory: Record<string, string[]> = {};
  for (const tech of detected) {
    if (!byCategory[tech.category]) {
      byCategory[tech.category] = [];
    }
    byCategory[tech.category].push(tech.name);
  }

  return {
    name: 'Technology Stack',
    passed: true, // This is informational, not a pass/fail check
    issues: [], // No issues - just detection
    details: {
      detected: detected.map(d => ({ name: d.name, category: d.category, confidence: d.confidence })),
      summary: byCategory
    }
  };
}
