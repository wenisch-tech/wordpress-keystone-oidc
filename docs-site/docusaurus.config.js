// @ts-check

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Keystone OIDC',
  tagline: 'Turn WordPress into an OpenID Connect identity provider',
  favicon: 'img/favicon.gif',
  // Override through the environment for a custom domain or sub-path.
  url: process.env.DOCS_URL || 'https://wenisch-tech.github.io',
  baseUrl: process.env.DOCS_BASE_URL || '/wordpress-keystone-oidc/',
  organizationName: 'wenisch-tech',
  projectName: 'wordpress-keystone-oidc',
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'warn',
  trailingSlash: true,

  // The pages are plain CommonMark; only files that opt in via .mdx are parsed as MDX.
  markdown: {
    format: 'detect',
    mermaid: true,
    hooks: { onBrokenMarkdownLinks: 'throw' },
  },
  themes: [
    '@docusaurus/theme-mermaid',
    [
      '@easyops-cn/docusaurus-search-local',
      { hashed: true, docsDir: '../docs', indexBlog: false, docsRouteBasePath: '/', highlightSearchTermsOnTargetPage: true },
    ],
  ],

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: '../docs',
          routeBasePath: '/',
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/wenisch-tech/wordpress-keystone-oidc/edit/main/docs/',
        },
        blog: false,
        theme: { customCss: './src/css/custom.css' },
      }),
    ],
  ],

  themeConfig: /** @type {import('@docusaurus/preset-classic').ThemeConfig} */ ({
    image: 'img/social-card.png',
    colorMode: { respectPrefersColorScheme: true },
    navbar: {
      title: 'Keystone OIDC',
      logo: { alt: 'Keystone OIDC', src: 'img/logo.gif' },
      items: [
        { type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Documentation' },
        { href: 'https://wordpress.org/plugins/keystone-oidc/', label: 'WordPress.org', position: 'right' },
        { href: 'https://github.com/wenisch-tech/wordpress-keystone-oidc', label: 'GitHub', position: 'right' },
      ],
    },
    footer: {
      style: 'dark',
      copyright:
        'Keystone OIDC is open-source software licensed under GPL v2 or later.<br/>' +
        '<a href="https://github.com/wenisch-tech/wordpress-keystone-oidc">GitHub</a> · ' +
        '<a href="https://github.com/wenisch-tech/wordpress-keystone-oidc/issues/new">Report a bug</a>',
    },
  }),
};

export default config;
