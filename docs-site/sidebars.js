/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    'README',
    'Installation',
    'Quick-Start',
    'Admin-Guide',
    {
      type: 'category', label: 'Concepts', collapsed: false,
      items: ['How-It-Works', 'Client-Types', 'Scopes-And-Claims', 'Security'],
    },
    'Extending',
    'Endpoint-Reference',
    'Upgrading',
    'Troubleshooting',
  ],
};
export default sidebars;
