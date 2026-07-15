import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'SeedNet',
  description: 'Decentralized private overlay network — one seed phrase, no accounts',

  locales: {
    root: {
      label: 'English',
      lang: 'en',
      themeConfig: {
        nav: [
          { text: 'Guide', link: '/en/guide/' },
          { text: 'Reference', link: '/en/reference/cli' },
          {
            text: 'Download',
            link: 'https://github.com/oboard/seednet/releases',
          },
        ],
        sidebar: {
          '/en/': [
            {
              text: 'Getting Started',
              items: [
                { text: 'Introduction', link: '/en/guide/' },
                { text: 'Quick Start', link: '/en/guide/quick-start' },
                { text: 'Installation', link: '/en/guide/installation' },
              ],
            },
            {
              text: 'Usage',
              items: [
                { text: 'TUI (Interactive)', link: '/en/guide/tui' },
                { text: 'CLI Commands', link: '/en/guide/cli' },
                { text: 'Connect Peers', link: '/en/guide/connect' },
              ],
            },
            {
              text: 'Reference',
              items: [{ text: 'CLI Reference', link: '/en/reference/cli' }],
            },
          ],
        },
      },
    },
    zh: {
      label: '中文',
      lang: 'zh-CN',
      themeConfig: {
        nav: [
          { text: '指南', link: '/zh/guide/' },
          { text: '参考', link: '/zh/reference/cli' },
          {
            text: '下载',
            link: 'https://github.com/oboard/seednet/releases',
          },
        ],
        sidebar: {
          '/zh/': [
            {
              text: '快速上手',
              items: [
                { text: '介绍', link: '/zh/guide/' },
                { text: '快速开始', link: '/zh/guide/quick-start' },
                { text: '安装', link: '/zh/guide/installation' },
              ],
            },
            {
              text: '使用指南',
              items: [
                { text: 'TUI 交互界面', link: '/zh/guide/tui' },
                { text: 'CLI 命令', link: '/zh/guide/cli' },
                { text: '连接设备', link: '/zh/guide/connect' },
              ],
            },
            {
              text: '参考',
              items: [{ text: 'CLI 参考', link: '/zh/reference/cli' }],
            },
          ],
        },
      },
    },
  },

  themeConfig: {
    logo: '/logo.svg',
    socialLinks: [
      { icon: 'github', link: 'https://github.com/oboard/seednet' },
    ],
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2024 oboard',
    },
  },

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/logo.svg' }],
    ['meta', { name: 'theme-color', content: '#22c55e' }],
  ],
})
