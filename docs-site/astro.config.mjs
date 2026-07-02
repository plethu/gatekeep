import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: process.env.SITE_URL ?? 'https://gatekeep.pages.dev',
  integrations: [
    starlight({
      title: 'Gatekeep',
      description: 'Code-first authorization for Rust services.',
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Start Here',
          items: [
            { label: 'Overview', slug: 'start-here/overview' },
            { label: 'Installation', slug: 'start-here/installation' },
            { label: 'Quickstart', slug: 'start-here/quickstart' }
          ]
        },
        {
          label: 'Concepts',
          items: [
            { label: 'Authorization Model', slug: 'concepts/authorization-model' },
            { label: 'Lattice Outcomes', slug: 'concepts/lattice-outcomes' },
            { label: 'Facts And Context', slug: 'concepts/facts-and-context' },
            { label: 'Decisions And Audit', slug: 'concepts/decisions-and-audit' }
          ]
        },
        {
          label: 'Guides',
          items: [
            { label: 'Axum Authorization', slug: 'guides/axum-authorization' },
            { label: 'SQLx List Filtering', slug: 'guides/sqlx-list-filtering' },
            { label: 'Durable Audit', slug: 'guides/durable-audit' },
            { label: 'Keepsake Entitlements', slug: 'guides/keepsake-entitlements' }
          ]
        },
        {
          label: 'Reference',
          items: [
            { label: 'Policy Combinators', slug: 'reference/policy-combinators' },
            { label: 'Feature Flags', slug: 'reference/feature-flags' },
            { label: 'SQLx Adapter', slug: 'reference/sqlx-adapter' },
            { label: 'Reason Catalogs', slug: 'reference/reason-catalogs' }
          ]
        },
        {
          label: 'Operations',
          items: [
            { label: 'Audit Export', slug: 'operations/audit-export' },
            { label: 'Migrations', slug: 'operations/migrations' }
          ]
        }
      ]
    })
  ]
});
