import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { access, stat } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { extname, join, normalize, relative, resolve } from 'node:path'
import process from 'node:process'
import { AxeBuilder } from '@axe-core/playwright'
import { chromium } from 'playwright'

const root = resolve(fileURLToPath(new URL('..', import.meta.url)))
const apps = [
  { name: 'admin', directory: join(root, 'web/admin/dist'), port: 5183 },
  { name: 'client', directory: join(root, 'web/client/dist'), port: 5184 },
]

const contentTypes = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
}

async function serve(directory, port) {
  const server = createServer(async (request, response) => {
    try {
      const requestPath = decodeURIComponent(new URL(request.url ?? '/', `http://127.0.0.1:${port}`).pathname)
      const candidate = resolve(directory, `.${requestPath}`)
      const relativePath = relative(directory, candidate)
      if (relativePath.startsWith('..') || relativePath.includes('..' + (process.platform === 'win32' ? '\\' : '/'))) {
        response.writeHead(400)
        response.end('invalid path')
        return
      }
      let filePath = candidate
      try {
        if ((await stat(filePath)).isDirectory()) filePath = join(filePath, 'index.html')
        await access(filePath)
      } catch {
        filePath = join(directory, 'index.html')
      }
      const body = await readFile(filePath)
      response.writeHead(200, { 'Content-Type': contentTypes[extname(filePath)] ?? 'application/octet-stream', 'Cache-Control': 'no-store' })
      response.end(body)
    } catch (error) {
      response.writeHead(500)
      response.end(error instanceof Error ? error.message : 'server error')
    }
  })
  await new Promise((resolvePromise, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', resolvePromise)
  })
  return server
}

const fixtureTime = '2026-01-01T00:00:00.000Z'

const adminFixture = {
  user: {
    id: '00000000-0000-7000-8000-000000000001',
    username: 'admin',
    role: 'admin',
    status: 'active',
    must_change_password: false,
    must_change_username: false,
  },
  stats: {
    active_users: 2,
    mappings: 3,
    pending: 1,
    errors: 0,
    server_uptime_seconds: 3661,
    frps_public_host: 'frps.example.test',
    frps_public_port: 7000,
  },
  users: {
    items: [
      {
        id: '00000000-0000-7000-8000-000000000002',
        username: 'ops-alice',
        role: 'user',
        status: 'active',
        desired_config_version: 4,
        applied_config_version: 3,
        created_at: fixtureTime,
        frp_credential: { status: 'active', secret_version: 2, rotated_at: fixtureTime },
      },
    ],
  },
  operations: {
    items: [
      {
        id: '00000000-0000-7000-8000-000000000010',
        resource_type: 'domain',
        resource_id: '00000000-0000-7000-8000-000000000020',
        operation_type: 'dns_sync',
        status: 'retry_wait',
        phase: 'provider',
        step: 'query-after-timeout',
        error_code: 'PROVIDER_TIMEOUT_AMBIGUOUS',
        error_message: 'Provider state requires a retry.',
        compensation_status: 'pending',
        external_residue_count: 1,
        external_residues: [{ provider: 'cloudflare', identifier: 'app.example.test', reason: 'fixture residue' }],
        created_at: fixtureTime,
      },
    ],
  },
  cloudflare: { configured: false, status: 'missing' },
}

const clientFixture = {
  user: {
    id: '00000000-0000-7000-8000-000000000002',
    username: 'ops-alice',
    role: 'user',
    status: 'active',
    must_change_password: false,
    must_change_username: false,
  },
  mapping: {
    id: '00000000-0000-7000-8000-000000000021',
    user_id: '00000000-0000-7000-8000-000000000002',
    name: 'home-dashboard',
    proxy_type: 'http',
    lifecycle_status: 'running',
    desired_state: 'enabled',
    observed_state: 'running',
    revision: 3,
    local_ip: '127.0.0.1',
    local_port: 8080,
    remote_port: null,
    created_at: fixtureTime,
    updated_at: fixtureTime,
  },
  domain: {
    id: '00000000-0000-7000-8000-000000000020',
    mapping_id: '00000000-0000-7000-8000-000000000021',
    hostname: 'app.example.test',
    normalized_domain: 'app.example.test',
    https_mode: 'auto_certificate',
    http_redirect: true,
    dns_type: 'CNAME',
    dns_content: 'frps.example.test',
    dns_ttl: 300,
    dns_proxied: false,
    dns_managed_by_panel: true,
    dns_adopted: false,
    status: 'pending_certificate',
    revision: 2,
    created_at: fixtureTime,
    updated_at: fixtureTime,
  },
  operation: {
    id: '00000000-0000-7000-8000-000000000030',
    resource_type: 'domain',
    resource_id: '00000000-0000-7000-8000-000000000020',
    operation_type: 'certificate_issue',
    status: 'failed',
    phase: 'acme',
    step: 'dns-01',
    error_code: 'ACME_BLOCKED_MISSING_TOKEN',
    error_message: 'ACME provider is waiting for verified Cloudflare access.',
    compensation_status: 'blocked',
    external_residue_count: 0,
    external_residues: [],
    created_at: fixtureTime,
  },
}

async function installFixtureAPI(page, appName) {
  await page.route('**/api/v1/**', async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const json = body => route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { 'Cache-Control': 'no-store' },
      body: JSON.stringify(body),
    })

    if (appName === 'admin') {
      if (path === '/api/v1/dashboard') return json({ user: adminFixture.user })
      if (path === '/api/v1/admin/stats') return json(adminFixture.stats)
      if (path === '/api/v1/admin/users') return json(adminFixture.users)
      if (path === '/api/v1/admin/operations') return json(adminFixture.operations)
      if (path === '/api/v1/cloudflare/status') return json(adminFixture.cloudflare)
    } else {
      if (path === '/api/v1/session') return json({ user: clientFixture.user, server_panel_url: 'https://panel.example.test:8443', csrf_token: 'fixture-csrf', expires_at: fixtureTime })
      if (path === '/api/v1/dashboard') return json({
        user: clientFixture.user,
        desired_config_version: 4,
        applied_config_version: 3,
        observed_client_status: 'running',
        frp_credential: { present: true, secret_version: 2, status: 'active', rotated_at: fixtureTime },
        last_heartbeat_at: fixtureTime,
        mappings: [clientFixture.mapping],
        counts: { total_mappings: 1, running: 1, pending: 0, offline: 0, errors: 0 },
      })
      if (path === '/api/v1/domains') return json({ items: [clientFixture.domain], page: 1, page_size: 20, total: 1 })
      if (path === '/api/v1/operations') return json({ items: [clientFixture.operation], page: 1, page_size: 20, total: 1 })
      if (path === '/api/v1/local-status') return json({ state: 'running', mode: 'simulated', pid: 1234, desired_config_version: 4, applied_config_version: 3, config_hash: 'fixture', last_good_available: true, updated_at: fixtureTime })
    }

    if (request.method !== 'GET') return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true }) })
    return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ code: 'FIXTURE_NOT_FOUND', detail: `No accessibility fixture for ${path}` }) })
  })
}

function accessibleName(element) {
  return element.getAttribute('aria-label') || element.getAttribute('title') || element.textContent?.trim() || ''
}

async function assertKeyboardAndLabels(page, appName) {
  const violations = await page.evaluate(() => {
    const controls = [...document.querySelectorAll('button, input, select, textarea, a, [role="button"], [tabindex]:not([tabindex="-1"])')]
    return controls.flatMap((element) => {
      const tag = element.tagName.toLowerCase()
      const label = element.getAttribute('aria-label') || element.getAttribute('title') || element.textContent?.trim() || ''
      const labelledInput = ['input', 'select', 'textarea'].includes(tag) && (element.getAttribute('aria-label') || element.closest('label')?.textContent?.trim())
      return label || labelledInput ? [] : [{ tag, html: element.outerHTML.slice(0, 240) }]
    })
  })
  if (violations.length > 0) throw new Error(`${appName}: unlabeled interactive controls: ${JSON.stringify(violations)}`)

  await page.emulateMedia({ reducedMotion: 'reduce' })
  const focusOrder = []
  for (let index = 0; index < 16; index += 1) {
    await page.keyboard.press('Tab')
    focusOrder.push(await page.evaluate(() => ({ tag: document.activeElement?.tagName, id: document.activeElement?.id })))
  }
  if (focusOrder.every(({ tag }) => !tag || tag === 'BODY')) throw new Error(`${appName}: keyboard Tab never reached a focusable control`)
}

async function assertSurface(page, appName, surface) {
  await page.waitForTimeout(50)
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze()
  if (result.violations.length > 0) {
    throw new Error(`${appName}/${surface}: axe violations\n${JSON.stringify(result.violations, null, 2)}`)
  }
  await assertKeyboardAndLabels(page, `${appName}/${surface}`)
  await page.setViewportSize({ width: 390, height: 844 })
  const overflow = await page.evaluate(() => {
    const offenders = [...document.querySelectorAll('*')]
      .map(element => ({ element, rect: element.getBoundingClientRect() }))
      .filter(({ rect }) => rect.right > window.innerWidth + 1 || rect.left < -1)
      .slice(0, 5)
      .map(({ element, rect }) => ({ tag: element.tagName.toLowerCase(), className: element.className, left: Math.round(rect.left), right: Math.round(rect.right) }))
    return { documentWidth: document.documentElement.scrollWidth, viewportWidth: window.innerWidth, offenders }
  })
  if (overflow.documentWidth > overflow.viewportWidth) throw new Error(`${appName}/${surface}: mobile overflow ${JSON.stringify(overflow)}`)
  await page.setViewportSize({ width: 1440, height: 900 })
}

async function scanAuthenticatedSurfaces(page, appName, labels) {
  await installFixtureAPI(page, appName)
  await page.goto(`http://127.0.0.1:${appName === 'admin' ? 5183 : 5184}/`, { waitUntil: 'networkidle' })
  await page.getByRole('navigation').waitFor()
  const navigation = page.getByRole('navigation').getByRole('button')
  for (let index = 0; index < await navigation.count(); index += 1) {
    await navigation.nth(index).click()
    await assertSurface(page, appName, labels[index])
  }

  if (appName === 'admin') {
    await navigation.nth(1).click()
    await page.getByRole('button', { name: /创建用户/ }).click()
    const dialog = page.getByRole('dialog')
    await dialog.waitFor()
    await assertSurface(page, appName, 'create-user-dialog')
    await dialog.getByRole('button', { name: '取消' }).click()
  } else {
    await navigation.nth(0).click()
    await page.getByRole('button', { name: /新建 Mapping/ }).click()
    let dialog = page.getByRole('dialog')
    await dialog.waitFor()
    await assertSurface(page, appName, 'mapping-dialog')
    await dialog.getByRole('button', { name: '取消' }).click()

    await navigation.nth(1).click()
    await page.getByRole('button', { name: /新建域名/ }).click()
    dialog = page.getByRole('dialog')
    await dialog.waitFor()
    await assertSurface(page, appName, 'domain-dialog')
    await dialog.getByRole('button', { name: '取消' }).click()
  }
}

async function main() {
  const servers = await Promise.all(apps.map(({ directory, port }) => serve(directory, port)))
  let browser
  try {
    browser = await chromium.launch({
      headless: true,
      executablePath: process.env.PLAYWRIGHT_EXECUTABLE_PATH || undefined,
    })
    for (const app of apps) {
      const context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
      const page = await context.newPage()
      await page.goto(`http://127.0.0.1:${app.port}/`, { waitUntil: 'networkidle' })
      const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze()
      if (result.violations.length > 0) {
        throw new Error(`${app.name}: axe violations\n${JSON.stringify(result.violations, null, 2)}`)
      }
      await assertKeyboardAndLabels(page, app.name)
      await page.setViewportSize({ width: 390, height: 844 })
      const overflow = await page.evaluate(() => {
        const mobileRules = []
        const visitRules = (rules, condition = 'global') => {
          for (const rule of rules) {
            if (rule.cssRules) visitRules(rule.cssRules, rule.conditionText || condition)
            else if (rule.cssText.includes('min-width') && rule.cssText.includes('body')) mobileRules.push({ condition, cssText: rule.cssText })
          }
        }
        for (const sheet of document.styleSheets) {
          try { visitRules(sheet.cssRules) } catch { /* cross-origin stylesheets are not inspected */ }
        }
        const offenders = [...document.querySelectorAll('*')]
          .map((element) => ({ element, rect: element.getBoundingClientRect() }))
          .filter(({ rect }) => rect.right > window.innerWidth + 1 || rect.left < -1)
          .slice(0, 5)
          .map(({ element, rect }) => ({ tag: element.tagName.toLowerCase(), className: element.className, left: Math.round(rect.left), right: Math.round(rect.right) }))
        return { documentWidth: document.documentElement.scrollWidth, viewportWidth: window.innerWidth, mobileMedia: window.matchMedia('(max-width: 767px)').matches, tabletMedia: window.matchMedia('(max-width: 1100px)').matches, bodyMinWidth: getComputedStyle(document.body).minWidth, mobileRules: mobileRules.slice(-8), offenders }
      })
      if (overflow.documentWidth > overflow.viewportWidth) throw new Error(`${app.name}: mobile login page has horizontal overflow ${JSON.stringify(overflow)}`)
      console.log(`${app.name}: WCAG 2.1 AA axe, labels, keyboard and mobile checks passed`)
      await context.close()
    }

    const adminContext = await browser.newContext({ viewport: { width: 1440, height: 900 } })
    const adminPage = await adminContext.newPage()
    await scanAuthenticatedSurfaces(adminPage, 'admin', ['overview', 'users', 'operations', 'cloudflare', 'system'])
    await adminContext.close()
    console.log('admin: authenticated navigation surfaces passed')

    const clientContext = await browser.newContext({ viewport: { width: 1440, height: 900 } })
    const clientPage = await clientContext.newPage()
    await scanAuthenticatedSurfaces(clientPage, 'client', ['tunnels', 'domains', 'local', 'operations', 'logs'])
    await clientContext.close()
    console.log('client: authenticated navigation surfaces passed')
  } finally {
    if (browser) await browser.close()
    await Promise.all(servers.map((server) => new Promise((resolvePromise) => server.close(resolvePromise))))
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error)
  process.exitCode = 1
})
