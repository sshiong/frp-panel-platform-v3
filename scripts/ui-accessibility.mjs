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
  } finally {
    if (browser) await browser.close()
    await Promise.all(servers.map((server) => new Promise((resolvePromise) => server.close(resolvePromise))))
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error)
  process.exitCode = 1
})
