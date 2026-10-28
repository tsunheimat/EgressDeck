import { readFileSync, readdirSync } from 'node:fs'
import { dirname, resolve, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse as parseSfc } from '@vue/compiler-sfc'
import { parse as parseTemplate } from '@vue/compiler-dom'
import ts from 'typescript'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const allowed = new Set(['EgressDeck', 'OPNsense', 'dae', 'TCP', 'UDP', 'QUIC', 'IP', 'IPv4', 'IPv6', 'ID', 'UUID', 'SSO', 'HTTP', 'HTTPS', 'URL', 'JSON', 'YAML', 'Clash', 'Base64', 'SIP008', 'SHA', 'MiB', 'DNS', 'CIDR', 'API', 'TLS', 'BPF', 'NAT', 'PF', 'entries', 'rules', 'rule_set_ids', 'DHCP'])

/** Product/protocol identifiers and example addresses are not translatable UI prose. */
export function untranslatedWords(text) {
  const prose = text
    .replace(/https?:\/\/[^\s"'<>]+/g, '')
    .replace(/\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*\b/gi, '')
    .replace(/\b[a-z][a-z0-9]*[._-][a-z0-9_.-]+\b/g, '')
    .replace(/\b(?:[a-f0-9]{1,4}:){1,7}[a-f0-9:]+\b/gi, '')
  return [...prose.matchAll(/[A-Za-z][A-Za-z0-9]*/g)].map(match => match[0]).filter(word => !allowed.has(word))
}
function files(dir) { return readdirSync(dir, { withFileTypes: true }).flatMap(item => item.isDirectory() ? files(resolve(dir, item.name)) : [resolve(dir, item.name)]) }
const violations = []
function check(file, kind, text, offset = 0) {
  if (kind === 'placeholder' && ['例如：lan', 'direct（直连）', '域名集格式：streaming=example.com, media.example'].includes(text)) return
  const words = untranslatedWords(text)
  if (!words.length) return
  const source = readFileSync(file, 'utf8')
  const line = source.slice(0, offset).split('\n').length
  violations.push(`${relative(root, file)}:${line} ${kind}: ${JSON.stringify(text.trim())}`)
}
function expression(file, content, offset) {
  const ast = ts.createSourceFile('display.ts', `const value = (${content})`, ts.ScriptTarget.Latest, true)
  function walk(node) {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || [ts.SyntaxKind.TemplateHead, ts.SyntaxKind.TemplateMiddle, ts.SyntaxKind.TemplateTail].includes(node.kind)) {
      // Condition operands, object keys and element lookups are wire identifiers, not labels.
      const parent = node.parent
      let enclosing = parent
      if (ts.isTemplateExpression(parent)) enclosing = parent.parent
      if (ts.isBinaryExpression(enclosing) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(enclosing.operatorToken.kind)) return
      if (ts.isBinaryExpression(parent) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(parent.operatorToken.kind)) return
      if (ts.isElementAccessExpression(parent) || (ts.isPropertyAssignment(parent) && parent.name === node)) return
      if (ts.isCallExpression(parent)) return // uiLabel/formatting functions own dynamic values.
      check(file, 'display expression', node.text, offset)
    }
    ts.forEachChild(node, walk)
  }
  walk(ast)
}
for (const file of files(resolve(root, 'src')).filter(file => file.endsWith('.vue'))) {
  const source = readFileSync(file, 'utf8')
  const { descriptor } = parseSfc(source)
  if (!descriptor.template) continue
  const block = descriptor.template
  const ast = parseTemplate(block.content)
  function walk(node, raw = false) {
    raw ||= ['pre', 'code'].includes(node.tag) || node.props?.some(prop => prop.name === 'data-raw-diagnostic')
    if (raw) return
    const offset = block.loc.start.offset + node.loc.start.offset
    if (node.type === 2) check(file, 'text', node.content, offset)
    if (node.type === 5) expression(file, node.content.content, offset)
    for (const prop of node.props || []) {
      if (prop.type === 6 && ['aria-label', 'title', 'placeholder', 'label'].includes(prop.name) && prop.value) check(file, prop.name, prop.value.content, offset)
      if (prop.type === 7 && prop.name === 'bind' && ['aria-label', 'title', 'placeholder', 'label'].includes(prop.arg?.content) && prop.exp) expression(file, prop.exp.content, offset)
    }
    for (const child of node.children || []) walk(child, raw)
  }
  walk(ast)
}
if (violations.length) {
  console.error(`Untranslated interface copy (${violations.length}):\n${violations.join('\n')}`)
  process.exitCode = 1
} else console.log('Chinese interface audit passed: template text, labels, placeholders and display literals.')
