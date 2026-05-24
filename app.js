const $ = id => document.getElementById(id)
const enc = new TextEncoder()
const dec = new TextDecoder()

const toB64 = u8 => btoa(String.fromCharCode(...u8))
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0))
const bytes = n => crypto.getRandomValues(new Uint8Array(n))

const ALGO_INFO = {
  caesar: {
    title: 'Caesar Cipher',
    text: 'Shifts letters by a number. Example: A becomes D when the shift is 3.',
    placeholder: 'Enter a numeric shift'
  },
  xor: {
    title: 'XOR Cipher',
    text: 'Mixes the message with a key so the text looks scrambled until the same key is used again.',
    placeholder: 'Generated or typed key'
  },
  reverse: {
    title: 'Reverse Text',
    text: 'Flips the whole message backward. It hides the reading order, but it is still a simple trick.',
    placeholder: 'Generated or typed key'
  },
  swap: {
  title: 'Swap Case',
  text: 'Turns uppercase into lowercase and lowercase into uppercase.',
  placeholder: 'No extra value needed'
},
  base64: {
    title: 'Base64 Layer',
    text: 'Turns text into a coded-looking string. It changes the look of the text, but it is not real security by itself.',
    placeholder: 'Generated or typed key'
  },
  rot13: {
    title: 'ROT13',
    text: 'Moves every letter 13 places in the alphabet. The same method unlocks it again.',
    placeholder: 'Generated or typed key'
  },
  atbash: {
    title: 'Atbash Cipher',
    text: 'Replaces each letter with the opposite letter in the alphabet, like A ↔ Z.',
    placeholder: 'Generated or typed key'
  },
  vigenere: {
    title: 'Vigenere Cipher',
    text: 'Uses a keyword to shift letters in a repeating pattern, so the same letter can change in different places.',
    placeholder: 'Generated or typed keyword'
  }
}

function randAlpha(n) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let out = ''
  for (let i = 0; i < n; i++) out += chars[Math.floor(Math.random() * chars.length)]
  return out
}

function randKey(n) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  let out = ''
  for (let i = 0; i < n; i++) out += chars[Math.floor(Math.random() * chars.length)]
  return out
}

function randDigits(n) {
  const digits = '1234567890'
  let out = digits[Math.floor(Math.random() * 9) + 1]
  for (let i = 1; i < n; i++) out += digits[Math.floor(Math.random() * digits.length)]
  return out
}

function generateKeyForAlg(alg, len) {
  const n = Math.max(1, Number(len) || 16)
  if (alg === 'caesar') return randKey(n)
  if (alg === 'vigenere') return randAlpha(n)
  return randKey(n)
}

function caesarShiftValue(key) {
  const str = String(key || '')
  if (!str.trim()) return 0
  let shift = 0
  for (let i = 0; i < str.length; i++) shift += str.charCodeAt(i)
  return shift % 26
}

async function derive(pass, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

async function seal(obj, pass) {
  const salt = bytes(16)
  const iv = bytes(12)
  const key = await derive(pass, salt)
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)))
  return JSON.stringify({ v: 1, s: toB64(salt), i: toB64(iv), d: toB64(new Uint8Array(data)) })
}

async function openPkg(pkg, pass) {
  const obj = JSON.parse(pkg)
  const key = await derive(pass, fromB64(obj.s))
  const data = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(obj.i) }, key, fromB64(obj.d))
  return JSON.parse(dec.decode(data))
}

function caesar(text, shift) {
  shift = caesarShiftValue(shift)
  return [...text].map(ch => {
    const c = ch.charCodeAt(0)
    if (c >= 65 && c <= 90) return String.fromCharCode(((c - 65 + shift) % 26 + 26) % 26 + 65)
    if (c >= 97 && c <= 122) return String.fromCharCode(((c - 97 + shift) % 26 + 26) % 26 + 97)
    return ch
  }).join('')
}

function xorCipher(text, key) {
  key = key || '0'
  let out = ''
  for (let i = 0; i < text.length; i++) out += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length))
  return out
}

function reverseText(text) {
  return [...text].reverse().join('')
}

function swapCase(text) {
  return [...text].map(ch => {
    const u = ch.toUpperCase()
    const l = ch.toLowerCase()
    return ch === u ? l : u
  }).join('')
}

function base64Enc(text) {
  return toB64(enc.encode(text))
}

function base64Dec(text) {
  return dec.decode(fromB64(text))
}

function atbash(text) {
  return [...text].map(ch => {
    const c = ch.charCodeAt(0)
    if (c >= 65 && c <= 90) return String.fromCharCode(90 - (c - 65))
    if (c >= 97 && c <= 122) return String.fromCharCode(122 - (c - 97))
    return ch
  }).join('')
}

function rot13(text) {
  return [...text].map(ch => {
    const c = ch.charCodeAt(0)
    if (c >= 65 && c <= 90) return String.fromCharCode(((c - 65 + 13) % 26) + 65)
    if (c >= 97 && c <= 122) return String.fromCharCode(((c - 97 + 13) % 26) + 97)
    return ch
  }).join('')
}

function vigenere(text, key, decryptMode = false) {
  key = (key || 'KEY').replace(/[^a-zA-Z]/g, '') || 'KEY'
  let j = 0
  return [...text].map(ch => {
    const c = ch.charCodeAt(0)
    const k = key.charCodeAt(j % key.length)
    const shift = (k >= 97 ? k - 97 : k - 65) % 26
    if (c >= 65 && c <= 90) {
      j++
      return String.fromCharCode(((c - 65 + (decryptMode ? -shift : shift)) % 26 + 26) % 26 + 65)
    }
    if (c >= 97 && c <= 122) {
      j++
      return String.fromCharCode(((c - 97 + (decryptMode ? -shift : shift)) % 26 + 26) % 26 + 97)
    }
    return ch
  }).join('')
}

function customFlow(text, steps, encrypt) {
  const seq = encrypt ? steps : [...steps].reverse()
  return seq.reduce((acc, s) => {
    if (s.type === 'caesar') return caesar(acc, encrypt ? s.value : -(Number(s.value) || 0))
    if (s.type === 'xor') return xorCipher(acc, s.value)
    if (s.type === 'reverse') return reverseText(acc)
    if (s.type === 'swap') return swapCase(acc)
    if (s.type === 'base64') return encrypt ? base64Enc(acc) : base64Dec(acc)
    if (s.type === 'rot13') return rot13(acc)
    if (s.type === 'atbash') return atbash(acc)
    if (s.type === 'vigenere') return vigenere(acc, s.value || 'KEY', !encrypt)
    return acc
  }, text)
}

function saveAs(filename, content, type = 'text/plain') {
  const blob = new Blob([content], { type })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 0)
}

function setText(id, value) {
  const node = $(id)
  if (node) node.textContent = value
}

function clearErrors(prefix) {
  ;['TextErr', 'AlgoErr', 'KeyErr', 'PassErr', 'OutErr', 'PkgErr', 'StepsErr'].forEach(suffix => {
    const node = $(prefix + suffix)
    if (node) node.textContent = ''
  })
}

function setPageActive() {
  const page = document.body.dataset.page || 'home'
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('active', a.dataset.nav === page))
}

function bindTooltips() {
  const box = $('tooltipBox')
  if (!box) return

  let current = null
  let timer = null

  const place = target => {
    const r = target.getBoundingClientRect()
    const pad = 10
    const bw = Math.max(220, Math.min(box.offsetWidth || 300, window.innerWidth - pad * 2))
    let left = r.left
    let top = r.bottom + 10

    if (left + bw > window.innerWidth - pad) left = window.innerWidth - bw - pad
    if (left < pad) left = pad
    if (top + box.offsetHeight > window.innerHeight - pad) top = r.top - (box.offsetHeight + 10)
    box.style.left = `${left}px`
    box.style.top = `${Math.max(pad, top)}px`
  }

  const show = (text, target) => {
    if (!text || !target) return
    current = target
    box.textContent = text
    box.classList.add('show')
    box.style.visibility = 'visible'
    place(target)
  }

  const hide = () => {
    current = null
    box.classList.remove('show')
    box.style.visibility = 'hidden'
  }

  document.querySelectorAll('[data-tip]').forEach(el => {
    el.addEventListener('mouseenter', () => show(el.dataset.tip, el))
    el.addEventListener('focus', () => show(el.dataset.tip, el))
    el.addEventListener('mouseleave', () => {
      clearTimeout(timer)
      timer = setTimeout(hide, 100)
    })
    el.addEventListener('blur', hide)
    el.addEventListener('mousemove', () => {
      if (current === el) place(el)
    })
  })

  window.addEventListener('scroll', () => { if (current) place(current) }, true)
  window.addEventListener('resize', () => { if (current) place(current) })
}

function bindEncryptPage() {
  const algoMap = ALGO_INFO

  const picker = $('algoPicker')
  const panel = $('algoMenuPanel')
  const trigger = $('algoSelectBtn')
  const menu = $('algoMenu')
  const encAlgo = $('encAlgo')
  const algoLabel = $('algoSelectLabel')
  const previewTitle = $('algoPreviewTitle')
  const previewText = $('algoPreviewText')
  const keyLen = $('keyLength')
  const key = $('encKey')
  const plain = $('plainText')
  const pass = $('encPass')
  const out = $('encOut')
  const pkgKey = $('encPkgKey')

  function updatePreview(value) {
    const info = algoMap[value]
    if (!info) return
    previewTitle.textContent = info.title
    previewText.textContent = info.text
  }

  function updateKeyPlaceholder(value) {
    if (!key) return
    key.placeholder = algoMap[value]?.placeholder || 'Generated or typed key'
  }

  function generate() {
    if (!key) return
    const alg = encAlgo?.value || 'caesar'
    key.value = generateKeyForAlg(alg, keyLen?.value || 16)
  }

  function selectAlgo(value, regenerate = true) {
    if (encAlgo) encAlgo.value = value
    if (algoLabel) algoLabel.textContent = algoMap[value]?.title || value
    updatePreview(value)
    updateKeyPlaceholder(value)
    document.querySelectorAll('.algo-item').forEach(item => {
      item.classList.toggle('active', item.dataset.value === value)
    })
    if (regenerate) generate()
  }

  function openPanel() {
    if (!panel) return
    panel.classList.add('open')
    if (trigger) trigger.setAttribute('aria-expanded', 'true')
  }

  function closePanel() {
    if (!panel) return
    panel.classList.remove('open')
    if (trigger) trigger.setAttribute('aria-expanded', 'false')
  }

  if (trigger && panel && menu && encAlgo) {
    trigger.addEventListener('click', e => {
      e.preventDefault()
      if (panel.classList.contains('open')) closePanel()
      else openPanel()
    })

    document.addEventListener('click', e => {
      if (picker && !picker.contains(e.target)) closePanel()
    })

    menu.querySelectorAll('.algo-item').forEach(item => {
      item.addEventListener('mouseenter', () => updatePreview(item.dataset.value))
      item.addEventListener('focus', () => updatePreview(item.dataset.value))
      item.addEventListener('click', () => {
        selectAlgo(item.dataset.value)
        closePanel()
      })
    })

    selectAlgo(encAlgo.value || 'caesar', false)
    updatePreview(encAlgo.value || 'caesar')
    updateKeyPlaceholder(encAlgo.value || 'caesar')
  }

  if (keyLen) keyLen.addEventListener('change', () => generate())
  const genBtn = $('genKeyBtn')
  if (genBtn) genBtn.addEventListener('click', generate)

  const copyKey = $('copyKeyBtn')
  if (copyKey) copyKey.addEventListener('click', async () => { if (key?.value) await navigator.clipboard.writeText(key.value) })

  const downKey = $('downloadKeyBtn')
  if (downKey) downKey.addEventListener('click', () => { if (key?.value) saveAs('encryptx-key.txt', key.value) })

  const copyPkg = $('copyPkgBtn')
  if (copyPkg) copyPkg.addEventListener('click', async () => { if (out?.value) await navigator.clipboard.writeText(out.value) })

  const downPkg = $('downloadPkgBtn')
  if (downPkg) downPkg.addEventListener('click', () => { if (out?.value) saveAs('encryptx-package.exx', out.value, 'application/json') })

  const copyEncKey = $('copyEncKeyBtn')
  if (copyEncKey) copyEncKey.addEventListener('click', async () => { if (pkgKey?.value) await navigator.clipboard.writeText(pkgKey.value) })

  const downEncKey = $('downloadEncKeyBtn')
  if (downEncKey) downEncKey.addEventListener('click', () => { if (pkgKey?.value) saveAs('encryptx-key.txt', pkgKey.value) })

  const clearBtn = $('clearEncBtn')
  if (clearBtn) clearBtn.addEventListener('click', () => {
    if (plain) plain.value = ''
    if (key) key.value = ''
    if (pass) pass.value = ''
    if (out) out.value = ''
    if (pkgKey) pkgKey.value = ''
    setText('encStatus', 'Ready to encrypt.')
    clearErrors('enc')
  })

  const encryptBtn = $('encryptBtn')
  if (encryptBtn) encryptBtn.addEventListener('click', async () => {
    clearErrors('enc')
    let ok = true

    if (!plain?.value.trim()) { setText('plainTextErr', 'Please enter some text to encrypt.'); ok = false }
    if (!pass?.value.trim()) { setText('encPassErr', 'Please set a passcode first.'); ok = false }
    if (!key?.value.trim()) { setText('encKeyErr', 'Please enter or generate a key.'); ok = false }
    if (encAlgo?.value === 'vigenere' && /[^a-zA-Z]/.test((key?.value || '').trim())) { setText('encKeyErr', 'Vigenere works best with letters only.'); ok = false }

    if (!ok) {
      setText('encStatus', 'Please fix the highlighted fields.')
      return
    }

    const alg = encAlgo.value
    let cipher = plain.value
    if (alg === 'caesar') cipher = caesar(plain.value, Number(key.value))
    if (alg === 'xor') cipher = xorCipher(plain.value, key.value)
    if (alg === 'reverse') cipher = reverseText(plain.value)
    if (alg === 'base64') cipher = base64Enc(plain.value)
    if (alg === 'rot13') cipher = rot13(plain.value)
    if (alg === 'atbash') cipher = atbash(plain.value)
    if (alg === 'vigenere') cipher = vigenere(plain.value, key.value, false)

    const payload = {
      alg,
      cipher,
      salt: Math.random().toString(36).slice(2, 10),
      key: key.value
    }
    payload.passHash = await crypto.subtle.digest('SHA-256', enc.encode(pass.value + payload.salt))
      .then(buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''))

    const packaged = await seal(payload, pass.value)
    out.value = packaged
    pkgKey.value = key.value
    setText('encStatus', 'Encrypted package created. Download the package and keep the key private.')
  })

  if (encAlgo && key) {
    encAlgo.addEventListener('change', () => selectAlgo(encAlgo.value, true))
  }

  generate()
}

function bindDecryptPage() {
  const pkg = $('decPkg')
  const key = $('decKey')
  const pass = $('decPass')
  const out = $('decOut')
  const pkgFile = $('decPkgFile')
  const keyFile = $('decKeyFile')

  const loadPkg = $('loadDecPkgBtn')
  if (loadPkg) loadPkg.addEventListener('click', () => pkgFile && pkgFile.click())
  const loadKey = $('loadDecKeyBtn')
  if (loadKey) loadKey.addEventListener('click', () => keyFile && keyFile.click())

  if (pkgFile) pkgFile.addEventListener('change', async () => {
    const file = pkgFile.files && pkgFile.files[0]
    if (file && pkg) pkg.value = await file.text()
    pkgFile.value = ''
  })

  if (keyFile) keyFile.addEventListener('change', async () => {
    const file = keyFile.files && keyFile.files[0]
    if (file && key) key.value = (await file.text()).trim()
    keyFile.value = ''
  })

  const copyBtn = $('copyDecBtn')
  if (copyBtn) copyBtn.addEventListener('click', async () => { if (out?.value) await navigator.clipboard.writeText(out.value) })

  const clearBtn = $('clearDecBtn')
  if (clearBtn) clearBtn.addEventListener('click', () => {
    if (pkg) pkg.value = ''
    if (key) key.value = ''
    if (pass) pass.value = ''
    if (out) out.value = ''
    clearErrors('dec')
    setText('decStatus', 'Ready to decrypt.')
  })

  const decryptBtn = $('decryptBtn')
  if (decryptBtn) decryptBtn.addEventListener('click', async () => {
    clearErrors('dec')
    let ok = true

    if (!pkg?.value.trim()) { setText('decPkgErr', 'Please paste or load the encrypted package.'); ok = false }
    if (!key?.value.trim()) { setText('decKeyErr', 'Please enter or load the key.'); ok = false }
    if (!pass?.value.trim()) { setText('decPassErr', 'Please enter the passcode.'); ok = false }

    if (!ok) {
      setText('decStatus', 'Please fix the highlighted fields.')
      return
    }

    try {
      const data = await openPkg(pkg.value.trim(), pass.value)
      if (data.key && data.key !== key.value) {
        setText('decKeyErr', 'The key looks wrong.')
        setText('decPassErr', 'The passcode does not match.')
        setText('decStatus', 'Wrong key or passcode.')
        if (out) out.value = ''
        return
      }

      let plain = data.cipher
      if (data.alg === 'caesar') plain = caesar(plain, -(Number(key.value) || 0))
      if (data.alg === 'xor') plain = xorCipher(plain, key.value)
      if (data.alg === 'reverse') plain = reverseText(plain)
      if (data.alg === 'base64') plain = base64Dec(plain)
      if (data.alg === 'rot13') plain = rot13(plain)
      if (data.alg === 'atbash') plain = atbash(plain)
      if (data.alg === 'vigenere') plain = vigenere(plain, key.value, true)
      if (data.alg === 'custom') plain = customFlow(plain, data.steps || [], false)

      if (out) out.value = plain
      setText('decStatus', 'Decryption successful.')
    } catch {
      setText('decPkgErr', 'This package is invalid or the passcode is wrong.')
      setText('decStatus', 'Wrong package or passcode.')
      if (out) out.value = ''
    }
  })
}


function buildAlgoPicker(selected, idx) {
  const info = ALGO_INFO[selected] || ALGO_INFO.caesar
  return `
    <div class="algo-picker step-picker" data-step-index="${idx}">
      <button class="algo-trigger step-trigger" type="button" aria-expanded="false">
        <span class="stepLabel">${info.title}</span>
        <span class="algo-arrow">▾</span>
      </button>
      <div class="algo-panel step-panel">
        <div class="algo-menu step-menu" role="listbox" aria-label="Custom algorithm steps">
          <button type="button" class="algo-item step-item" data-value="caesar" data-preview-title="Caesar Cipher" data-preview-text="Shifts letters by a number. Example: A becomes D when the shift is 3.">
            <strong>Caesar Cipher</strong>
            <span>Moves letters forward or backward.</span>
          </button>
          <button type="button" class="algo-item step-item" data-value="xor" data-preview-title="XOR Cipher" data-preview-text="Mixes the message with a key so the text looks scrambled until the same key is used again.">
            <strong>XOR Cipher</strong>
            <span>Scrambles text with a secret key.</span>
          </button>
          <button type="button" class="algo-item step-item" data-value="reverse" data-preview-title="Reverse Text" data-preview-text="Flips the whole message backward. It hides the reading order, but it is still a simple trick.">
            <strong>Reverse Text</strong>
            <span>Reads the message backward.</span>
          </button>
          <button type="button" class="algo-item step-item" data-value="swap" data-preview-title="Swap Case" data-preview-text="Turns uppercase into lowercase and lowercase into uppercase.">
  <strong>Swap Case</strong>
  <span>Flips upper and lower case letters.</span>
</button>
          <button type="button" class="algo-item step-item" data-value="base64" data-preview-title="Base64 Layer" data-preview-text="Turns text into a coded-looking string. It changes the look of the text, but it is not real security by itself.">
            <strong>Base64 Layer</strong>
            <span>Changes text into coded characters.</span>
          </button>
          <button type="button" class="algo-item step-item" data-value="rot13" data-preview-title="ROT13" data-preview-text="Moves every letter 13 places in the alphabet. The same method unlocks it again.">
            <strong>ROT13</strong>
            <span>Simple letter rotation.</span>
          </button>
          <button type="button" class="algo-item step-item" data-value="atbash" data-preview-title="Atbash Cipher" data-preview-text="Replaces each letter with the opposite letter in the alphabet, like A ↔ Z.">
            <strong>Atbash Cipher</strong>
            <span>Uses opposite alphabet letters.</span>
          </button>
          <button type="button" class="algo-item step-item" data-value="vigenere" data-preview-title="Vigenere Cipher" data-preview-text="Uses a keyword to shift letters in a repeating pattern, so the same letter can change in different places.">
            <strong>Vigenere Cipher</strong>
            <span>Uses a keyword for shifting.</span>
          </button>
        </div>
        <div class="algo-preview step-preview">
          <div class="algo-preview-title">${info.title}</div>
          <div class="algo-preview-text">${info.text}</div>
          <div class="algo-preview-note">Hover any item to see its plain-language explanation.</div>
        </div>
      </div>
    </div>`
}

function getStepValueMeta(type) {
  if (type === 'caesar') return { label: 'Caesar Shift Value', placeholder: 'Enter Caesar shift value', tip: 'How many letters the text should move forward or backward.' }
  if (type === 'xor') return { label: 'Key Value', placeholder: 'Enter a secret key', tip: 'This key is mixed with the text to scramble it.' }
  if (type === 'vigenere') return { label: 'Keyword', placeholder: 'Enter a keyword', tip: 'Letters used again and again to shift the text.' }
  return { label: 'Value', placeholder: 'Enter a value', tip: 'This value changes based on the selected step.' }
}

function bindCustomPage() {
  const stepsBox = $('stepsBox')
  const tpl = $('stepTemplate')
  const customText = $('customText')
  const customKeyLen = $('customKeyLength')
  const customKey = $('customKey')
  const customPass = $('customPass')
  const customOut = $('customOut')
  const loadInput = $('loadPresetInput')
  const summary = $('customSummary')

  let steps = []

  function renderSummary() {
    if (!summary) return
    if (!steps.length) {
      summary.textContent = 'No custom steps saved yet.'
      return
    }
    summary.textContent = steps.map(s => {
      if (s.type === 'caesar') return `Caesar(${Number(s.value) || 0})`
      if (s.type === 'xor') return `XOR("${s.value || ''}")`
      if (s.type === 'reverse') return 'Reverse'
      if (s.type === 'swap') return 'Swap Case'
      if (s.type === 'base64') return 'Base64'
      if (s.type === 'rot13') return 'ROT13'
      if (s.type === 'atbash') return 'Atbash'
      return `Vigenere("${s.value || ''}")`
    }).join(' → ')
  }

  function render() {
    if (!stepsBox || !tpl) return
    stepsBox.innerHTML = ''
    steps.forEach((s, i) => {
      const node = tpl.content.cloneNode(true)
      const row = node.querySelector('.step-row')
      const picker = node.querySelector('.stepPicker')
      const trigger = node.querySelector('.stepTrigger')
      const panel = node.querySelector('.stepPanel')
      const menu = node.querySelector('.stepMenu')
      const label = node.querySelector('.stepLabel')
      const previewTitle = node.querySelector('.stepPreviewTitle')
      const previewText = node.querySelector('.stepPreviewText')
      const val = node.querySelector('.stepValue')
      const valWrap = node.querySelector('.stepValueWrap')
      const valLabel = node.querySelector('.stepValueLabel')
      const rem = node.querySelector('.removeStep')

      const applyType = type => {
        s.type = type
        const info = ALGO_INFO[type] || ALGO_INFO.caesar
        const meta = getStepValueMeta(type)
        if (label) label.textContent = info.title
        if (previewTitle) previewTitle.textContent = info.title
        if (previewText) previewText.textContent = info.text
        if (valWrap) {
  valWrap.style.display = ['caesar', 'xor', 'vigenere'].includes(type) ? 'grid' : 'none'
}

if (val) {
  if (['swap', 'reverse', 'base64', 'rot13', 'atbash'].includes(type)) {
    val.value = ''
    val.placeholder = 'No extra value needed'
  }
}
        if (valLabel) valLabel.textContent = meta.label
        if (val) {
  val.placeholder = meta.placeholder
  val.title = meta.tip
  val.setAttribute('data-tip', meta.tip)
const numberTypes = ['caesar']

if (numberTypes.includes(type)) {
  val.type = 'number'
  val.inputMode = 'numeric'
  val.step = '1'
} else {
  val.type = 'text'
}
  if (!s.value) {
    val.value = ''
  } else {
    val.value = s.value
  }
}
        if (valLabel) valLabel.title = meta.tip
        if (valWrap) valWrap.title = meta.tip
        node.querySelectorAll('.step-item').forEach(item => item.classList.toggle('active', item.dataset.value === type))
      }

      applyType(s.type || 'caesar')
      val.value = s.value || ''
    

      trigger.addEventListener('click', e => {
        e.preventDefault()
        document.querySelectorAll('.stepPanel.open').forEach(pnl => {
          if (pnl !== panel) pnl.classList.remove('open')
        })
        panel.classList.toggle('open')
        trigger.setAttribute('aria-expanded', panel.classList.contains('open') ? 'true' : 'false')
      })

     menu.querySelectorAll('.step-item').forEach(item => {

  item.addEventListener('mouseenter', () => {
    const info = ALGO_INFO[item.dataset.value] || ALGO_INFO.caesar
    if (previewTitle) previewTitle.textContent = info.title
    if (previewText) previewText.textContent = info.text
  })

  item.addEventListener('focus', () => {
    const info = ALGO_INFO[item.dataset.value] || ALGO_INFO.caesar
    if (previewTitle) previewTitle.textContent = info.title
    if (previewText) previewText.textContent = info.text
  })

  item.addEventListener('click', () => {

    menu.querySelectorAll('.step-item').forEach(i => {
      i.classList.remove('active')
    })

    item.classList.add('active')

    applyType(item.dataset.value)

if (customKey) {
  customKey.value = generateKeyForAlg(item.dataset.value, customKeyLen?.value || 16)
}

panel.classList.remove('open')
trigger.setAttribute('aria-expanded', 'false')

renderSummary()
  })

})

      val.addEventListener('input', () => {
        if (['caesar'].includes(s.type)) {
  val.value = val.value.replace(/[^0-9-]/g, '')
}
        s.value = val.value
        renderSummary()
      })

      rem.addEventListener('click', () => {
        steps.splice(i, 1)
        render()
        renderSummary()
      })

      stepsBox.appendChild(node)
    })
    renderSummary()
  }


  document.addEventListener('click', e => {
    if (!e.target.closest('.stepPicker')) {
      document.querySelectorAll('.stepPanel.open').forEach(pnl => pnl.classList.remove('open'))
      document.querySelectorAll('.stepTrigger').forEach(btn => btn.setAttribute('aria-expanded', 'false'))
    }
  })

  const generate = () => {
    if (!customKey) return
    customKey.value = generateKeyForAlg('xor', customKeyLen?.value || 16)
  }

  const genBtn = $('genCustomKeyBtn')
  if (genBtn) genBtn.addEventListener('click', generate)
  if (customKeyLen) customKeyLen.addEventListener('change', generate)

  const copyKeyBtn = $('copyCustomKeyBtn')
  if (copyKeyBtn) copyKeyBtn.addEventListener('click', async () => { if (customKey?.value) await navigator.clipboard.writeText(customKey.value) })

  const downKeyBtn = $('downloadCustomKeyBtn')
  if (downKeyBtn) downKeyBtn.addEventListener('click', () => { if (customKey?.value) saveAs('encryptx-key.txt', customKey.value) })

  const copyPkgBtn = $('copyCustomPkgBtn')
  if (copyPkgBtn) copyPkgBtn.addEventListener('click', async () => { if (customOut?.value) await navigator.clipboard.writeText(customOut.value) })

  const downPkgBtn = $('downloadCustomPkgBtn')
  if (downPkgBtn) downPkgBtn.addEventListener('click', () => { if (customOut?.value) saveAs('encryptx-package.exx', customOut.value, 'application/json') })

  const addStepBtn = $('addStepBtn')
  if (addStepBtn) addStepBtn.addEventListener('click', () => {
    steps.push({ type: 'caesar', value: '' })
    render()
  })

  const clearStepsBtn = $('clearStepsBtn')
  if (clearStepsBtn) clearStepsBtn.addEventListener('click', () => {
    steps = []
    render()
    setText('customStatus', 'Steps cleared.')
  })

  const savePresetBtn = $('savePresetBtn')
  if (savePresetBtn) savePresetBtn.addEventListener('click', () => {
    saveAs('encryptx-preset.json', JSON.stringify(steps, null, 2), 'application/json')
    setText('customStatus', 'Preset downloaded successfully.')
  })

  const loadPresetBtn = $('loadPresetBtn')
  if (loadPresetBtn) loadPresetBtn.addEventListener('click', () => loadInput && loadInput.click())

  if (loadInput) loadInput.addEventListener('change', async () => {
    const file = loadInput.files && loadInput.files[0]
    if (!file) return
    try {
      const text = await file.text()
      const data = JSON.parse(text)
      if (!Array.isArray(data)) throw new Error('Invalid preset')
      steps = data.map(s => ({ type: s.type || 'caesar', value: s.value || '' }))
      render()
      setText('customStatus', 'Preset loaded from file.')
    } catch {
      setText('customStatus', 'Could not load that preset file.')
    }
    loadInput.value = ''
  })

  const clearCustomBtn = $('clearCustomBtn')
  if (clearCustomBtn) clearCustomBtn.addEventListener('click', () => {
    if (customText) customText.value = ''
    if (customKey) customKey.value = ''
    if (customPass) customPass.value = ''
    if (customOut) customOut.value = ''
    steps = []
    render()
    clearErrors('custom')
    setText('customStatus', 'Ready to encrypt.')
  })

  const encryptBtn = $('customEncryptBtn')
  if (encryptBtn) encryptBtn.addEventListener('click', async () => {
    clearErrors('custom')
    let ok = true

    if (!customText?.value.trim()) { setText('customTextErr', 'Please enter some text to encrypt.'); ok = false }
    if (!customPass?.value.trim()) { setText('customPassErr', 'Please set a passcode first.'); ok = false }
    if (!customKey?.value.trim()) { setText('customKeyErr', 'Please enter or generate a key.'); ok = false }
    if (!steps.length) { setText('stepsErr', 'Please add at least one step.'); ok = false }

    if (!ok) {
      setText('customStatus', 'Please fix the highlighted fields.')
      return
    }

    try {
      const cipher = customFlow(customText.value, steps, true)
      const pkg = await seal({ alg: 'custom', cipher, key: customKey.value, steps }, customPass.value)
      if (customOut) customOut.value = pkg
      setText('customStatus', 'Custom encrypted package created.')
    } catch {
      setText('customStatus', 'Something went wrong while encrypting.')
    }
  })

  generate()
  render()
}

setPageActive()
bindTooltips()
if ($('encryptBtn')) bindEncryptPage()
if ($('decryptBtn')) bindDecryptPage()
if ($('customEncryptBtn')) bindCustomPage()
