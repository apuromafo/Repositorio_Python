const Settings = (function() {
    const STORAGE_KEY = 'quizbuilder_settings'
    let current = null

    const defaults = {
        theme: 'dark',
        lang: 'es',
        fontSize: 'normal',
        showTimer: true,
        autoSave: true
    }

    function load() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY)
            current = raw ? { ...defaults, ...JSON.parse(raw) } : { ...defaults }
        } catch {
            current = { ...defaults }
        }
        return current
    }

    function save() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(current))
        } catch {}
    }

    function get(key) {
        if (!current) load()
        return key ? current[key] : current
    }

    function set(key, val) {
        if (!current) load()
        current[key] = val
        save()
        apply()
    }

    function apply() {
        if (!current) load()
        document.documentElement.setAttribute('data-theme', current.theme)
        document.documentElement.setAttribute('lang', current.lang)
        document.documentElement.style.fontSize =
            current.fontSize === 'large' ? '18px' :
            current.fontSize === 'small' ? '14px' : '16px'
        const t = document.getElementById('timer-display')
        if (t) t.style.display = current.showTimer ? 'block' : 'none'
    }

    function t(key) {
        if (!current) load()
        const keys = key.split('.')
        let val = null
        if (typeof Lang !== 'undefined') {
            val = Lang
            for (const k of keys) {
                val = val[k]
                if (val === undefined) break
            }
        }
        return val || key
    }

    function tTemplate(key, vars) {
        let s = t(key)
        if (vars) {
            for (const [k, v] of Object.entries(vars)) {
                s = s.replace(`{${k}}`, v)
            }
        }
        return s
    }

    function showModal() {
        let el = document.getElementById('settings-modal')
        if (!el) el = buildModal()
        syncForm()
        el.style.display = 'flex'
    }

    function hideModal() {
        const el = document.getElementById('settings-modal')
        if (el) el.style.display = 'none'
    }

    function buildModal() {
        const d = document.createElement('div')
        d.id = 'settings-modal'
        d.className = 'modal'
        d.innerHTML = `
<div class="modal-content" style="max-width:480px;text-align:left">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
<h3 style="margin:0">${t('settings.title')}</h3>
<button class="nav-btn" onclick="Settings.hideModal()" style="font-size:1.2rem;padding:2px 10px">x</button>
</div>

<label style="display:block;margin-bottom:12px">
<span style="font-size:0.85rem;color:var(--text-muted);display:block;margin-bottom:4px">${t('settings.language')}</span>
<select id="set-lang" class="text-input" style="width:100%">
<option value="es">Español</option>
<option value="en">English</option>
</select>
</label>

<label style="display:block;margin-bottom:12px">
<span style="font-size:0.85rem;color:var(--text-muted);display:block;margin-bottom:4px">${t('settings.theme')}</span>
<select id="set-theme" class="text-input" style="width:100%">
<option value="dark">${t('settings.themes.dark')}</option>
<option value="light">${t('settings.themes.light')}</option>
<option value="sepia">${t('settings.themes.sepia')}</option>
<option value="hc">${t('settings.themes.hc')}</option>
</select>
</label>

<label style="display:block;margin-bottom:12px">
<span style="font-size:0.85rem;color:var(--text-muted);display:block;margin-bottom:4px">${t('settings.font_size')}</span>
<select id="set-fontsize" class="text-input" style="width:100%">
<option value="small">${t('settings.font_small')}</option>
<option value="normal" selected>${t('settings.font_normal')}</option>
<option value="large">${t('settings.font_large')}</option>
</select>
</label>

<label style="display:flex;align-items:center;gap:10px;margin-bottom:8px;cursor:pointer;color:var(--text)">
<input type="checkbox" id="set-timer" checked> ${t('settings.show_timer')}
</label>

<label style="display:flex;align-items:center;gap:10px;margin-bottom:20px;cursor:pointer;color:var(--text)">
<input type="checkbox" id="set-autosave" checked> ${t('settings.auto_save')}
</label>

<button class="btn btn-primary" onclick="Settings.saveFromForm()" style="width:100%">${t('settings.save')}</button>
</div>`
        document.body.appendChild(d)
        d.addEventListener('click', e => { if (e.target === d) hideModal() })
        return d
    }

    function syncForm() {
        const s = get()
        byId('set-theme', s.theme)
        byId('set-lang', s.lang)
        byId('set-fontsize', s.fontSize)
        byId('set-timer', s.showTimer)
        byId('set-autosave', s.autoSave)
    }

    function byId(id, val) {
        const el = document.getElementById(id)
        if (!el) return
        if (el.type === 'checkbox') el.checked = !!val
        else el.value = val
    }

    function saveFromForm() {
        current.theme = document.getElementById('set-theme').value
        current.lang = document.getElementById('set-lang').value
        current.fontSize = document.getElementById('set-fontsize').value
        current.showTimer = document.getElementById('set-timer').checked
        current.autoSave = document.getElementById('set-autosave').checked
        save()
        apply()
        hideModal()
        showToast(t('settings.saved'))
    }

    function showToast(msg) {
        let t = document.getElementById('settings-toast')
        if (!t) {
            t = document.createElement('div')
            t.id = 'settings-toast'
            t.style.cssText = 'position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:var(--primary);color:#fff;padding:12px 24px;border-radius:8px;font-size:0.9rem;z-index:99999;opacity:0;transition:opacity .3s'
            document.body.appendChild(t)
        }
        t.textContent = msg
        t.style.opacity = '1'
        clearTimeout(t._hide)
        t._hide = setTimeout(() => { t.style.opacity = '0' }, 2000)
    }

    load()
    apply()

    return {
        load, save, get, set, apply,
        t, tTemplate,
        showModal, hideModal, saveFromForm
    }
})()

document.addEventListener('DOMContentLoaded', () => Settings.apply())
