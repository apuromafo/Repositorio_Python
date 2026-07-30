const PDFExport = (function() {
    let loaded = false
    let loading = false
    const queue = []

    function loadJsPDF() {
        return new Promise((resolve, reject) => {
            if (typeof jsPDF !== 'undefined') { resolve(); return }
            if (typeof window.jspdf !== 'undefined') { resolve(); return }
            if (loading) { queue.push(resolve); return }
            loading = true
            const s = document.createElement('script')
            s.src = 'js/jspdf.umd.min.js'
            s.onload = () => { loaded = true; queue.forEach(r => r()); resolve() }
            s.onerror = reject
            document.head.appendChild(s)
        })
    }

    function showModal() {
        let el = document.getElementById('pdf-export-modal')
        if (!el) el = buildModal()
        populateTopics()
        el.style.display = 'flex'
    }

    function hideModal() {
        const el = document.getElementById('pdf-export-modal')
        if (el) el.style.display = 'none'
    }

    function buildModal() {
        const d = document.createElement('div')
        d.id = 'pdf-export-modal'
        d.className = 'pdf-modal-overlay'
        d.innerHTML = `
<div class="pdf-modal-content">
<div class="pdf-modal-header">
<h3>Exportar a PDF</h3>
<button class="pdf-modal-close" onclick="PDFExport.hideModal()">x</button>
</div>
<div class="pdf-modal-body">
<div class="pdf-section">
<h4>Tipo de Exportacion</h4>
<div class="pdf-mode-grid">
<label class="pdf-mode-option"><input type="radio" name="pdf-mode" value="practice" checked>
<div class="pdf-mode-card"><strong>Modo Practica</strong><small>Solo preguntas y opciones.</small></div></label>
<label class="pdf-mode-option"><input type="radio" name="pdf-mode" value="study">
<div class="pdf-mode-card"><strong>Modo Estudio</strong><small>Respuestas correctas marcadas.</small></div></label>
<label class="pdf-mode-option"><input type="radio" name="pdf-mode" value="official">
<div class="pdf-mode-card"><strong>Test Oficial</strong><small>Respuestas agrupadas al final.</small></div></label>
</div></div>
<div class="pdf-section">
<h4>Filtrar por Temas</h4>
<div class="pdf-topic-header">
<label class="pdf-checkbox"><input type="checkbox" id="pdf-select-all-topics" checked><span>Seleccionar todos</span></label>
</div>
<div class="pdf-topic-grid" id="pdf-topic-list"></div>
</div>
<div class="pdf-section">
<h4>Opciones</h4>
<div class="pdf-options-grid">
<label class="pdf-checkbox"><input type="checkbox" id="pdf-include-explanations"><span>Incluir explicaciones</span></label>
<label class="pdf-checkbox"><input type="checkbox" id="pdf-include-ids"><span>Mostrar IDs</span></label>
<label class="pdf-checkbox"><input type="checkbox" id="pdf-randomize"><span>Orden aleatorio</span></label>
</div></div></div>
<div class="pdf-modal-footer">
<button class="btn btn-secondary" onclick="PDFExport.hideModal()">Cancelar</button>
<button class="btn btn-primary" onclick="PDFExport.generate()">Generar PDF</button>
</div></div>`
        document.body.appendChild(d)
        d.addEventListener('click', e => { if (e.target === d) hideModal() })
        setTimeout(() => {
            const sa = document.getElementById('pdf-select-all-topics')
            if (sa) sa.addEventListener('change', e => {
                document.querySelectorAll('#pdf-topic-list input[type="checkbox"]')
                    .forEach(cb => cb.checked = e.target.checked)
            })
        }, 100)
        return d
    }

    function populateTopics() {
        const list = document.getElementById('pdf-topic-list')
        if (!list || typeof questionBank === 'undefined') return
        const topics = [...new Set(questionBank.map(q => q.topic))].sort()
        const names = AppState.topicNames || {}
        list.innerHTML = topics.map(t => `
<label class="pdf-checkbox pdf-topic-checkbox">
<input type="checkbox" value="${t}" checked>
<span>${names[t] || t}</span>
<small>(${questionBank.filter(q => q.topic === t).length} preguntas)</small>
</label>`).join('')
    }

    function readState() {
        const mode = (document.querySelector('input[name="pdf-mode"]:checked') || {}).value || 'practice'
        const topics = Array.from(document.querySelectorAll('#pdf-topic-list input:checked')).map(cb => cb.value)
        return {
            mode,
            topics,
            explanations: document.getElementById('pdf-include-explanations')?.checked || false,
            ids: document.getElementById('pdf-include-ids')?.checked || false,
            random: document.getElementById('pdf-randomize')?.checked || false
        }
    }

    async function generate() {
        const opts = readState()
        if (!opts.topics.length) { alert('Selecciona al menos un tema.'); return }
        let questions = questionBank.filter(q => opts.topics.includes(q.topic))
        if (!questions.length) { alert('No hay preguntas para los temas seleccionados.'); return }
        if (opts.random) questions = shuffle(questions)

        try {
            await loadJsPDF()
        } catch {
            alert('Error al cargar la libreria PDF.'); return
        }
        showLoader()
        try {
            const { jsPDF } = window.jspdf
            const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
            await render(doc, questions, opts)
            doc.save(filename(AppState.title, opts))
            hideModal()
        } catch (e) {
            console.error(e)
            alert('Error al generar el PDF.')
        } finally {
            hideLoader()
        }
    }

    function render(doc, questions, opts) {
        const pw = doc.internal.pageSize.getWidth()
        const ph = doc.internal.pageSize.getHeight()
        const cw = pw - 30
        let y = 0

        function newPage() {
            doc.addPage(); y = 15
        }

        // cover
        y = 60
        doc.setFontSize(24); doc.setTextColor(37, 99, 235)
        doc.text(opts.title || 'Examen', pw / 2, y, { align: 'center' })
        y += 15
        doc.setFontSize(14); doc.setTextColor(30, 41, 59)
        doc.text('Banco de Preguntas', pw / 2, y, { align: 'center' })
        y += 20
        doc.setFillColor(241, 245, 249)
        doc.roundedRect(40, y, pw - 80, 40, 3, 3, 'F')
        y += 15
        doc.setFontSize(11); doc.setTextColor(30, 41, 59)
        doc.text(`Total de preguntas: ${questions.length}`, pw / 2, y, { align: 'center' })
        y += 10
        doc.setFontSize(9); doc.setTextColor(100, 116, 139)
        doc.text(`Generado el ${new Date().toLocaleDateString('es-ES')}`, pw / 2, y, { align: 'center' })

        // questions
        let pageNum = 2
        newPage()
        const answers = []

        for (let i = 0; i < questions.length; i++) {
            const q = questions[i]
            const qNum = i + 1
            const estH = estimateHeight(doc, q, opts)
            if (y + estH > ph - 15) { newPage(); pageNum++ }
            addPageNum(doc, pageNum, pw, ph)
            y = renderQ(doc, q, qNum, y, opts, answers)
            y += 3
            doc.setDrawColor(220, 220, 220)
            doc.line(15, y, pw - 15, y)
            y += 5
        }

        // answers (official mode)
        if (opts.mode === 'official' && answers.length) {
            newPage(); pageNum++
            addPageNum(doc, pageNum, pw, ph)
            doc.setFontSize(14); doc.setTextColor(37, 99, 235)
            doc.text('RESPUESTAS', 15, y)
            y += 10
            doc.setFontSize(10); doc.setTextColor(30, 41, 59)
            answers.forEach(a => {
                if (y > ph - 15) { newPage(); pageNum++; addPageNum(doc, pageNum, pw, ph) }
                doc.text(`Pregunta ${a.q}: ${a.a}`, 15, y)
                y += 6
            })
        }
    }

    function renderQ(doc, q, qNum, y, opts, answers) {
        const pw = doc.internal.pageSize.getWidth()
        const cw = pw - 30
        const multi = Array.isArray(q.answer)
        const input = q.type === 'input'

        doc.setFontSize(9); doc.setTextColor(100, 116, 139)
        let h = `Pregunta ${qNum}`
        if (opts.ids) h += ` (ID: ${q.id})`
        h += ` | Tema: ${q.topic}`
        doc.text(h, 15, y); y += 6

        doc.setFontSize(11); doc.setTextColor(30, 41, 59)
        const ql = doc.splitTextToSize(q.question, cw)
        ql.forEach(l => { doc.text(l, 15, y); y += 6 }); y += 2

        if (!input && q.options) {
            q.options.forEach((opt, idx) => {
                const letter = String.fromCharCode(65 + idx)
                let txt = `${letter}. ${opt}`
                const correct = multi ? q.answer.includes(idx) : q.answer === idx
                if (opts.mode === 'study' && correct) {
                    doc.setTextColor(22, 163, 74); txt = `* ${txt}`
                } else doc.setTextColor(30, 41, 59)
                doc.setFontSize(10)
                const ol = doc.splitTextToSize(txt, cw - 5)
                ol.forEach(l => { doc.text(l, 18, y); y += 5 })
            })
        }

        if (input) {
            doc.setFontSize(10); doc.setTextColor(100, 116, 139)
            doc.text('[ Respuesta: _________________ ]', 18, y)
            if (opts.mode === 'study') {
                doc.setTextColor(22, 163, 74)
                doc.text(`(Respuesta: ${q.answer.join(' / ')})`, 78, y)
            }
            y += 6
        }

        if (opts.mode === 'official') {
            const correct = input ? q.answer.join(' / ')
                : multi ? q.answer.map(i => String.fromCharCode(65 + i)).join(', ')
                : String.fromCharCode(65 + q.answer)
            answers.push({ q: qNum, a: correct })
        }

        if (opts.explanations && q.explanation && opts.mode !== 'practice') {
            y += 2
            doc.setFontSize(9); doc.setTextColor(80, 80, 80)
            doc.setFillColor(248, 250, 252)
            const el = doc.splitTextToSize(q.explanation, cw - 6)
            const bh = el.length * 4 + 4
            doc.roundedRect(15, y - 2, cw, bh, 1, 1, 'F')
            el.forEach(l => { doc.text(l, 18, y); y += 4 })
        }
        return y
    }

    function estimateHeight(doc, q, opts) {
        let h = 30
        h += doc.splitTextToSize(q.question, 170).length * 6
        if (q.type !== 'input' && q.options) h += q.options.length * 5
        if (opts.explanations && q.explanation) h += doc.splitTextToSize(q.explanation, 170).length * 4 + 10
        return h
    }

    function addPageNum(doc, n, pw, ph) {
        doc.setFontSize(9); doc.setTextColor(100, 116, 139)
        doc.text(`Pagina ${n}`, pw - 15, ph - 10, { align: 'right' })
    }

    function shuffle(a) {
        const s = [...a]
        for (let i = s.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [s[i], s[j]] = [s[j], s[i]]
        }
        return s
    }

    function filename(title, opts) {
        const d = new Date().toISOString().split('T')[0]
        const labels = { practice: 'practica', study: 'estudio', official: 'test' }
        const t = opts.topics.length < 5 ? '-' + opts.topics.join('-') : '-completo'
        return `${title.replace(/\s+/g, '_')}${t}_${labels[opts.mode]}_${d}.pdf`
    }

    function showLoader() {
        const d = document.createElement('div')
        d.id = 'pdf-loader'
        d.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;z-index:10000"><div style="background:#fff;padding:2em;border-radius:8px;text-align:center"><div class="pdf-spinner"></div><p>Generando PDF...</p></div></div>'
        document.body.appendChild(d)
    }

    function hideLoader() {
        const d = document.getElementById('pdf-loader')
        if (d) d.remove()
    }

    return {
        showModal,
        hideModal,
        generate,
        init: function() {
            if (typeof jsPDF === 'undefined' && typeof window.jspdf === 'undefined') {
                const s = document.createElement('script')
                s.src = 'js/jspdf.umd.min.js'
                document.head.appendChild(s)
            }
        }
    }
})()

document.addEventListener('DOMContentLoaded', () => PDFExport.init())
