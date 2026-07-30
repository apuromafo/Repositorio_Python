const app = {
    init: () => {
        Storage.initUser();
        app.renderUserNav();
        if (typeof questionBank === 'undefined') {
            document.getElementById('q-count').innerText = "ERROR: No se encuentra el archivo de preguntas";
            document.getElementById('q-count').style.color = "red";
            return;
        }
        Storage.loadHistory();
        document.getElementById('q-count').innerText = questionBank.length;

        // Iniciar atajos de teclado
        if (typeof Shortcuts !== 'undefined') Shortcuts.init();

        // Pre-cargar lista de temas en el modal
        app.populateTopics();

        // Actualizar título de la página si existe en AppState
        if(AppState.title) {
            document.getElementById('page-title').innerText = AppState.title;
            document.title = AppState.title;
        }

        // Check saved state
        const saved = localStorage.getItem(`${Storage._prefix()}${AppState.examId}_progress`);
        if (saved) {
            if (confirm("Se ha encontrado un examen guardado. ¿Deseas continuar?")) {
                const loadedState = JSON.parse(saved);
                Object.assign(AppState, loadedState);
                Exam.start(AppState.mode, true);
            } else {
                localStorage.removeItem(`${Storage._prefix()}${AppState.examId}_progress`);
            }
        }
    },

    // Generar botones de temas dinámicamente
    populateTopics: () => {
        const container = document.getElementById('topic-list');
        if (!container) return;

        // Extraer temas únicos del banco de preguntas
        const topics = [...new Set(questionBank.map(q => q.topic))].sort();

        container.innerHTML = '';

        topics.forEach(t => {
            const btn = document.createElement('button');
            btn.className = 'topic-btn';
            // Usamos los nombres definidos en AppState.topicNames
            btn.innerText = AppState.topicNames[t] || `Tema ${t}`;
            btn.onclick = () => {
                app.hideTopicSelector();
                app.startTopicExam(t);
            };
            container.appendChild(btn);
        });
    },

    showTopicSelector: () => {
        document.getElementById('topic-modal').style.display = 'flex';
    },

    hideTopicSelector: () => {
        document.getElementById('topic-modal').style.display = 'none';
    },

    startExam: (mode) => Exam.start(mode, false),

    // Iniciar examen solo de un tema
    startTopicExam: (topic) => {
        AppState.selectedTopic = topic; // Guardamos el tema seleccionado
        Exam.start('study', false); // Iniciamos en modo estudio (sin tiempo)
    },

    // Usar el módulo Adaptive para generar preguntas
    startAdaptiveExam: () => {
        // 1. Configurar Estado
        AppState.questions = Adaptive.generateAdaptiveSet(60);
        AppState.answers = {};
        AppState.flags = [];
        AppState.mode = 'adaptive';
        AppState.currentIndex = 0;
        AppState.selectedTopic = null; // Aseguramos que no hay tema filtrado

        // 2. Gestión de UI (Mostrar/Ocultar)
        document.getElementById('menu-screen').style.display = 'none';
        document.getElementById('results-screen').style.display = 'none';
        document.getElementById('sidebar').style.display = 'flex';
        document.getElementById('question-container').style.display = 'block';
        document.getElementById('top-controls').style.display = 'block';

        // 3. Timer (Oculto en modo adaptativo)
        document.getElementById('timer-display').style.display = 'none';

        // 4. Renderizado inicial
        Navigation.renderGrid();
        Renderer.loadQuestion(0);
        Navigation.updateStats();

        // 5. Inicializar módulos opcionales
        if (typeof Solution !== 'undefined') Solution.init();
        if (typeof Filters !== 'undefined') Filters.init();
    },

    nextQuestion: () => Navigation.next(),
    prevQuestion: () => Navigation.prev(),
    toggleFlag: () => Navigation.toggleFlag(),
    finishExam: () => Exam.finish(),
    reviewMistakes: () => Review.mistakes(),
    resetExam: () => Storage.resetExam(),

    renderUserNav: () => {
        const nav = document.querySelector('.top-nav');
        if (!nav) return;
        const existing = document.getElementById('user-selector');
        if (existing) existing.remove();
        const div = document.createElement('div');
        div.id = 'user-selector';
        div.style.cssText = 'display:flex;align-items:center;gap:6px;margin-left:auto;margin-right:12px;';
        const users = Storage.getUsers();
        const current = AppState.currentUser || 'default';
        const sel = document.createElement('select');
        sel.style.cssText = 'padding:4px 8px;border-radius:4px;border:1px solid var(--border);background:var(--light);color:var(--text);font-size:.8rem;';
        users.forEach(u => {
            const opt = document.createElement('option');
            opt.value = u; opt.textContent = u;
            if (u === current) opt.selected = true;
            sel.appendChild(opt);
        });
        sel.onchange = () => {
            const name = sel.value;
            if (name === '__add__') return;
            Storage.switchUser(name);
        };
        div.appendChild(sel);
        const addBtn = document.createElement('button');
        addBtn.textContent = '+';
        addBtn.className = 'nav-btn';
        addBtn.style.cssText = 'padding:2px 8px;font-size:.8rem;';
        addBtn.onclick = () => {
            const name = prompt('Nombre de usuario:');
            if (name && name.trim()) {
                const n = name.trim();
                const users = Storage.getUsers();
                if (!users.includes(n)) {
                    users.push(n);
                    Storage.saveUsers(users);
                }
                Storage.switchUser(n);
            }
        };
        div.appendChild(addBtn);
        const configBtn = nav.querySelector('button:last-child');
        if (configBtn) nav.insertBefore(div, configBtn);
        else nav.appendChild(div);
    }
};

// Start
app.init();
