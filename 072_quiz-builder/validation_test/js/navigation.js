const Navigation = {
    next: () => {
        if (AppState.currentIndex < AppState.questions.length - 1) {
            Renderer.loadQuestion(AppState.currentIndex + 1);
        }
    },

    prev: () => {
        if (AppState.currentIndex > 0) {
            Renderer.loadQuestion(AppState.currentIndex - 1);
        }
    },

    toggleFlag: () => {
        const idx = AppState.currentIndex;
        if (AppState.flags.includes(idx)) {
            AppState.flags = AppState.flags.filter(i => i !== idx);
        } else {
            AppState.flags.push(idx);
        }
        Navigation.updateHighlight();
        Navigation.updateStats();
        Storage.saveProgress();
        Filters.apply(Filters.current); // Refrescar filtro
    },

    renderGrid: () => {
        const grid = document.getElementById('nav-grid');
        grid.innerHTML = '';
        AppState.questions.forEach((q, i) => {
            const btn = document.createElement('div');
            btn.className = 'q-btn';
            btn.innerText = i + 1;
	    btn.dataset.index = i;
            btn.onclick = () => Renderer.loadQuestion(i);
            Navigation.updateBtnStyle(btn, i);
            grid.appendChild(btn);
        });
        Navigation.updateStats();
    },
    
    updateBtnStyle: (btn, index) => {
        btn.className = 'q-btn';
        const isAnswered = AppState.answers[index] !== undefined;
        const isFlagged = AppState.flags.includes(index);
        const isCurrent = AppState.currentIndex === index;

        // Si estamos revisando fallos, mostramos colores diferentes
        if (AppState.mode === 'review') {
            const q = AppState.questions[index];
            // Como es revisión de fallos, en este modo todas son "incorrectas" por defecto 
            // si no se contestan bien de nuevo, pero para diferenciar:
            if (isCurrent) btn.classList.add('current');
            if (isAnswered) {
                 if (Exam.checkCorrectness(q, AppState.answers[index])) {
                     btn.classList.add('correct'); // Azul/Verde (definir en CSS)
                 } else {
                     btn.classList.add('incorrect'); // Rojo
                 }
            }
            if (isFlagged) btn.classList.add('flagged');
        } else {
            // Modo normal
            if (isCurrent) btn.classList.add('current');
            if (isAnswered) btn.classList.add('answered');
            if (isFlagged) btn.classList.add('flagged');
        }
    },

    updateHighlight: () => {
        const btns = document.querySelectorAll('.q-btn');
	btns.forEach(btn => {
	    const idx = parseInt(btn.dataset.index);
	    Navigation.updateBtnStyle(btn, idx);
	});
    },

    updateStats: () => {
        const answered = Object.keys(AppState.answers).length;
        const flagged = AppState.flags.length;
        const pending = AppState.questions.length - answered;
        const total = AppState.questions.length;

        document.getElementById('stat-answered').innerText = answered;
        document.getElementById('stat-pending').innerText = pending;
        document.getElementById('stat-flagged').innerText = flagged;

        // Barra de progreso
        const percent = total > 0 ? (answered / total) * 100 : 0;
        const bar = document.getElementById('progress-bar');
        if(bar) bar.style.width = `${percent}%`;
    }
};
