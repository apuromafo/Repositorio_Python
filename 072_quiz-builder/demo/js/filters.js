const Filters = {
    current: 'all',

    init: () => {
        const header = document.querySelector('.sidebar-header');
        if (document.getElementById('filter-btns')) return; // Evitar duplicados

        const container = document.createElement('div');
        container.id = 'filter-btns';
        
        const buttons = [
            { id: 'all', label: 'Todas' },
            { id: 'unanswered', label: 'Pendientes' },
            { id: 'answered', label: 'Hechas' },
            { id: 'flagged', label: '🚩' }
        ];

        buttons.forEach(b => {
            const btn = document.createElement('button');
            btn.innerText = b.label;
            btn.className = 'filter-btn' + (b.id === 'all' ? ' active' : '');
            btn.dataset.filter = b.id;
            btn.onclick = () => Filters.apply(b.id);
            container.appendChild(btn);
        });

        header.appendChild(container);
    },

    apply: (filterType) => {
        Filters.current = filterType;
        
        // Actualizar clases de botones
        document.querySelectorAll('.filter-btn').forEach(btn => {
            if (btn.dataset.filter === filterType) btn.classList.add('active');
            else btn.classList.remove('active');
        });

        // Re-renderizar grid
        const grid = document.getElementById('nav-grid');
        grid.innerHTML = '';
        
        AppState.questions.forEach((q, i) => {
            const isAnswered = AppState.answers[i] !== undefined;
            const isFlagged = AppState.flags.includes(i);
            
            let show = false;
            if (filterType === 'all') show = true;
            else if (filterType === 'unanswered' && !isAnswered) show = true;
            else if (filterType === 'answered' && isAnswered) show = true;
            else if (filterType === 'flagged' && isFlagged) show = true;

            if (show) {
                const btn = document.createElement('div');
                btn.className = 'q-btn';
                btn.innerText = i + 1;
		btn.dataset.index = i;
                btn.onclick = () => Renderer.loadQuestion(i);
                Navigation.updateBtnStyle(btn, i);
                grid.appendChild(btn);
            }
        });
    }
};
