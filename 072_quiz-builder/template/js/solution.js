const Solution = {
    visible: false,

    init: () => {
        // Buscamos el contenedor de botones
        const actionBar = document.querySelector('.action-bar');
        if (!actionBar) return;

        // Evitar duplicados
        if (document.getElementById('btn-solution')) return;

        // Crear botón
        const btn = document.createElement('button');
        btn.id = 'btn-solution';
        btn.className = 'btn btn-secondary';
        btn.innerText = '💡 Ver Solución';
        btn.onclick = Solution.toggle;
        
        // Insertar en la barra de acciones
        const leftDiv = actionBar.querySelector('div');
        if(leftDiv) leftDiv.appendChild(btn);
        else actionBar.appendChild(btn);
        
        Solution.updateVisibility();
    },

    toggle: () => {
        Solution.visible = !Solution.visible;
        const btn = document.getElementById('btn-solution');
        
        if (Solution.visible) {
            btn.innerText = '🙈 Ocultar';
            btn.classList.add('active');
        } else {
            btn.innerText = '💡 Ver Solución';
            btn.classList.remove('active');
        }
        
        // Re-renderizar para mostrar/ocultar
	const q = AppState.questions[AppState.currentIndex];
	Renderer.renderOptions(q);
    },

    isActive: () => {
        return Solution.visible;
    },

    // Muestra u oculta el botón según el modo
    updateVisibility: () => {
        const btn = document.getElementById('btn-solution');
        if (btn) {
            // Solo visible en modo estudio y revisión
            if (AppState.mode === 'study' || AppState.mode === 'review') {
                btn.style.display = 'inline-flex';
            } else {
                btn.style.display = 'none';
                Solution.visible = false; // Reset al cambiar de modo
            }
        }
    }
};
