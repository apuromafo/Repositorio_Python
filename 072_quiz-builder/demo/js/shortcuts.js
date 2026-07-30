const Shortcuts = {
    init: () => {
        document.addEventListener('keydown', (e) => {
            if (e.target.tagName === 'INPUT') return;

            const key = e.key.toLowerCase();

            // Números 1-5 para seleccionar opciones
            if (['1', '2', '3', '4', '5'].includes(key)) {
                const index = parseInt(key) - 1;
                const labels = document.querySelectorAll('.option-label');
                if (labels[index]) labels[index].click();
            }

            // Navegación
            if (key === 'arrowright' || key === 'enter') Navigation.next();
            if (key === 'arrowleft') Navigation.prev();

            // Marcar
            if (key === 'f') Navigation.toggleFlag();
        });
    }
};
