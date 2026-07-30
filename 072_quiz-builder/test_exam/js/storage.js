const Storage = {
    _prefix: () => {
        const user = AppState.currentUser || 'default';
        return user + '_';
    },

    saveProgress: () => {
        localStorage.setItem(`${Storage._prefix()}${AppState.examId}_progress`, JSON.stringify(AppState));
    },
    
    loadHistory: () => {
        const history = JSON.parse(localStorage.getItem(`${Storage._prefix()}${AppState.examId}_history`) || '[]');
        const list = document.getElementById('history-list');
        if (!list) return;

        if (history.length === 0) {
            list.innerHTML = "<li>No hay intentos previos</li>";
            return;
        }
        list.innerHTML = history.slice(-5).reverse().map(h => 
            `<li>${h.date} - Puntuación: <strong>${h.score}%</strong></li>`
        ).join('');
    },

    resetExam: () => {
        localStorage.removeItem(`${Storage._prefix()}${AppState.examId}_progress`);
        AppState.selectedTopic = null;
        location.reload();
    },

    getUsers: () => {
        const raw = localStorage.getItem('_users');
        return raw ? JSON.parse(raw) : ['default'];
    },

    saveUsers: (users) => {
        localStorage.setItem('_users', JSON.stringify(users));
    },

    switchUser: (name) => {
        const old = AppState.currentUser || 'default';
        if (old !== name) {
            AppState.currentUser = name;
            localStorage.setItem('_currentUser', name);
            location.reload();
        }
    },

    initUser: () => {
        const saved = localStorage.getItem('_currentUser');
        AppState.currentUser = saved || 'default';
    }
};
