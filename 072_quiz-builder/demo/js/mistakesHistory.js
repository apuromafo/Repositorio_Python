const MistakesHistory = {
    STORAGE_KEY: `${AppState.examId}_mistakes_history`,

    saveMistakes(mistakes) {
        const history = JSON.parse(localStorage.getItem(this.STORAGE_KEY)) || [];

        mistakes.forEach(m => {
            const exists = history.find(q => q.question === m.question);
            if (!exists) {
                history.push(m);
            }

        });

        localStorage.setItem(this.STORAGE_KEY, JSON.stringify(history));
    },

    loadMistakes() {
        return JSON.parse(localStorage.getItem(this.STORAGE_KEY)) || [];
    },

    review() {

        let mistakes = this.loadMistakes();

	// NUEVO: Ordenar por frecuencia de fallo (Adaptive)
	mistakes = Adaptive.getWeightedMistakes(mistakes);

	if (mistakes.length === 0) {
            alert("No hay fallos históricos todavía.");
            return;
        }

        AppState.questions = mistakes;
        AppState.answers = {};
        AppState.flags = [];
        AppState.mode = "review";
        AppState.currentIndex = 0;

        document.getElementById('results-screen').style.display = 'none';
        document.getElementById('sidebar').style.display = 'flex';
        document.getElementById('question-container').style.display = 'block';

        Navigation.renderGrid();
        Renderer.loadQuestion(0);
        Navigation.updateStats();
    },

    clear() {
        localStorage.removeItem(this.STORAGE_KEY);
    }
};
