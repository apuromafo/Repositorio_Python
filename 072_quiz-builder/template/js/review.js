const Review = {
    mistakes: () => {

        const mistakes = AppState.lastMistakes || [];

        if (mistakes.length === 0) {
            alert("¡No hay preguntas falladas!");
            return;
        }

        AppState.questions = mistakes;

        // Restaurar respuestas del usuario
        AppState.answers = {};
        mistakes.forEach((m, i) => {
            if (m.userAnswer !== undefined) {
                AppState.answers[i] = m.userAnswer;
            }
        });

        AppState.flags = [];
        AppState.mode = 'review';
        AppState.currentIndex = 0;

        document.getElementById('results-screen').style.display = 'none';
        document.getElementById('sidebar').style.display = 'flex';
        document.getElementById('question-container').style.display = 'block';

        Navigation.renderGrid();
        Renderer.loadQuestion(0);
        Navigation.updateStats();

        if (typeof Solution !== 'undefined') {
            Solution.updateVisibility();
        }
    }
};
