const Exam = {
    generate: () => {
        // Si hay un tema seleccionado en AppState, filtrar por él
        if (AppState.selectedTopic) {
            // CAMBIO: Eliminado el .sort() para mantener orden estático en temas
            return questionBank.filter(q => q.topic === AppState.selectedTopic);
        }

        // Lógica normal para modo estudio general
        if (AppState.mode === 'study') {
            // CAMBIO: Eliminado el .sort() para mantener orden estático en estudio
            return [...questionBank];
        }

        // Lógica para modo examen (aleatorio ponderado)
        // SIN CAMBIOS: Se mantiene el orden aleatorio original
        const topics = AppState.examTopics; 
        let selected = [];
        for (const [topic, count] of Object.entries(topics)) {
            let pool = questionBank.filter(q => q.topic === topic);
            pool.sort(() => Math.random() - 0.5); // Mezcla el pool de este tema
            selected = selected.concat(pool.slice(0, count));
        }
        return selected.sort(() => Math.random() - 0.5); // Mezcla el examen final
    },

    start: (mode, resume = false) => {
        AppState.mode = mode;
        AppState.active = true;

        if (!resume) {
            AppState.answers = {};
            AppState.flags = [];
            AppState.currentIndex = 0;
            AppState.timeRemaining = 90 * 60;

            AppState.questions = Exam.generate();
            Storage.saveProgress();
        }

        document.getElementById('menu-screen').style.display = 'none';
        document.getElementById('results-screen').style.display = 'none';
        document.getElementById('sidebar').style.display = 'flex';
        document.getElementById('question-container').style.display = 'block';
        document.getElementById('top-controls').style.display = 'block';

        Navigation.renderGrid();
        Renderer.loadQuestion(0);

        if (mode === 'exam') {
            document.getElementById('timer-display').style.display = 'block';
            Timer.start();
        } else {
            document.getElementById('timer-display').style.display = 'none';
        }

        if (typeof Filters !== 'undefined') Filters.init();

        // Gestionar botón de solución
        if (typeof Solution !== 'undefined') {
            Solution.init();
            Solution.updateVisibility();
        }
    },

    finish: () => {
        const unanswered = AppState.questions.length - Object.keys(AppState.answers).length;
        let msg = "¿Estás seguro de que deseas finalizar el examen?";
        if (unanswered > 0) {
            msg = `Quedan ${unanswered} preguntas sin responder. ¿Finalizar de todas formas?`;
        }
        if (!confirm(msg)) return;

        clearInterval(AppState.timerInterval);
        AppState.active = false;
        localStorage.removeItem(`${AppState.examId}_progress`);

        // Detectar si es tipo likert
        const isLikert = AppState.questions.some(q => q.type === 'likert');

        let resultText, scoreValue;

        if (isLikert) {
            // Sumar valores de escala seleccionados
            let total = 0;
            let maxPossible = 0;
            AppState.questions.forEach((q, i) => {
                const userAns = AppState.answers[i];
                const scale = q.scale || [];
                if (userAns !== undefined && userAns !== null && scale.length > userAns) {
                    total += scale[userAns];
                }
                if (scale.length > 0) {
                    maxPossible += Math.max(...scale);
                }
            });
            scoreValue = total;

            const resultRanges = window._examConfig ? window._examConfig.result_ranges : null;
            let matchedRange = null;
            if (resultRanges) {
                for (const r of resultRanges) {
                    if (total >= r.min && total <= r.max) {
                        matchedRange = r;
                        break;
                    }
                }
            }

            resultText = matchedRange
                ? `Puntuacion: ${total} pts - ${matchedRange.label}`
                : `Puntuacion: ${total} pts`;

            const key = `${Storage._prefix()}${AppState.examId}_history`;
            const history = JSON.parse(localStorage.getItem(key) || '[]');
            history.push({ date: new Date().toLocaleString(), score: total });
            localStorage.setItem(key, JSON.stringify(history));

            document.getElementById('sidebar').style.display = 'none';
            document.getElementById('question-container').style.display = 'none';
            document.getElementById('results-screen').style.display = 'block';
            document.getElementById('score-display').innerText = total + ' pts';
            document.getElementById('score-details').innerText = resultText;

            if (matchedRange) {
                const colorMap = { green: 'var(--success)', yellow: 'var(--warning)', orange: 'var(--warning)', red: 'var(--danger)', darkred: 'var(--danger)' };
                document.getElementById('score-display').style.color = colorMap[matchedRange.color] || 'var(--primary)';
            } else {
                document.getElementById('score-display').style.color = 'var(--primary)';
            }
        } else {
            let correct = 0;
            let mistakes = [];
            AppState.questions.forEach((q, i) => {
                const userAns = AppState.answers[i];
                const isCorrect = Exam.checkCorrectness(q, userAns);
                Analytics.trackAttempt(q.id, isCorrect);
                if (!isCorrect) {
                    mistakes.push({ ...q, originalIndex: i, userAnswer: userAns });
                }
                if (isCorrect) correct++;
            });

            AppState.lastMistakes = mistakes;
            MistakesHistory.saveMistakes(mistakes);
            AppState.selectedTopic = null;

            const percent = Math.round((correct / AppState.questions.length) * 100);
            scoreValue = percent;

            const key = `${Storage._prefix()}${AppState.examId}_history`;
            const history = JSON.parse(localStorage.getItem(key) || '[]');
            history.push({ date: new Date().toLocaleString(), score: percent });
            localStorage.setItem(key, JSON.stringify(history));

            document.getElementById('sidebar').style.display = 'none';
            document.getElementById('question-container').style.display = 'none';
            document.getElementById('results-screen').style.display = 'block';
            document.getElementById('score-display').innerText = percent + '%';
            document.getElementById('score-details').innerText = `Has acertado ${correct} de ${AppState.questions.length} preguntas.`;

            const passing = window._examConfig ? window._examConfig.passing_grade : 50;
            if (percent >= passing) document.getElementById('score-display').style.color = 'var(--success)';
            else document.getElementById('score-display').style.color = 'var(--danger)';

            if (typeof Stats !== 'undefined') Stats.showResults();
        }
    },

    checkCorrectness: (q, userAns) => {
        if (userAns === undefined || userAns === null) return false;

        if (q.type === 'input') {
            return String(userAns).toLowerCase().trim() === String(q.answer[0]).toLowerCase().trim();
        } else if (Array.isArray(q.answer)) {
            if (!Array.isArray(userAns) || userAns.length !== q.answer.length) return false;
            return [...userAns].sort().join(',') === [...q.answer].sort().join(',');
        } else {
            return userAns === q.answer;
        }
    }
};