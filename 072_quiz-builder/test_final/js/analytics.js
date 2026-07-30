// js/analytics.js

const Analytics = {
    KEY: `${AppState.examId}_analytics_data`, // Usar ID dinámico
    // Obtener todos los datos
    getData: () => {
        return JSON.parse(localStorage.getItem(Analytics.KEY)) || {};
    },

    // Guardar datos
    saveData: (data) => {
        localStorage.setItem(Analytics.KEY, JSON.stringify(data));
    },

    // Registrar un intento (llamado desde exam.js o solution.js)
    trackAttempt: (questionId, isCorrect) => {
        const data = Analytics.getData();
        if (!data[questionId]) {
            data[questionId] = { correct: 0, incorrect: 0, attempts: 0 };
        }

        data[questionId].attempts++;
        if (isCorrect) {
            data[questionId].correct++;
        } else {
            data[questionId].incorrect++;
        }

        Analytics.saveData(data);
    },

    // Obtener puntuación de dificultad (para el modo adaptativo)
    // Cuanto más alto, más "problemática" es la pregunta
    getDifficultyScore: (questionId) => {
        const stats = Analytics.getData()[questionId];
        if (!stats) return 0; // Nunca vista
        
        // Fórmula simple: (Fallos * 2) - Aciertos
        // Damos más peso a los fallos recientes o históricos
        return (stats.incorrect * 2) - stats.correct;
    },

    // Obtener estadísticas agregadas por tema (para Heatmap)
    getTopicStats: () => {
        const data = Analytics.getData();
        const topicMap = {};

        // Necesitamos mapear IDs a Temas. 
        // Como questionBank no está cargado en todos los contextos, 
        // podemos usar AppState si está disponible, o iterar questionBank global.
        if (typeof questionBank === 'undefined') return {};

        questionBank.forEach(q => {
            if (!topicMap[q.topic]) topicMap[q.topic] = { correct: 0, total: 0 };
            
            const stats = data[q.id];
            if (stats) {
                topicMap[q.topic].total += stats.attempts;
                topicMap[q.topic].correct += stats.correct;
            }
        });

        return topicMap;
    }
};
