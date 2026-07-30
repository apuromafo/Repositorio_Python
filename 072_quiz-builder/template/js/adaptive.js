// js/adaptive.js

const Adaptive = {
    // Generar examen adaptativo: prioriza las preguntas con mayor dificultad
    generateAdaptiveSet: (limit = 60) => {
        if (typeof questionBank === 'undefined') return [];

        // Ordenar por dificultad (descendente)
        const sorted = [...questionBank].sort((a, b) => {
            return Adaptive.getWeight(b.id) - Adaptive.getWeight(a.id);
        });

        // Seleccionar las top 'limit'
        // Podríamos añadir algo de aleatoriedad para no hacer predecible el orden
        const selection = sorted.slice(0, limit);
        
        // Mezclar un poco las primeras posiciones para no sacar siempre las mismas seguidas
        return selection.sort(() => Math.random() - 0.3); 
    },

    // Calcular peso para la selección (Probabilidad por fallo histórico)
    getWeight: (questionId) => {
        const stats = Analytics.getData()[questionId];
        if (!stats) return 0.5; // Probabilidad media si es nueva

        // Peso basado en ratio de fallo
        const failRatio = stats.incorrect / stats.attempts;
        return failRatio + (Math.random() * 0.2); // Un poco de ruido
    },

    // Selección ponderada para "Repaso de Fallos"
    getWeightedMistakes: (pool) => {
        if (pool.length === 0) return [];
        
        // Calcular peso total
        let totalWeight = 0;
        const weightedPool = pool.map(q => {
            const weight = Analytics.getDifficultyScore(q.id) + 1; // +1 para evitar 0
            totalWeight += weight;
            return { q, weight };
        });

        // Seleccionar basado en probabilidad (Roulette Wheel Selection)
        // Simplificación: Ordenar por peso y tomar un corte aleatorio
        weightedPool.sort((a, b) => b.weight - a.weight);
        
        // Devolvemos las preguntas, ordenadas por peso (las que más duelen primero)
        return weightedPool.map(item => item.q);
    }
};
