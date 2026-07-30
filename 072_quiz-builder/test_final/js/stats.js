const Stats = {
    showResults: () => {
        const topicStats = {};
        
        AppState.questions.forEach((q, i) => {
            const topic = q.topic;
            if (!topicStats[topic]) topicStats[topic] = { correct: 0, total: 0 };
            
            topicStats[topic].total++;
            if (Exam.checkCorrectness(q, AppState.answers[i])) {
                topicStats[topic].correct++;
            }
        });

        const resultsDiv = document.getElementById('results-screen');
        const oldDetails = document.getElementById('topic-details');
        if (oldDetails) oldDetails.remove();

        const detailsContainer = document.createElement('div');
        detailsContainer.id = 'topic-details';
        detailsContainer.style.cssText = 'text-align:left; margin-top:20px; background:#f8fafc; padding:15px; border-radius:6px; max-width:500px; margin:20px auto;';
        
        let html = '<h3>📊 Rendimiento por Tema</h3>';
        
        Object.keys(topicStats).sort().forEach(topic => {
            const stat = topicStats[topic];
            const percent = Math.round((stat.correct / stat.total) * 100);
            const color = percent >= 70 ? 'var(--success)' : (percent >= 50 ? 'var(--warning)' : 'var(--danger)');
            
            html += `
                <div style="display:flex; justify-content:space-between; margin:5px 0; align-items:center; font-size:0.9rem;">
                    <span style="width:80px;">Tema ${topic}</span>
                    <div style="flex:1; background:#e2e8f0; height:8px; border-radius:4px; margin:0 10px; overflow:hidden;">
                        <div style="width:${percent}%; background:${color}; height:100%;"></div>
                    </div>
                    <span style="width:40px; text-align:right; font-weight:bold; color:${color};">${percent}%</span>
                </div>
            `;
        });

        detailsContainer.innerHTML = html;
        resultsDiv.appendChild(detailsContainer);
    }
};
