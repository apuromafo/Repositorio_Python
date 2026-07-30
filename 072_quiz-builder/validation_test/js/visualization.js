// js/visualization.js

const Visualization = {
    // Contenedor donde se pintará
    containerId: 'stats-viz-container',

    renderRadar: (containerId, topicStats) => {
        const container = document.getElementById(containerId);
        if (!container) return;
        container.innerHTML = ''; // Limpiar

        const topics = Object.keys(topicStats).sort();
        const labels = topics.map(t => `T${t}`);
        const data = topics.map(t => {
            const s = topicStats[t];
            return s.total > 0 ? Math.round((s.correct / s.total) * 100) : 0;
        });

        // Crear gráfico simple con Canvas (Implementación básica)
        const canvas = document.createElement('canvas');
        canvas.width = 300;
        canvas.height = 300;
        container.appendChild(canvas);
        
        // Dibujar (Lógica simplificada de un gráfico de barras circulares/radar)
        // Para un radar real necesitaríamos matemáticas trigonométricas.
        // Vamos a hacer una "Tarjeta de Rendimiento" visual tipo barra.
        
        let html = '<div style="text-align:left; padding: 10px;">';
        topics.forEach((t, i) => {
            const percent = data[i];
            const color = percent >= 70 ? 'var(--success)' : (percent >= 40 ? 'var(--warning)' : 'var(--danger)');
            html += `
                <div style="margin-bottom: 8px;">
                    <div style="display:flex; justify-content:space-between; font-size:0.8rem;">
                        <span>Tema ${t}</span>
                        <span>${percent}%</span>
                    </div>
                    <div style="background:#e2e8f0; height:6px; border-radius:3px; width:100%;">
                        <div style="background:${color}; height:100%; width:${percent}%; border-radius:3px; transition:width 0.5s;"></div>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        
        // Si queremos un Radar de verdad, descomentamos esto y usamos librería Chart.js,
        // pero para mantenerlo modular sin deps, usamos el HTML generado:
        container.innerHTML = html;
    }
};
