// js/profile.js

const Profile = {
    show: () => {
        // Crear modal si no existe
        let modal = document.getElementById('profile-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'profile-modal';
            modal.className = 'modal';
            modal.innerHTML = `
                <div class="modal-content" style="max-width: 600px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <h3>📊 Mi Progreso</h3>
                        <button class="btn btn-secondary" onclick="Profile.hide()">✖</button>
                    </div>
                    <div id="profile-content" style="margin-top:20px;"></div>
                </div>
            `;
            document.body.appendChild(modal);
        }
        
        modal.style.display = 'flex';
        Profile.renderContent();
    },

    hide: () => {
        document.getElementById('profile-modal').style.display = 'none';
    },

    renderContent: () => {
        const history = JSON.parse(localStorage.getItem(`${Storage._prefix()}${AppState.examId}_history`) || '[]');
        const content = document.getElementById('profile-content');
        
        // Cálculos
        const scores = history.map(h => h.score);
        const avg = scores.length > 0 ? Math.round(scores.reduce((a,b)=>a+b,0) / scores.length) : 0;
        const max = scores.length > 0 ? Math.max(...scores) : 0;
        const min = scores.length > 0 ? Math.min(...scores) : 0;

        // Stats Cards
        let html = `
            <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:10px; margin-bottom:20px;">
                <div class="stat-box" style="padding:15px;">
                    <span style="font-size:0.8rem; color:#64748b;">Mejor Nota</span>
                    <span class="stat-num" style="color:var(--success); font-size:1.5rem;">${max}%</span>
                </div>
                <div class="stat-box" style="padding:15px;">
                    <span style="font-size:0.8rem; color:#64748b;">Media</span>
                    <span class="stat-num" style="color:var(--primary); font-size:1.5rem;">${avg}%</span>
                </div>
                <div class="stat-box" style="padding:15px;">
                    <span style="font-size:0.8rem; color:#64748b;">Peor Nota</span>
                    <span class="stat-num" style="color:var(--danger); font-size:1.5rem;">${min}%</span>
                </div>
            </div>
            <div style="margin-top:20px;">
                <h4>🎯 Heatmap de Temas (Nivel de acierto)</h4>
                <div id="stats-viz-container"></div>
            </div>
            
            <! Sección de peligro -->
            <div style="margin-top:30px; padding-top:15px; border-top:1px solid var(--border); text-align:center;">
                <button class="btn btn-danger" onclick="Profile.clearAllData()" style="font-size:0.85rem;">
                    🗑️ Borrar Historial y Estadísticas
                </button>
                <p style="font-size:0.75rem; color:#94a3b8; margin-top:5px;">Esto eliminará tu historial de notas y errores guardados.</p>
            </div>
	`;

        content.innerHTML = html;

        // Renderizar gráfico
        Visualization.renderRadar('stats-viz-container', Analytics.getTopicStats());
    },

    // Función para borrar datos
    clearAllData: () => {
        if(confirm("¿Estás seguro? Se borrarán tu historial de notas, tus estadísticas de aprendizaje y tu lista de fallos guardados.")) {
            localStorage.removeItem(`${AppState.examId}_history`);
            localStorage.removeItem(`${AppState.examId}_analytics_data`);
            localStorage.removeItem(`${AppState.examId}_mistakes_history`);
            // No borramos _progress para no romper el examen actual si está en curso, pero sí al recargar
            
            alert("Datos borrados correctamente.");
            Profile.hide();
            location.reload(); // Recargar para refrescar la interfaz
	}
    }
};
