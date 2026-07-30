const Timer = {
    start: () => {
        clearInterval(AppState.timerInterval);
        Timer.updateDisplay();
        AppState.timerInterval = setInterval(() => {
            AppState.timeRemaining--;
            Timer.updateDisplay();
            Storage.saveProgress();
            if (AppState.timeRemaining <= 0) {
                clearInterval(AppState.timerInterval);
                alert("¡Tiempo agotado!");
                Exam.finish();
            }
        }, 1000);
    },

    updateDisplay: () => {
        const m = Math.floor(AppState.timeRemaining / 60);
        const s = AppState.timeRemaining % 60;
        const el = document.getElementById('timer-display');
        el.innerText = `${m}:${s < 10 ? '0' : ''}${s}`;
        if (AppState.timeRemaining < 300) el.classList.add('warning'); 
        else el.classList.remove('warning');
    }
};
