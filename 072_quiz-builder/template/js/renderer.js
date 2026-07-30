const Renderer = {
    loadQuestion: (index) => {

	if (typeof Solution !== 'undefined') {
	    Solution.visible = false;

	    const btn = document.getElementById('btn-solution');
	    if (btn) {
	        btn.innerText = '💡 Ver Solución';
	        btn.classList.remove('active');
	    }
	}

	AppState.currentIndex = index;
        const q = AppState.questions[index];
        
        const total = AppState.questions.length;
        document.getElementById('q-counter').innerText = `Pregunta ${index + 1} de ${total}`;
        document.getElementById('q-topic-display').innerText = q.topic;
        //document.getElementById('q-text').innerHTML = q.question;
	document.getElementById('q-text').innerHTML = q.question
	    .replace(/\n/g, '<br>')
	    .replace(/\t/g, '&nbsp;&nbsp;&nbsp;&nbsp;');
        
        const imgEl = document.getElementById('q-image');
        if (q.image) {
            imgEl.src = q.image;
            imgEl.style.display = 'block';
        } else {
            imgEl.style.display = 'none';
        }

        Renderer.renderOptions(q);
        Navigation.updateHighlight();
        Storage.saveProgress();
    },

    renderOptions: (q) => {
        const container = document.getElementById('options-container');
        container.innerHTML = '';
        
        const isMultiple = Array.isArray(q.answer);
        const isInput = q.type === 'input';
        const currentAns = AppState.answers[AppState.currentIndex];
        const letters = ['A', 'B', 'C', 'D', 'E'];

        // Normalizamos las respuestas correctas a un array para facilitar comprobación
        const correctAnswers = isMultiple ? q.answer : (isInput ? [q.answer[0]] : [q.answer]);

        if (isInput) {
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'text-input';
            input.placeholder = 'Escribe la respuesta...';
            input.value = currentAns || '';
            
            // Si mostramos solución, marcamos el input
            if (Solution.isActive()) {
                input.disabled = true; // Bloqueamos input al mostrar solución
                if (correctAnswers[0]) {
                    input.value = correctAnswers[0];
                    input.style.borderColor = 'var(--success)';
                    input.style.color = 'var(--success)';
                    input.style.fontWeight = 'bold';
                }
            } else {
                input.oninput = (e) => {
                    AppState.answers[AppState.currentIndex] = e.target.value;
                    Navigation.updateStats();
                    Navigation.updateHighlight();
                    Storage.saveProgress();
                };
            }
            container.appendChild(input);
        } else {
            q.options.forEach((opt, i) => {
                const label = document.createElement('label');
                label.className = 'option-label';
                
                let isSelected = false;
                if (isMultiple) {
                    if (Array.isArray(currentAns) && currentAns.includes(i)) isSelected = true;
                } else {
                    if (currentAns === i) isSelected = true;
                }
                if (isSelected) label.classList.add('selected');

                // Lógica de "Ver Solución"
                if (Solution.isActive()) {
                    if (correctAnswers.includes(i)) {
                        label.classList.add('solution-correct');
                    } else if (isSelected) {
                        // Si la seleccionó pero es incorrecta
                        label.classList.add('solution-incorrect');
                    }
                    // Bloqueamos interacción
                    label.style.pointerEvents = 'none';
                }

                const marker = document.createElement('div');
                marker.className = 'option-marker';
                marker.innerText = letters[i];
                
                const text = document.createElement('div');
                text.className = 'option-text';
                text.innerText = opt;

                const input = document.createElement('input');
                input.style.display = 'none';
                input.type = isMultiple ? 'checkbox' : 'radio';
                input.name = 'opt';
                input.checked = isSelected;
                
                input.onchange = () => {
                    if (isMultiple) {
                        const limit = q.answer.length;
                        const currentSelected = AppState.answers[AppState.currentIndex] || [];
                        
                        if (input.checked) {
                            if (currentSelected.length < limit) {
                                if (!AppState.answers[AppState.currentIndex]) AppState.answers[AppState.currentIndex] = [];
                                AppState.answers[AppState.currentIndex].push(i);
                            } else {
                                input.checked = false;
                                return;
                            }
                        } else {
                            AppState.answers[AppState.currentIndex] = currentSelected.filter(v => v !== i);
                        }
                    } else {
                        AppState.answers[AppState.currentIndex] = i;
                    }
                    Renderer.renderOptions(q); 
                    Navigation.updateStats();
                    Navigation.updateHighlight();
                    Storage.saveProgress();
                };

                label.appendChild(input);
                label.appendChild(marker);
                label.appendChild(text);
                container.appendChild(label);
            });
        }

        // Renderizar explicación si está activa
        if (Solution.isActive()) {
            const explanationDiv = document.createElement('div');
            explanationDiv.className = 'explanation-box';
            explanationDiv.innerHTML = `<strong>Explicación:</strong> ${q.explanation || 'No hay explicación disponible.'}`;
            container.appendChild(explanationDiv);
        }
    }
};
