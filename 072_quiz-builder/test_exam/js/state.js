// Estado global y configuración de la aplicación

const AppState = {
    examId: 'test_exam', // Identificador único para este examen
    title: 'Examen de Prueba', // Título para mostrar
    currentUser: null, // Se asigna en Storage.initUser()

    // --- CONFIGURACIÓN DE TEMAS (Modificar aquí para otros exámenes) ---
    // Pesos para el modo Examen (Tema: Cantidad de preguntas)
    // Total preguntas: 60
    examTopics: {
        'tema1': 3,
        'tema2': 2
},

    // Nombres descriptivos para los selectores
    topicNames: {
        'tema1': 'tema1 - Tema Uno',
        'tema2': 'tema2 - Tema Dos'
},
    // -----------------------------------------------------------------

    mode: null, // 'exam' or 'study' or 'adaptive'
    questions: [],
    answers: {}, // { index: answer }
    flags: [], // [indexes]
    currentIndex: 0,
    timerInterval: null,
    timeRemaining: 3600, // seconds
    active: false,
    lastMistakes: [],
    selectedTopic: null,

    // --- CONFIGURACIÓN PARA EXPORTACIÓN PDF ---
    pdfExport: {
        modalVisible: false,
        mode: 'practice', // 'practice', 'study', 'official'
        selectedTopics: [], // Array de temas seleccionados
        includeExplanations: false,
        includeIds: false,
        randomize: false
    }
};
