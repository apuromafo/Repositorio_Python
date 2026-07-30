// Estado global y configuración de la aplicación

const AppState = {
    examId: 'humo_test', // Identificador único para este examen
    title: 'Smoke Test', // Título para mostrar
    currentUser: null, // Se asigna en Storage.initUser()

    // --- CONFIGURACIÓN DE TEMAS (Modificar aquí para otros exámenes) ---
    // Pesos para el modo Examen (Tema: Cantidad de preguntas)
    // Total preguntas: 60
    examTopics: {
        'mod1': 4,
        'mod2': 3,
        'mod3': 2
},

    // Nombres descriptivos para los selectores
    topicNames: {
        'mod1': 'mod1 - Modulo 1',
        'mod2': 'mod2 - Modulo 2',
        'mod3': 'mod3 - Modulo 3'
},
    // -----------------------------------------------------------------

    mode: null, // 'exam' or 'study' or 'adaptive'
    questions: [],
    answers: {}, // { index: answer }
    flags: [], // [indexes]
    currentIndex: 0,
    timerInterval: null,
    timeRemaining: 1800, // seconds
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
