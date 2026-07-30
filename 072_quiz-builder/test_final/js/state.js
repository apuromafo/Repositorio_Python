// Estado global y configuración de la aplicación

const AppState = {
    examId: 'test_final', // Identificador único para este examen
    title: 'Test Final', // Título para mostrar
    currentUser: null, // Se asigna en Storage.initUser()

    // --- CONFIGURACIÓN DE TEMAS (Modificar aquí para otros exámenes) ---
    // Pesos para el modo Examen (Tema: Cantidad de preguntas)
    // Total preguntas: 60
    examTopics: {
        'mod_a': 2,
        'mod_b': 1
},

    // Nombres descriptivos para los selectores
    topicNames: {
        'mod_a': 'mod_a - Modulo A',
        'mod_b': 'mod_b - Modulo B'
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
