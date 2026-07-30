// Estado global y configuración de la aplicación

const AppState = {
    examId: 'validation_test', // Identificador único para este examen
    title: 'Validation Test', // Título para mostrar
    currentUser: null, // Se asigna en Storage.initUser()

    // --- CONFIGURACIÓN DE TEMAS (Modificar aquí para otros exámenes) ---
    // Pesos para el modo Examen (Tema: Cantidad de preguntas)
    // Total preguntas: 60
    examTopics: {
        'topic_1': 2,
        'topic_2': 2
},

    // Nombres descriptivos para los selectores
    topicNames: {
        'topic_1': 'topic_1 - Topic One',
        'topic_2': 'topic_2 - Topic Two'
},
    // -----------------------------------------------------------------

    mode: null, // 'exam' or 'study' or 'adaptive'
    questions: [],
    answers: {}, // { index: answer }
    flags: [], // [indexes]
    currentIndex: 0,
    timerInterval: null,
    timeRemaining: 2700, // seconds
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
