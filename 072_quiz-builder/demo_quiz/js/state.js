// Estado global y configuración de la aplicación

const AppState = {
    examId: 'demo_quiz', // Identificador único para este examen
    title: 'Demo Quiz Builder', // Título para mostrar
    currentUser: null, // Se asigna en Storage.initUser()

    // --- CONFIGURACIÓN DE TEMAS (Modificar aquí para otros exámenes) ---
    // Pesos para el modo Examen (Tema: Cantidad de preguntas)
    // Total preguntas: 60
    examTopics: {
        'dummy1': 3,
        'dummy2': 3,
        'dummy3': 4
},

    // Nombres descriptivos para los selectores
    topicNames: {
        'dummy1': 'dummy1 - Dummy Topic One',
        'dummy2': 'dummy2 - Dummy Topic Two',
        'dummy3': 'dummy3 - Dummy Topic Three'
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
