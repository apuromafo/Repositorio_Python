// Estado global y configuración de la aplicación

const AppState = {
    examId: 'lpic1_101', // Identificador único para este examen
    title: 'LPIC-1 Exam 101', // Título para mostrar
    currentUser: null, // Se asigna en Storage.initUser()

    // --- CONFIGURACIÓN DE TEMAS (Modificar aquí para otros exámenes) ---
    // Pesos para el modo Examen (Tema: Cantidad de preguntas)
    // Total preguntas: 60
    examTopics: {
        "101": 8,
        "102": 12,
        "103": 26,
        "104": 14
    },

    // Nombres descriptivos para los selectores
    topicNames: {
        "101": "101 - Arquitectura Sistema",
        "102": "102 - Instalación y Paquetes",
        "103": "103 - Comandos GNU/Unix",
        "104": "104 - Dispositivos y FHS"
    },
    // -----------------------------------------------------------------

    mode: null, // 'exam' or 'study' or 'adaptive'
    questions: [],
    answers: {}, // { index: answer }
    flags: [], // [indexes]
    currentIndex: 0,
    timerInterval: null,
    timeRemaining: 90 * 60, // seconds
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
