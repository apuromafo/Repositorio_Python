// ============================================================
// PREGUNTAS — Validation Test
// ============================================================
// ID: validation_test
//
// Formato de cada pregunta:
//   {
//     id:        1,
//     topic:     "Tema1",
//     type:      "input",                // omitir si es choice/multi
//     question:  "Texto pregunta?",
//     options:   ["A", "B", "C", "D"],
//     answer:    2,                      // indice (0-based) o array [1,3] para multi
//     image:     "ruta/a/imagen.jpg",   // opcional
//     explanation: "Explicacion..."
//   }

// TEMA topic_1: Topic One
// TEMA topic_2: Topic Two

const questionBank = [

    // --- topic_1: Topic One ---
    {
        id: 1,
        topic: "topic_1",
        question: "Pregunta 1 del tema topic_1 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 1", "Respuesta B para pregunta 1", "Respuesta C para pregunta 1", "Respuesta D para pregunta 1"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 2,
        topic: "topic_1",
        question: "Pregunta 2 del tema topic_1 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 2", "Respuesta B para pregunta 2", "Respuesta C para pregunta 2", "Respuesta D para pregunta 2"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },

    // --- topic_2: Topic Two ---
    {
        id: 3,
        topic: "topic_2",
        question: "Pregunta 1 del tema topic_2 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 3", "Respuesta B para pregunta 3", "Respuesta C para pregunta 3", "Respuesta D para pregunta 3"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 4,
        topic: "topic_2",
        question: "Pregunta 2 del tema topic_2 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 4", "Respuesta B para pregunta 4", "Respuesta C para pregunta 4", "Respuesta D para pregunta 4"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },

];
