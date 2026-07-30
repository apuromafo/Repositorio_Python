// ============================================================
// PREGUNTAS — Examen de Prueba
// ============================================================
// ID: test_exam
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

// TEMA tema1: Tema Uno
// TEMA tema2: Tema Dos

const questionBank = [

    // --- tema1: Tema Uno ---
    {
        id: 1,
        topic: "tema1",
        question: "Pregunta 1 del tema tema1 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 1", "Respuesta B para pregunta 1", "Respuesta C para pregunta 1", "Respuesta D para pregunta 1"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 2,
        topic: "tema1",
        question: "Pregunta 2 del tema tema1 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 2", "Respuesta B para pregunta 2", "Respuesta C para pregunta 2", "Respuesta D para pregunta 2"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 3,
        topic: "tema1",
        question: "Pregunta 3 del tema tema1 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 3", "Respuesta B para pregunta 3", "Respuesta C para pregunta 3", "Respuesta D para pregunta 3"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },

    // --- tema2: Tema Dos ---
    {
        id: 4,
        topic: "tema2",
        question: "Pregunta 1 del tema tema2 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 4", "Respuesta B para pregunta 4", "Respuesta C para pregunta 4", "Respuesta D para pregunta 4"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 5,
        topic: "tema2",
        question: "Pregunta 2 del tema tema2 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 5", "Respuesta B para pregunta 5", "Respuesta C para pregunta 5", "Respuesta D para pregunta 5"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },

];
