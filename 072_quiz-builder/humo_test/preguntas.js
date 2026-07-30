// ============================================================
// PREGUNTAS — Smoke Test
// ============================================================
// ID: humo_test
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

// TEMA mod1: Modulo 1
// TEMA mod2: Modulo 2
// TEMA mod3: Modulo 3

const questionBank = [

    // --- mod1: Modulo 1 ---
    {
        id: 1,
        topic: "mod1",
        question: "Pregunta 1 del tema mod1 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 1", "Respuesta B para pregunta 1", "Respuesta C para pregunta 1", "Respuesta D para pregunta 1"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 2,
        topic: "mod1",
        question: "Pregunta 2 del tema mod1 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 2", "Respuesta B para pregunta 2", "Respuesta C para pregunta 2", "Respuesta D para pregunta 2"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 3,
        topic: "mod1",
        question: "Pregunta 3 del tema mod1 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 3", "Respuesta B para pregunta 3", "Respuesta C para pregunta 3", "Respuesta D para pregunta 3"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 4,
        topic: "mod1",
        question: "Pregunta 4 del tema mod1 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 4", "Respuesta B para pregunta 4", "Respuesta C para pregunta 4", "Respuesta D para pregunta 4"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },

    // --- mod2: Modulo 2 ---
    {
        id: 5,
        topic: "mod2",
        question: "Pregunta 1 del tema mod2 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 5", "Respuesta B para pregunta 5", "Respuesta C para pregunta 5", "Respuesta D para pregunta 5"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 6,
        topic: "mod2",
        question: "Pregunta 2 del tema mod2 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 6", "Respuesta B para pregunta 6", "Respuesta C para pregunta 6", "Respuesta D para pregunta 6"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 7,
        topic: "mod2",
        question: "Pregunta 3 del tema mod2 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 7", "Respuesta B para pregunta 7", "Respuesta C para pregunta 7", "Respuesta D para pregunta 7"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },

    // --- mod3: Modulo 3 ---
    {
        id: 8,
        topic: "mod3",
        question: "Pregunta 1 del tema mod3 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 8", "Respuesta B para pregunta 8", "Respuesta C para pregunta 8", "Respuesta D para pregunta 8"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 9,
        topic: "mod3",
        question: "Pregunta 2 del tema mod3 -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 9", "Respuesta B para pregunta 9", "Respuesta C para pregunta 9", "Respuesta D para pregunta 9"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },

];
