// ============================================================
// PREGUNTAS — Test Final
// ============================================================
// ID: test_final
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

// TEMA mod_a: Modulo A
// TEMA mod_b: Modulo B

const questionBank = [

    // --- mod_a: Modulo A ---
    {
        id: 1,
        topic: "mod_a",
        question: "Pregunta 1 del tema mod_a -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 1", "Respuesta B para pregunta 1", "Respuesta C para pregunta 1", "Respuesta D para pregunta 1"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },
    {
        id: 2,
        topic: "mod_a",
        question: "Pregunta 2 del tema mod_a -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 2", "Respuesta B para pregunta 2", "Respuesta C para pregunta 2", "Respuesta D para pregunta 2"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },

    // --- mod_b: Modulo B ---
    {
        id: 3,
        topic: "mod_b",
        question: "Pregunta 1 del tema mod_b -- reemplaza este texto.",
        options: ["Respuesta A para pregunta 3", "Respuesta B para pregunta 3", "Respuesta C para pregunta 3", "Respuesta D para pregunta 3"],
        answer: 0,
        explanation: "Reemplaza esta explicacion."
    },

];
