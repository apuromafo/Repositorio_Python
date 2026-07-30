#!/usr/bin/env python3
"""
Quiz Builder — Genera un examen completo en 2 minutos.
Uso: python generar.py
"""

import os, json, shutil, re
from datetime import datetime

TEMPLATE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(TEMPLATE_DIR, 'examenes.json')

def preguntar(texto, default=''):
    r = input(f'{texto} [{default}]: ').strip()
    return r if r else default

def main():
    print('''
╔══════════════════════════════════════╗
║        Quiz Builder v1.0              ║
║  Genera un examen completo y listo    ║
╚══════════════════════════════════════╝
''')

    tipo = preguntar('Tipo (quiz/likert)', 'quiz')
    passing = preguntar('Nota de aprobacion (0-100, Enter=50)', '50')
    ranges_raw = preguntar('Rangos de resultado (opcional, ej: "Minimo:0-4|Moderado:5-9|Severo:10-14")', '')
    result_ranges = []
    if ranges_raw:
        for part in ranges_raw.split('|'):
            m = re.match(r'([^:]+):(\d+)-(\d+)', part.strip())
            if m:
                result_ranges.append({'label': m.group(1), 'min': int(m.group(2)), 'max': int(m.group(3)), 'color': 'primary'})

    examen = {
        'id': preguntar('ID unico (ej: lpica1_101)', 'mi_examen'),
        'titulo': preguntar('Titulo del examen', 'Mi Examen'),
        'tiempo': int(preguntar('Tiempo en minutos', '90')),
        'tipo': tipo,
        'passing_grade': int(passing) if passing else 50,
        'result_ranges': result_ranges,
        'temas': []
    }

    print('\n--- Temas del examen ---')
    print('Cada tema tiene: id, nombre, cantidad de preguntas en modo examen')
    while True:
        tema_id = preguntar('  ID del tema (o Enter para terminar)', '')
        if not tema_id: break
        tema_nombre = preguntar('  Nombre del tema', f'Tema {tema_id}')
        tema_peso = int(preguntar('  Preguntas en modo examen', '10'))
        examen['temas'].append({
            'id': tema_id,
            'nombre': tema_nombre,
            'peso': tema_peso
        })
        print()

    total_peso = sum(t['peso'] for t in examen['temas'])
    print(f'Total preguntas modo examen: {total_peso}')

    # Crear directorio
    dir_examen = os.path.join(TEMPLATE_DIR, examen['id'])
    if os.path.exists(dir_examen):
        if input(f'\nYa existe {examen["id"]}. Sobrescribir? (s/n): ').lower() != 's':
            print('Cancelado'); return
        shutil.rmtree(dir_examen)

    # Copiar template
    template = os.path.join(TEMPLATE_DIR, 'template')
    shutil.copytree(template, dir_examen)
    print(f'\n  Template copiado a {examen["id"]}/')

    # Generar state.js
    topic_names = {t['id']: f"{t['id']} - {t['nombre']}" for t in examen['temas']}
    topic_weights = {t['id']: t['peso'] for t in examen['temas']}

    state_path = os.path.join(dir_examen, 'js', 'state.js')
    with open(state_path, 'r', encoding='utf-8') as f:
        state_js = f.read()

    state_js = re.sub(r"examId:\s*'[^']*'", f"examId: '{examen['id']}'", state_js)
    state_js = re.sub(r"title:\s*'[^']*'", f"title: '{examen['titulo']}'", state_js)
    state_js = re.sub(r"timeRemaining:\s*\d+(?:\s*\*\s*\d+)?", f"timeRemaining: {examen['tiempo'] * 60}", state_js)

    # Replace examTopics object
    wt = json.dumps(topic_weights, indent=8).replace('"', "'")
    state_js = re.sub(
        r'examTopics:\s*\{[^}]+\}',
        f'examTopics: {wt}',
        state_js, flags=re.DOTALL
    )

    # Replace topicNames object
    tn = json.dumps(topic_names, indent=8).replace('"', "'")
    state_js = re.sub(
        r'topicNames:\s*\{[^}]+\}',
        f'topicNames: {tn}',
        state_js, flags=re.DOTALL
    )

    with open(state_path, 'w', encoding='utf-8') as f:
        f.write(state_js)

    # Generar index.html
    html_path = os.path.join(dir_examen, 'index.html')
    with open(html_path, 'r', encoding='utf-8') as f:
        html = f.read()
    html = html.replace('{NOMBRE_EXAMEN}', examen['titulo'])
    html = html.replace('{TIEMPO}', str(examen['tiempo']))

    # Fill exam config
    cfg_json = json.dumps({'tipo': tipo, 'passing_grade': int(passing) if passing else 50, 'result_ranges': result_ranges})
    html = html.replace("var _examConfig = { tipo: 'quiz', passing_grade: 50, result_ranges: [] };", f'var _examConfig = {cfg_json};')

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)

    # Generar preguntas.js con preguntas placeholder por cada tema
    preguntas_path = os.path.join(dir_examen, 'preguntas.js')
    with open(preguntas_path, 'r', encoding='utf-8') as f:
        preg = f.read()

    preg = preg.replace('{ID_EXAMEN}', examen['id'])
    preg = preg.replace('{NOMBRE_EXAMEN}', examen['titulo'])

    topic_blocks = '\n'.join([f'// TEMA {t["id"]}: {t["nombre"]}' for t in examen['temas']])
    preg = preg.replace('// {TEMAS}', topic_blocks)

    # Generate placeholder questions per topic
    lines = []
    qid = 1
    for t in examen['temas']:
        lines.append(f'\n    // --- {t["id"]}: {t["nombre"]} ---')
        for i in range(t['peso']):
            enun = f"Pregunta {i+1} del tema {t['id']} — reemplaza este texto por la pregunta real."
            opts = [f"Respuesta A para pregunta {qid}", f"Respuesta B para pregunta {qid}", f"Respuesta C para pregunta {qid}", f"Respuesta D para pregunta {qid}"]
            is_multi = (i % 5 == 0)
            is_input = (i % 7 == 0 and i > 0)
            q = f'    {{\n        id: {qid},\n        topic: "{t["id"]}",\n'
            if is_input:
                q += f'        type: "input",\n        question: "{enun}",\n        answer: ["Respuesta modelo 1", "Respuesta modelo 2"],\n        explanation: "Reemplaza esta explicacion."\n    }},'
            else:
                q += f'        question: "{enun}",\n        options: [{", ".join(f'"{o}"' for o in opts)}],\n'
                if is_multi:
                    q += f'        answer: [0, 2],\n'
                else:
                    q += f'        answer: 0,\n'
                q += f'        explanation: "Reemplaza esta explicacion."\n    }},'
            lines.append(q)
            qid += 1

    preg = preg.replace('const questionBank = [', 'const questionBank = [\n' + '\n'.join(lines) + '\n')

    with open(preguntas_path, 'w', encoding='utf-8') as f:
        f.write(preg)

    # Registrar en examenes.json
    examenes = []
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            examenes = json.load(f)

    entry = {
        'id': examen['id'],
        'titulo': examen['titulo'],
        'tiempo': examen['tiempo'],
        'tipo': tipo,
        'temas': examen['temas'],
        'creado': datetime.now().strftime('%Y-%m-%d %H:%M')
    }
    if tipo == 'likert':
        entry['result_ranges'] = result_ranges
    if passing:
        entry['passing_grade'] = int(passing) if passing else 50
    examenes.append(entry)

    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(examenes, f, indent=2, ensure_ascii=False)

    print(f'''
╔══════════════════════════════════════╗
║  EXAMEN CREADO                        ║
║  {examen["id"]:<35s} ║
║  Tiempo: {examen["tiempo"]} min                      ║''')
    for t in examen['temas']:
        print(f'║  {t["id"]:>8s}: {t["peso"]:2d} preg  {t["nombre"]:<20s} ║')
    print(f'''║                                       ║
║  Edita:  {examen["id"]}/preguntas.js  ║
║  Abre:   {examen["id"]}/editor.html     ║
╚══════════════════════════════════════╝
''')

if __name__ == '__main__':
    main()
