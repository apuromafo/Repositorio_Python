#!/usr/bin/env python3
"""
Quiz Builder - CLI para gestionar preguntas
Uso: python preguntas.py [-lang es|en] [-e EXAM|--all] <comando> [opciones]

Comandos:
  list [tema]       Listar preguntas (opcional: filtrar por tema)
  show <id>         Mostrar detalle de una pregunta
  add               Agregar pregunta (interactivo)
  edit <id>         Editar pregunta
  delete <id>       Eliminar pregunta
  count             Total de preguntas y por tema
  validate          Validar estructura y referencias de preguntas
  export <archivo>  Exportar a JSON
  import <archivo>  Importar desde JSON
  exams             Listar examenes registrados
  reindex           Renumerar IDs secuencialmente
  doctor            Escanear todos los examenes en busca de problemas
  search <texto>    Buscar texto en preguntas de todos los examenes
  stats             Estadisticas globales
  backup            Crear respaldo de preguntas.js
  help              Esta ayuda

Flags globales:
  -e, --exam <id>   ID del examen (omitir para seleccion interactiva)
  --all             Ejecutar comando en todos los examenes
  --json            Salida en JSON (para scripting)
  --fix             Auto-corregir errores (validate)
  -lang es|en       Idioma (defecto: es)
"""

import os, sys, re, json, argparse, shutil
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))

LANG = {
    'es': {
        'no_exam_list': 'No hay examenes registrados.',
        'no_exam_json': 'No hay examenes.json. Ejecuta "python generar.py" primero.',
        'no_exams': 'No hay examenes.',
        'select_exam': 'Selecciona numero (Enter = 1)',
        'invalid_num': 'Numero invalido',
        'no_questions': 'No hay preguntas.',
        'no_q_topic': 'No hay preguntas del tema "{t}".',
        'no_q_id': 'No se encuentra ID {qid}',
        'q_saved': '{n} preguntas guardadas en {f}',
        'q_exported': '{n} preguntas exportadas a {f}',
        'q_imported': '{n} preguntas importadas.',
        'total': 'Total: {n} preguntas',
        'id': 'ID',
        'type': 'Tipo',
        'topic': 'Tema',
        'question': 'Pregunta',
        'image': 'Imagen',
        'options': 'Opciones',
        'answer': 'Respuesta',
        'explanation': 'Explicacion',
        'no_answer': 'Debes ingresar al menos una respuesta.',
        'min_opts': 'Minimo 2 opciones.',
        'enter_keep': '(Enter para mantener valor actual)',
        'unknown_cmd': 'Comando desconocido: {cmd}',
        'new_q': '--- Nueva pregunta #{n} ---',
        'topics_avail': 'Temas: {t}',
        'q_type': 'Tipo de pregunta:',
        'q_type_1': '  1. Multiple choice (respuesta unica)',
        'q_type_2': '  2. Multiple choice (multiples respuestas)',
        'q_type_3': '  3. Texto libre (input)',
        'q_type_prompt': 'Opcion (1)',
        'statement': 'Enunciado',
        'answers_pipe': 'Respuesta(s) separadas por |',
        'opts_enter': 'Opciones (Enter para terminar):',
        'correct_idx': 'Indice de respuesta correcta (0-{max})',
        'multi_comma': 'Multiples separados por coma (ej: 1,3)',
        'idx_prompt': 'Indice',
        'opt_img': 'Ruta de imagen (opcional)',
        'opt_exp': 'Explicacion (opcional)',
        'new_opts_pipe': 'Nuevas opciones separadas por | (Enter mantener)',
        'validate_title': 'Validacion de "{id}" ({title})',
        'validate_qs': 'Preguntas: {n}',
        'validate_topics': 'Temas configurados: {n}',
        'validate_warn_empty': 'No hay preguntas en el banco.',
        'validate_err_dup': 'ID duplicado: {qid}',
        'validate_err_empty': '#{qid}: enunciado vacio',
        'validate_err_no_topic': '#{qid}: sin topic',
        'validate_warn_topic': '#{qid}: tema "{t}" no definido en state.js',
        'validate_warn_img': '#{qid}: imagen no encontrada: {img}',
        'validate_err_no_ans': '#{qid}: pregunta input sin respuestas',
        'validate_err_few_opts': '#{qid}: menos de 2 opciones ({n})',
        'validate_err_no_ans_field': '#{qid}: sin answer',
        'validate_err_idx_range': '#{qid}: answer index {idx} fuera de rango (0-{max})',
        'validate_ok': 'Sin errores',
        'validate_err_count': '{n} errores',
        'exams_header': '{id:<20s} {titulo:<25s} {tiempo:<8s} {temas:<6s} {creado:<20s}',
        'exams_sep': '-' * 80,
        'exams_total': '{n} examenes, {q} preguntas en total',
        'del_confirm': 'Eliminar #{qid} "{txt}"? (s/n)',
        'del_cancel': 'Cancelado.',
        'file_not_found': 'No se encuentra: {f}',
        'topic_required': 'Tema requerido.',
        'file_err': 'Error al leer {f}',
        'doctor_title': '=== ESCANEO DOCTOR ===',
        'doctor_ok': '  [OK] {id}: OK',
        'doctor_missing_dir': '  [ERR] {id}: directorio faltante',
        'doctor_missing_js': '  [ERR] {id}: preguntas.js faltante',
        'doctor_parse_err': '  [ERR] {id}: error de parseo: {err}',
        'doctor_no_exam_dir': '  [WARN] {id}: no hay directorio en disco',
        'doctor_dangling': '  [WARN] {id}: en disco pero no en examenes.json',
        'doctor_total': '\n{n} examenes, {ok} OK, {errs} con errores, {dangling} huerfanos',
        'reindex_done': 'IDs re-indexados: {n} preguntas',
        'search_header': 'Resultados para "{q}":',
        'search_result': '  [{id}] #{qid} ({tema}): {txt}',
        'search_none': 'Sin resultados para "{q}".',
        'backup_done': 'Respaldo creado: {f}',
        'backup_skip': '  - {id}: sin preguntas.js',
        'stats_title': '=== ESTADISTICAS GLOBALES ===',
        'stats_exams': 'Examenes registrados: {n}',
        'stats_with_dir': 'Con directorio en disco: {n}',
        'stats_total_q': 'Total preguntas: {n}',
        'stats_avg': 'Promedio por examen: {n:.0f}',
        'stats_most': 'Examen con mas preguntas: {id} ({n})',
        'stats_least': 'Examen con menos preguntas: {id} ({n})',
        'stats_empty': 'Examenes sin preguntas: {n}',
        'stats_types': 'Preguntas por tipo:',
        'stats_type_line': '  {t}: {n}',
        'fix_dup_ids': '  [FIX] IDs duplicados reasignados',
        'fix_empty_q': '  [FIX] Preguntas vacias eliminadas: {n}',
        'fix_bad_idx': '  [FIX] Indices de answer corregidos: {n}',
        'validate_err_likert_scale': '#{qid}: scale tiene {got} valores, pero hay {expected} opciones',
        'grade_title': '=== ESTRUCTURA DE NOTA ===',
        'grade_exam_type': 'Tipo: {t}',
        'grade_likert_scale': 'Escala Likert: {min}-{max} puntos',
        'grade_ranges': 'Rangos de resultado:',
        'grade_range_line': '  {min}-{max}: {label}',
        'grade_passing': 'Nota de aprobacion: {n}%',
        'grade_weighted': 'Ponderacion por tema:',
        'grade_weight_line': '  {t}: {peso} preg ({pct}%)',
        'grade_weight_total': '  Total: {n} preguntas',
        'grade_boundaries': 'Calificacion:',
        'grade_bound_line': '  {min}-{max}%: {letra}',
        'grade_no_pass': 'Sin nota de aprobacion definida',
        'menu_grade': 'Ver estructura de nota',
    },
    'en': {
        'no_exam_list': 'No exams registered.',
        'no_exam_json': 'No examenes.json. Run "python generar.py" first.',
        'no_exams': 'No exams.',
        'select_exam': 'Select number (Enter = 1)',
        'invalid_num': 'Invalid number',
        'no_questions': 'No questions.',
        'no_q_topic': 'No questions for topic "{t}".',
        'no_q_id': 'ID {qid} not found',
        'q_saved': '{n} questions saved to {f}',
        'q_exported': '{n} questions exported to {f}',
        'q_imported': '{n} questions imported.',
        'total': 'Total: {n} questions',
        'id': 'ID',
        'type': 'Type',
        'topic': 'Topic',
        'question': 'Question',
        'image': 'Image',
        'options': 'Options',
        'answer': 'Answer',
        'explanation': 'Explanation',
        'no_answer': 'You must enter at least one answer.',
        'min_opts': 'Minimum 2 options.',
        'enter_keep': '(Enter to keep current value)',
        'unknown_cmd': 'Unknown command: {cmd}',
        'new_q': '--- New question #{n} ---',
        'topics_avail': 'Topics: {t}',
        'q_type': 'Question type:',
        'q_type_1': '  1. Multiple choice (single answer)',
        'q_type_2': '  2. Multiple choice (multiple answers)',
        'q_type_3': '  3. Free text (input)',
        'q_type_prompt': 'Option (1)',
        'statement': 'Question text',
        'answers_pipe': 'Answer(s) separated by |',
        'opts_enter': 'Options (Enter to stop):',
        'correct_idx': 'Correct answer index (0-{max})',
        'multi_comma': 'Multiple indices separated by comma (e.g. 1,3)',
        'idx_prompt': 'Index',
        'opt_img': 'Image path (optional)',
        'opt_exp': 'Explanation (optional)',
        'new_opts_pipe': 'New options separated by | (Enter to keep)',
        'validate_title': 'Validation of "{id}" ({title})',
        'validate_qs': 'Questions: {n}',
        'validate_topics': 'Configured topics: {n}',
        'validate_warn_empty': 'No questions in the bank.',
        'validate_err_dup': 'Duplicate ID: {qid}',
        'validate_err_empty': '#{qid}: empty question text',
        'validate_err_no_topic': '#{qid}: missing topic',
        'validate_warn_topic': '#{qid}: topic "{t}" not defined in state.js',
        'validate_warn_img': '#{qid}: image not found: {img}',
        'validate_err_no_ans': '#{qid}: input question has no answers',
        'validate_err_few_opts': '#{qid}: less than 2 options ({n})',
        'validate_err_no_ans_field': '#{qid}: missing answer field',
        'validate_err_idx_range': '#{qid}: answer index {idx} out of range (0-{max})',
        'validate_ok': 'No errors',
        'validate_err_count': '{n} errors',
        'exams_header': '{id:<20s} {title:<25s} {time:<8s} {topics:<6s} {created:<20s}',
        'exams_sep': '-' * 80,
        'exams_total': '{n} exams, {q} total questions',
        'del_confirm': 'Delete #{qid} "{txt}"? (y/n)',
        'del_cancel': 'Canceled.',
        'file_not_found': 'File not found: {f}',
        'topic_required': 'Topic is required.',
        'file_err': 'Error reading {f}',
        'doctor_title': '=== DOCTOR SCAN ===',
        'doctor_ok': '  [OK] {id}: OK',
        'doctor_missing_dir': '  [ERR] {id}: missing directory',
        'doctor_missing_js': '  [ERR] {id}: missing preguntas.js',
        'doctor_parse_err': '  [ERR] {id}: parse error: {err}',
        'doctor_no_exam_dir': '  [WARN] {id}: no directory on disk',
        'doctor_dangling': '  [WARN] {id}: on disk but not in examenes.json',
        'doctor_total': '\n{n} exams, {ok} OK, {errs} errors, {dangling} orphaned',
        'reindex_done': 'IDs reindexed: {n} questions',
        'search_header': 'Results for "{q}":',
        'search_result': '  [{id}] #{qid} ({tema}): {txt}',
        'search_none': 'No results for "{q}".',
        'backup_done': 'Backup created: {f}',
        'backup_skip': '  - {id}: no preguntas.js',
        'stats_title': '=== GLOBAL STATS ===',
        'stats_exams': 'Registered exams: {n}',
        'stats_with_dir': 'With directory on disk: {n}',
        'stats_total_q': 'Total questions: {n}',
        'stats_avg': 'Average per exam: {n:.0f}',
        'stats_most': 'Most questions: {id} ({n})',
        'stats_least': 'Fewest questions: {id} ({n})',
        'stats_empty': 'Exams without questions: {n}',
        'stats_types': 'Questions by type:',
        'stats_type_line': '  {t}: {n}',
        'fix_dup_ids': '  [FIX] Duplicate IDs reassigned',
        'fix_empty_q': '  [FIX] Empty questions removed: {n}',
        'fix_bad_idx': '  [FIX] Answer indices fixed: {n}',
        'validate_err_likert_scale': '#{qid}: scale has {got} values but {expected} options',
        'grade_title': '=== GRADE STRUCTURE ===',
        'grade_exam_type': 'Type: {t}',
        'grade_likert_scale': 'Likert scale: {min}-{max} points',
        'grade_ranges': 'Result ranges:',
        'grade_range_line': '  {min}-{max}: {label}',
        'grade_passing': 'Passing grade: {n}%',
        'grade_weighted': 'Topic weights:',
        'grade_weight_line': '  {t}: {peso} qs ({pct}%)',
        'grade_weight_total': '  Total: {n} questions',
        'grade_boundaries': 'Grade boundaries:',
        'grade_bound_line': '  {min}-{max}%: {letra}',
        'grade_no_pass': 'No passing grade defined',
        'menu_grade': 'Show grade structure',
    }
}

def _(lang, key, **kw):
    t = LANG.get(lang, LANG['es']).get(key, key)
    return t.format(**kw) if kw else t

def examenes():
    cfg = os.path.join(ROOT, 'examenes.json')
    if not os.path.exists(cfg):
        print(_(lang, 'no_exam_json'))
        sys.exit(1)
    with open(cfg, encoding='utf-8') as f:
        return json.load(f)

def elegir_examen(lista, lang):
    if not lista:
        print(_(lang, 'no_exams'))
        sys.exit(1)
    if len(lista) == 1:
        return lista[0]
    print()
    for i, ex in enumerate(lista):
        print(f'  {i+1}. {ex["id"]} - {ex["titulo"]}')
    while True:
        r = input(f'\n{_(lang, "select_exam")}: ').strip()
        if not r:
            return lista[0]
        try:
            return lista[int(r) - 1]
        except:
            print(_(lang, 'invalid_num'))

def preguntas_path(examen):
    d = os.path.join(ROOT, 'examenes', examen['id'])
    if os.path.isdir(d):
        return os.path.join(d, 'preguntas.js')
    return os.path.join(ROOT, examen['id'], 'preguntas.js')

def leer(path):
    if not os.path.exists(path):
        return [], [], False
    try:
        with open(path, encoding='utf-8') as f:
            src = f.read()
    except Exception as e:
        return [], [], str(e)
    m = re.search(r'(const\s+questionBank\s*=\s*)\[(.*)\]', src, re.DOTALL)
    if not m:
        return src.split('\n'), [], False
    header = src[:m.start(1)].split('\n')
    raw = m.group(2).strip()
    preguntas = _parse_objects(raw)
    return header, preguntas, False

def _parse_objects(raw):
    objs = []
    depth = 0
    buf = ''
    for ch in raw:
        if ch == '{':
            if depth > 0:
                buf += ch
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                q = _js2dict(buf.strip().rstrip(','))
                if q:
                    objs.append(q)
                buf = ''
            else:
                buf += ch
        else:
            if depth > 0:
                buf += ch
    return objs

def _js2dict(texto):
    d = {}
    texto = re.sub(r'//.*', '', texto)
    texto = texto.strip().strip(',').strip()
    if not texto:
        return d
    pares = re.findall(r'(\w+)\s*:\s*(.*?)(?=,\s*\w+\s*:|,\s*\n\s*\w+\s*:|$)', texto, re.DOTALL)
    for key, val in pares:
        key = key.strip()
        val = val.strip().rstrip(',').strip()
        if key in ('answer',):
            if val.startswith('['):
                inner = val[1:].rstrip(']').strip()
                items = [x.strip() for x in inner.split(',') if x.strip()]
                if items and items[0].startswith(('"', "'")):
                    d[key] = [x.strip('\'"') for x in items]
                elif items:
                    d[key] = [int(x) for x in items if x.lstrip('-').isdigit()]
                else:
                    d[key] = []
            else:
                try:
                    d[key] = int(val)
                except:
                    d[key] = val.strip('"\'')
        elif key in ('type',):
            d[key] = val.strip('"\'')
        elif val.startswith('"') or val.startswith("'"):
            d[key] = val[1:-1]
        elif val.startswith('['):
            inner = val[1:].rstrip(']').strip()
            d[key] = [x.strip().strip('"\'') for x in inner.split(',') if x.strip()]
        elif val.lower() == 'true':
            d[key] = True
        elif val.lower() == 'false':
            d[key] = False
        else:
            try:
                d[key] = int(val)
            except:
                d[key] = val
    return d

def _q2js(q, indent=4):
    sp = ' ' * indent
    lines = ['{']
    order = ['id', 'type', 'topic', 'question', 'image', 'options', 'answer', 'explanation']
    for key in order:
        if key not in q:
            continue
        val = q[key]
        if isinstance(val, str):
            esc = val.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            lines.append(f'{sp}{key}: "{esc}",')
        elif isinstance(val, bool):
            lines.append(f'{sp}{key}: {"true" if val else "false"},')
        elif isinstance(val, int):
            lines.append(f'{sp}{key}: {val},')
        elif isinstance(val, list):
            if key == 'answer' and all(isinstance(x, int) for x in val):
                items = ', '.join(str(x) for x in val)
                lines.append(f'{sp}{key}: [{items}],')
            else:
                esc = lambda s: s.replace('\\', '\\\\').replace('"', '\\"')
                items = ', '.join(f'"{esc(x)}"' for x in val)
                lines.append(f'{sp}{key}: [{items}],')
    lines.append('}')
    return '\n'.join(lines)

def escribir(path, header, preguntas, lang):
    body = '\n\n'.join(_q2js(q) for q in preguntas)
    h = '\n'.join(header) if isinstance(header, list) else header
    src = f'{h}\nconst questionBank = [\n{body}\n];\n'
    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)
    print(_(lang, 'q_saved', n=len(preguntas), f=os.path.basename(path)))

def _q_brief(q):
    txt = q.get('question', '?')[:55]
    ans = q.get('answer', '?')
    if isinstance(ans, list):
        ans = ','.join(str(a) for a in ans)
    n_opts = len(q.get('options', []))
    extras = []
    if q.get('image'): extras.append('img')
    if q.get('type') == 'input': extras.append('input')
    if q.get('type') == 'likert': extras.append('likert')
    tag = f' [{",".join(extras)}]' if extras else ''
    return f'  #{q["id"]:>3d}  {txt}{tag} | {n_opts} opts | ans={ans}'

# ---- COMMANDS ----

def cmd_list(examen, lang, tema=None, json_out=False):
    h, qs, err = leer(preguntas_path(examen))
    if err:
        print(f'  Error: {err}')
        return
    if not qs:
        print(_(lang, 'no_questions'))
        return
    if tema:
        qs = [q for q in qs if q.get('topic') == tema]
        if not qs:
            print(_(lang, 'no_q_topic', t=tema))
            return
    if json_out:
        print(json.dumps(qs, indent=2, ensure_ascii=False))
        return
    agrupadas = {}
    for q in qs:
        agrupadas.setdefault(q.get('topic', '?'), []).append(q)
    for t in sorted(agrupadas):
        items = agrupadas[t]
        print(f'\n  [{t}] ({len(items)})')
        for q in items:
            print(_q_brief(q))

def cmd_show(examen, lang, qid):
    h, qs, err = leer(preguntas_path(examen))
    if err:
        print(f'  Error: {err}'); return
    for q in qs:
        if q.get('id') == qid:
            print(f'\n{_(lang, "id")}:          {q.get("id")}')
            print(f'{_(lang, "type")}:        {q.get("type", "multiple")}')
            print(f'{_(lang, "topic")}:        {q.get("topic")}')
            print(f'{_(lang, "question")}:    {q.get("question")}')
            if q.get('image'):
                print(f'{_(lang, "image")}:      {q["image"]}')
            opts = q.get('options', [])
            if opts:
                print(f'{_(lang, "options")}:')
                for i, o in enumerate(opts):
                    letra = chr(65 + i)
                    print(f'  {letra}. {o}')
            if q.get('type') == 'likert':
                scale = q.get('scale', [])
                if scale:
                    print(f'  Escala: {", ".join(str(s) for s in scale)}')
            else:
                ans = q.get('answer')
                if isinstance(ans, list):
                    if q.get('type') == 'input':
                        print(f'{_(lang, "answer")}:   {", ".join(map(str, ans))}')
                    else:
                        labels = [chr(65 + a) for a in ans]
                        print(f'{_(lang, "answer")}:   {", ".join(labels)}')
                else:
                    print(f'{_(lang, "answer")}:   {chr(65 + ans) if opts else ans}')
            if q.get('explanation'):
                print(f'{_(lang, "explanation")}: {q["explanation"]}')
            return
    print(_(lang, 'no_q_id', qid=qid))

def cmd_add(examen, lang):
    path = preguntas_path(examen)
    h, qs, err = leer(path)
    if err:
        print(f'  Error: {err}'); return
    next_id = max((q.get('id', 0) for q in qs), default=0) + 1
    print(f'\n{_(lang, "new_q", n=next_id)}')
    temas = examen.get('temas', [])
    if temas:
        print(_(lang, 'topics_avail', t=', '.join(t["id"] for t in temas)))
    topic = input(f'{_(lang, "topic")}: ').strip()
    if not topic and temas:
        topic = temas[0]['id']
    if not topic:
        print(_(lang, 'topic_required')); return
    print(f'\n{_(lang, "q_type")}')
    print(_(lang, 'q_type_1'))
    print(_(lang, 'q_type_2'))
    print(_(lang, 'q_type_3'))
    tipo_op = input(f'{_(lang, "q_type_prompt")}: ').strip() or '1'
    q = {'id': next_id, 'topic': topic}
    if tipo_op == '3':
        q['type'] = 'input'
        q['question'] = input(f'{_(lang, "statement")}: ').strip()
        r = input(f'{_(lang, "answers_pipe")}: ').strip()
        q['answer'] = [x.strip() for x in r.split('|') if x.strip()]
        if not q['answer']:
            print(_(lang, 'no_answer')); return
    else:
        q['question'] = input(f'{_(lang, "statement")}: ').strip()
        print(_(lang, 'opts_enter'))
        opts = []
        for letra in 'ABCDEFGH':
            o = input(f'  {letra}: ').strip()
            if not o:
                break
            opts.append(o)
        if len(opts) < 2:
            print(_(lang, 'min_opts')); return
        q['options'] = opts
        print(f'\n{_(lang, "correct_idx", max=len(opts)-1)}')
        if tipo_op == '2':
            r = input(f'{_(lang, "multi_comma")}: ').strip()
            q['answer'] = [int(x.strip()) for x in r.split(',')] if r else [0]
        else:
            r = input(f'{_(lang, "idx_prompt")}: ').strip()
            q['answer'] = int(r) if r else 0
    img = input(f'{_(lang, "opt_img")}: ').strip()
    if img:
        q['image'] = img
    exp = input(f'{_(lang, "opt_exp")}: ').strip()
    if exp:
        q['explanation'] = exp
    qs.append(q)
    escribir(path, h, qs, lang)

def cmd_edit(examen, lang, qid):
    path = preguntas_path(examen)
    h, qs, err = leer(path)
    if err:
        print(f'  Error: {err}'); return
    for i, q in enumerate(qs):
        if q.get('id') == qid:
            print(_(lang, 'enter_keep'))
            r = input(f'{_(lang, "topic")} [{q.get("topic")}]: ').strip()
            if r: q['topic'] = r
            r = input(f'{_(lang, "question")} [{q.get("question", "")[:40]}...]: ').strip()
            if r: q['question'] = r
            r = input(f'{_(lang, "image")} [{q.get("image", "")}]: ').strip()
            if r: q['image'] = r
            elif r == '' and 'image' in q: del q['image']
            if q.get('type') == 'input':
                actual = ', '.join(map(str, q.get('answer', [])))
                r = input(f'{_(lang, "answer")} [{actual}]: ').strip()
                if r: q['answer'] = [x.strip() for x in r.split('|')]
            else:
                opts = q.get('options', [])
                print(f'{_(lang, "options")} ({len(opts)}):')
                for idx, o in enumerate(opts):
                    print(f'  {idx}. {o}')
                r = input(f'{_(lang, "new_opts_pipe")}: ').strip()
                if r:
                    q['options'] = [x.strip() for x in r.split('|') if x.strip()]
                ans = q.get('answer')
                if isinstance(ans, list):
                    r = input(f'{_(lang, "answer")} [{",".join(str(a) for a in ans)}]: ').strip()
                else:
                    r = input(f'{_(lang, "answer")} [{ans}]: ').strip()
                if r:
                    q['answer'] = [int(x.strip()) for x in r.split(',')] if ',' in r else int(r)
            r = input(f'{_(lang, "explanation")} [{q.get("explanation", "")[:40]}...]: ').strip()
            if r: q['explanation'] = r
            elif r == '' and 'explanation' in q: del q['explanation']
            qs[i] = q
            escribir(path, h, qs, lang)
            return
    print(_(lang, 'no_q_id', qid=qid))

def cmd_delete(examen, lang, qid):
    path = preguntas_path(examen)
    h, qs, err = leer(path)
    if err:
        print(f'  Error: {err}'); return
    for i, q in enumerate(qs):
        if q.get('id') == qid:
            txt = q.get('question', '?')[:50]
            r = input(f'{_(lang, "del_confirm", qid=qid, txt=txt)}: ').strip().lower()
            if r in ('s', 'y'):
                qs.pop(i)
                escribir(path, h, qs, lang)
            else:
                print(_(lang, 'del_cancel'))
            return
    print(_(lang, 'no_q_id', qid=qid))

def cmd_export(examen, lang, archivo):
    h, qs, err = leer(preguntas_path(examen))
    if err:
        print(f'  Error: {err}'); return
    data = {'examen': examen['id'], 'titulo': examen['titulo'], 'preguntas': qs}
    with open(archivo, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(_(lang, 'q_exported', n=len(qs), f=archivo))

def cmd_import(examen, lang, archivo):
    if not os.path.exists(archivo):
        print(_(lang, 'file_not_found', f=archivo)); return
    with open(archivo, encoding='utf-8') as f:
        data = json.load(f)
    src = data.get('preguntas', data) if isinstance(data, dict) else data
    path = preguntas_path(examen)
    h, qs, err = leer(path)
    if err:
        print(f'  Error: {err}'); return
    nid = max((q.get('id', 0) for q in qs), default=0)
    for q in src:
        nid += 1
        q['id'] = nid
        qs.append(q)
    escribir(path, h, qs, lang)
    print(_(lang, 'q_imported', n=len(src)))

def cmd_count(examen, lang, json_out=False):
    h, qs, err = leer(preguntas_path(examen))
    if err:
        print(f'  Error: {err}'); return
    if json_out:
        temas = {}
        for q in qs:
            t = q.get('topic', '?')
            temas[t] = temas.get(t, 0) + 1
        print(json.dumps({'total': len(qs), 'temas': temas}, indent=2, ensure_ascii=False))
        return
    print(f'\n{_(lang, "total", n=len(qs))}')
    temas = {}
    for q in qs:
        t = q.get('topic', '?')
        temas[t] = temas.get(t, 0) + 1
    for t in sorted(temas):
        print(f'  {t}: {temas[t]}')

def cmd_validate(examen, lang, fix=False, json_out=False):
    path = preguntas_path(examen)
    h, qs, err = leer(path)
    if err:
        result = {'id': examen['id'], 'error': err, 'valid': False}
        if json_out:
            print(json.dumps(result, indent=2))
        else:
            print(f'  [ERR] Error de lectura: {err}')
        return False
    temas_val = {t['id'] for t in examen.get('temas', [])}
    errors, warns = _validate_qs(qs, temas_val, fix=fix, exam_path=os.path.dirname(path))
    temas_count = len(temas_val)

    if fix and (errors or warns):
        fixed_dup = any(e['type'] == 'dup' for e in errors)
        fixed_empty = sum(1 for e in errors if e['type'] == 'empty')
        fixed_idx = sum(1 for e in errors if e['type'] == 'idx_range')
        if fixed_dup:
            for i, q in enumerate(qs):
                q['id'] = i + 1
            print(_(lang, 'fix_dup_ids'))
        if fixed_empty:
            print(_(lang, 'fix_empty_q', n=fixed_empty))
        if fixed_idx:
            print(_(lang, 'fix_bad_idx', n=fixed_idx))
        qs = [q for q in qs if q.get('question', '').strip()]
        escribir(path, h, qs, lang)
        errors, warns = _validate_qs(qs, temas_val, fix=False, exam_path=os.path.dirname(path))

    if json_out:
        out = {
            'id': examen['id'],
            'titulo': examen['titulo'],
            'total': len(qs),
            'errors': len(errors),
            'warns': len(warns),
            'details': errors + [{'type': 'warn', 'msg': w} for w in warns],
            'valid': len(errors) == 0
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return len(errors) == 0

    print(f'\n{_(lang, "validate_title", id=examen["id"], title=examen["titulo"])}')
    print(f'  {_(lang, "validate_qs", n=len(qs))}')
    print(f'  {_(lang, "validate_topics", n=temas_count)}')
    if warns:
        for w in warns:
            print(f'  [!] {_parse_warn(w, lang)}')
    if errors:
        for e in errors:
            print(f'  [X] {_parse_err(e, lang)}')
        print(f'\n  [X] {_(lang, "validate_err_count", n=len(errors))}')
        return False
    else:
        print(f'  [OK] {_(lang, "validate_ok")}')
        return True

def _validate_qs(qs, temas_val, fix=False, exam_path=None):
    errors = []
    warns = []
    fixed_dup = False
    fixed_empty = 0
    fixed_idx = 0

    if not qs:
        warns.append('no_questions')

    seen_ids = set()
    for i, q in enumerate(qs):
        qid = q.get('id', f'#{i}')
        if qid in seen_ids:
            errors.append({'type': 'dup', 'qid': qid})
            if fix:
                qid = max(seen_ids) + 1 if seen_ids else 1
                q['id'] = qid
                fixed_dup = True
        seen_ids.add(qid)

        if not q.get('question', '').strip():
            fixed_empty += 1
            errors.append({'type': 'empty', 'qid': qid})
            continue

        if 'topic' not in q:
            errors.append({'type': 'no_topic', 'qid': qid})
        elif temas_val and q['topic'] not in temas_val:
            warns.append({'type': 'topic_mismatch', 'qid': qid, 't': q['topic']})

        if q.get('type') == 'likert':
            opts = q.get('options', [])
            if len(opts) < 2:
                errors.append({'type': 'few_opts', 'qid': qid, 'n': len(opts)})
            scale = q.get('scale', [])
            if scale and len(scale) != len(opts):
                errors.append({'type': 'likert_scale_len', 'qid': qid, 'got': len(scale), 'expected': len(opts)})
        elif q.get('type') == 'input':
            ans = q.get('answer', [])
            if not ans or not any(str(a).strip() for a in ans):
                errors.append({'type': 'no_ans', 'qid': qid})
        else:
            opts = q.get('options', [])
            if len(opts) < 2:
                errors.append({'type': 'few_opts', 'qid': qid, 'n': len(opts)})
            ans = q.get('answer')
            if ans is None:
                errors.append({'type': 'no_ans_field', 'qid': qid})
            elif isinstance(ans, list):
                new_ans = []
                for a in ans:
                    if a < 0 or a >= len(opts):
                        errors.append({'type': 'idx_range', 'qid': qid, 'idx': a, 'max': len(opts) - 1})
                        if fix:
                            a = max(0, min(a, len(opts) - 1))
                            fixed_idx += 1
                    new_ans.append(a)
                q['answer'] = new_ans
            elif isinstance(ans, int):
                if ans < 0 or ans >= len(opts):
                    errors.append({'type': 'idx_range', 'qid': qid, 'idx': ans, 'max': len(opts) - 1})
                    if fix:
                        q['answer'] = max(0, min(ans, len(opts) - 1))
                        fixed_idx += 1

        img = q.get('image', '')
        if img and not img.startswith('data:'):
            if not os.path.isabs(img) and exam_path:
                img_path = os.path.join(exam_path, img)
                if not os.path.exists(img_path):
                    warns.append({'type': 'img_missing', 'qid': qid, 'img': img})

    if fix:
        if fixed_dup:
            for i, q in enumerate(qs):
                q['id'] = i + 1
            warns.append({'type': 'fix_msg', 'msg': 'fix_dup_ids'})
        if fixed_empty:
            warns.append({'type': 'fix_msg', 'msg': ('fix_empty_q', fixed_empty)})
        if fixed_idx:
            warns.append({'type': 'fix_msg', 'msg': ('fix_bad_idx', fixed_idx)})

    return errors, warns

def _parse_err(e, lang):
    t = e['type']
    if t == 'dup': return _(lang, 'validate_err_dup', qid=e['qid'])
    if t == 'empty': return _(lang, 'validate_err_empty', qid=e['qid'])
    if t == 'no_topic': return _(lang, 'validate_err_no_topic', qid=e['qid'])
    if t == 'no_ans': return _(lang, 'validate_err_no_ans', qid=e['qid'])
    if t == 'few_opts': return _(lang, 'validate_err_few_opts', qid=e['qid'], n=e['n'])
    if t == 'no_ans_field': return _(lang, 'validate_err_no_ans_field', qid=e['qid'])
    if t == 'idx_range': return _(lang, 'validate_err_idx_range', qid=e['qid'], idx=e['idx'], max=e['max'])
    if t == 'likert_scale_len': return _(lang, 'validate_err_likert_scale', qid=e['qid'], got=e['got'], expected=e['expected'])
    return str(e)

def _parse_warn(w, lang):
    if isinstance(w, str):
        if w == 'no_questions':
            return _(lang, 'validate_warn_empty')
        return w
    if w.get('type') == 'topic_mismatch':
        return _(lang, 'validate_warn_topic', qid=w['qid'], t=w['t'])
    if w.get('type') == 'img_missing':
        return _(lang, 'validate_warn_img', qid=w['qid'], img=w['img'])
    msg = w.get('msg', str(w))
    if isinstance(msg, tuple):
        return _(lang, msg[0], n=msg[1])
    if isinstance(msg, str) and msg.startswith('fix_'):
        return _(lang, msg)
    return msg

def cmd_exams(lang, json_out=False):
    exs = examenes()
    if not exs:
        print(_(lang, 'no_exam_list'))
        return
    if json_out:
        print(json.dumps(exs, indent=2, ensure_ascii=False))
        return
    hdr_s = {'es': 'ID', 'en': 'ID'}
    hdr_t = {'es': 'Titulo', 'en': 'Title'}
    hdr_ti = {'es': 'Tiempo', 'en': 'Time'}
    hdr_to = {'es': 'Temas', 'en': 'Topics'}
    hdr_c = {'es': 'Creado', 'en': 'Created'}
    hdr = f'{hdr_s[lang]:<20s} {hdr_t[lang]:<25s} {hdr_ti[lang]:<8s} {hdr_to[lang]:<6s} {hdr_c[lang]:<20s}'
    print(f'\n{hdr}')
    print(_(lang, 'exams_sep'))
    for ex in exs:
        t = ex.get('tiempo', 0)
        temas = len(ex.get('temas', []))
        creado = ex.get('creado', '')
        print(f'{ex["id"]:<20s} {ex["titulo"]:<25s} {t} min  {temas:<5d} {creado:<20s}')
    total_pregs = 0
    for ex in exs:
        for t in ex.get('temas', []):
            total_pregs += int(t.get('peso', 0))
    print(f'\n{_(lang, "exams_total", n=len(exs), q=total_pregs)}')

# ---- NEW COMMANDS ----

def cmd_doctor(lang):
    exs = examenes()
    dirs_en_disco = set()
    
    print(f'\n{_(lang, "doctor_title")}\n')
    ok = 0
    errs = 0
    dangling = []

    examenes_dir = os.path.join(ROOT, 'examenes')
    scan_roots = [ROOT]
    if os.path.isdir(examenes_dir):
        scan_roots.append(examenes_dir)
    for sr in scan_roots:
        for entry in os.listdir(sr):
            d = os.path.join(sr, entry)
            if os.path.isdir(d) and not entry.startswith(('.', '_', 'template', 'css', 'js', 'examples', 'ejemplos', 'examenes')):
                if entry != 'template' and os.path.exists(os.path.join(d, 'preguntas.js')):
                    dirs_en_disco.add(entry)

    ids_en_json = {ex['id'] for ex in exs}
    huerfanos = dirs_en_disco - ids_en_json

    for ex in exs:
        eid = ex['id']
        d = os.path.join(ROOT, eid)
        if not os.path.isdir(d):
            d = os.path.join(ROOT, 'examenes', eid)
        if not os.path.isdir(d):
            print(_(lang, 'doctor_no_exam_dir', id=eid))
            errs += 1
            continue
        js = os.path.join(d, 'preguntas.js')
        if not os.path.exists(js):
            print(_(lang, 'doctor_missing_js', id=eid))
            errs += 1
            continue
        h, qs, err = leer(js)
        if err:
            print(_(lang, 'doctor_parse_err', id=eid, err=err))
            errs += 1
            continue
        print(_(lang, 'doctor_ok', id=eid))
        ok += 1

    for huerfano in sorted(huerfanos):
        print(_(lang, 'doctor_dangling', id=huerfano))
        dangling.append(huerfano)

    print(_(lang, 'doctor_total', n=len(exs), ok=ok, errs=errs, dangling=len(dangling)))

    if huerfanos:
        r = input('\n  [?] Eliminar directorios huerfanos? (s/n): ').strip().lower()
        if r in ('s', 'y'):
            for h in huerfanos:
                p = os.path.join(ROOT, h)
                if not os.path.isdir(p):
                    p = os.path.join(ROOT, 'examenes', h)
                shutil.rmtree(p)
                print(f'    Eliminado: {h}')
            print('  Hecho.')

def cmd_reindex(examen, lang):
    path = preguntas_path(examen)
    h, qs, err = leer(path)
    if err:
        print(f'  Error: {err}'); return
    if not qs:
        print(_(lang, 'no_questions'))
        return
    backup_path = path + '.bak'
    try:
        shutil.copy2(path, backup_path)
    except:
        pass
    for i, q in enumerate(qs):
        q['id'] = i + 1
    escribir(path, h, qs, lang)
    print(_(lang, 'reindex_done', n=len(qs)))

def cmd_search(texto, lang):
    import fnmatch
    texto_l = texto.lower()
    exs = examenes()
    results = []
    for ex in exs:
        h, qs, err = leer(preguntas_path(ex))
        if err or not qs:
            continue
        for q in qs:
            txt = q.get('question', '')
            opts = ' '.join(q.get('options', []))
            exp = q.get('explanation', '')
            if texto_l in txt.lower() or texto_l in opts.lower() or texto_l in exp.lower():
                results.append((ex['id'], q.get('id', '?'), q.get('topic', '?'), txt[:80]))
    if not results:
        print(_(lang, 'search_none', q=texto))
        return
    print(f'\n{_(lang, "search_header", q=texto)}\n')
    for eid, qid, tema, txt in results:
        print(_(lang, 'search_result', id=eid, qid=qid, tema=tema, txt=txt[:72]))

def cmd_stats(lang, json_out=False):
    exs = examenes()
    total_q = 0
    total_tipos = {}
    max_q = 0
    max_id = ''
    min_q = float('inf')
    min_id = ''
    empty_count = 0
    with_dir = 0

    for ex in exs:
        d = os.path.join(ROOT, ex['id'])
        if not os.path.isdir(d):
            d = os.path.join(ROOT, 'examenes', ex['id'])
        if os.path.isdir(d):
            with_dir += 1
        h, qs, err = leer(preguntas_path(ex))
        if err:
            continue
        n = len(qs)
        total_q += n
        if n > max_q:
            max_q = n
            max_id = ex['id']
        if n < min_q:
            min_q = n
            min_id = ex['id']
        if n == 0:
            empty_count += 1
        for q in qs:
            t = q.get('type', 'multiple')
            total_tipos[t] = total_tipos.get(t, 0) + 1

    if json_out:
        print(json.dumps({
            'exams': len(exs),
            'with_dir': with_dir,
            'total_questions': total_q,
            'avg': round(total_q / len(exs), 1) if exs else 0,
            'most': {'id': max_id, 'count': max_q},
            'least': {'id': min_id, 'count': min_q if min_q != float('inf') else 0},
            'empty': empty_count,
            'types': total_tipos
        }, indent=2, ensure_ascii=False))
        return

    print(f'\n{_(lang, "stats_title")}')
    print(f'  {_(lang, "stats_exams", n=len(exs))}')
    print(f'  {_(lang, "stats_with_dir", n=with_dir)}')
    print(f'  {_(lang, "stats_total_q", n=total_q)}')
    avg = total_q / len(exs) if exs else 0
    print(f'  {_(lang, "stats_avg", n=avg)}')
    if max_id:
        print(f'  {_(lang, "stats_most", id=max_id, n=max_q)}')
    if min_id and min_q != float('inf'):
        print(f'  {_(lang, "stats_least", id=min_id, n=min_q)}')
    print(f'  {_(lang, "stats_empty", n=empty_count)}')
    if total_tipos:
        print(f'\n  {_(lang, "stats_types")}')
        for t in sorted(total_tipos):
            print(f'    {_(lang, "stats_type_line", t=t, n=total_tipos[t])}')

def cmd_backup(lang):
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = os.path.join(ROOT, 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    zip_name = os.path.join(backup_dir, f'preguntas_{ts}.zip')
    import zipfile
    count = 0
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zf:
        exs = examenes()
        for ex in exs:
            js = preguntas_path(ex)
            if os.path.exists(js):
                zf.write(js, f'{ex["id"]}/preguntas.js')
                count += 1
            else:
                print(_(lang, 'backup_skip', id=ex['id']))
    print(_(lang, 'backup_done', f=zip_name))
    print(f'  {count} archivos respaldados')

def cmd_validate_all(examenes, lang, fix=False, json_out=False):
    results = []
    ok = True
    for ex in examenes:
        if json_out:
            h, qs, err = leer(preguntas_path(ex))
            temas_val = {t['id'] for t in ex.get('temas', [])}
            errors, warns = _validate_qs(qs, temas_val, fix=fix, exam_path=os.path.dirname(preguntas_path(ex)))
            r = len(errors) == 0
            results.append({
                'id': ex['id'],
                'titulo': ex['titulo'],
                'total': len(qs) if not err else 0,
                'errors': len(errors),
                'warns': len(warns),
                'valid': r
            })
            if not r:
                ok = False
        else:
            r = cmd_validate(ex, lang, fix=fix, json_out=False)
            if not r:
                ok = False
                print()
    if json_out:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    return ok

def cmd_grade(examen, lang, json_out=False):
    path = preguntas_path(examen)
    h, qs, err = leer(path)
    if err:
        print(f'  Error: {err}'); return

    tipo = examen.get('tipo', 'quiz')
    passing = examen.get('passing_grade')
    ranges = examen.get('result_ranges', [])
    temas = examen.get('temas', [])

    if json_out:
        out = {
            'id': examen['id'],
            'titulo': examen['titulo'],
            'tipo': tipo,
            'total_questions': len(qs),
            'passing_grade': passing,
        }
        if tipo == 'likert':
            scales = []
            for q in qs:
                if q.get('type') == 'likert':
                    s = q.get('scale', [])
                    if s: scales.append((min(s), max(s)))
            if scales:
                out['likert_min'] = min(s[0] for s in scales)
                out['likert_max'] = sum(s[1] for s in scales)
            out['result_ranges'] = ranges
        else:
            out['temas'] = [{'id': t['id'], 'nombre': t['nombre'], 'peso': t.get('peso', 0)} for t in temas]
            total_peso = sum(int(t.get('peso', 0)) for t in temas)
            out['total_peso'] = total_peso
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return

    print(f'\n{_(lang, "grade_title")}')
    print(f'  {_(lang, "grade_exam_type", t=tipo)}')
    print(f'  Total: {len(qs)} preguntas')

    if tipo == 'likert':
        scales = []
        for q in qs:
            if q.get('type') == 'likert':
                s = q.get('scale', [])
                if s: scales.append((min(s), max(s)))
        if scales:
            total_min = sum(s[0] for s in scales)
            total_max = sum(s[1] for s in scales)
            print(f'  {_(lang, "grade_likert_scale", min=total_min, max=total_max)}')
        if ranges:
            print(f'  {_(lang, "grade_ranges")}')
            for r in ranges:
                print(f'    {_(lang, "grade_range_line", min=r["min"], max=r["max"], label=r["label"])}')
        else:
            print(f'  {_(lang, "grade_no_pass")}')
    else:
        if passing:
            print(f'  {_(lang, "grade_passing", n=passing)}')
        else:
            print(f'  {_(lang, "grade_no_pass")}')
        if temas:
            print(f'  {_(lang, "grade_weighted")}')
            total_peso = sum(int(t.get('peso', 0)) for t in temas)
            for t in temas:
                p = int(t.get('peso', 0))
                pct = round(p / total_peso * 100) if total_peso else 0
                print(f'    {_(lang, "grade_weight_line", t=t["nombre"], peso=p, pct=pct)}')
            print(f'    {_(lang, "grade_weight_total", n=total_peso)}')

def cmd_count_all(examenes, lang, json_out=False):
    total_p = 0
    total_q = 0
    items = []
    for ex in examenes:
        h, qs, err = leer(preguntas_path(ex))
        if err:
            continue
        t = len(ex.get('temas', []))
        n = len(qs)
        items.append({'id': ex['id'], 'temas': t, 'preguntas': n})
        total_p += t
        total_q += n
    if json_out:
        print(json.dumps({'total_temas': total_p, 'total_preguntas': total_q, 'examenes': items}, indent=2, ensure_ascii=False))
        return
    for item in items:
        print(f'  {item["id"]:<35s} {item["temas"]:>3d} temas  {item["preguntas"]:>5d} preg')
    print(f'  {"-" * 48}')
    print(f'  {"TOTAL":<35s} {total_p:>3d} temas  {total_q:>5d} preg')

# ---- MAIN ----
def main():
    global lang
    parser = argparse.ArgumentParser(description='Quiz Builder - CLI para gestionar preguntas', add_help=False)
    parser.add_argument('command', nargs='?', help='Comando')
    parser.add_argument('-lang', choices=['es', 'en'], default='es', help='Idioma (es/en)')
    parser.add_argument('-h', '--help', action='store_true', help='Mostrar ayuda')
    parser.add_argument('-e', '--exam', help='ID del examen (omitir para seleccion interactiva)')
    parser.add_argument('--all', action='store_true', help='Ejecutar comando en todos los examenes')
    parser.add_argument('--json', action='store_true', help='Salida en JSON')
    parser.add_argument('--fix', action='store_true', help='Auto-corregir errores (validate)')
    parsed, extra = parser.parse_known_args()
    lang = parsed.lang

    if parsed.help or not parsed.command:
        if parsed.lang == 'en':
            print(__doc__.replace('Uso:', 'Usage:').replace('Esta ayuda', 'This help')
                  .replace('Comandos:', 'Commands:').replace('Agregar pregunta (interactivo)', 'Add question (interactive)')
                  .replace('Editar pregunta', 'Edit question').replace('Eliminar pregunta', 'Delete question')
                  .replace('Mostrar detalle', 'Show detail').replace('Listar preguntas', 'List questions')
                  .replace('Exportar a JSON', 'Export to JSON').replace('Importar desde JSON', 'Import from JSON')
                  .replace('Total de preguntas y por tema', 'Total questions per topic')
                  .replace('Validar estructura y referencias de preguntas', 'Validate question structure')
                  .replace('Listar examenes registrados', 'List registered exams')
                  .replace('(opcional: filtrar por tema)', '(optional: filter by topic)')
                  .replace('Tipos de pregunta:', 'Question types:')
                  .replace('respuesta unica', 'single answer').replace('multiples respuestas', 'multiple answers')
                  .replace('texto libre', 'free text').replace('con imagen', 'with image')
                  .replace('Renumerar IDs secuencialmente', 'Renumber IDs sequentially')
                  .replace('Escanear todos los examenes en busca de problemas', 'Scan all exams for issues')
                  .replace('Buscar texto en preguntas de todos los examenes', 'Search text in all exam questions')
                  .replace('Estadisticas globales', 'Global statistics')
                  .replace('Crear respaldo de preguntas.js', 'Backup preguntas.js files')
                  .replace('Flags globales:', 'Global flags:')
                  .replace('Salida en JSON (para scripting)', 'JSON output (for scripting)')
                  .replace('Auto-corregir errores (validate)', 'Auto-fix errors (validate)')
                  .replace('ID del examen (omitir para seleccion interactiva)', 'Exam ID (omit for interactive selection)')
                  .replace('Ejecutar comando en todos los examenes', 'Run command on all exams'))
        else:
            print(__doc__)
        return

    cmd = parsed.command

    if cmd == 'help':
        print(__doc__)
        return

    if cmd == 'exams':
        cmd_exams(lang, json_out=parsed.json)
        return

    if cmd == 'doctor':
        cmd_doctor(lang)
        return

    if cmd == 'search':
        if not extra:
            print(f'  Uso: preguntas.py search <texto>')
            sys.exit(1)
        cmd_search(' '.join(extra), lang)
        return

    if cmd == 'stats':
        cmd_stats(lang, json_out=parsed.json)
        return

    if cmd == 'backup':
        cmd_backup(lang)
        return

    exs = examenes()

    if parsed.all:
        if cmd == 'validate':
            ok = cmd_validate_all(exs, lang, fix=parsed.fix, json_out=parsed.json)
            sys.exit(0 if ok else 1)
        elif cmd == 'count':
            cmd_count_all(exs, lang, json_out=parsed.json)
        elif cmd == 'grade':
            for ex in exs:
                print(f'\n{"=" * 50}')
                print(f'  {ex["id"]}')
                cmd_grade(ex, lang, json_out=parsed.json)
        elif cmd == 'list':
            for ex in exs:
                print(f'\n{"=" * 50}')
                print(f'  {ex["id"]}')
                cmd_list(ex, lang, json_out=parsed.json)
        else:
            print(f'  --all no soportado para "{cmd}"')
            sys.exit(1)
        return

    if parsed.exam:
        match = [ex for ex in exs if ex['id'] == parsed.exam]
        if not match:
            match = [ex for ex in exs if parsed.exam.lower() in ex['id'].lower()]
        if not match:
            print(f'  Examen "{parsed.exam}" no encontrado.')
            sys.exit(1)
        ex = match[0]
        if len(match) > 1:
            print(f'  Multiples coincidencias para "{parsed.exam}":')
            for m in match:
                print(f'    {m["id"]}')
            sys.exit(1)
    else:
        ex = elegir_examen(exs, lang)

    if cmd == 'list':
        cmd_list(ex, lang, extra[0] if extra else None, json_out=parsed.json)
    elif cmd == 'show':
        if not extra: print(_(lang, 'no_q_id', qid='<id>')); sys.exit(1)
        cmd_show(ex, lang, int(extra[0]))
    elif cmd == 'add':
        cmd_add(ex, lang)
    elif cmd == 'edit':
        if not extra: print(_(lang, 'no_q_id', qid='<id>')); sys.exit(1)
        cmd_edit(ex, lang, int(extra[0]))
    elif cmd == 'delete':
        if not extra: print(_(lang, 'no_q_id', qid='<id>')); sys.exit(1)
        cmd_delete(ex, lang, int(extra[0]))
    elif cmd == 'count':
        cmd_count(ex, lang, json_out=parsed.json)
    elif cmd == 'validate':
        ok = cmd_validate(ex, lang, fix=parsed.fix, json_out=parsed.json)
        sys.exit(0 if ok else 1)
    elif cmd == 'export':
        if not extra: print(_(lang, 'file_not_found', f='<archivo>')); sys.exit(1)
        cmd_export(ex, lang, extra[0])
    elif cmd == 'import':
        if not extra: print(_(lang, 'file_not_found', f='<archivo>')); sys.exit(1)
        cmd_import(ex, lang, extra[0])
    elif cmd == 'reindex':
        cmd_reindex(ex, lang)
    elif cmd == 'grade':
        cmd_grade(ex, lang, json_out=parsed.json)
    elif cmd == 'menu':
        cmd_menu(lang)
    else:
        print(_(lang, 'unknown_cmd', cmd=cmd))
        print()

def cmd_menu(lang):
    while True:
        print(f'\n{"=" * 50}')
        print(f'  {_(lang, "menu_title")}')
        print(f'{"=" * 50}')
        items = [
            ('list', 'menu_list'),
            ('show', 'menu_show'),
            ('add', 'menu_add'),
            ('edit', 'menu_edit'),
            ('delete', 'menu_delete'),
            ('count', 'menu_count'),
            ('validate', 'menu_validate'),
            ('reindex', 'menu_reindex'),
            ('export', 'menu_export'),
            ('import', 'menu_import'),
            ('exams', 'menu_exams'),
            ('doctor', 'menu_doctor'),
            ('search', 'menu_search'),
            ('stats', 'menu_stats'),
            ('backup', 'menu_backup'),
            ('grade', 'menu_grade'),
        ]
        for i, (cmd, key) in enumerate(items, 1):
            print(f'  {i:2d}. {_(lang, key)}')
        print(f'  0. {_(lang, "menu_exit")}')
        r = input(f'\n{_(lang, "menu_prompt")}: ').strip()
        if r == '0':
            print(f'  {_(lang, "menu_bye")}')
            break
        try:
            idx = int(r) - 1
            if idx < 0 or idx >= len(items):
                print(f'  {_(lang, "invalid_num")}')
                continue
            cmd_name = items[idx][0]
            if cmd_name in ('doctor', 'stats', 'backup', 'exams'):
                globals()[f'cmd_{cmd_name}'](lang)
            elif cmd_name == 'search':
                q = input(f'  {_(lang, "menu_search_q")}: ').strip()
                if q:
                    cmd_search(q, lang)
                else:
                    print(f'  {_(lang, "menu_cancel")}')
            else:
                exs = examenes()
                if not exs:
                    print(f'  {_(lang, "no_exam_list")}')
                    continue
                ex = elegir_examen(exs, lang)
                if cmd_name == 'list':
                    cmd_list(ex, lang)
                elif cmd_name == 'show':
                    r = input(f'  ID: ').strip()
                    try:
                        cmd_show(ex, lang, int(r))
                    except ValueError:
                        print(f'  {_(lang, "invalid_num")}')
                elif cmd_name == 'add':
                    cmd_add(ex, lang)
                elif cmd_name == 'edit':
                    r = input(f'  ID: ').strip()
                    try:
                        cmd_edit(ex, lang, int(r))
                    except ValueError:
                        print(f'  {_(lang, "invalid_num")}')
                elif cmd_name == 'delete':
                    r = input(f'  ID: ').strip()
                    try:
                        cmd_delete(ex, lang, int(r))
                    except ValueError:
                        print(f'  {_(lang, "invalid_num")}')
                elif cmd_name == 'count':
                    cmd_count(ex, lang)
                elif cmd_name == 'validate':
                    cmd_validate(ex, lang)
                elif cmd_name == 'reindex':
                    cmd_reindex(ex, lang)
                elif cmd_name == 'grade':
                    cmd_grade(ex, lang)
                elif cmd_name == 'export':
                    f = input(f'  {_(lang, "menu_export_file")}: ').strip()
                    if f:
                        cmd_export(ex, lang, f)
                    else:
                        print(f'  {_(lang, "menu_cancel")}')
                elif cmd_name == 'import':
                    f = input(f'  {_(lang, "menu_import_file")}: ').strip()
                    if f:
                        cmd_import(ex, lang, f)
                    else:
                        print(f'  {_(lang, "menu_cancel")}')
        except (ValueError, IndexError):
            print(f'  {_(lang, "invalid_num")}')
        except KeyboardInterrupt:
            print(f'\n  {_(lang, "menu_bye")}')
            break

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(0)
    except Exception as e:
        print(f'\n  [ERR] Error inesperado: {e}')
        sys.exit(1)
