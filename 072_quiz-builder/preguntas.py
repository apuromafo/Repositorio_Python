#!/usr/bin/env python3
"""
Quiz Builder — CLI para gestionar preguntas
Uso: python preguntas.py [-lang es|en] <comando> [opciones]

Comandos:
  list [tema]       Listar preguntas (opcional: filtrar por tema)
  add               Agregar pregunta (interactivo)
  edit <id>         Editar pregunta
  delete <id>       Eliminar pregunta
  show <id>         Mostrar detalle
  export <archivo>  Exportar a JSON
  import <archivo>  Importar desde JSON
  count             Total de preguntas y por tema
  validate          Validar estructura y referencias de preguntas
  exams             Listar examenes registrados
  help              Esta ayuda

Tipos de pregunta:
  - multiple choice (respuesta unica)
  - multiple choice (multiples respuestas: answer: [1, 3])
  - tipo input (texto libre: type: "input", answer: ["respuesta"])
  - con imagen (image: "ruta/a/imagen.jpg")
"""

import os, sys, re, json, argparse

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
        print(f'  {i+1}. {ex["id"]} — {ex["titulo"]}')
    while True:
        r = input(f'\n{_(lang, "select_exam")}: ').strip()
        if not r:
            return lista[0]
        try:
            return lista[int(r) - 1]
        except:
            print(_(lang, 'invalid_num'))

def preguntas_path(examen):
    return os.path.join(ROOT, examen['id'], 'preguntas.js')

def leer(path):
    if not os.path.exists(path):
        return [], []
    with open(path, encoding='utf-8') as f:
        src = f.read()
    m = re.search(r'(const\s+questionBank\s*=\s*)\[(.*)\]', src, re.DOTALL)
    if not m:
        return src.split('\n'), []
    header = src[:m.start(1)].split('\n')
    raw = m.group(2).strip()
    preguntas = _parse_objects(raw)
    return header, preguntas

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
    src = f'{h}\n\n{body}\n];\n'
    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)
    print(_(lang, 'q_saved', n=len(preguntas), f=os.path.basename(path)))

# ---- COMMANDS ----
def cmd_list(examen, lang, tema=None):
    h, qs = leer(preguntas_path(examen))
    if not qs:
        print(_(lang, 'no_questions'))
        return
    if tema:
        qs = [q for q in qs if q.get('topic') == tema]
        if not qs:
            print(_(lang, 'no_q_topic', t=tema))
            return
    agrupadas = {}
    for q in qs:
        agrupadas.setdefault(q.get('topic', '?'), []).append(q)
    for t in sorted(agrupadas):
        items = agrupadas[t]
        print(f'\n  [{t}] ({len(items)})')
        for q in items:
            ans = q.get('answer', '?')
            if isinstance(ans, list):
                ans = ','.join(str(a) for a in ans)
            n_opts = len(q.get('options', []))
            extras = []
            if q.get('image'): extras.append('img')
            if q.get('type') == 'input': extras.append('input')
            tag = f' [{",".join(extras)}]' if extras else ''
            txt = q.get('question', '?')[:55]
            print(f'    #{q["id"]:>3d}  {txt}{tag} | {n_opts} opts | ans={ans}')

def cmd_show(examen, lang, qid):
    h, qs = leer(preguntas_path(examen))
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
    h, qs = leer(path)
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
    h, qs = leer(path)
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
    h, qs = leer(path)
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
    h, qs = leer(preguntas_path(examen))
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
    h, qs = leer(path)
    nid = max((q.get('id', 0) for q in qs), default=0)
    for q in src:
        nid += 1
        q['id'] = nid
        qs.append(q)
    escribir(path, h, qs, lang)
    print(_(lang, 'q_imported', n=len(src)))

def cmd_count(examen, lang):
    h, qs = leer(preguntas_path(examen))
    print(f'\n{_(lang, "total", n=len(qs))}')
    temas = {}
    for q in qs:
        t = q.get('topic', '?')
        temas[t] = temas.get(t, 0) + 1
    for t in sorted(temas):
        print(f'  {t}: {temas[t]}')

def cmd_validate(examen, lang):
    path = preguntas_path(examen)
    h, qs = leer(path)
    temas_val = {t['id'] for t in examen.get('temas', [])}
    errors = []
    warns = []
    if not qs:
        warns.append(_(lang, 'validate_warn_empty'))
    seen_ids = set()
    for i, q in enumerate(qs):
        qid = q.get('id', f'#{i}')
        if qid in seen_ids:
            errors.append(_(lang, 'validate_err_dup', qid=qid))
        seen_ids.add(qid)
        if not q.get('question', '').strip():
            errors.append(_(lang, 'validate_err_empty', qid=qid))
        if 'topic' not in q:
            errors.append(_(lang, 'validate_err_no_topic', qid=qid))
        elif temas_val and q['topic'] not in temas_val:
            warns.append(_(lang, 'validate_warn_topic', qid=qid, t=q['topic']))
        if q.get('type') == 'input':
            ans = q.get('answer', [])
            if not ans or not any(str(a).strip() for a in ans):
                errors.append(_(lang, 'validate_err_no_ans', qid=qid))
        else:
            opts = q.get('options', [])
            if len(opts) < 2:
                errors.append(_(lang, 'validate_err_few_opts', qid=qid, n=len(opts)))
            ans = q.get('answer')
            if ans is None:
                errors.append(_(lang, 'validate_err_no_ans_field', qid=qid))
            elif isinstance(ans, list):
                for a in ans:
                    if a < 0 or a >= len(opts):
                        errors.append(_(lang, 'validate_err_idx_range', qid=qid, idx=a, max=len(opts)-1))
            elif isinstance(ans, int):
                if ans < 0 or ans >= len(opts):
                    errors.append(_(lang, 'validate_err_idx_range', qid=qid, idx=ans, max=len(opts)-1))
    print(f'\n{_(lang, "validate_title", id=examen["id"], title=examen["titulo"])}')
    print(f'  {_(lang, "validate_qs", n=len(qs))}')
    print(f'  {_(lang, "validate_topics", n=len(temas_val))}')
    if warns:
        for w in warns:
            print(f'  ⚠ {w}')
    if errors:
        for e in errors:
            print(f'  ✗ {e}')
        print(f'\n  ❌ {_(lang, "validate_err_count", n=len(errors))}')
        return False
    else:
        print(f'  ✅ {_(lang, "validate_ok")}')
        return True

def cmd_exams(lang, unused=None):
    exs = examenes()
    if not exs:
        print(_(lang, 'no_exam_list'))
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

# ---- MAIN ----
def main():
    global lang
    parser = argparse.ArgumentParser(description='Quiz Builder — CLI para gestionar preguntas', add_help=False)
    parser.add_argument('command', nargs='?', help='Comando')
    parser.add_argument('args', nargs=argparse.REMAINDER, help='Argumentos del comando')
    parser.add_argument('-lang', choices=['es', 'en'], default='es', help='Idioma (es/en)')
    parser.add_argument('-h', '--help', action='store_true', help='Mostrar ayuda')
    parsed, _ = parser.parse_known_args()
    lang = parsed.lang

    if parsed.help or not parsed.command:
        if parsed.lang == 'en':
            print(__doc__.replace('Uso:', 'Usage:').replace('Esta ayuda', 'This help')
                  .replace('Comandos:', 'Commands:').replace('Agregar pregunta (interactivo)', 'Add question (interactive)')
                  .replace('Editar pregunta', 'Edit question').replace('Eliminar pregunta', 'Delete question')
                  .replace('Mostrar detalle', 'Show detail').replace('Listar preguntas', 'List questions')
                  .replace('Exportar a JSON', 'Export to JSON').replace('Importar desde JSON', 'Import from JSON')
                  .replace('Total de preguntas y por tema', 'Total questions per topic')
                  .replace('Validar estructura y referencias de preguntas', 'Validate question structure and references')
                  .replace('Listar examenes registrados', 'List registered exams')
                  .replace('(opcional: filtrar por tema)', '(optional: filter by topic)')
                  .replace('Tipos de pregunta:', 'Question types:')
                  .replace('respuesta unica', 'single answer').replace('multiples respuestas', 'multiple answers')
                  .replace('texto libre', 'free text').replace('con imagen', 'with image'))
        else:
            print(__doc__)
        return

    cmd = parsed.command
    args = parsed.args

    if cmd == 'help':
        if lang == 'en':
            print(__doc__.replace('Uso:', 'Usage:').replace('Esta ayuda', 'This help'))
        else:
            print(__doc__)
        return

    if cmd == 'exams':
        cmd_exams(lang)
        return

    exs = examenes()
    ex = elegir_examen(exs, lang)

    if cmd == 'list':
        cmd_list(ex, lang, args[0] if args else None)
    elif cmd == 'show':
        if not args: print(_(lang, 'no_q_id', qid='<id>')); sys.exit(1)
        cmd_show(ex, lang, int(args[0]))
    elif cmd == 'add':
        cmd_add(ex, lang)
    elif cmd == 'edit':
        if not args: print(_(lang, 'no_q_id', qid='<id>')); sys.exit(1)
        cmd_edit(ex, lang, int(args[0]))
    elif cmd == 'delete':
        if not args: print(_(lang, 'no_q_id', qid='<id>')); sys.exit(1)
        cmd_delete(ex, lang, int(args[0]))
    elif cmd == 'count':
        cmd_count(ex, lang)
    elif cmd == 'validate':
        cmd_validate(ex, lang)
    elif cmd == 'export':
        if not args: print(_(lang, 'file_not_found', f='<archivo>')); sys.exit(1)
        cmd_export(ex, lang, args[0])
    elif cmd == 'import':
        if not args: print(_(lang, 'file_not_found', f='<archivo>')); sys.exit(1)
        cmd_import(ex, lang, args[0])
    else:
        print(_(lang, 'unknown_cmd', cmd=cmd)); print()

if __name__ == '__main__':
    main()
