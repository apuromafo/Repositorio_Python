import os, sys, json, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from preguntas import _parse_objects, _js2dict, _q2js, LANG, _

class TestParse(unittest.TestCase):
    def test_parse_empty(self):
        self.assertEqual(_parse_objects(''), [])

    def test_parse_single(self):
        raw = '{id:1,topic:"T1",question:"Q?",options:["A","B"],answer:0}'
        r = _parse_objects(raw)
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]['id'], 1)
        self.assertEqual(r[0]['topic'], 'T1')
        self.assertEqual(r[0]['answer'], 0)

    def test_parse_multi_answer(self):
        raw = '{id:2,topic:"T2",question:"Q?",options:["A","B","C"],answer:[0,2]}'
        r = _parse_objects(raw)
        self.assertEqual(r[0]['answer'], [0, 2])

    def test_parse_input_type(self):
        raw = '{id:3,topic:"T3",type:"input",question:"Q?",answer:["R1","R2"]}'
        r = _parse_objects(raw)
        self.assertEqual(r[0]['type'], 'input')
        self.assertEqual(r[0]['answer'], ['R1', 'R2'])

    def test_parse_multiple(self):
        raw = '{id:1,q:"Q1"},{id:2,q:"Q2"}'
        r = _parse_objects(raw)
        self.assertEqual(len(r), 2)

    def test_js2dict_basic(self):
        d = _js2dict('id: 5, topic: "test", answer: 2')
        self.assertEqual(d['id'], 5)
        self.assertEqual(d['topic'], 'test')

    def test_q2js_choice(self):
        q = {'id': 1, 'topic': 'T1', 'question': 'Q?', 'options': ['A', 'B'], 'answer': 0}
        js = _q2js(q)
        self.assertIn('id: 1', js)
        self.assertIn('answer: 0', js)

    def test_q2js_multi(self):
        q = {'id': 2, 'topic': 'T1', 'question': 'Q?', 'options': ['A', 'B', 'C'], 'answer': [0, 2]}
        js = _q2js(q)
        self.assertIn('answer: [0, 2]', js)

    def test_q2js_input(self):
        q = {'id': 3, 'topic': 'T1', 'type': 'input', 'question': 'Q?', 'answer': ['R1', 'R2']}
        js = _q2js(q)
        self.assertIn('type: "input"', js)
        self.assertIn('"R1"', js)

    def test_q2js_with_image(self):
        q = {'id': 1, 'topic': 'T1', 'question': 'Q?', 'options': ['A', 'B'], 'answer': 0, 'image': 'img.jpg'}
        js = _q2js(q)
        self.assertIn('image: "img.jpg"', js)

    def test_q2js_escapes(self):
        q = {'id': 1, 'topic': 'T', 'question': 'Line1\\nLine2', 'options': ['"A"'], 'answer': 0}
        js = _q2js(q)
        self.assertIn('Line1\\\\nLine2', js)
        self.assertIn('\\"A\\"', js)

    def test_q2js_escapes_list(self):
        q = {'id': 1, 'topic': 'T', 'question': 'Q', 'options': ['it\\s', '"hi"'], 'answer': 0}
        js = _q2js(q)
        self.assertIn('it\\\\s', js)
        self.assertIn('\\"hi\\"', js)

class TestLang(unittest.TestCase):
    def test_lang_es(self):
        self.assertEqual(_('es', 'no_questions'), 'No hay preguntas.')

    def test_lang_en(self):
        self.assertEqual(_('en', 'no_questions'), 'No questions.')

    def test_lang_fallback(self):
        self.assertEqual(_('fr', 'no_questions'), 'No hay preguntas.')

    def test_lang_unknown_key(self):
        self.assertEqual(_('es', 'nonexistent_key'), 'nonexistent_key')

    def test_lang_format(self):
        r = _('es', 'no_q_topic', t='T1')
        self.assertIn('T1', r)

class TestLANGDict(unittest.TestCase):
    def test_es_has_all_keys(self):
        en_keys = set(LANG['en'].keys())
        es_keys = set(LANG['es'].keys())
        missing = en_keys - es_keys
        extra = es_keys - en_keys
        self.assertEqual(missing, set(), f'ES missing keys: {missing}')
        self.assertEqual(extra, set(), f'ES extra keys: {extra}')

    def test_lang_not_empty(self):
        for lang_code in ('es', 'en'):
            for key, val in LANG[lang_code].items():
                with self.subTest(lang=lang_code, key=key):
                    self.assertTrue(val.strip(), f'Empty value for {lang_code}.{key}')

if __name__ == '__main__':
    unittest.main()
