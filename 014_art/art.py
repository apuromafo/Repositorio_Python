import argparse
import pyfiglet
import random
import unicodedata
#import textwrap


def sanitize_input(text):
    return unicodedata.normalize('NFKD', text)
        
def generar_arte_ascii():
    """
    Genera arte ASCII a partir de una cadena de texto, con opciones de fuente aleatoria, ancho y justificación.
    """
    # Crear un objeto de análisis de argumentos
    parser = argparse.ArgumentParser(description='Generador de arte ASCII')

    # Agregar argumentos para personalizar la salida
    parser.add_argument('-s', '--string', type=str, required=True, help='Cadena de texto para convertir a ASCII')
    parser.add_argument('-r', '--random', action='store_true', help='Seleccionar una fuente aleatoria')
    parser.add_argument('-f', '--font', type=str, default='slant', help='Fuente a utilizar (ver opciones disponibles en pyfiglet)')
    parser.add_argument('-w', '--width', type=int, default=200, help='Ancho máximo del banner')
    #parser.add_argument('-j', '--justify', type=str, choices=['left', 'center', 'right'], default='center', help='Justificación del texto')
    parser.add_argument('-o', '--output', type=str, help='Nombre del archivo para guardar el resultado')

    # Analizar los argumentos proporcionados por el usuario
    args = parser.parse_args()
    args.string = sanitize_input(args.string)

    # Lista de fuentes disponibles
    lista_fuentes = [
        "1943____", "1row", "3-d", "3d-ascii", "3d_diagonal",
        "3x5", "4max", "4x4_offr", "5lineoblique", "5x7",
        "5x8", "64f1____", "6x10", "6x9", "acrobatic",
        "advenger", "alligator", "alligator2", "alpha", "alphabet",
        "amc_3_line", "amc_3_liv1", "amc_aaa01", "amc_neko", "amc_razor",
        "amc_razor2", "amc_slash", "amc_slider", "amc_thin", "amc_tubes",
        "amc_untitled", "ansi_regular", "ansi_shadow", "aquaplan", "arrows",
        "ascii_new_roman", "ascii___", "asc_____", "assalt_m", "asslt__m",
        "atc_gran", "atc_____", "avatar", "a_zooloo", "b1ff",
        "banner", "banner3-D", "banner3", "banner4", "barbwire",
        "basic", "battlesh", "battle_s", "baz__bil", "bear",
        "beer_pub", "bell", "benjamin", "big", "bigchief",
        "bigfig", "big_money-ne", "big_money-nw", "big_money-se", "big_money-sw",
        "binary", "block", "blocks", "blocky", "bloody",
        "bolger", "braced", "bright", "brite", "briteb",
        "britebi", "britei", "broadway", "broadway_kb", "bubble",
        "bubble_b", "bubble__", "bulbhead", "b_m__200", "c1______",
        "c2______", "calgphy2", "caligraphy", "calvin_s", "cards",
        "catwalk", "caus_in_", "char1___", "char2___", "char3___",
        "char4___", "charact1", "charact2", "charact3", "charact4",
        "charact5", "charact6", "characte", "charset_", "chartr",
        "chartri", "chiseled", "chunky", "clb6x10", "clb8x10",
        "clb8x8", "cli8x8", "clr4x6", "clr5x10", "clr5x6",
        "clr5x8", "clr6x10", "clr6x6", "clr6x8", "clr7x10",
        "clr7x8", "clr8x10", "clr8x8", "coil_cop", "coinstak",
        "cola", "colossal", "computer", "com_sen_", "contessa",
        "contrast", "convoy__", "cosmic", "cosmike", "cour",
        "courb", "courbi", "couri", "crawford", "crawford2",
        "crazy", "cricket", "cursive", "cyberlarge", "cybermedium",
        "cybersmall", "cygnet", "c_ascii_", "c_consen", "danc4",
        "dancing_font", "dcs_bfmo", "decimal", "deep_str", "defleppard",
        "def_leppard", "delta_corps_priest_1", "demo_1__", "demo_2__", "demo_m__",
        "devilish", "diamond", "diet_cola", "digital", "doh",
        "doom", "dos_rebel", "dotmatrix", "double", "double_shorts",
        "drpepper", "druid___", "dwhistled", "d_dragon", "ebbs_1__",
        "ebbs_2__", "eca_____", "eftichess", "eftifont", "eftipiti",
        "eftirobot", "eftitalic", "eftiwall", "eftiwater", "efti_robot",
        "electronic", "elite", "epic", "etcrvs__", "e__fist_",
        "f15_____", "faces_of", "fairligh", "fair_mea", "fantasy_",
        "fbr12___", "fbr1____", "fbr2____", "fbr_stri", "fbr_tilt",
        "fender", "filter", "finalass", "fireing_", "fire_font-k",
        "fire_font-s", "flipped", "flower_power", "flyn_sh", "fourtops",
        "fp1_____", "fp2_____", "fraktur", "funky_dr", "fun_face",
        "fun_faces", "future_1", "future_2", "future_3", "future_4",
        "future_5", "future_6", "future_7", "future_8", "fuzzy",
        "gauntlet", "georgi16", "georgia11", "ghost", "ghost_bo",
        "ghoulish", "glenyn", "goofy", "gothic", "gothic__",
        "graceful", "gradient", "graffiti", "grand_pr", "greek",
        "green_be", "hades___", "heart_left", "heart_right", "heavy_me",
        "helv", "helvb", "helvbi", "helvi", "henry_3d",
        "heroboti", "hex", "hieroglyphs", "high_noo", "hills___",
        "hollywood", "home_pak", "horizontal_left", "horizontal_right", "house_of",
        "hypa_bal", "hyper___", "icl-1900"
    ]
    # Seleccionar fuente aleatoria si se indica la opción `-r`
    if args.random:
        fuente = random.choice(lista_fuentes)
        print(f"Se ha seleccionado la fuente aleatoria: {fuente}")
    else:
        fuente = args.font

    # Verificar si la fuente especificada existe
    if fuente not in pyfiglet.FigletFont.getFonts():
        print(f"La fuente '{fuente}' no se encontró. Por favor, elige una de las siguientes:")
        for font in pyfiglet.FigletFont.getFonts():
            print(font)
        exit(1)

    # Generar el arte ASCII
    resultado_ascii = pyfiglet.figlet_format(args.string, font=fuente, width=args.width)
    #print(resultado_ascii2)
    #resultado_ascii = pyfiglet.figlet_format(args.string, font=fuente, width=args.width, justify=args.justify)

    # Ajustar el texto al ancho deseado
    #texto_ajustado = textwrap.fill(resultado_ascii, width=args.width)

    # Si se especificó un archivo de salida, guardar el resultado en él
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8', newline='\n') as archivo:
                archivo.write(resultado_ascii)
            print(f"El arte ASCII se guardó en {args.output}")
        except IOError as e:
            print(f"Error al escribir en el archivo: {e}")
    else:
        # Si no se especificó un archivo de salida, mostrar el resultado en la consola
        print(resultado_ascii)

if __name__ == "__main__":
    generar_arte_ascii()