#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Uso de frames para animación ASCII, inspirado en [curl.exe ascii.live/parrot].
"""
import time
import os
import itertools # Para iterar la animación indefinidamente o un número fijo de veces.

# --- Metadatos ---
__description__ = 'Uso de frames para animación ASCII'
__author__ = 'Apuromafo'
__version__ = '0.0.2'
__date__ = '29.11.2024'

# --- Funciones de Utilidad ---

def clear_screen():
    """Limpia la pantalla usando el comando apropiado para el sistema operativo."""
    # Nota: os.system llama a un proceso externo, es la forma más simple pero no la más rápida.
    # Para mayor optimización en un bucle muy rápido, se podría usar librerías como 'curses' o 'rich'.
    os.system('cls' if os.name == 'nt' else 'clear')

def display_frame(frame):
    """Limpia la pantalla e imprime un frame."""
    clear_screen()
    print(frame)

def animate_loro(frames, delay=0.05, repeat_count=2):
    """
    Anima al loro ASCII.

    Args:
        frames (list[str]): Una lista de strings representando cada frame.
        delay (float): El tiempo de espera entre cada frame en segundos.
        repeat_count (int): Número de veces que se repetirá la animación.
                            Usa None para repetición infinita.
    """
    if repeat_count is None:
        # Repetición infinita
        frame_iterator = itertools.cycle(frames)
    else:
        # Repetición por un número de veces
        frame_iterator = itertools.chain.from_iterable(itertools.repeat(frames, repeat_count))

    try:
        for frame in frame_iterator:
            display_frame(frame)
            time.sleep(delay)
    except KeyboardInterrupt:
        # Permite al usuario detener la animación con Ctrl+C
        pass

# --- Frames de la Animación ---

# Se recomienda mantener los frames en su propia estructura de datos (lista de strings).
# Usar una función para obtener los frames podría ser útil si el contenido viniera de un archivo.
# Nota: he eliminado las tabulaciones iniciales excesivas dentro de los frames para un mejor centrado
# en la mayoría de las terminales, aunque esto es sensible al formato original.

LORO_FRAMES = [
"""
          .cccc;;cc;';c.
        .,:dkdc:;;:c:,:d:.
       .loc'.,cc::::::,..,:.
     .cl;....;dkdccc::,...c;
   .c:,';:'..ckc',;::;....;c.
 .c:'.,dkkoc:ok:;llllc,,c,';:.
.;c,';okkkkkkkk:,llllc,:kd;.;:,.
co..:kkkkkkkkkk:;llllc':kkc..oNc
.cl;.,okkkkkkkkc,:cll;,okkc'.cO;
;k:..ckkkkkkkkkl..,;,.;xkko:',l'
.,...';dkkkkkkkd;.....ckkkl'.cO;
.,,:,.;oo:ckkkkkdoc;;cdkkkc..cd,
.cclo;,ccdkkl;llccdkkkkkkkd,.c;
.lol:;;okkkkkxooc::loodkkkko'.oc
.c:'..lkkkkkkkkkkkkkkkkkkkkd,.oc
.lo;,ccdkkkkkkkkkkkkkkkkkkd,.c;
,dx:..;lllllllllllllllllllloc'...
cNO;........................................,
""",
"""
         .ckx;'........':c.
      .,:c:c:::oxxocoo::::,',.
    .odc'..:lkkoolllllo;..;d,
    ;c..:o:..;:..',;'.......;.
   ,c..:0Xx::o:.,cllc:,'::,.,c.
   ;c;lkXXXXXXl.;lllll;lXXOo;':c.
 ,dc.oXXXXXXXXl.,lllll;lXXXXx,c0:
 ;Oc.oXXXXXXXXo.':ll:;'oXXXXO;,l'
 'l;;OXXXXXXXXd'.'::'..dXXXXO;,l'
 'l;:0XXXXXXXX0x:...,:o0XXXXk,:x,
 'l;;kXXXXXXKXXXkol;oXXXXXXXO;oNc
,c'..ckk0XXXXXXXXXX00XXXXXXX0:;o:.
.:;..:dd::ooooOXXXXXXXXXXXXXXXo..c;
.',',:co0XX0kkkxx0XXXXXXXXXXXXXX0c..;l.
.:;'..oXXXXXXXXXXXXXXXXXXXXXXXXXXXXXko;';:.
.cdc..:oOXXXXXXXXKXXXXXXXXXXXXXXXXXXXXXXo..oc
:0o...:dxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxo,.:,
cNo........................................;',
""",
"""
         .cc;. .cc.
    .,,cc:cc:lxxxl:ccc:;,.
    .lo;...lKKklllookl..cO;
  .cl;.,;'.okl;...'.;,..';:.
  .:o;;dkx,.ll..,cc::,..,'.;:,.
  co..lKKKkokl.':lllo;''ol..;dl.
.,c;.,xKKKKKKo.':llll;.'oOxo,.cl,.
cNo..lKKKKKKKo'';llll;;okKKKl..oNc
cNo..lKKKKKKKko;':c:,'lKKKKKo'.oNc
cNo..lKKKKKKKKKl.....'dKKKKKxc,l0:
.c:'.lKKKKKKKKKk;....oKKKKKKo'.oNc
  ,:.,oxOKKKKKKKOxxxxOKKKKKKxc,;ol:.
  ;c..'':oookKKKKKKKKKKKKKKKKKk:.'clc.
,dl'.,oxo;'';oxOKKKKKKKKKKKKKKKOxxl::;,,.
.dOc..lKKKkoooookKKKKKKKKKKKKKKKKKKKxl,;ol.
cx,';okKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKl..;lc.
co..:dddddddddddddddddddddddddddddddddl:;''::.
co...........................................",
""",
"""
         .ccccccc.
   .,,,;cooolccol;;,,.
  .dOx;..;lllll;..;xOd.
.cdo,',loOXXXXXkll;';odc.
,oo:;c,':oko:cccccc,...ckl.
;c.;kXo..::..;c::'.......oc
,dc..oXX0kk0o.':lll;..cxxc.,ld,
kNo.'oXXXXXXo'':lll;..oXXOd;cOd.
KOc;oOXXXXXXo.':lol,..dXXXXl';xc
Ol,:k0XXXXXX0c.,clc'.:0XXXXx,.oc
KOc;dOXXXXXXXl..';'..lXXXXXd..oc
dNo..oXXXXXXXOx:..'lxOXXXXXk,.:; ..
cNo..lXXXXXXXXXOolkXXXXXXXXXkl;..;:.;.
.,;'.,dkkkkk0XXXXXXXXXXXXXXXXXOxxl;,;,;l:.
  ;c.;:''''':doOXXXXXXXXXXXXXXXXXXOdo;';clc.
  ;c.lOdood:'''oXXXXXXXXXXXXXXXXXXXXXk,..;ol.
  ';.:xxxxxocccoxxxxxxxxxxxxxxxxxxxxxxl::'.';;.
  ';........................................;l',
""",
"""
.;:;;,.,;;::,.
.;':;........'co:.
.clc;'':cllllc::,.':c.
.lo;;o:coxdlooollc;',::,,.
.c:'.,cl,.'lc',,;;'......cO;
do;';oxoc::l;;llllc'.';;'.';.
c..ckkkkkkkd,;llllc'.:kkd;.':c.
'.,okkkkkkkkc;llllc,.:kkkdl,cO;
..;xkkkkkkkkc,ccll:,;okkkkk:,cl,
..,dkkkkkkkkc..,;,'ckkkkkkkc;ll.
..'okkkkkkkko,....'okkkkkkkc,:c.
c..ckkkkkkkkkdl;,:okkkkkkkkd,.',';.
d..':lxkkkkkkkkxxkkkkkkkkkkkdoc;,;'..'.,.
o...'';llllldkkkkkkkkkkkkkkkkkkdll;..'cdo.
o..,l;'''''';dkkkkkkkkkkkkkkkkkkkkdlc,..;lc.
o..;lc;;;;;;,,;clllllllllllllllllllllc'..,:c.
o..........................................;',
""",
"""
        .,,,,,,,,,.
      .ckKxodooxOOdcc.
    .cclooc'....';;cool.
    .loc;;;;clllllc;;;;;:;,.
  .c:'.,okd;;cdo:::::cl,..oc
  .:o;';okkx;';;,';::;'....,;,.
  co..ckkkkkddk:,cclll;.,c:,:o:.
  co..ckkkkkkkk:,cllll;.:kkd,.':c.
.,:;.,okkkkkkkk:,cclll;.:kkkdl;;o:.
cNo..ckkkkkkkkko,.;llc,.ckkkkkc..oc
,dd;.:kkkkkkkkkx;..;:,.'lkkkkko,.:,
  ;c.ckkkkkkkkkkc.....;ldkkkkkk:.,'
,dc..'okkkkkkkkkxoc;;cxkkkkkkkkc..,;,.
kNo..':lllllldkkkkkkkkkkkkkkkkkdcc,.;l.
KOc,l;''''''';lldkkkkkkkkkkkkkkkkkc..;lc.
xx:':;;;;,.,,...,;;cllllllllllllllc;'.;oo,
cNo.....................................oc,
""",
"""
         .ccccccc.
      .ccckNKOOOOkdcc.
    .;;cc:ccccccc:,::::,,.
  .c;:;.,cccllxOOOxlllc,;ol.
  .lkc,coxo:;oOOxooooooo;..:,
.cdc.,dOOOc..cOd,.',,;'....':c.
cNx'.lOOOOxlldOl..;lll;.....cO;
,do;,:dOOOOOOOOOl'':lll;..:d:.'c,
co..lOOOOOOOOOOOl'':lll;.'lOd,.cd.
co.,dOOOOOOOOOOOo,.;llc,.,dOOc..dc
co..lOOOOOOOOOOOOc.';:,..cOOOl..oc
.,:;.'::lxOOOOOOOOo:'...,:oOOOc..dc
;Oc..cl'':llxOOOOOOOOdcclxOOOOx,.cd.
.:;';lxl''''':lldOOOOOOOOOOOOOOc..oc
,dl,.'cooc:::,....,::coooooooooooc'.c:
cNo.................................oc,
""",
"""
            .cccccccc.
      .,,,;;cc:cccccc:;;,.
    .cdxo;..,::cccc::,..;l.
   ,oo:,,:c:cdxxdllll:;,';:,.
  .cl;.,oxxc'.,cc,.',;;'...oNc
  ;Oc..cxxxc'.,c;..;lll;...cO;
.;;',:ldxxxdoldxc..;lll:'...'c,
;c..cxxxxkxxkxxxc'.;lll:'','.cdc.
.c;.;odxxxxxxxxxxxd;.,cll;.,l:.'dNc
.:,''ccoxkxxkxxxxxxx:..,:;'.:xc..oNc
.lc,.'lc':dxxxkxxxxxdl,...',lx:..dNc
.:,',coxoc;;ccccoxxxxxo:::oxxo,.cdc.
.;':;.'oxxxxxc''''';cccoxxxxxxxxxkxc..oc
,do:'..,:llllll:;;;;;;,..,;:lllllllll;..oc
cNo.....................................oc,
""",
"""
              .ccccc.
            .cc;'coooxkl;.
         .:c:::c:,;,,,;c;;,.'.
       .clc,',:,..:xxocc;...c;
     .c:,';:ox:..:c,,,,,,...cd,
   .c:'.,oxxxxl::l:.;loll;..;ol.
   ;Oc..:xxxxxxxxx:.,llll,....oc
.,;,',:loxxxxxxxxx:.,llll;.,;.'ld,
.lo;..:xxxxxxxxxxxx:.'cllc,.:l:'cO;
.:;...'cxxxxxxxxxxxxol;,::,..cdl;;l'
.cl;':;'';oxxxxxxxxxxxxx:....,cooc,cO;
.,,,::;,lxoc:,,:lxxxxxxxxo:,,;lxxl;'oNc
.cdxo;':lxxxxxxc'';cccccoxxxxxxxxxxxxo,.;lc.
.loc'.'lxxxxxxxxocc;''''';ccoxxxxxxxxx:..oc
occ'..',:cccccccccccc:;;;;;;;;:ccccccccc,.'c,
Ol;......................................;l',
""",
"""
              ,ddoodd,
           .cc' ,ooccoo,'cc.
        .ccldo;....,,...;oxdc.
      .,,:cc;.''..;lol;;,'..lkl.
    .dkc';:ccl;..;dl,.''.....oc
  .,lc',cdddddlccld;.,;c::'..,cc:.
  cNo..:ddddddddddd;':clll;,c,';xc
  .lo;,clddddddddddd;':clll;:kc..;'
.,:;..:ddddddddddddd:';clll;;ll,..
;Oc..';:ldddddddddddl,.,c:;';dd;..
.''',:lc,'cdddddddddo:,'...'cdd;..
.cdc';lddd:';lddddddddd;.';lddl,..
.,;::;,cdddddol;;lllllodddddddlcodddd:.'l,
.dOc..,lddddddddlccc;'';cclddddddddddd;,ll.
.coc,;::ldddddddddddl:ccc:ldddddddddlc,ck;
,dl::,..,cccccccccccccccccccccccccccc:;':xx,
cNd.........................................;lOc
"""]

# --- Ejecución Principal ---

def main():
    """Función principal para ejecutar la animación."""
    # Puedes ajustar el delay (velocidad) y el número de repeticiones aquí.
    # repeat_count=None para repetición infinita (hasta Ctrl+C)
    animate_loro(LORO_FRAMES, delay=0.08, repeat_count=2)
    
    # Limpia la pantalla después de terminar
    clear_screen()
    
    print("¡Animación finalizada!")
    print(f"Versión: {__version__}")
    print(f"Autor: {__author__}")

if __name__ == "__main__":
    main()