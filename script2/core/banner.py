#!/usr/bin/env python
# -*- coding: utf-8 -*-
#autor @apuromafo
#history: i was search how do a banner in python3, and see many examples, not was like a static,and was see what happen if can be random
#idea core as name  https://www.programcreek.com/python/?CodeExample=print+banner (many use core.py)
#use choice from https://www.w3schools.com/python/module_random.asp 
#colored use  from https://www.stechies.com/print-colored-text-python/ 
#banner001 created from https://patorjk.com/software/taag/#p=display&h=1&v=0&w=%20&f=THIS&t=Bienvenido 
#banner002 created from https://patorjk.com/software/taag/#p=display&h=1&v=0&w=%20&f=Small&t=Men%C3%BA%0ALaboral 
#banner003 created from https://patorjk.com/software/taag/#p=display&h=1&v=0&w=%20&f=Slant&t=Men%C3%BA%0ALaboral

from random import choice
from termcolor import colored
from colorama import init

def bienvenida() :
	init() #reset the terminal color
 
_colorido = ["red", "green", "yellow", "blue", "magenta", "cyan", "white", "light_grey", "dark_grey", "light_red", "light_green", "light_yellow", "light_blue", "light_magenta", "light_cyan"]  #random  color in this case 

_autor = '''
                                                 Menú Laboral
                                                 version: 1.0
                                     	       Autor: @Apuromafo
'''
_banner001 = """
 ▄▀▀█▄▄   ▄▀▀█▀▄   ▄▀▀█▄▄▄▄  ▄▀▀▄ ▀▄  ▄▀▀▄ ▄▀▀▄  ▄▀▀█▄▄▄▄  ▄▀▀▄ ▀▄  ▄▀▀█▀▄    ▄▀▀█▄▄   ▄▀▀▀▀▄  
▐ ▄▀   █ █   █  █ ▐  ▄▀   ▐ █  █ █ █ █   █    █ ▐  ▄▀   ▐ █  █ █ █ █   █  █  █ ▄▀   █ █      █ 
  █▄▄▄▀  ▐   █  ▐   █▄▄▄▄▄  ▐  █  ▀█ ▐  █    █    █▄▄▄▄▄  ▐  █  ▀█ ▐   █  ▐  ▐ █    █ █      █ 
  █   █      █      █    ▌    █   █     █   ▄▀    █    ▌    █   █      █       █    █ ▀▄    ▄▀ 
 ▄▀▄▄▄▀   ▄▀▀▀▀▀▄  ▄▀▄▄▄▄   ▄▀   █       ▀▄▀     ▄▀▄▄▄▄   ▄▀   █    ▄▀▀▀▀▀▄   ▄▀▄▄▄▄▀   ▀▀▀▀   
█    ▐   █       █ █    ▐   █    ▐               █    ▐   █    ▐   █       █ █     ▐           
▐        ▐       ▐ ▐        ▐                    ▐        ▐        ▐       ▐ ▐                 """

_banner002 = '''
  __  __              __              
 |  \/  | ___  _ _  _/_/              
 | |\/| |/ -_)| ' \| || |             
 |_|  |_|\___||_||_|\_,_|             
                                      
  _           _                     _ 
 | |    __ _ | |__  ___  _ _  __ _ | |
 | |__ / _` || '_ \/ _ \| '_|/ _` || |
 |____|\__,_||_.__/\___/|_|  \__,_||_|
                                                                                                                                                                                                                                 
'''
_banner003 = '''
    __  ___                __                 
   /  |/  /___   ____   __/_/_                
  / /|_/ // _ \ / __ \ / / / /                
 / /  / //  __// / / // /_/ /                 
/_/  /_/ \___//_/ /_/ \__,_/                  
                                              
    __           __                         __
   / /   ____ _ / /_   ____   _____ ____ _ / /
  / /   / __ `// __ \ / __ \ / ___// __ `// / 
 / /___/ /_/ // /_/ // /_/ // /   / /_/ // /  
/_____/\__,_//_.___/ \____//_/    \__,_//_/   
'''                                   

_opcion=[_banner001,_banner002,_banner003]
print(colored(choice(_opcion), choice(_colorido)))
print(colored(_autor,choice(_colorido)))
''''''
