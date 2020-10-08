import benchmarck as bn
import numpy as np
from decimal import *

getcontext().prec=9
def geo_mean(iterable):
    a = np.array(iterable)
    return a.prod()**(1.0/len(a))

a=[]
k2 = []
s2 = []
v2 = []
k4 = []
s4 = []
v4 = []
kr = []
sr = []
kd = []
sd = []

for i in range(0,1000):
    dt = bn.data()
    k2.append(dt[0])
    s2.append(dt[1])
    v2.append(dt[2])
    k4.append(dt[3])
    s4.append(dt[4])
    v4.append(dt[5])
    kr.append(dt[6])
    sr.append(dt[7])
    kd.append(dt[8])
    sd.append(dt[9])
    if i==250 or i ==500 or i==750:
        print("avance: "+ str(i))

print("Creación de llaves")
print("             Promedio                    Desviación estándar                 Med. Geom")
print("X25519       " + str(np.mean(k2)) + "                    " + str(np.std(k2)) + "                 "+ str(geo_mean(k2)))
print("X448         " + str(np.mean(k4)) + "                    " + str(np.std(k4)) + "                 "+ str(geo_mean(k4)))
print("RSA          " + str(np.mean(kr)) + "                    " + str(np.std(kr)) + "                 "+ str(geo_mean(kr)))
print("DSA          " + str(np.mean(kd)) + "                    " + str(np.std(kd)) + "                 "+ str(geo_mean(kd)))
print("")
print("Firmado")
print("             Promedio                    Desviación estándar                 Med. Geom")
print("X25519       " + str(np.mean(s2)) + "                    " + str(np.std(s2)) + "                 "+ str(geo_mean(s2)))
print("X448         " + str(np.mean(s4)) + "                    " + str(np.std(s4)) + "                 "+ str(geo_mean(s4)))
print("RSA          " + str(np.mean(sr)) + "                    " + str(np.std(sr)) + "                 "+ str(geo_mean(sr)))
print("DSA          " + str(np.mean(sd)) + "                    " + str(np.std(sd)) + "                 "+ str(geo_mean(sd)))
print("")
print("Verificación")
print("             Promedio                    Desviación estándar                 Med. Geom")
print("X25519       " + str(np.mean(v2)) + "                    " + str(np.std(v2)) + "                 "+ str(geo_mean(v2)))
print("X448         " + str(np.mean(v4)) + "                    " + str(np.std(v4)) + "                 "+ str(geo_mean(v4)))