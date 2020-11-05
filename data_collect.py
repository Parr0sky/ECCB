# encoding: utf-8
import benchmarck as bn
import numpy as np
from decimal import *

getcontext().prec=9


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
n=int(input("Ingrese el número de vehículos en la red \n"))
iterations = 10000 if int(input("Ingrese el contexto: \n 1 para infraestructura \n 2 para vehículo \n")) == 1 else 100
for i in range(0,n):
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
print("             Promedio                    Desviación estándar                ")
print("X25519       " + str(np.mean(k2)) + "                    " + str(np.std(k2)))
print("X448         " + str(np.mean(k4)) + "                    " + str(np.std(k4)))
print("RSA          " + str(np.mean(kr)) + "                    " + str(np.std(kr)))
print("DSA          " + str(np.mean(kd)) + "                    " + str(np.std(kd)))
print("")
print("Firmado")
print("             Promedio                    Desviación estándar                ")
print("X25519       " + str(np.mean(s2)) + "                    " + str(np.std(s2)))
print("X448         " + str(np.mean(s4)) + "                    " + str(np.std(s4)))
print("RSA          " + str(np.mean(sr)) + "                    " + str(np.std(sr)))
print("DSA          " + str(np.mean(sd)) + "                    " + str(np.std(sd)))
print("")
print("Verificación")
print("             Promedio                    Desviación estándar                 ")
print("X25519       " + str(np.mean(v2)) + "                    " + str(np.std(v2)))
print("X448         " + str(np.mean(v4)) + "                    " + str(np.std(v4)))