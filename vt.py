# Analizar Samples 
# Api VirusTotal
# Desarrollado por Eric Alberto Martínez
# Hacking Público y sistemas informáticos
# AguasHack - No Hacking No Fun
# Version 1.0
''' Este script permite calcular el Hash MD5 de archivos
    y manipular los resultados obtenidos en Virus Total,
    el código puede ser manipulado y/o copiado manteniendo las 
    11 primeras líneas de código.
''' 
# Importamos librerías

import requests
import hashlib

# Tu clave API de virusTotal (Tienes que registrarte)
apiKey = ''
    
# clase para obtener datos o subir archivos
class virusApi:
    

    # Función para escanear un archivo
    def escanear(self, apiKey, archivo):
        print "Analizando el archivo...\n"
        # Configuramos la APIKEY
        params = {'apikey': apiKey}
        # Abrimos el archivo en modo binario                                    
        files = {'file': (archivo, open(archivo, 'rb'))} 
        # Hacemos la petición al sitio              
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', 
                                files=files, params=params)
        # obtenemos la respuesta del sitio
        json_response = response.json()                                 
    
    # Función para Re-escanear
    def rescanear(self, apiKey, md5):
        # configuramos la APIKEY y el hashMD5
        params = {'apikey': apiKey, 
                'resource': md5}                                        
        # Hacemos la petición al sitio
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan',
                                params=params)
        # Obtenemos la Respuesta del sitio                          
        json_response = response.json()                                 
    
    # Función para Obtener los resultados de un análisis
    def obtenerResultados(self, apiKey, md5):
        print "Obteniendo Resultados...\n"
        # Configuramos la APIKEY y el HashMD5
        params = {'apikey': apiKey, 
                'resource': md5} 
        # Creamos las cabeceras                                     
        headers = {
          "Accept-Encoding": "gzip, deflate",
          "User-Agent" : "gzip,  Mi Aplicacion python para VirusTotal"
          }     
        # hacemos la petición al sitio                                                      
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                params=params, headers=headers)
        # obtenemos la respuesta del sitio      
        json_response = response.json() 
        # obtenemos solo las claves de la respuesta                             
        claves = json_response.keys()   
        # declare una variable                              
        x = 'scans'     
        # ciclo para obtener los primeros resultados excepto los de la detección                                                 
        for clave, valor in json_response.items():  
            # si la clave no es igual a 'scans'                 
            if clave != x:
                # imprimimos los primeros resultados                                                
                print clave, ':\t\t', valor
        # declaramos una lista                          
        lista = []
        # ciclo para obtener las claves del segundo resultado                                                       
        for i in json_response['scans'].keys(): 
            # agrega cada clave a la lista                              
            lista.append(i) 
            # Asignamos la variable                                           
            j = json_response
            # Variable que contiene si el archivo es detectado o no p/c antivirus                                           
            detectado = str(j['scans'][i]['detected'])
            # Variable que contiene el tipo de amenaza que es detectada p/c antivirus                  
            resultado = str(j['scans'][i]['result'])
            # imprimimos el resultado                   
            print i + "\t\t" + detectado + "\t\t" + resultado           

# Instanciamos la clase
virusTotal = virusApi()                                                 
'''
Creo que apartir de aqui el codigo no necesita explicación
ya que son cosas básicas que son fáciles de entender, aun 
así si existen dudas no duden en comentar en el grupo de
Hacking Público & sistemas informáticos
'''
print "\nHola, Bienvenido\nQue deseas hacer?"
print '''
[1] Escanear
[2] Re Escanear
[3] Obtener resultados
'''
eleccion = raw_input("\n::> ")
if eleccion == '1':
    archivo = raw_input("\nIngresa la ruta del archivo \n::> ")
    virusTotal.escanear(apiKey, archivo)                                
    archivo = open(archivo, 'rb')
    # Calculamos el MD5 del archivo                                     
    md5 = hashlib.md5(archivo.read()).hexdigest()                       
    archivo.close()
    print "El hashMD5 del archivo es: " + md5
    virusTotal.obtenerResultados(apiKey, md5)
elif eleccion == '2':
    archivo = raw_input("\nIngresa la ruta del archivo \n::> ")
    archivo = open(archivo, 'rb')
    # Calculamos el MD5 del archivo
    md5 = hashlib.md5(archivo.read()).hexdigest()
    archivo.close()
    print "El hashMD5 del archivo es: " + md5
    virusTotal.rescanear(apiKey, md5)
    virusTotal.obtenerResultados(apiKey, md5)
else:
    archivo = raw_input("\nIngresa la ruta del archivo \n::> ")
    archivo = open(archivo, 'rb')
    # Calculamos el MD5 del archivo
    md5 = hashlib.md5(archivo.read()).hexdigest()
    archivo.close()
    print "El hashMD5 del archivo es: " + md5
    virusTotal.obtenerResultados(apiKey, md5)
