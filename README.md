# Porxy SOCKS V5

# Estructura del proyecto
En el directorio principal se puede encontrar el Makefile principal y el informe del proyecto.

En el directorio src se encuntran los siguientes subdirectorios:

* **buffer** - Contiene el codigo fuente para el manejo de un buffer
* **dog-client** - Contiene el codigo fuente del cliente administrador DOG del servidor proxy
* **include** - Contiene todas las definiciones de librerias utilizadas en el proyecto
* **logger** - Contiene el codigo fuente para el manejo de los logs
* **managers** - Contiene el codigo fuente para el handling de conexiones al servidor SOCKSv5 y al administrador bajo los subdirectorios socksv5 y dog_manager respectivamente. En el directorio dog_manager se encuentra el codigo fuente del handler en dog_manager.c y el codigo de utilidades para dicho handler en dog.c
* **parser** - Contiene subdirectorios para los dos protocolos que se requrieron parsear: POP3 y SOCKSv5. En el subdirectorio POP3 se encuentra unicamente un archivo con el parsing de la negociación inicial de usuario y contraseña. En el subdirectorio socksv5 se encuentran los archivos para parsear los tres paquetes posibles: hello, authentication y request.
* **selector** - Contiene el codigo fuente para el manejo de los fd.
* **statistics** - Contiene el codigo fuente para el manejo de estadisticas volatiles del servidor.
* **stm** - Contiene el codigo fuente de la máquina de estados
* **utils** - Contiene el codigo fuente de librerias de utilities: manejo de usuarios y utilidades para manejo de direcciones.

En el directorio src se encuntran a su vez los archivos args.c, encargado de parsear y resolver los argumentos al ejecutar el servidor, y main.c, encargado de iniciar los sockets pasivos y demás configuraciones iniciales del servidor.

# Construcción
En el directorio principal hacer un make all para construir o un make clean para eliminar los archivos generados.

# Ejecución

Luego el ejecutable del servidor proxy se encuentra en el directorio principal bajo el nombre **socks5d**, el
ejecutable del administrador del servidor tambien esta bajo el mismo directorio con el nombre **dog**

# Opciones de ejecución del servidor proxy SOCKSv5

-h               Imprime la ayuda y termina
-l   dirección   Dirección donde servirá el proxy SOCKS
-L   dirección   Dirección donde servirá el servicio de adminsitración
-p   puerto      Puerto entrante conexiones SOCKS
-P   puerto      Puerto entrante conexiones adminsitración
-u   name:pass   Usuario y contraseña de usuario que puede usar el proxy, hasta 10
-N               Deshabilitar spoofing de contrasenias sobre POP3
-v               Imprime información sobre la versión y termina
  
# Comandos al utiliza el administrador de servidor

list        page_number   Retorna la página indicada del listado de usuarios registrados en el servidor SOCKS
hist                      Retorna la cantidad de conexiones historicas del servidor SOCKS
conc                      Retorna la cantidad de conexiones concurrentes en el servidor SOCKS
bytes                     Retorna la cantidad de bytes transferidos en el servidor SOCKS
checksniff                Retorna el estado del sniffer de credenciales sobre POP3
checkauth                 Retorna el estado de la autenticación en el servidor
getpage                   Retorna la cantidad de usuarios en una página
add         user:pass     Agrega el usuario especificado
del         user          Borrar el usuario especificado
sniff       on/off        Apagar o prender el sniffer de credenciales sobre POP3
auth        on/off        Apagar o prender la autenticación en el servidor
setpage     page_size     Establecer el tamaño de página para el listado de usuarios, donde el tamaño debe ser 
                          entre 1 y 200


 
