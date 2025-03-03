# Anticheat-Prym

Creado por:
https://kevinkorduner.com/

Contacto:
info@kevinkorduner.com
---

# Anticheat por Hashes

Este proyecto implementa un sistema anticheat en forma de DLL para plataformas Windows, basado en la verificación de hashes SHA256 de módulos cargados en procesos en ejecución. Su objetivo es detectar la presencia de software no autorizado (cheats) mediante la comparación de hashes predefinidos y, en caso de encontrar coincidencias, terminar de forma inmediata el proceso sospechoso (o tomar otra determinada acción).

## Características Principales

- **Detección por Hashes:**  
  El sistema compara el hash SHA256 de cada módulo cargado contra una lista de hashes conocidos asociados a cheats (por ejemplo, Cheat Engine y Autoclicker).  
- **Optimización con Caché:**  
  Se utiliza una caché global para almacenar los hashes de archivos ya calculados, evitando recálculos y mejorando el rendimiento.
- **Multi-hilo y Paralelismo:**  
  La función `ScanAllProcesses` lanza un hilo por cada proceso detectado para realizar el escaneo de forma paralela, optimizando el tiempo de respuesta.
- **Registro de Actividades:**  
  Los eventos relevantes se registran en un archivo `logs.txt`, facilitando el seguimiento de las acciones y posibles errores. Esta funcionalidad se activa o desactiva según la variable `g_ShowLogs`.
- **Interfaz COM y Compatibilidad:**  
  La DLL exporta la función `RealizarScan` en formato BSTR, lo que facilita su integración con aplicaciones en VB6 u otros entornos que requieran interoperabilidad con COM.

## Cómo Funciona

1. **Inicialización y Preparación:**  
   Al cargarse, la DLL almacena su módulo en una variable global. El entorno se prepara para el escaneo de procesos y módulos.

2. **Cálculo del Hash:**  
   - La función `ComputeFileSHA256` abre el archivo correspondiente al módulo, lo lee en bloques y utiliza las funciones de la API de Windows (`CryptAcquireContextA`, `CryptCreateHash` y `CryptHashData`) para calcular su hash SHA256.
   - Si el hash ya fue calculado anteriormente, se recupera desde la caché global para evitar redundancias.

3. **Escaneo de Procesos:**  
   - Se obtiene una lista de procesos activos mediante `CreateToolhelp32Snapshot`.
   - Por cada proceso, se recorren los módulos cargados y se calcula el hash de cada uno.
   - Se compara el hash obtenido con la lista de hashes de cheats. En caso de detectar un match, se registra el evento y se termina el proceso utilizando `TerminateProcess`.

4. **Ejecución en Paralelo:**  
   - El escaneo se realiza en un hilo separado (lanzado a través de `CreateThread`), de modo que la aplicación principal (por ejemplo, una aplicación VB6) no se vea afectada.
   - Al finalizar, se muestra un `MessageBox` con el resultado (en modo desarrollo) y se escribe un log detallado del proceso.

## Uso e Integración

- **Modo Desarrollo vs. Modo Sigiloso:**  
  La variable `g_ShowLogs` permite alternar entre la generación de logs y la visualización de mensajes (ideal para pruebas en desarrollo) y un funcionamiento sigiloso en producción.

- **Exportación de Función:**  
  La función exportada `RealizarScan` recibe un parámetro booleano que indica si se deben mostrar los logs y mensajes. Este parámetro permite que el anticheat se adapte a distintos escenarios operativos.

## Consideraciones Finales

Este anticheat es una herramienta sencilla pero poderosa para proteger aplicaciones de software malicioso o cheats ya teniendo su HASH. Su implementación modular y el uso de técnicas de programación concurrente lo hacen eficiente y adaptable a diferentes entornos de ejecución.

---
