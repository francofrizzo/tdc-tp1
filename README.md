# Modo de uso

Colocar las capturas `XXX.pcap` dentro de la carpeta `data`.

En el archivo `Makefile` modificar la variable `CAPTURE_FILES` para que posea
el nombre de las capturas (No incluir extensión):

        CAPTURE_FILES=data/XXX data/YYY

Finalmente ejecutar:

        make

El mismo generará toda la información y gráficos necesarios para compilar el
informe.
