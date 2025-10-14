# Trabajo_Seguridad
Password Manager unlocked by Smart Card

Instalaciones necesarias:
pip install click cryptography python-pkcs11

En windows puede ser necesario añadir las direcciones de los modulos OpenSC al path, la localización por defecto es:
C:\Program Files\OpenSC Project\OpenSC\tools
C:\Program Files\OpenSC Project\OpenSC\pkcs11

Comandos para ejecutar:
cd /Ubicacion/Del/Proyecto

python -m src.cli test //Prueba que se lea el DNIe y que puede se puede extraer el certificado, tiene la capacidad de firmar y que se firma correctamente

python -m src.cli sign Documento_importante_.txt -o mi_firma.json //Se indica el fichero a firmar y se puede dar nombre a la firma generada, en caso de no querer darle nombre a la firma solo hay que quitar el trozo -o mi_firma.json

python -m src.cli verify Documento_importante.txt mi_firma.signature.json //Para verificar la firma hay que indicar el nombre del fichero firmado y el de la firma generada