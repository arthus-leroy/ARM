# PROJET ARM

### Bootloader
1 - Flasher le code
2 - Lancer l'UI avec ./UI.py <chemin du tty> <baudrate> dans un terminal
3 - Reset la carte avec le bouton noir
4 - Attendre qu'un "Begin" s'affiche dans le terminal
5 - Envoyer le Bootloader choisi si le boutton User est poussé

Le boutton User permet d'envoyer un code au booloader au lieu de jump
directement sur le code en flash.
Un bouton "Flush input buffer" est là pour les rares cas où un message
arriverait incomplet et qu'on ne recevrait que 1 octet ou 2. Dans ce cas
preci, le message suivant serait invalide.

Le Bootloader est correct en tout point : le code est au bon endroit, le
le pc et sp sont corrects, mais le code ne se lance pas (meme en placant
la flash de l'application à FLASH_PROGRAM).

### Manager
1 - Flasher le code
2 - Lancer l'UI avec ./UI.py <chemin du tty> <baudrate> dans un terminal
3 - Reset la carte avec le bouton noir
4 - Attendre qu'un "Welcome to the Manager !" s'affiche dans le terminal

Toute les operations, sauf l'envoie de la clé publique et le le fait de
quitter le manager ont besoin du mot de passe principal. Il est possible
de le modifier.
Les champs à coté de "Send public key" et "Sign" sont là pour afficher
les informations reçues.

Le Manager est fini avec les bonus, sauf l'interface CDC (pour manque
de matériel permettant de faire GPIO -> USB). Tout marche parfaitement
d'aussi loin que nous avons pu tester.