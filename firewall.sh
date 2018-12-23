#! /bin/bash
I="/sbin/iptables"
function flush() {
        $I --table filter --flush
        $I --table nat --flush
        $I --table mangle --flush
        $I --table raw --flush
        $I --table security --flush
        $I --delete-chain
        $I --table filter --policy INPUT DROP
        $I --table filter --policy OUTPUT DROP
        $I --table filter --policy FORWARD DROP
}

#Policy de base en BLOCK --> tout ce qui n'est pas autorisé est bloqué

#Par mesure de sécurité ajout d'une règle qui deny pour le traffic entrant
function youshouldnotpass() {
        $I -A INPUT --protocol all --jump DROP
        $I -A FORWARD --protocol all --jump DROP
}

#Fonction qui laisse passer tous les connexions sortantes
function youcanpass() {
        $I -A OUTPUT --protocol all --jump ACCEPT
}

#Fonction qui autorise uniquement l'envoie de paquet vers le localhost depuis l'interface de loopback vers l'interface de loopback
function lo() {
        $I -A INPUT --protocol all --source localhost ! --in-interface lo --jump DROP
        $I -A INPUT --in-interface lo --protocol all --jump ACCEPT
        $I -A OUTPUT --out-interface lo --protocol all --jump ACCEPT
        $I -A FORWARD --in-interface lo --out-interface lo --protocol all --jump ACCEPT
}

#Fonction d'autorisation icmp pour les connexions entrantes, sortantes, forwardées
function icmp(){
        $I -A INPUT --protocol icmp --jump ACCEPT
        $I -A OUTPUT --protocol icmp --jump ACCEPT
        $I -A FORWARD --protocol icmp --jump ACCEPT
}

#Fonction d'ouverture des ports 80 et 443 pour les connexion entrantes
function http(){
        $I -A INPUT --protocol tcp --sport 80 --jump ACCEPT
        $I -A INPUT --protocol tcp --sport 443 --jump ACCEPT
        $I -A FORWARD --protocol tcp --sport 80 --jump ACCEPT
        $I -A FORWARD --protocol tcp --sport 443 --jump ACCEPT
}

#Fonction d'ouverture du port 53 pour les connexions entrantes
function dns() {
        $I -A INPUT --protocol udp --sport 53 --jump ACCEPT
        $I -A FORWARD --protocol udp --sport 53 --jump ACCEPT
        $I -A INPUT --protocol tcp --sport 53 --jump ACCEPT
        $I -A FORWARD --protocol tcp --sport 53 --jump ACCEPT
}

#Fonction d'autorisation du flux SSH

function ssh() {
        $I -A INPUT --protocol tcp --dport 22 --jump ACCEPT
}

#Fonction d'autorisation du flux DHCP
function dhcp() {
        $I -A INPUT --protocol tcp --sport 67 --jump ACCEPT
        $I -A INPUT --protocol udp --sport 67 --jump ACCEPT
        $I -A INPUT --protocol tcp --dport 68 --jump ACCEPT
        $I -A INPUT --protocol udp --dport 68 --jump ACCEPT
}

#$I -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

flush

youcanpass

lo

icmp

http

dns

ssh

dhcp

youshouldnotpass