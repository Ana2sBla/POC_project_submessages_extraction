# -*- coding: utf-8 -*-
"""
Created on Tue Nov  7 14:06:54 2023

@author: bella
"""

# =============================================================================
# =============================================================================
# # Blibli
# =============================================================================
# =============================================================================



#Pour lire les paquets
from scapy.all import rdpcap, IP, TCP
from scapy.utils import hexdump

#For package
import numpy as np
import pandas as pd

#importation
import os



# =============================================================================
# Fonctions
# =============================================================================
print("\n--------------------------fonctions à utiliser-----------------------------------------\n")

print("\nafficher_tcp_hexdump_to_str")
print("In:filename d'un packet.pcap ou pcapng\nOut: df comme dans wireshark ")

def tcp_messages_from_pcap_to_df(filename):
    # Charger le fichier PCAPNG
    packets = rdpcap(filename)

    # Data informations
    Time = []
    src_adresses = []
    dst_adresses = []

    # Packet data
    packets_data = []

    # Initialiser une chaîne pour stocker le résultat
    payload = []

    # All protocol payload
    tcp_payload = []

    # tcp payload and port 102
    tcp_payload_102 = []

    for packet in packets:
        # Packet data
        packets_data.append(packet)

        # Time informations
        Time.append(float(packet.time))
        Time_packets = [x - Time[0] for x in Time]

        # IP adresses (add checks for IP layer)
        if IP in packet:
            src_adresses.append(packet[IP].src)
            dst_adresses.append(packet[IP].dst)
        else:
            src_adresses.append('NaN')
            dst_adresses.append('NaN')

        # tcp payload and port 102
        if TCP in packet and (packet[TCP].dport == 102 or packet[TCP].sport == 102):
            tcp_payload_102.append(packet[TCP].payload.original.hex())
        else:
            tcp_payload_102.append('NaN')

        # payload
        if 'TCP' in packet:
            payload.append(hexdump(packet, dump=True))
        else:
            payload.append('NaN')

        # Tcp payload
        if TCP in packet:
            tcp_payload.append(packet[TCP].payload.original.hex())
        else:
            tcp_payload.append('NaN')

    # Vérification de la longueur des listes et remplissage avec 'NaN' si nécessaire
    max_length = max(len(Time_packets), len(src_adresses), len(dst_adresses),
                     len(packets_data), len(payload), len(tcp_payload),
                     len(tcp_payload_102))

    for l in [Time_packets, src_adresses, dst_adresses, packets_data,
              payload, tcp_payload, tcp_payload_102]:
        l.extend(['NaN'] * (max_length - len(l)))

    # Dataframe
    df = pd.DataFrame({
        'Time_packets': Time_packets,
        'src_addresses': src_adresses,
        'dst_addresses': dst_adresses,
        'payload': payload,
        'tcp_payload': tcp_payload,
        'tcp_payload_102': tcp_payload_102,
    })

    return df


print("\ndataframe_for_all_repository")
print("In:listes des repertoires contenant des packets .pcap ou pcapng\nOut: df concatené de tous les packets")
def df_from_pcap_to_df_for_all_repository(repertoire_list):
    
    # Liste pour stocker les DataFrames résultants
    liste_dataframes = []
    
    #Boucle sur les repertoire après
    for repertoire in repertoire_list:

        fichiers = os.listdir(repertoire)
        # Filtre les fichiers avec l'extension ".pcap" ou ".pcapng"
        fichiers_pcap = [fichier for fichier in fichiers if ( fichier.endswith(".pcap") or fichier.endswith(".pcapng") ) ]
        for i in range(len(fichiers_pcap)):
            nom_fichier = fichiers_pcap[i]
            fichiers_pcap[i] = str(repertoire) +"\\" +nom_fichier
    
    
        # Liste des noms de fichiers
        noms_fichiers = fichiers_pcap
    

    
        #test pour quelques packets
        noms_fichiers = noms_fichiers
        
        # Boucle pour traiter chaque fichier
        for fichier in noms_fichiers:
            # Appel de la fonction pour chaque fichier
            df_resultant = tcp_messages_from_pcap_to_df(fichier)
            
            #Ajout de la colonne pour connaitre le nom du repertoire
            df_resultant['Nom_du_repertoire'] = repertoire.split("\\")[1]
            df_resultant['Nom_du_packet'] = fichier.split("\\")[2]
            # Ajout du DataFrame résultant à la liste
            liste_dataframes.append(df_resultant)

    df = pd.concat(liste_dataframes, ignore_index=True)

    return liste_dataframes, df





# =============================================================================
# =============================================================================
# # Début du programme: Création du dataframe regroupant tout les fichiers pcap/pcapng
# =============================================================================
# =============================================================================
print("\n--------------------------Code-----------------------------------------\n")



# PCAPNG/PCAP file from github opensource
# https://github.com/Ana2sBla/ICS-Security-Tools
# https://github.com/Ana2sBla/s7-pcaps

repertoire1= "Data_found\\all_s7_data_from_ics_security_tools"
repertoire2= "Data_found\\all_s7_data_from_s7_pcaps"

#Création du dataframe concaténé df
repertoire_list = [repertoire1,repertoire2]
l_df,df = df_from_pcap_to_df_for_all_repository(repertoire_list)


# Enregistrer le DataFrame au format CSV
print("\nEnregistrement du dataframe au format CSV...")
df.to_csv('df_packets.csv',sep=';', index=False)





