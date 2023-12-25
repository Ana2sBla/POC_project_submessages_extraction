# -*- coding: utf-8 -*-
"""
Created on Tue Nov 28 14:31:46 2023

@author: bella
"""

#Blibliothèques classiques
from matplotlib import pyplot as plt
import pandas as pd 


import math
from collections import Counter
import random
import copy
import os

import numpy as np
from statistics import mean,variance
from scipy.stats import pearsonr

#Pour lire les paquets
from scapy.all import rdpcap, IP, TCP
from scapy.utils import hexdump





def tcp_messages_from_pcap_to_df(filename):
    """
    Extrait les informations pertinentes des paquets TCP d'un fichier PCAPNG et crée un DataFrame.

    Entrée:
    - filename (str): Le chemin du fichier PCAPNG.

    Sortie:
    - df (DataFrame): Un DataFrame Pandas contenant les colonnes suivantes :
        - Time_packets (float): Temps écoulé depuis le premier paquet.
        - src_addresses (str): Adresses IP source.
        - dst_addresses (str): Adresses IP de destination.
        - payload (str): Hexdump de la charge utile du paquet (ou 'NaN' si non applicable).
        - tcp_payload (str): Représentation hexadécimale de la charge utile TCP (ou 'NaN' si non applicable).
        - tcp_payload_102 (str): Représentation hexadécimale de la charge utile TCP lorsque le port est 102 (ou 'NaN' si non applicable).
    """


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


def df_from_pcap_to_df_for_all_repository(repertoire_list):
    """
    Crée un DataFrame à partir de fichiers PCAPNG/PCAP pour plusieurs répertoires.

    Entrée:
    - repertoire_list (list): Liste des répertoires contenant des fichiers PCAPNG/PCAP.

    Sortie:
    - liste_dataframes (list): Liste des DataFrames résultants pour chaque fichier.
    - df (DataFrame): DataFrame Pandas contenant les colonnes résultantes de la concaténation.
    """
    
    
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


#------------

def data_open_source_to_df(filename_df_data_open_source):
    """
    Convertit les données d'un fichier CSV en un DataFrame formaté.

    Entrée:
    - filename_df_data_open_source (str): Le chemin du fichier CSV.

    Sortie:
    - payload_df_formate (DataFrame): DataFrame Pandas contenant la colonne 'tcp_payload' formatée.
    """
    df = pd.read_csv(filename_df_data_open_source,sep=';')
    df_filtree = df.dropna(subset=['tcp_payload']).loc[df['tcp_payload'].str.len() >= 5] #Suppression des messages sans tcp payload et dont la tcp payload est très courte, 5 est un valeur abitraire. La condition > 5 n'est pas obligatoire ici car les message très court sont traités par la suite
    payload_df = pd.DataFrame(df_filtree['tcp_payload']).reset_index(drop=True)
    
    #Ajout d'espace entre les octets
    n = len(payload_df)
    messages_formates = []
    for No_i in range(n):
        message = list(payload_df.iloc[No_i])[0]
        message_formate = ' '.join(message[i:i+2] for i in range(0, len(message), 2))
        messages_formates.append(message_formate)
        
    payload_df_formate = pd.DataFrame(messages_formates, columns=['tcp_payload'])
    
    return payload_df_formate


#------------

def data_from_paper_txt_to_df(filename):
    """
     Convertit les données à partir d'un fichier texte en un DataFrame.
     
     Entrée:
     - filename (str): Le chemin du fichier texte.
     
     Sortie:
     - df (DataFrame): Un DataFrame Pandas contenant les colonnes suivantes :
         - No: Numéro du message.
         - time: Horodatage du message.
         - src_adresses: Adresse IP source.
         - dst_adresses: Adresse IP de destination.
         - tcp_payload: Représentation hexadécimale de la charge utile TCP.
         - Commands: Commandes du message.
     """ 
    
    
# Charger le contenu du fichier texte
    with open(filename, 'r') as file:
        data = file.read()
    
    # Séparer les lignes du fichier texte
    lines = data.split('\n')
    lines_messages = []
    for line in lines:
        if line.startswith('m'):
            lines_messages.append(line)
        
    
    
    # Initialiser les listes pour chaque colonne du DataFrame
    No = []
    time = []
    src_adresses = []
    dst_adresses = []
    tcp_payload = []
    Commands = []
    
    # Parcourir chaque ligne du fichier texte
    for line in lines_messages:
        
        line_split =line.split(' ')
        
    
        # Trouver l'indice de la première lettre majuscule
        index_maj = next((i for i, c in enumerate(line) if c.isupper()), -1)
        
        # Trouver l'indice où débute le payload
        #Les conditions permettent de resoudre le problème en cas où un 03 est compris dans l'IP ou dans le Temps
        index_payload = line.find("03")
        if index_payload < 30: #on commence à chercher après l'IP
            index_payload  = line.find("03", index_payload + 1)



        # Couper la chaîne en deux parties
        if index_maj != -1:
            line_payload = line[index_payload :index_maj].strip()
            line_command = line[index_maj:].strip()
            
        #adding items
        No.append(line_split[0])
        
        time.append(line_split[1])
        src_adresses.append(line_split[2])
        dst_adresses.append(line_split[3])
        
        tcp_payload.append(line_payload)
        Commands.append(line_command)
        
    # Créer le DataFrame
    df = pd.DataFrame({
        'No': No,
        'time': time,
        'src_adresses': src_adresses,
        'dst_adresses': dst_adresses,
        'tcp_payload': tcp_payload,
        'Commands': Commands
    })
    
    return df


#---------------------------------------------------------------------------------------------------------


def split_message(df):
    """
       Divise les messages hexadécimaux d'une colonne 'tcp_payload' en listes d'octets.
    
       Entrée:
       - df (DataFrame): Le DataFrame contenant la colonne 'tcp_payload' à diviser.
    
       Sortie:
       - messages_df (list): Liste des messages hexadécimaux d'origine.
       - messages (list): Liste des messages divisés en listes d'octets.
       """
    messages_df = list(df['tcp_payload'])
    messages=[]
    for message in messages_df :
        split_message = message.split(' ')
        messages.append(split_message)
    return messages_df,messages


#---------------------------------------------------------------------------------------------------------

def calculer_entropie_H_bx(messages, position_byte):
        """
    Calcule l'entropie de l'octet à une position spécifiée dans une liste de messages.
    
    Paramètres :
    - messages (List[str]) : Liste de messages (chaque message est représenté sous forme de chaîne de caractères).
    - position_byte (int) : Position de l'octet bx à analyser.
    
    Retourne :
    - entropie_H_bx (float) : Valeur d'entropie de l'octet à la position spécifiée.
    - bytes_name (List[str]) : Liste des octets différents présents à la position spécifiée.
    - probabilites_bx (List[float]) : Liste des probabilités des octets correspondants à la position spécifiée.
    
    Remarques :
    - L'entropie mesure l'incertitude ou la désorganisation dans la distribution des octets à la position bx.
    - La fonction utilise la formule de l'entropie : H(X) = -Σ(p_i * log2(p_i)) où p_i est la probabilité de l'octet i.
    
    Utilisation :
    calculer_entropie_H_bx(messages, position_byte)
    """
    #position_byte: position de l'octet bx
    #messages: tout les messages du tableau Fig1
    
    #Recupération des octets (ou bytes en anglais) à la position bx
        valeurs_a_la_position = []
    
    # Extraire les valeurs à la position spécifiée pour tous les messages
        for message in messages:
            if position_byte < len(message):
                valeurs_a_la_position.append(message[position_byte])
        
        # Extraire les octets différents afin de savoir à quelle proba ils correspondent (variable probabilities_bx)
        bytes_name = list(Counter(valeurs_a_la_position).keys())
        
        # Calculer la distribution de probabilité des valeurs à la position
        probabilites_bx = [count / len(messages) for count in Counter(valeurs_a_la_position).values()]

        # Calculer la distribution de probabilité des valeurs à la position
        p_i = [count / len(valeurs_a_la_position) for count in Counter(valeurs_a_la_position).values()]
        
        
        
        # Calculer l'entropie en utilisant la formule
        entropie_H_bx = -sum(p * math.log2(p) for p in p_i)
        
     
        return entropie_H_bx, bytes_name,probabilites_bx



#---------------------------------------------------------------------------------------------------------



def calculer_EP_bx(messages, position_byte):
    """
    Calcule la fréquence relative de présence de l'octet à une position spécifiée dans une liste de messages.

    Paramètres :
    - messages (List[str]) : Liste de messages (chaque message est représenté sous forme de chaîne de caractères - Fig1 article).
    - position_byte (int) : Position de l'octet bx à analyser.

    Retourne :
    - EP_bx (float) : Fréquence relative de présence de l'octet à la position spécifiée.

    Remarques :
    - La fréquence relative de présence (EP) mesure le pourcentage de messages où l'octet bx existe à la position spécifiée.

    Utilisation :
    calculer_EP_bx(messages, position_byte)
    """

    
    
    #Recupération des octets (ou bytes en anglais)
    valeurs_a_la_position = []
    
    # Extraire les valeurs à la position spécifiée pour tous les messages
    bx_is_present = 0 #On compte le nombre de message où la position bx existe
    for message in messages:
        if position_byte < len(message):
            valeurs_a_la_position.append(message[position_byte])
            bx_is_present +=1
            
   
    #Calcul de EP: percentage of messages that are at the position bx
    #EP = max(probabilites)
    #EP = sum(probabilites_bx)
    
    #Exemple tous les messages ont au moins un premiere octet donc EP(b0) = 1, à partir de 7 octets EP(b6)=16/17
    EP_bx =  bx_is_present / len(messages)
     
    return EP_bx



#---------------------------------------------------------------------------------------------------------


def calculer_entropie_modifiee_total_messages(messages):
    """
    Calcule et affiche l'entropie modifiée par rapport à la position de l'octet (bx) et la fréquence relative de sa présence (EP) dans une liste de messages.

    Paramètres :
    - messages (List[str]) : Liste de messages (chaque message est représenté sous forme de chaîne de caractères).

    Retourne :
    - calculer_entropie_modifiee_total_messages (List[float]) : Liste des valeurs d'entropie modifiée pour chaque position d'octet.

    Remarques :
    - L'entropie modifiée est calculée comme le rapport entre l'entropie H(bx) et la fréquence relative de présence EP(bx).

    Utilisation :
    calculer_entropie_modifiee_total_messages(messages)
    """
    
    length_longest_message = max([len(message) for message in messages ])
    
    entropie_total_messages,bytes_name_total_messages,ep_total_messages = [], [], []
    for octet in range(length_longest_message):    
        entropie,bytes_name,probabilites = calculer_entropie_H_bx(messages, position_byte=octet)
        entropie_total_messages.append(entropie)
        bytes_name_total_messages.append(bytes_name)
        
        ep = calculer_EP_bx(messages, position_byte=octet)
        ep_total_messages.append(ep)
        
        
    paires = zip(entropie_total_messages,ep_total_messages)
    calculer_entropie_modifiee_total_messages = []
    for x,y in paires:
        if y !=0:
            
            calculer_entropie_modifiee_total_messages.append(x/y)
        else:
            calculer_entropie_modifiee_total_messages.append(0)
    
    #plotting
    plt.figure()
    plt.plot(list(range(length_longest_message)),calculer_entropie_modifiee_total_messages,'o-',label='calculer_entropie_modifiee_total_messages')
    plt.plot(list(range(length_longest_message)),entropie_total_messages,label='H(bx)')
    plt.plot(list(range(length_longest_message)),ep_total_messages, label='EP(bx)')
    plt.ylabel('H(bx) / EP(bx)')
    plt.xlabel('bx')
    plt.title('Figure 3.(a) bis')
    plt.legend()
    
    return calculer_entropie_modifiee_total_messages
    
    
#---------------------------------------------------------------------------------------------------------


def calculer_entropie_H_mi(messages, No):
    """
    Calcule l'entropie de l'octet (mi) pour un message spécifique dans une liste de messages.

    Paramètres :
    - messages (List[str]) : Liste de messages (chaque message est représenté sous forme de chaîne de caractères).
    - No (int) : Numéro du message pour lequel l'entropie de l'octet (mi) doit être calculée.

    Retourne :
    - entropie_mi (float) : Valeur de l'entropie de l'octet (mi) pour le message spécifié.

    Remarques :
    - Le numéro du message correspond au numéro de message présent sur l'article.

    Utilisation :
    calculer_entropie_H_mi(messages, No)
    """
    
    
    #print("\nAttention, le numéro du message correspond au numéro de message présent sur l'article")
    message_mi = messages[No-1]
    
    bytes_names = list(Counter(message_mi ).keys())
    probabilites = [count / len(message_mi ) for count in Counter(message_mi ).values()]
    entropie_mi = -sum(p * math.log2(p) for p in probabilites)
             
    return entropie_mi



#---------------------------------------------------------------------------------------------------------


def H_entropie_mi_bx(messages, position_byte,No):
    """
    Calcule l'entropie modifiée pour une position spécifique (bx) par rapport à un octet spécifique (mi) dans un message particulier.

    Paramètres :
    - messages (List[str]) : Liste de messages (chaque message est représenté sous forme de chaîne de caractères).
    - position_byte (int) : Position de l'octet (bx) pour lequel l'entropie modifiée doit être calculée.
    - No (int) : Numéro du message pour lequel l'entropie de l'octet (mi) doit être calculée.

    Retourne :
    - H_mi_bx_value (float) : Valeur de l'entropie modifiée pour la position spécifiée (bx) par rapport à l'octet spécifié (mi) dans le message spécifié.

    Remarques :
    - Le numéro du message correspond au numéro de message présent sur l'article.

    Utilisation :
    H_entropie_mi_bx(messages, position_byte, No)
    """
    
    # Calcul de l'entropie modifiée pour une position spécifique

  
    # Calcul de l'entropie pour chaque message
    H_mi_value = calculer_entropie_H_mi(messages, No) 
    
    # Calcul de l'entropie modifiée pour chaque message
    
    H_bx = calculer_entropie_H_bx(messages, position_byte)[0]
    EP_bx = calculer_EP_bx(messages, position_byte)
    if (float(H_bx) == 0.0) | (float(EP_bx) == 0.0):
        H_mi_bx_value = 0
    else: 
        H_mi_bx_value = H_mi_value / (H_bx* EP_bx) 
    
    return H_mi_bx_value
    
    

#---------------------------------------------------------------------------------------------------------


def calculer_entropie_modifiee_message_mi(messages,No):
    """
    Calcule l'entropie modifiée pour chaque position (bx) par rapport à un octet spécifique (mi) dans un message particulier et génère un graphique.
    
    Paramètres :
    - messages (List[str]) : Liste de messages (chaque message est représenté sous forme de chaîne de caractères).
    - No (int) : Numéro du message pour lequel l'entropie modifiée doit être calculée.
    
    Retourne :
    - H_mi_bx_values (List[float]) : Liste des valeurs d'entropie modifiée pour chaque position (bx) par rapport à l'octet spécifié (mi) dans le message spécifié.
    
    Remarques :
    - Le numéro du message correspond au numéro de message présent sur l'article.
    
    Utilisation :
    calculer_entropie_modifiee_message_mi(messages, No)
    """
    
    #message sur lequel on calcule
    message_mi = messages[No-1]
    length_message_mi = len(message_mi)
    
    #boucle sur les bx
    H_mi_bx_values = []
    for octet in range(length_message_mi):
        H_mi_bx_values.append(H_entropie_mi_bx(messages, octet,No))
    
    
    #plotting
    plt.figure()
    plt.plot(list(range(length_message_mi)),H_mi_bx_values,'o-',label=' H_mi_bx_values')
    plt.ylabel('Hmi(bx)')
    plt.xlabel('bx')
    plt.title('Figure 3.(b) pour le message m' + str(No))
    plt.legend()
    
    return H_mi_bx_values



#---------------------------------------------------------------------------------------------------------




def n_gramms_and_pearson_correlation(messages_hex,No):
    """
    Analyse des N-grams dans un message hexadécimal spécifique pour déterminer la corrélation de Pearson entre les valeurs décimales des N-grams et leurs longueurs.

    Paramètres :
    - messages_hex (List[str]) : Liste de messages hexadécimaux (chaque message est représenté sous forme de chaîne de caractères hexadécimaux).
    - No (int) : Numéro du message pour lequel l'analyse doit être effectuée.

    Retourne :
    - Taille_probable_de_sous_message (List[int]) : Liste des tailles probables de sous-messages déduites de la corrélation de Pearson.

    Remarques :
    - Le numéro du message No correspond au numéro de message présent sur l'article.

    Utilisation :
    n_gramms_and_pearson_correlation(messages_hex, No)
    """
    
    #message sur lequel on calcule
    message_mi = messages_hex[No-1]
    message_mi = "".join(message_mi.split())
    
    #correlation between message_decimal and message_length for different value of n
    ngramm_message_length = []
    message_decimal = []
    message_hexa = []
    for n in range(1,int(len(message_mi)/2)+1):
        
        # Définir la longueur des N-grams
        # Créer les N-grams
        n_grams = [message_mi[i:i+2*n ] for i in range(0, len(message_mi), n )]
        n_grams = [n_grams[i] for i in range(0, len(n_grams), 2)]
        
        message_hexa.append([byte for byte in n_grams])
        
        # Convertion en décimal
        message_decimal.append([float(int(byte, 16)) for byte in n_grams])
        
        ngramm_message_length.append([float(n)]*len(n_grams))
        
        
    
        
    # Calculer la corrélation de Pearson pour tous les n de n_gramms
    message_decimal_all = [item for sublist in message_decimal for item in sublist]
    ngramm_message_length_all =  [item for sublist in ngramm_message_length for item in sublist]
    message_hexa_all =  [item for sublist in message_hexa for item in sublist]
    
    correlation,_= pearsonr(message_decimal_all, ngramm_message_length_all)
    
    #Variable permettant d'avoir des résultats équivalent à l'article
    message_length = [len(message_mi)/2] * len(message_decimal_all)
    
    #On cherche les tailles de sous messages probables
    Taille_probable_de_sous_message = []

    for i, (elem1, elem2) in enumerate(zip(message_decimal_all, message_length)):
        if elem1 == elem2:
            Taille_probable_de_sous_message.append(i+1)
    print(f"L'octet donnant l'indication sur longueur du message est l'octet numéro: {Taille_probable_de_sous_message[0]}")
   
    

    #return correlation,message_decimal_all, ngramm_message_length_all,message_hexa_all,message_length
    return Taille_probable_de_sous_message[0]



#---------------------------------------------------------------------------------------------------------


def calculer_position_moyenne_premier_sous_message(messages):
    
    """
    Calcule la position moyenne du premier octet d'un sous-message pour tous les messages en fonction de l'entropie modifiée.
    
    Paramètres :
    - messages (List[str]) : Liste de messages (chaque message est représenté sous forme de chaîne de caractères).
    
    Retourne :
    - sub_message_starting_position_total_message (int) : Position moyenne du premier octet d'un sous-message pour tous les messages.
    
    Remarques :
    - La position moyenne est déterminée en fonction de l'entropie modifiée.
    - La redline de la figure 3(a) est indiquée par la position moyenne du premier octet d'un sous-message.
    - La fonction utilise le seuil theta_H_for_total_messages (fixé à 0.8 par défaut) pour déterminer la position moyenne.
    
    Utilisation :
    calculer_position_moyenne_premier_sous_message(messages)
    """
    #On reprend le programme de la fonction calculer_entropie_modifiee_total_messages(messages)
    length_longest_message = max([len(message) for message in messages ])
    
    entropie_total_messages,bytes_name_total_messages,ep_total_messages,probabilites_total_messages = [], [], [],[]
    for octet in range(length_longest_message):    
        entropie,bytes_name,probabilites = calculer_entropie_H_bx(messages, position_byte=octet)
        entropie_total_messages.append(entropie)
        bytes_name_total_messages.append(bytes_name)
        probabilites_total_messages.append(probabilites)
        
        ep = calculer_EP_bx(messages, position_byte=octet)
        ep_total_messages.append(ep)
    
    #Les variables probabilites_total_message_sum et bytes_name_total_messages correspond sous forme de liste au FP-tree (Frequent Pattern tree) - Figure 3(d)
    #On cherche la redline de la figure 3(a) - On cherche la position moyenne du premier bytes qui constitue le début d'un sous message pour tous les message 
    probabilites_total_message_sum = [sum(p) for p in probabilites_total_messages]
    theta_H_for_total_messages = 0.8 # Quand moins de 80% des messages, n'ont pas pas l'octet bh, octet à la position h, on considérera que sur tout les messages en moyenne le sous messages commence au bit bh
    
    
    #on récupère la position du sous message
    for i in range(len(probabilites_total_message_sum)):
        if probabilites_total_message_sum[i] < theta_H_for_total_messages:
            sub_message_starting_position_total_message = i
            break
    
    entropie_modifiee_total_messages = calculer_entropie_modifiee_total_messages(messages)
    plt.close()
    
    #plotting
    plt.figure()
    plt.plot(list(range(length_longest_message)),entropie_modifiee_total_messages,'o-',label='entropie_modifiee_total_messages')
    plt.axvline(x=sub_message_starting_position_total_message, color='red', linestyle='--', label='sub_message_starting_position_total_message')
    plt.ylabel('H(bx) / EP(bx)')
    plt.xlabel('bx')
    plt.title('Figure 3.(a)')
    plt.legend(loc='lower right')
    
    
    return 



#---------------------------------------------------------------------------------------------------------


def calculer_position_premier_sous_message(No,messages_hex_split,messages_hex):
    
    """
    Calcule la position du premier octet d'un sous-message dans un message spécifique en fonction de l'entropie modifiée.
    
    Paramètres :
    - No (int) : Numéro du message pour lequel la position doit être calculée.
    - messages_hex_split (List[str]) : Liste de messages hexadécimaux (chaque message est représenté sous forme de chaîne de caractères hexadécimaux, splités).
    - messages_hex (List[str]) : Liste de messages hexadécimaux (chaque message est représenté sous forme de chaîne de caractères hexadécimaux).
    
    Retourne :
    - first_sub_message_position_b1 (str) : Position du premier octet d'un sous-message, considérant que le premier bit est b1 (dans la notation "mX_bY").
    
    Remarques :
    - La position est déterminée en fonction de l'entropie modifiée.
    - La fonction affiche également un graphique (Figure 3.(b)) montrant les valeurs d'entropie modifiée pour chaque position.
    
    Utilisation :
    calculer_position_premier_sous_message(No, messages_hex_split, messages_hex)
    """
    
    #message sur lequel on calcule
    message_mi = messages_hex[No-1]
    message_mi = message_mi.split()
    
    #On récupère les proba comme dans la fonctions calculer_position_moyenne_premier_sous_message
    length_message_mi = len(message_mi)
    length_longest_message = max([len(message) for message in messages_hex_split ])

    bytes_name_total_messages,probabilites_total_messages = [], []
    for octet in range(length_longest_message):    
        entropie,bytes_name,probabilites = calculer_entropie_H_bx(messages_hex_split, position_byte=octet)

        bytes_name_total_messages.append(bytes_name)
        probabilites_total_messages.append(probabilites)
    
    #On récupère les proba qui nous interesse pour notre message
    probabilities_message_mi = []
    for i in range(len(message_mi)):
        octet_message = message_mi[i]
        for j in range(len(bytes_name_total_messages[i])):
            if octet_message == bytes_name_total_messages[i][j]:
                probabilities_message_mi.append(probabilites_total_messages[i][j])
    
    #On récupère l'indice d'intérêt
    theta_H_for_one_message_high = 0.2 #seuil haut
    theta_H_for_one_message_low =0.15 #seuil bas
    sub_message_starting_position_message =[]
    for i in range(len(probabilities_message_mi)):
        if theta_H_for_one_message_low < probabilities_message_mi[i] < theta_H_for_one_message_high:
            sub_message_starting_position_message.append(i)
    
    
    
    #Variable qui donnera la position du premier sous message
    res_first_sub_message_position = 0
    
    #On recupère que la position du premier sous message pour les message long 
    if len(sub_message_starting_position_message) > 1:
        #Supposition pour prendre en compte la taille de la liste
        #On prend le première indice qui est positionner à l'index j > n/len(sub_message_starting_position_message)
        sub_message_starting_position_message= [index for index in sub_message_starting_position_message if index > length_message_mi/len(sub_message_starting_position_message)]
        res_first_sub_message_position = sub_message_starting_position_message[0] 
    elif len(sub_message_starting_position_message) == 1:
        res_first_sub_message_position = sub_message_starting_position_message[0] 

        
   
    #Si la position du premier sous message est inférieur ou = 3  ( Le 3eme octet correspond à la longueur du message Résultat trouvé avec la fonction nsegmentation)
    #------à modifier en ajoutant la fonction au lieu de 3-----
    elif int(res_first_sub_message_position) < int(n_gramms_and_pearson_correlation(messages_hex,No)):
        print("\n !----Le message ne contient pas de sous messages----!")
        res_first_sub_message_position = 0
        
    #Si la position du premier sous message n'est pas trouvé, c'est qu'il y a sans doute pas de sous message
    elif res_first_sub_message_position == 0:
        print("\n !----Le message ne contient pas de sous messages----!")
        res_first_sub_message_position = 0                 

    
    
    # ---------------plotting
    # On récupère les valeurs de Hmi(bx)
    H_mi_bx_values = calculer_entropie_modifiee_message_mi(messages_hex_split,No)
    plt.close()
    plt.figure()
    plt.plot(list(range(length_message_mi)),H_mi_bx_values,'o-',label=' H_mi_bx_values')
    if sub_message_starting_position_message != []:
        plt.axvline(x=res_first_sub_message_position, color='red', linestyle='--', label='sub_message_position')

    # for i in range(len(sub_message_starting_position_message)):
        # plt.axvline(x=sub_message_starting_position_message[i], color='yellow', linestyle='--', label='sub_message_position')
        #plt.axvline(x=sub_message_starting_position_message[1], color='red', linestyle='--', label='sub_message_position')
        #plt.axvline(x=sub_message_starting_position_message[2], color='yellow', linestyle='--', label='sub_message_position')
    plt.ylabel('Hmi(bx)')
    plt.xlabel('bx')
    plt.title('Figure 3.(b) pour le message m' + str(No))
    plt.legend()
    
    
    #--------------Out
    if res_first_sub_message_position == 0:
        first_sub_message_position_b1 = res_first_sub_message_position + 1 
    else:    
        first_sub_message_position_b0 = str (int(res_first_sub_message_position))   #position si on considère que le premier bit est b0 
        first_sub_message_position_b1 = str (int(res_first_sub_message_position) + 1) #position si on considère que le premier bit est b1
        
    return first_sub_message_position_b1



#---------------------------------------------------------------------------------------------------------




def ACF_matrix(messages_hex,No):
    """
    Calcule la matrice de la fonction d'autocorrélation (ACF) pour un message hexadécimal spécifique et génère une heatmap. Identifie les indices (bx, by) où l'ACF est supérieure à 99% et trouve la paire (bx, by) avec le produit maximal qui satisfait certains critères.

    Paramètres :
    - messages_hex (List[str]) : Liste de messages hexadécimaux (chaque message est représenté sous forme de chaîne de caractères hexadécimaux).
    - No (int) : Numéro du message pour lequel l'ACF doit être calculée.

    Retourne :
    - window_max_index (List[int]) : Indices (bx, by) où l'ACF est supérieure à 99%.

    Remarques :
    - La fonction affiche une heatmap de la matrice ACF.
    - Les critères de validité de l'ACF sont déterminés selon la longueur, la moyenne et la variance du message.

    Utilisation :
    ACF_matrix(messages_hex, No)
    """

    message = messages_hex[No-1]
    
    #Traitement du message
    message_split = message.split()
    message_main=[int(x, 16) for x in message_split]
    message_main_npa  = np.array(message_main)
    message_main_npa =  message_main_npa.astype(np.float64)

    
    #Filtrage de message, est ce que l'ACF peut être réalisé
    #Cette méthode ne fonctionne que pour les long message généralement doté d'une structure de sous message:
       #Critère 1: les messages dont l longueur_message > moyenne 
       #Critère 2: (longueur_message - moyenne)**2 >  variance
    
    length_message = len(message_main)
    moyenne_message = mean(message_main)
    variance_message = variance(message_main)
    critere2_condition = (length_message - moyenne_message)**2
    
    length_message = len(message_split)
    length_messages = [ len(message) for message in message_split ]
    moyenne_length_messages = mean(length_messages)
    variance_length_messages = variance(length_messages)
    critere2_condition = (length_message - moyenne_length_messages)**2
    
    if (length_message > moyenne_length_messages) & ( critere2_condition > variance_length_messages):
        #print("L'ACF du message est possible selon les critères, self.critere_valide_acf_matrix = 1")
        critere_valide_acf_matrix = 1
    else:
        #print("!!Attention!! L'ACF du message n'est pas possible selon les critères, le résultat ne doit donc pas être pris en compte, self.critere_valide_acf_matrix = 0")
        critere_valide_acf_matrix = 0

       
    #To illustrate that the sub-messages may be a part of the payload,
    # Ajoutez 10 nombres aléatoires à la liste
    for _ in range(10):
        random_number = random.randint(0, 200)
        message_split.append('{:02x}'.format(random_number))   


    message_main=[int(x, 16) for x in message_split]
    message_main_npa  = np.array(message_main)
    message_main_npa =  message_main_npa.astype(np.float64)  
    n = len(message_main_npa)
    #----------------------------------------------------------
    #On remplit la matrice message_moving avec les octets qui compose le message pour quelle devienne triangulaire supérieur 
    #Cette opération est nécessaire pour retrouver un graphique équivalent à celui de l'article
    message_window = np.zeros((n , n))
    for j in range(n):
        message_window[:, j] = message_main_npa
    message_window = np.triu(message_window)

    window_size = np.zeros((n))  


    ACF_matrix = np.zeros((n,n))

        
    # Méthode 2 - Calculer l'ACF par ligne par ligne
    message_main_matrix = np.zeros((n,n))
    for i in range((n)):
        message_main_matrix[i,:] = message_main



    p = np.zeros((n,n))

    for i in range(n):
        for j in range(n):
            v1 = message_main_matrix[i,j]
            v2 = message_window[i,j]
            value = np.correlate(np.array([message_main_matrix[i,j]]), np.array([message_window[i,j]]), mode='full')
            ACF_matrix[i,j] = value
            
            #product with the window size
            p[i,j] =ACF_matrix[i,j]*(j-i)

        
        
    # Trouver l'indice où l'ACF atteint sa valeur maximale
    max_value = np.max(ACF_matrix)
    #ACF_matrix: En pourcentage
    ACF_matrix_p = ACF_matrix/max_value


    # Créer la heatmap
    plt.figure()
    plt.imshow(ACF_matrix_p, cmap='viridis')
    plt.colorbar(label='Valeur ACF normalisée')
    plt.title('Matrice d\'auto-corrélation normalisée')
    plt.xlabel('Décalage by')
    plt.ylabel('Décalage bx')
         
        
    #On cherche le produit produit max p qui respecte les critères
    max_index_99 = np.argwhere(ACF_matrix_p > 0.99)


    # Trouver les indices (bx, by) où l'ACF est supérieur à XX%
    max_product_values =[ p[i,j] for i,j in zip(max_index_99[:,0],max_index_99[:,1])]


    # Trouver la valeur maximale
    max_product = max(max_product_values)
    # Trouver l'indice de la valeur maximale
    indice_max_product = max_product_values.index(max_product)

    #On trouve les valeurs de bx et by --> variable bxy
    window_max_index = max_index_99[indice_max_product]   
        
    

    return critere_valide_acf_matrix, window_max_index

#---------------------------------------------------------------------------------------------------------



def ACF_matrix_V0(messages_hex_split,No):
        
    

    sequence_base = messages_hex_split[No-1]
    sequence = [int(octet,16) for octet in sequence_base]
    
    random_numbers= [193, 186, 209, 189, 220, 246, 40, 207, 186, 66]
    sequence = sequence + [item for item in random_numbers]
    
    
    
    
    
    #Filtrage de message, est ce que l'ACF peut être réalisé
    #Cette méthode ne fonctionne que pour les long message généralement doté d'une structure de sous message:
       #Critère 1: les messages dont l longueur_message > moyenne 
       #Critère 2: (longueur_message - moyenne)**2 >  variance
    
    length_message = len(sequence)
    moyenne_message = mean(sequence)
    variance_message = variance(sequence)
    critere2_condition = (length_message - moyenne_message)**2
    
    length_messages = [ len(message) for message in messages_hex_split ]
    moyenne_length_messages = mean(length_messages)
    variance_length_messages = variance(length_messages)
    critere2_condition = (length_message - moyenne_length_messages)**2
    
    if (length_message > moyenne_length_messages) & ( critere2_condition > variance_length_messages):
        #print("L'ACF du message est possible selon les critères, self.critere_valide_acf_matrix = 1")
        critere_valide_acf_matrix = 1
    else:
        #print("!!Attention!! L'ACF du message n'est pas possible selon les critères, le résultat ne doit donc pas être pris en compte, self.critere_valide_acf_matrix = 0")
        critere_valide_acf_matrix = 0
    
        
    # Taille de la séquence
    N = len(sequence)
    
    # Initialiser la matrice d'auto-corrélation normalisée
    acf_matrix = np.zeros((N, N))
    p = np.zeros((N, N))
    window_matrix_bx = np.zeros((N, N))
    window_matrix_by = np.zeros((N, N))
    
    
    # Calculer l'auto-corrélation normalisée
    for bx in range(N):
        for by in range(N):
            window_size_bx = bx + 1  # Incrémenter la taille de la fenêtre bx
            window_size_by = by + 1  # Incrémenter la taille de la fenêtre by
    
            if window_size_bx <= N and window_size_by <= N:  # Vérifier si la fenêtre glissante a une taille valide
                window_sequence_bx = sequence[bx:bx + window_size_bx]
                window_sequence_by = sequence[by:by + window_size_by]
    
                # Normalisation en utilisant les écarts types
                normalization_factor = np.std(window_sequence_bx) * np.std(window_sequence_by)
    
                # Calculer l'auto-corrélation normalisée
                acf_values = np.correlate(window_sequence_by, window_sequence_bx, mode='valid')
                if normalization_factor !=0:
                    acf_matrix[bx, by] = acf_values[0] / normalization_factor
                else:
                    acf_matrix[bx, by] = 0
                
                #window value
                window_matrix_bx[bx, by] = window_size_bx
                window_matrix_by[bx, by] = window_size_by
                
                #product
                p[bx, by] = acf_matrix[bx, by] *  (window_size_by-window_size_bx)
                
    #Actualisation de acf_matrix
    # Remplacer Inf par 0
    acf_matrix[np.isinf(acf_matrix)] = 0
    # Remplacer NaN par 0
    acf_matrix[np.isnan(acf_matrix)] = 0
    # #Actualisation de acf_matrix - Plus simple
    #acf_matrix = acf_matrix[:-1, :-1]
    
    
    # Remplacer Inf par 0
    p[np.isinf(p)] = 0
    
    # Remplacer NaN par 0
    p[np.isnan(p)] = 0
    
    
    # Trouver l'indice de la valeur maximale dans la matrice d'auto-corrélation normalisée
    max_index = np.unravel_index(np.argmax(acf_matrix), acf_matrix.shape)
    # Obtenir les valeurs maximales et les indices correspondants
    max_acf_value = acf_matrix[max_index]
    
    
    acf_matrix_p = acf_matrix/100 #○déjà correctement normalisé
    
    
    # Tracé de la matrice d'auto-corrélation normalisée
    plt.imshow(acf_matrix_p, cmap='viridis')
    plt.colorbar(label='Valeur ACF normalisée')
    plt.title('Matrice d\'auto-corrélation normalisée')
    plt.xlabel('Décalage by')
    plt.ylabel('Décalage bx')
    plt.show()            
    
    
    #bx et by ?
    #On cherche le produit produit max p qui respecte les critères
    max_index_99 = np.argwhere(acf_matrix_p > 0.85)
    
    # Trouver les indices (bx, by) où l'ACF est supérieur à XX%
    max_product_values =[ p[i,j] for i,j in zip(max_index_99[:,0],max_index_99[:,1])]
    
    # Trouver la valeur maximale
    max_product = max(max_product_values)
    # Trouver l'indice de la valeur maximale
    indice_max_product = max_product_values.index(max_product)
    
    
    
    #On trouve les valeurs de bx et by --> variable bxy
    window_max_index = max_index_99[indice_max_product]
    
    
    return critere_valide_acf_matrix, window_max_index
    
 #---------------------------------------------------------------------------------------------------------

    
    
    

def ACF(B,acf_seuil,first_sub_message_position):
    
    """
    Calcule la fonction d'autocorrélation (ACF) pour un message hexadécimal spécifique,
    détecte le k optimal, et retourne le template correspondant.

    Paramètres :
    - B (List[str]) : Liste d'octets représentant le message hexadécimal.
    - acf_seuil (float) : Seuil pour la fonction d'autocorrélation (ACF).
    - first_sub_message_position (str) : Position du premier octet du sous-message.

    Retourne :
    - template (dict) : Dictionnaire contenant les informations sur le template,
      notamment le k optimal et le template hexadécimal.

    Remarques :
    - La fonction affiche également un graphique montrant la fonction d'autocorrélation avec les pics détectés.
    - Le paramètre 'B' doit être une liste d'octets hexadécimaux représentant le message complet.
    - Le seuil de l'ACF ('acf_seuil') est généralement fixé à 2, notamment pour les protocoles Modbus/TCP Read Multiple Registers.
    - Assurez-vous que 'first_sub_message_position' est la position correcte du premier octet du sous-message dans le message complet.

    Utilisation :
    ACF(B, acf_seuil, first_sub_message_position)
    """

    
    #message en décimal
    message_dec = [int(byte, 16) for byte in B]
    n = len(message_dec)-1
    
    #moyenne du message
    b_moy = np.mean(message_dec)

    
    #Pour avoir les index alignés avec B = (b1,....,bn), section 4.1
    message_dec.insert(0,'Nan')   
    
    
    #On récupère tous les valeurs de ACFk pour différent k
    acf_values_for_all_k = []  
    
    for k in range(0,n): #k prend la valeurs de  0 à n 
    
    
        numerator = []
        denominator = []
        for i in range(1,n-k+1):
            numerator.append((message_dec[i+k] - b_moy) * (message_dec[i] - b_moy))
            denominator.append((message_dec[i] - b_moy) ** 2)
            numerator_sum = np.sum(numerator)
            denominator_sum = np.sum(denominator)
            
            acf_value_k= numerator_sum / denominator_sum
    
        acf_values_for_all_k.append(acf_value_k)


    #D'après l'article il est intéressant de le fixer acf_seuil à 2 notament lorsqu'on manipule les protocoles Modbus/TCP Read Multiple Registers par exemple
    #acf_seuil = 2
    
    acf_values_for_all_k_with_threshold = acf_values_for_all_k[acf_seuil+1:]
    for i in range(acf_seuil):
        acf_values_for_all_k_with_threshold.insert(i,0.0)
    acf_values_for_all_k_with_threshold.insert(0,0.0)    # Pour faire correspondre les indices au numéro de l'octet
        
    
    
    #On remplace par 0 les valeurs de ACF qui sont supérieurs à 100% car non significatives et freine pour trouver k_opt
    for k in range(len(acf_values_for_all_k_with_threshold)):
        #Hypothèse: le premier pique est détecter si la valeur de l'ACF est supérieur à 20%
        if abs(acf_values_for_all_k_with_threshold[k])> 1:
            acf_values_for_all_k_with_threshold[k] = 0.0
        
    
    #On cherche les valeurs k où un pique apparait
    k_opt_list = []
    for k in range(len(acf_values_for_all_k_with_threshold)):
        #Hypothèse: le premier pique est détecter si la valeur de l'ACF est supérieur à 20%
        #Hypothèse: on ne considère que les piques positifs
        if acf_values_for_all_k_with_threshold[k]> 0.2:
            k_opt_list.append(k)
        
          
    #Apparition du premier pique dans la première partie du message
    k_opt, acf_max_value = max(enumerate(acf_values_for_all_k_with_threshold[:int(len(acf_values_for_all_k_with_threshold)/2.5)]), key=lambda x: x[1])
    
    #La valeur de k ne peut pas faire dépasser de la taille du message, condition sur k dans le cas où le premier template dépasserait la longueur du message
    if int(first_sub_message_position) + k_opt > n+1:
        k_opt = n+2 - int(first_sub_message_position) 
    #Par observation si les valeurs de l'acf ne pique que de manière négative, c'est que k correspond à la taille du payload complet, il y a donc qu'un seul sous message
    if k_opt == 0:
        k_opt = n+1 - int(first_sub_message_position) +1 
    


    
    
    #Plotting
    #Graphique comme dans l'article - Figure 5 
    plt.figure()
    x_lim =  int(len(message_dec)/2.5)
    x_values = list(range(0,x_lim))
    y_values = acf_values_for_all_k_with_threshold[:x_lim]
    y_zero = [0]*len(y_values)
    # Créer le nuage de points
    s = 30
    plt.scatter(x_values, y_values,s)
    plt.plot(x_values,y_zero)
    plt.vlines(x_values, 0, y_values, linestyles='solid')
    plt.scatter(k_opt, acf_values_for_all_k_with_threshold[k_opt],s*3,edgecolors='red')
    texte = 'k_opt = ' + str(k_opt)
    plt.text(k_opt, acf_values_for_all_k_with_threshold[k_opt], texte, ha='center', va='center', color='black')
    plt.xlabel("k")
    plt.ylabel("ACF(k)")
    plt.title("Affichage restreint sans la symétrie (comme dans l'article)")
    
    #plotting
    #Graphique complet 
    plt.figure()
    x_values = list(range(0,len(message_dec)-2))
    y_values = acf_values_for_all_k_with_threshold
    y_zero = [0]*len(y_values)
    # Créer le nuage de points
    plt.scatter(x_values, y_values,s=10)
    plt.plot(x_values,y_zero)
    plt.vlines(x_values, 0, y_values, linestyles='solid')
    plt.xlabel("k")
    plt.ylabel("ACF(k)")
    plt.title("Affichage complet avec symétrie ")

    #Création du template t = (b1,b2,...bk*)
    
    template = {}
    template['k'] = k_opt
    template['first_sub_message_index'] = int(first_sub_message_position)
    
    template['template_hex_t'] = B[template['first_sub_message_index'] -1:template['first_sub_message_index']-1 + template['k']]
    
    template['template_dec_t'] = [int(x, 16) for x in template['template_hex_t']]
    
    return template



#---------------------------------------------------------------------------------------------------------


def calculate_penalty_linear(bi, bj):
    """
    Calcule la pénalité pour un modèle linéaire entre deux valeurs.

    Paramètres :
    - bi (float) : Valeur de la première position.
    - bj (float) : Valeur de la deuxième position.

    Retourne :
    - res (float) : Pénalité calculée.

    Utilisation :
    calculate_penalty_linear(bi, bj)
    """
    if bj == None:
        bj = 0
    if bi== None:
        bi = 0
            
    res = -2 * abs(bi - bj) / 255 + 1
    return res


#---------------------------------------------------------------------------------------------------------


def calculate_penalty_dirac(bi, bj):
    """
    Calcule la pénalité pour un modèle dirac entre deux valeurs.

    Paramètres :
    - bi (float) : Valeur de la première position.
    - bj (float) : Valeur de la deuxième position.

    Retourne :
    - res (float) : Pénalité calculée.

    Utilisation :
    calculate_penalty_dirac(bi, bj)
    """
    res = 0
    if bi == bj:
        res = 1
    return res


#---------------------------------------------------------------------------------------------------------


def nw_alignment(message1, message2, g_seuil, penalty_matrix, pg):
    """
    Effectue l'alignement de Needleman-Wunsch entre deux messages.

    Paramètres :
    - message1 (list) : Liste représentant le premier message.
    - message2 (list) : Liste représentant le deuxième message.
    - g_seuil (int) : Seuil pour le nombre de gaps autorisés.
    - penalty_matrix (str) : Matrice de pénalité à utiliser ('linear' ou 'dirac').
    - pg (float) : Pénalité pour l'insertion ou la suppression d'un gap.

    Retourne :
    - aligned_messages (list) : Liste contenant l'alignement des messages en décimal et en hexadécimal.

    Utilisation :
    nw_alignment(message1, message2, g_seuil, penalty_matrix, pg)
    """
    
    n = len(message1)
    m = len(message2)

    # Initialisation NW matrix
    nw_matrix = np.zeros((n + 1, m + 1))

    # Création de la première ligne manuellement en utilisant la valeur de pg
    for j in range(m + 1):
        nw_matrix[0, j] = pg * j

    # Création de la première colonne manuellement en utilisant la valeur de pg
    for i in range(n + 1):
        nw_matrix[i, 0] = pg * i

    if penalty_matrix == 'linear':
        # Fill in the NW matrix
        for i in range(1, n + 1):
            for j in range(1, m + 1):
                bi = message1[i - 1] if isinstance(message1[i - 1], int) else None
                bj = message2[j - 1] if isinstance(message2[j - 1], int) else None
                match = nw_matrix[i - 1, j - 1] + calculate_penalty_linear(bi, bj)
                delete = nw_matrix[i - 1, j] + pg
                insert = nw_matrix[i, j - 1] + pg
                nw_matrix[i, j] = max(match, delete, insert)

    if penalty_matrix == 'dirac':
        # Fill in the NW matrix
        for i in range(1, n + 1):
            for j in range(1, m + 1):
                bi = message1[i - 1] if isinstance(message1[i - 1], int) else None
                bj = message2[j - 1] if isinstance(message2[j - 1], int) else None
                match = nw_matrix[i - 1, j - 1] + calculate_penalty_dirac(bi, bj)
                delete = nw_matrix[i - 1, j] + pg
                insert = nw_matrix[i, j - 1] + pg
                nw_matrix[i, j] = max(match, delete, insert)

    # Ajout de gap par l'algorithme de NW
    aligned_message1 = []
    aligned_message2 = []
    i, j = n, m
    while i > 0 or j > 0:
        bi = message1[i - 1] if i > 0 and isinstance(message1[i - 1], int) else None
        bj = message2[j - 1] if j > 0 and isinstance(message2[j - 1], int) else None
        condition_1 = (nw_matrix[i, j] == nw_matrix[i - 1, j - 1] + calculate_penalty_linear(bi, bj)) & (
                    penalty_matrix == 'linear')
        condition_2 = (nw_matrix[i, j] == nw_matrix[i - 1, j - 1] + calculate_penalty_dirac(bi, bj)) & (
                    penalty_matrix == 'dirac')

        if condition_1 or condition_2:
            aligned_message1.insert(0, message1[i - 1])
            aligned_message2.insert(0, message2[j - 1])
            i -= 1
            j -= 1

        elif nw_matrix[i, j] == nw_matrix[i, j - 1] + pg:
            aligned_message2.insert(0, message2[j - 1])
            aligned_message1.insert(0, '-')  # Representing a gap
            j -= 1

        elif nw_matrix[i, j] == nw_matrix[i - 1, j] + pg:
            aligned_message1.insert(0, message1[i - 1])
            aligned_message2.insert(0, '-')  # Representing a gap
            i -= 1

    # Création d'une matrice avec l'alignement des messages
    aligned_messages_dec = [aligned_message1, aligned_message2]

    # Création d'une matrice avec l'alignement des messages en hexa
    aligned_messages_hex = [
        [f'0x{int(element):02x}' if element != '-' and element is not None else '-' for element in ligne]
        for ligne in aligned_messages_dec]

    # ----------------------Respect du seuil ?
    # Nouvelles listes pour stocker les éléments
    new_aligned_messages_hex = [[] for _ in range(2)]
    new_aligned_messages_dec = [[] for _ in range(2)]

    max_length = max([len(s) for s in aligned_messages_hex])
    for i in range(max_length):
        octets = [aligned_messages_hex[0][i], aligned_messages_hex[1][i]]
        number_of_gaps = octets.count('-')

        if number_of_gaps < g_seuil:
            # Conserver les éléments
            for j in range(2):
                new_aligned_messages_hex[j].append(aligned_messages_hex[j][i])
                new_aligned_messages_dec[j].append(aligned_messages_dec[j][i])

    # Mettre à jour les listes originales
    aligned_messages_hex = new_aligned_messages_hex
    aligned_messages_dec = new_aligned_messages_dec

    aligned_messages = [aligned_messages_dec, aligned_messages_hex]

    return aligned_messages


#----------------------------------------------------------------------------------------------------------

def Segmentation(B,template,pg,penalty_matrix):
    """
    Réalise la segmentation du message en sous-messages en utilisant l'algorithme Needleman-Wunsch.

    Paramètres :
    - B (list) : Liste représentant le message en hexadécimal.
    - template (dict) : Dictionnaire contenant les informations sur le template.
      - 'k' (int) : Taille du template.
      - 'first_sub_message_index' (int) : Position du premier sous-message dans le message complet.
      - 'template_hex_t' (list) : Liste hexadécimale représentant le template.
    - pg (float) : Pénalité pour l'insertion ou la suppression d'un gap.
    - penalty_matrix (str) : Matrice de pénalité à utiliser ('linear' ou 'dirac').

    Remarques :
    - Le paramètre 'B' doit être une liste d'octets hexadécimaux représentant le message complet.
    - Le paramètre 'template' doit être un dictionnaire contenant des informations valides sur le template.
    - Le paramètre 'pg' spécifie la pénalité pour l'insertion ou la suppression d'un gap.
    - Le paramètre 'penalty_matrix' doit être 'linear' ou 'dirac' pour spécifier la matrice de pénalité à utiliser.

    Exemples d'Utilisation :
    >>> B = ['0x01', '0x02', '0x03', '0x04', '0x05', '0x06']
    >>> template = {'k': 2, 'first_sub_message_index': 1, 'template_hex_t': ['0x01', '0x02']}
    >>> pg = 1.0
    >>> penalty_matrix = 'linear'
    >>> result = Segmentation(B, template, pg, penalty_matrix)

    Résultats Attendus :
    - La fonction renvoie un dictionnaire contenant la segmentation du message en sous-messages, tant en décimal qu'en hexadécimal.
    """
    
    #message en decimal
    message_dec = [int(byte, 16) for byte in B]

    #longueur du template
    n_template = len(template['template_hex_t'])
    template_hex = template['template_hex_t'].copy()
    template_dec = [int(hex_value, 16) for hex_value in template_hex]
    template_hex.insert(0,'0') #pour s'adapter à la dimension de NW qui à une ligne et une colonne en plus de zéro
    template_dec.insert(0,0) #pour s'adapter à la dimension de NW qui à une ligne et une colonne en plus de zéro

    
    #on récupère le payload en coupant l'en tête du protocole
    index_first_sub_message_position = template['first_sub_message_index']-1
    
    payload_dec = message_dec[index_first_sub_message_position:]
    payload_hex = ['0x{:02x}'.format(element) for element in payload_dec]
    payload_dec.insert(0,0) #pour s'adapter à la dimension de NW qui à une ligne et une colonne en plus de zéro
    payload_hex.insert(0,0) #pour s'adapter à la dimension de NW qui à une ligne et une colonne en plus de zéro
    n = len(payload_dec)
    
    
    #On récupère les matrices NW à chaque itération  Figure 7 (a)
    NW_matrix_list = []
    #On récupère les lignes de la matrice - Figure 7 (b) pour creer M
    DP_list = []
        
    
    
    
#---------Step 1: On calcule tous les matrices NW nécessaire pour le DP et on construit la matrice DP_matrix------------
    for i_dp in range(n):
        
        #Abaissement itératif de la dimension de la matrice NW selon l'axe 0 (lignes)
        n_dp = n-i_dp
        
        
        # Initialize the score matrix NW
        NW_matrix= np.zeros((n_dp, n_template+1))
        
        # Création de la première ligne manuellement en utilisant la valeur de pg
        if pg != 0:
            for j in range(n_template+1):
                NW_matrix[0,j] = pg * j
        
        # Création de la première colonne manuellement en utilisant la valeur de pg
        if pg != 0:
            for i in range(n_dp):
                NW_matrix[i,0] = pg * i
        
    
        if penalty_matrix =='dirac':
            
            # Penalty matrix, initialized with zeros      
            P = np.zeros((256, 256))  
            for i in range(256):
                for j in range(256):
                    P[i, j] = 1 if i == j else 0     
                    
            # Filling
            for i in range(1, n_dp):
                for j in range(1, n_template+1):
                    bi = payload_dec[i+i_dp]
                    bj = template_dec[j]
                    nw1 = NW_matrix[i-1, j-1] + calculate_penalty_dirac(bi, bj)
                    nw2 = NW_matrix[i-1, j] + pg
                    nw3 = NW_matrix[i, j-1] + pg
        
                    NW_matrix[i, j] = max(nw1, nw2, nw3)
     
        
        if penalty_matrix =='linear':
            
            # Filling
            for i in range(1,n_dp):
                for j in range(1,n_template+1):
                    bi = payload_dec[i+i_dp]
                    bj = template_dec[j]
                    nw1 = NW_matrix[i-1, j-1] + calculate_penalty_linear(bi, bj)
                    nw2 = NW_matrix[i-1, j] + pg
                    nw3 = NW_matrix[i, j-1] + pg    
                    
                    NW_matrix[i, j] = max(nw1, nw2, nw3)    
    
    
        
        #On récupère les matrices NW à chaque itération 
        NW_matrix = np.round(NW_matrix, decimals=1)
        NW_matrix_list.append(NW_matrix)
        
        #On récupère la colonne d'intérêt connaissant la longueur du template k_opt
        DP_list.append(NW_matrix[1:, template['k']])
        
    
    #Valeur non nécessaire
    DP_list.pop(-1)  
    
    
    #-----Création de la matrice triangulaire supérieure avec la zone de zéros en bas à gauche: DP_matrix
    max_size = max(len(lst) for lst in DP_list)
    
    DP_matrix = np.triu(np.zeros((max_size, max_size)))
    
    # Remplissage de la matrice avec les valeurs de DP_list
    for i, lst in enumerate(DP_list):
        DP_matrix[i,max_size - len(lst):] = lst
        
        
    
#---------Step 2: On crée la matrice M, permettant d'avoir l'inférence des sous messages------------
    M = np.zeros_like(DP_matrix)
    

    #Filling
    for i in range(0, DP_matrix.shape[0]):
        for j in range(0, DP_matrix.shape[1]):
            if i< 1 or j< 1:
                M[i, j] = DP_matrix[i, j]
            else:
                m_val = M[:i-1+1, i-1]
                M[i, j] = DP_matrix[i, j] + np.max(m_val)

    #Seul les valeurs sur la zone triangulaire supérieur sont des valeurs d'intérêt
    M = np.triu(M)



#---------Step 3: On récupère la segmentation S, en récupérant les valeurs max------------
   
     #Attention non dit dans l'article - Condition si le premier sous message est supérieur à k
    #Il faut que le premier sous messages soit obligatoirement de taille k
    #On imposera donc le premier sous message, on travaille par la suite sur la matrice en supprimant les lignes et les colonnes associées en premier sous message
    
    #on récupère le message pure en décimale avec les bonnes dimensions
    message_payload = payload_dec[1:]
    #Le premier sous message est déja imposé
    sub_messages = [message_payload[0: template['k']]]
    
    #On récupère les autres sous messages
    M1 = M[template['k']:,template['k']:]    
    if M1 != []:
        
        # Récupération des indices du maximum pour chaque colonne
        index_submessage_list = []
        
        #Attention si des valeurs sont égales dans la colonne on priviligiera la première qui apparait selon i croissant avec i l'indice de la ligne de M
        for j in range(M1.shape[1]):  # Parcours de chaque colonne
            i_max = np.argmax(M1[:, j])  # Indice de la valeur maximale dans la colonne
            index_submessage_list.append((i_max, j))
        
        
        #Recupération des indices j de chaques sous message
        i_to_j_dict = {}
        for i, j in index_submessage_list:
            if i not in i_to_j_dict:
                i_to_j_dict[i] = [j]
            else:
                i_to_j_dict[i].append(j)
    
        # Filtrer les valeurs où il y a plus d'un indice j
        index_j_submessage_list = [j_list for j_list in i_to_j_dict.values() if len(j_list) > 1]
        
        #Recupération des sous messaage dans M1
        message_payload_M1 = message_payload[template['k']:]
        for segment in index_j_submessage_list:
            segment_temp = []
            for octet in segment:
                segment_temp.append(message_payload_M1[octet])
            sub_messages.append(segment_temp)

    
    
    
    #Au format hexadécimal
    sub_messages_hex = [['0x{:02x}'.format(element) for element in sublist] for sublist in sub_messages]    
    
    #Placement dans un dictionnaire S
    keys = [] #clés du dictionnaire
    for nom in range(len(sub_messages)):
        keys.append('s' + str(nom +1))
    
    S_dec = dict(zip(keys, sub_messages))
    S_hexa = dict(zip(keys, sub_messages_hex))
    
    S = {}
    S['Segmentation_hex'] = S_hexa
    S['Segmentation_dec'] = S_dec
    
    
    
    return S


def Segmentation_show(B,template,pg,penalty_matrix):
    """
    Réalise la segmentation du message en sous-messages en utilisant l'algorithme Needleman-Wunsch.

    Paramètres :
    - B (list) : Liste représentant le message en hexadécimal.
    - template (dict) : Dictionnaire contenant les informations sur le template.
      - 'k' (int) : Taille du template.
      - 'first_sub_message_index' (int) : Position du premier sous-message dans le message complet.
      - 'template_hex_t' (list) : Liste hexadécimale représentant le template.
    - pg (float) : Pénalité pour l'insertion ou la suppression d'un gap.
    - penalty_matrix (str) : Matrice de pénalité à utiliser ('linear' ou 'dirac').

    Remarques :
    - Le paramètre 'B' doit être une liste d'octets hexadécimaux représentant le message complet.
    - Le paramètre 'template' doit être un dictionnaire contenant des informations valides sur le template.
    - Le paramètre 'pg' spécifie la pénalité pour l'insertion ou la suppression d'un gap.
    - Le paramètre 'penalty_matrix' doit être 'linear' ou 'dirac' pour spécifier la matrice de pénalité à utiliser.

    Exemples d'Utilisation :
    >>> B = ['0x01', '0x02', '0x03', '0x04', '0x05', '0x06']
    >>> template = {'k': 2, 'first_sub_message_index': 1, 'template_hex_t': ['0x01', '0x02']}
    >>> pg = 1.0
    >>> penalty_matrix = 'linear'
    >>> result = Segmentation(B, template, pg, penalty_matrix)

    Résultats Attendus :
    - La fonction renvoie un dictionnaire contenant la segmentation du message en sous-messages, tant en décimal qu'en hexadécimal.
    """
    
    #message en decimal
    message_dec = [int(byte, 16) for byte in B]

    #longueur du template
    n_template = len(template['template_hex_t'])
    template_hex = template['template_hex_t'].copy()
    template_dec = [int(hex_value, 16) for hex_value in template_hex]
    template_hex.insert(0,'0') #pour s'adapter à la dimension de NW qui à une ligne et une colonne en plus de zéro
    template_dec.insert(0,0) #pour s'adapter à la dimension de NW qui à une ligne et une colonne en plus de zéro

    
    #on récupère le payload en coupant l'en tête du protocole
    index_first_sub_message_position = template['first_sub_message_index']-1
    
    payload_dec = message_dec[index_first_sub_message_position:]
    payload_hex = ['0x{:02x}'.format(element) for element in payload_dec]
    payload_dec.insert(0,0) #pour s'adapter à la dimension de NW qui à une ligne et une colonne en plus de zéro
    payload_hex.insert(0,0) #pour s'adapter à la dimension de NW qui à une ligne et une colonne en plus de zéro
    n = len(payload_dec)
    
    
    #On récupère les matrices NW à chaque itération  Figure 7 (a)
    NW_matrix_list = []
    #On récupère les lignes de la matrice - Figure 7 (b) pour creer M
    DP_list = []
        
    
    
    
#---------Step 1: On calcule tous les matrices NW nécessaire pour le DP et on construit la matrice DP_matrix------------
    for i_dp in range(n):
        
        #Abaissement itératif de la dimension de la matrice NW selon l'axe 0 (lignes)
        n_dp = n-i_dp
        
        
        # Initialize the score matrix NW
        NW_matrix= np.zeros((n_dp, n_template+1))
        
        # Création de la première ligne manuellement en utilisant la valeur de pg
        if pg != 0:
            for j in range(n_template+1):
                NW_matrix[0,j] = pg * j
        
        # Création de la première colonne manuellement en utilisant la valeur de pg
        if pg != 0:
            for i in range(n_dp):
                NW_matrix[i,0] = pg * i
        
    
        if penalty_matrix =='dirac':
            
            # Penalty matrix, initialized with zeros      
            P = np.zeros((256, 256))  
            for i in range(256):
                for j in range(256):
                    P[i, j] = 1 if i == j else 0     
                    
            # Filling
            for i in range(1, n_dp):
                for j in range(1, n_template+1):
                    bi = payload_dec[i+i_dp]
                    bj = template_dec[j]
                    nw1 = NW_matrix[i-1, j-1] + calculate_penalty_dirac(bi, bj)
                    nw2 = NW_matrix[i-1, j] + pg
                    nw3 = NW_matrix[i, j-1] + pg
        
                    NW_matrix[i, j] = max(nw1, nw2, nw3)
     
        
        if penalty_matrix =='linear':
            
            # Filling
            for i in range(1,n_dp):
                for j in range(1,n_template+1):
                    bi = payload_dec[i+i_dp]
                    bj = template_dec[j]
                    nw1 = NW_matrix[i-1, j-1] + calculate_penalty_linear(bi, bj)
                    nw2 = NW_matrix[i-1, j] + pg
                    nw3 = NW_matrix[i, j-1] + pg    
                    
                    NW_matrix[i, j] = max(nw1, nw2, nw3)    
    
    
        
        #On récupère les matrices NW à chaque itération 
        NW_matrix = np.round(NW_matrix, decimals=1)
        NW_matrix_list.append(NW_matrix)
        
        #On récupère la colonne d'intérêt connaissant la longueur du template k_opt
        DP_list.append(NW_matrix[1:, template['k']])
        
    
    #Valeur non nécessaire
    DP_list.pop(-1)  
    
    
    #-----Création de la matrice triangulaire supérieure avec la zone de zéros en bas à gauche: DP_matrix
    max_size = max(len(lst) for lst in DP_list)
    
    DP_matrix = np.triu(np.zeros((max_size, max_size)))
    
    # Remplissage de la matrice avec les valeurs de DP_list
    for i, lst in enumerate(DP_list):
        DP_matrix[i,max_size - len(lst):] = lst
        
        
    
#---------Step 2: On crée la matrice M, permettant d'avoir l'inférence des sous messages------------
    M = np.zeros_like(DP_matrix)
    

    #Filling
    for i in range(0, DP_matrix.shape[0]):
        for j in range(0, DP_matrix.shape[1]):
            if i< 1 or j< 1:
                M[i, j] = DP_matrix[i, j]
            else:
                m_val = M[:i-1+1, i-1]
                M[i, j] = DP_matrix[i, j] + np.max(m_val)

    #Seul les valeurs sur la zone triangulaire supérieur sont des valeurs d'intérêt
    M = np.triu(M)



#---------Step 3: On récupère la segmentation S, en récupérant les valeurs max------------
   
     #Attention non dit dans l'article - Condition si le premier sous message est supérieur à k
    #Il faut que le premier sous messages soit obligatoirement de taille k
    #On imposera donc le premier sous message, on travaille par la suite sur la matrice en supprimant les lignes et les colonnes associées en premier sous message
    
    #on récupère le message pure en décimale avec les bonnes dimensions
    message_payload = payload_dec[1:]
    #Le premier sous message est déja imposé
    sub_messages = [message_payload[0: template['k']]]
    
    #On récupère les autres sous messages
    M1 = M[template['k']:,template['k']:]    
    if M1 != []:
        
        # Récupération des indices du maximum pour chaque colonne
        index_submessage_list = []
        
        #Attention si des valeurs sont égales dans la colonne on priviligiera la première qui apparait selon i croissant avec i l'indice de la ligne de M
        for j in range(M1.shape[1]):  # Parcours de chaque colonne
            i_max = np.argmax(M1[:, j])  # Indice de la valeur maximale dans la colonne
            index_submessage_list.append((i_max, j))
        
        
        #Recupération des indices j de chaques sous message
        i_to_j_dict = {}
        for i, j in index_submessage_list:
            if i not in i_to_j_dict:
                i_to_j_dict[i] = [j]
            else:
                i_to_j_dict[i].append(j)
    
        # Filtrer les valeurs où il y a plus d'un indice j
        index_j_submessage_list = [j_list for j_list in i_to_j_dict.values() if len(j_list) > 1]
        
        #Recupération des sous messaage dans M1
        message_payload_M1 = message_payload[template['k']:]
        for segment in index_j_submessage_list:
            segment_temp = []
            for octet in segment:
                segment_temp.append(message_payload_M1[octet])
            sub_messages.append(segment_temp)

    
    
    
    #Au format hexadécimal
    sub_messages_hex = [['0x{:02x}'.format(element) for element in sublist] for sublist in sub_messages]    
    
    #Placement dans un dictionnaire S
    keys = [] #clés du dictionnaire
    for nom in range(len(sub_messages)):
        keys.append('s' + str(nom +1))
    
    S_dec = dict(zip(keys, sub_messages))
    S_hexa = dict(zip(keys, sub_messages_hex))
    
    S = {}
    S['Segmentation_hex'] = S_hexa
    S['Segmentation_dec'] = S_dec
    
    
    
    return NW_matrix_list,DP_matrix,M,S
#---------------------------------------------------------------------------------------------------------

def merge_messages(aligned_messages):
    """
Fusionne des messages alignés en prenant la valeur maximale de chaque position.

Paramètres :
- aligned_messages (List[List[List[Union[str, int]]]]) : Liste de messages alignés.
  Chaque message aligné est une liste de listes représentant les valeurs décimales et hexadécimales.

Retourne :
- merged_messages (List[List[Union[str, int]]]) : Message fusionné résultant de la fusion des messages alignés.

Remarques :
- Les messages alignés doivent être fournis sous forme de liste de listes, où chaque liste représente les valeurs décimales et hexadécimales alignées.
- La fonction fusionne les messages en prenant la valeur maximale de chaque position alignée.
- Les valeurs '-' (gaps) sont ignorées lors de la fusion.
- Le message fusionné est renvoyé sous forme de liste contenant les valeurs décimales et hexadécimales fusionnées.

Utilisation :
merge_messages(aligned_messages)
    """
    merged_message_dec = []
    merged_message_hex = []

    for dec_values in zip(*aligned_messages[0]):
        valid_values = [value for value in dec_values if value != '-']

        if valid_values:
            max_value = max(valid_values)
            merged_message_dec.append(max_value)
            merged_message_hex.append('0x{:02x}'.format(max_value))
        else:
            # Toutes les valeurs étaient des '-'
            merged_message_dec.append('-')
            merged_message_hex.append('-')

    merged_messages = [merged_message_dec, merged_message_hex]
    
    return  merged_messages


#--------------------------------------------------------------


def Revert_messages(reverted_segments,g_seuil,penalty_matrix,pg):
    """
    Rétablit les segments alignés après l'opération de revert.

    Paramètres :
    - reverted_segments (List[List[Union[str, int]]]) : Liste de segments résultant de l'opération de revert.
      Chaque segment est une liste de valeurs décimales et hexadécimales alignées.
    - g_seuil (int) : Seuil pour le retrait des colonnes excédant le nombre maximal de gaps autorisés.
    - penalty_matrix (str) : Type de matrice de pénalité à utiliser ('linear' ou 'dirac').
    - pg (int) : Pénalité pour l'ajout d'un gap lors de l'alignement.

    Retourne :
    - reverted_segments_aligned_dec_hex (List[List[Union[str, int]]]) : Segments alignés après l'opération de revert.
      La liste contient les segments avec les valeurs décimales et hexadécimales alignées.

    Remarques :
    - La fonction prend en compte le segment le plus long qui ne subira pas d'ajout ou de retrait de gaps.
    - Elle aligne les autres segments par rapport à ce segment de référence.
    - Les valeurs '-' sont utilisées pour représenter les gaps.
    - Les colonnes excédant le seuil de gaps autorisés sont retirées des segments alignés.
    
    Utilisation :
    Revert_messages(reverted_segments, g_seuil, penalty_matrix, pg)
    """    
    
    
    #On récupère le segment le plus qui ne changera pas après l'opération de revert + d'alignement
    length_segments = [len(s) for s in reverted_segments]
    length_max = max(length_segments)
    pos_longest_segment = length_segments.index(length_max)    
    longuest_segment = reverted_segments[pos_longest_segment]

    
    #Initialisation avec le plus long segments qui ne subira pas d'ajout ou de retrait de gaps
    reverted_segments_aligned = [longuest_segment]
    
    #on récupère les indices nécessaires pour l'itération (ne comprenant pas longuest_segment)
    index_list = [i for i in range(len(reverted_segments))]
    index_list.pop(pos_longest_segment)
    
    for s in index_list:
        alignement =  nw_alignment(longuest_segment,reverted_segments[s], g_seuil, penalty_matrix, pg)
        reverted_segments_aligned.append(alignement[0][1])
    
    #segment en hexadécimal
    reverted_segments_aligned_hex = [[f'0x{int(element):02x}' if isinstance(element, int) and element != '-' else element for element in sublist] for sublist in reverted_segments_aligned]
    
    #Respect du seuil --> discard?
    #Vérifier et supprimer les colonnes dépassant le seuil
    transposed_list = list(map(list, zip(*reverted_segments_aligned)))
    columns_to_remove = [i for i in range(len(transposed_list)) if transposed_list[i].count('-') > g_seuil]
    for i in reversed(columns_to_remove):
        for row in reverted_segments_aligned:
            del row[i]
        for row in reverted_segments_aligned_hex:
            del row[i]
        
    reverted_segments_aligned_dec_hex = [reverted_segments_aligned,reverted_segments_aligned_hex]
    
    return reverted_segments_aligned_dec_hex


#---------------------------------------

def TemplateUpdate(S, g_seuil, penalty_matrix, pg,template_0):
    """
    Met à jour le template en itérant sur les segments alignés à l'aide de l'alignement de Needleman-Wunsch.

    Paramètres :
    - S (dict) : Dictionnaire contenant les segments alignés.
    - g_seuil (int) : Seuil pour le retrait des colonnes excédant le nombre maximal de gaps autorisés.
    - penalty_matrix (str) : Type de matrice de pénalité à utiliser ('linear' ou 'dirac').
    - pg (int) : Pénalité pour l'ajout d'un gap lors de l'alignement.
    - template_0 (dict) : Template initial avant l'itération.

    Retourne :
    - dict_template (dict) : Dictionnaire contenant les informations sur le template mis à jour.
      Les informations incluent le k optimal, la position du premier sous-message, le template hexadécimal et décimal.

    Remarques :
    - La fonction itère sur les paires de segments alignés à l'aide de l'alignement de Needleman-Wunsch.
    - Les colonnes excédant le seuil de gaps autorisés sont retirées des segments alignés.
    - La taille du template itéré ne peut pas être inférieure strictement à k.
    - Si S ne contient qu'un segment, le template reste inchangé, correspondant à la segmentation.

    Utilisation :
    TemplateUpdate(S, g_seuil, penalty_matrix, pg, template_0)
    """
    # Récupérer la liste des segments
    segment_keys = list(S['Segmentation_dec'].keys())

    # Initialiser le template avec le premier segment
    template_in =  S['Segmentation_dec'][segment_keys[0]]
    template_in_hex = ['0x{:02x}'.format(value) for value in template_in]
    


    #Stockage des segments alignés pour le merge
    alignment_segments_history = []
    #Condition S ne contient qu'un segment, c'est qu'il n'y a qu'un seul sous message, Pas besoin d'itéré le template, le template correspond à la segmentation
    if len(segment_keys)>1:
        # Itérer sur les paires de segments
        for i in range(1,len(segment_keys)): #
             alignment = nw_alignment(template_in,S['Segmentation_dec'][segment_keys[i]], g_seuil, penalty_matrix, pg)
             alignment_segments_history.append(alignment[0][0])
             alignment_segments_history.append(alignment[0][1])
             
             #On supprime le message alignée correspondant au merge précédent qui est à présent inutile
             if i>1 :
                 alignment_segments_history.pop(i)  
     
             # Alignment_segments_history en hexadécimal 
             alignment_segments_history_hex = [[f'0x{int(element):02x}' if isinstance(element, int) and element != '-' else element for element in sublist] for sublist in alignment_segments_history]
             alignment_segments_history_dec_hex = [alignment_segments_history,alignment_segments_history_hex]
             
         
             #Il faut prendre en compte l'historiques des messages
             reverted_segments_aligned = Revert_messages(alignment_segments_history,g_seuil,penalty_matrix,pg)
             # Récupération du template avec un merge
             template = merge_messages(reverted_segments_aligned) 
             
             template = template[0]
             template_hex = ['{:02x}'.format(value) for value in template]
     
    
        template_dec_hex = [template,template_hex]
    
    else:
        template = template_in
        template_dec_hex = [template_in,template_in_hex]
     
 
    #Création du template itéré
    dict_template ={}
    first_sub_message_position = template_0['first_sub_message_index']
    k = template_0['k']
    dict_template['first_sub_message_index'] = first_sub_message_position
    dict_template['k'] = k
    
    #Condition1: Le template n'est pas itéré si la condition sur la taille du template (ne peut pas être de taille inférieur strict à k) n'est pas respectée
    #Condition2: si S ne contient qu'un segment, c'est qu'il n'y a qu'un seul sous message, Pas besoin d'itéré le template, le template correspond à la segmentation

    if len(template) < k or len(segment_keys)==1:
        dict_template['template_hex_t'] = template_in_hex
        dict_template['template_dec_t'] = template_in
    else:     
        dict_template['template_hex_t'] = template_dec_hex[1]
        dict_template['template_dec_t'] = template_dec_hex[0]

    

    return dict_template 




def SAMS_criteria(Segmentation_real,Segmentation_all_messages,messages_hex_split,No,w):
    """
    Calcule le critère SAMS (Sub-message Alignment Matching Score) pour évaluer la correspondance entre
    la segmentation réelle et la segmentation trouvée pour un message donné.

    Paramètres :
    - Segmentation_real : Dictionnaire contenant les segmentations réelles des messages.
    - Segmentation_all_messages : Dictionnaire contenant toutes les segmentations trouvées pour tous les messages par "SEIP Process".
    - messages_hex_split : Liste des messages en hexadécimal.
    - No : Numéro du message à évaluer.
    - w : Paramètre pour ajuster le score en fonction de l'alignement des sous-messages.

    Retourne :
    - res : Score final du critère SAMS.
    - w_borne_inf_sup : Borne inférieure et supérieure pour le paramètre w.
    - w_opt : Valeur optimale de w qui minimise le score du critère.

    Remarque :
    - Les segmentations sont représentées en hexadécimal.
    - Le résultat final (res) est basé sur le match_gain, l'Offset_penalty et la segmentation_penaly.
    """

    B_dec = [int(x,16) for x in messages_hex_split[No - 1]]
    n = len(B_dec)

    Segmentation_real_No = Segmentation_real[No]
    keys_dict = list(Segmentation_real_No.keys())

    
    
    if keys_dict != []:
        Segmentation_real_dec_No = Segmentation_real_No[keys_dict[1]]
        keys_real_segmentation = list(Segmentation_real_dec_No.keys())
        keys_real_segmentation = list(reversed(keys_real_segmentation))
        
        #-----match gain
        brk =[]
        for  segment in keys_real_segmentation :
            segment_k = Segmentation_real_dec_No[segment]
            real_right_boundary_octet = segment_k[-1]
            pos = n - 1
            for octet in list(reversed(B_dec)):
                if real_right_boundary_octet == octet:
                    real_right_boundary_pos = pos
                    break
                else:
                    pos = pos -1
            brk.append(real_right_boundary_pos)
    else: 
        brk = []
        Segmentation_real_dec_No = []
    
    Segmentation_trouve_No = Segmentation_all_messages[No]
    keys_dict_found = list(Segmentation_real_No.keys())

    if keys_dict_found != []:
    
    
        Segmentation_trouve_dec_No = Segmentation_trouve_No[keys_dict_found [1]]
        keys_found_segmentation = list(Segmentation_trouve_dec_No.keys())
        keys_found_segmentation = list(reversed(keys_found_segmentation))
    
        bsi = []
        for  segment in keys_found_segmentation :
            segment_k = Segmentation_trouve_dec_No[segment]
            found_right_boundary_octet = segment_k[-1]
            pos = n - 1
            for octet in list(reversed(B_dec)):
                if found_right_boundary_octet == octet:
                    found_right_boundary_pos = pos
                    break
                else:
                    pos = pos -1
                    #found_right_boundary_pos = []
            bsi.append(found_right_boundary_pos)
            
            
    else :
        bsi = []
        Segmentation_trouve_dec_No = []

    
    #-----Offset_penaly
    if Segmentation_real_dec_No != []:
        tailles_elements = {cle: len(valeur) for cle, valeur in Segmentation_trouve_dec_No.items()}
        s_moy_length = sum(list(tailles_elements.values()))/len(tailles_elements)
        # Borne inf et sup de w comme définit dans l'article
        w_borne_inf_sup = 1/2 *  s_moy_length
        
        Offset_penalty = math.exp(-abs(w/abs(s_moy_length)))

    else:
        Offset_penalty = 0
        w_borne_inf_sup = 0
        


    #----matchgain suite
    #Attention si nombre de segment différent
    n_bsi = len(bsi)
    n_brk = len(brk)
    n_b = min(n_bsi,n_brk)
    bsi = bsi[0:n_b+1]
    brk = brk[0:n_b+1]




    match_gain = 0
    
    #On cherche w_optimal, que l'utilisateur peut choisir d'apliquer si il le souhaite avec la variable w 
    if w_borne_inf_sup != 0:
        sum_deltar_list_by_w = []
        w_bottom = -abs(w_borne_inf_sup)
        wtop = abs(w_borne_inf_sup)
        pas_w = wtop/10
        w_list = np.arange(w_bottom, wtop + pas_w, pas_w).tolist()
        for w_val in w_list:
            sum_deltar = 0
            for s in range(n_b):
                deltar = bsi[s]-brk[s]+w_val
                sum_deltar += deltar
            sum_deltar_list_by_w.append(sum_deltar)
                  
        sum_deltar_list_by_w_min = min(sum_deltar_list_by_w)
        index_sum_deltar_list_by_w_min = sum_deltar_list_by_w.index(sum_deltar_list_by_w_min)
        w_opt = w_list[index_sum_deltar_list_by_w_min]
    else: 
        w_opt = 0
    
    
    
    
    #On réalise le calcul avec w donnée par l'utilisateur
    for s in range(n_b):
        deltar = bsi[s]-brk[s]+w
        if deltar < 0:
            deltar = - deltar
        deltar_term = math.exp(-(deltar/2)**2)
        match_gain += deltar_term
        
        
    if Segmentation_real_dec_No != [] and len(Segmentation_real_dec_No) !=1:
        match_gain = 1/ ((len(Segmentation_real_dec_No)) -1 ) * match_gain
    
    elif len(Segmentation_real_dec_No) ==1 :
        match_gain = 0
    else:
        match_gain = 1/ ( -1 ) * match_gain
    

    

    #-----segmentation_penaly
    numSP = abs(len(Segmentation_real_dec_No)) - abs(len(Segmentation_trouve_dec_No))
    denSP = abs(len(Segmentation_real_No)) -1
    segmentation_penaly = math.exp(-(numSP/denSP)**2)

    res = match_gain*Offset_penalty*segmentation_penaly 
    
    
    #On borne le résultat entre 0 et 1
    if res>1:
        res = 1
        
    return res,w_borne_inf_sup,w_opt


