# -*- coding: utf-8 -*-
"""
Created on Thu Nov 30 22:07:19 2023

@author:BA
"""
# =============================================================================
# Blibliothèques
# =============================================================================
#Pour lire les paquets
from scapy.all import rdpcap, IP, TCP
from scapy.utils import hexdump


import os


import pandas as pd
import numpy as np
from matplotlib import pyplot as plt
import math
from collections import Counter
from statistics import mean,variance
from scipy.stats import pearsonr
import random
import copy
from decimal import Decimal  




# =============================================================================
# Class Data
# =============================================================================


class All_messages:
    
    def __init__(self, filename_data_from_paper_txt, filename_data_open_source_df_csv, data_type):
        """ 
        Entrée:
        - filename_data_from_paper_txt, filename_data_open_source_df_csv: filenames of data
        - data_type (str): Le type de données ('data_from_paper' ou 'data_open_source')
        
        Remarques:
        - Au lieu d'utiliser df_from_pcap_to_df_for_all_repository dans ce script pour récuperer les données open source 
        - On récupère le dataframe crée directement avec le script "pcap_files_to_df.py" afin d'éviter le temps nécessaires pour récupérer et traiter les fichiers pcap
        
        """
        
        self.df_data_open_source = self.data_open_source_to_df(filename_data_open_source_df_csv)
        
        #Les dichiers pcap utilisés dans l'articles sontrécupérés dans un fichier .txt
        self.df_data_from_paper = self.data_from_paper_txt_to_df(filename_data_from_paper_txt)

        
        self.messages_hex = []
        self.messages_hex_split = []
        self.number_of_messages = []
        self.split_message(data_type)

        self.length_longest_message = []
        self.modified_entropy_messages = []
        self.entropie_total_messages = []
        self.ep_total_messages = []
        self.calculer_entropie_modifiee_total_messages()
        #self.Plot_entropie_modifiee_total_messages
        
        self.position_moyenne_premier_sous_message = []
        self.calculer_position_moyenne_premier_sous_message()
        #self.Plot_entropie_modifiee_total_messages()
        
#---------------------------Open source data extraction NB: tcp_messages_from_pcap_to_df et df_from_pcap_to_df_for_all_repository sont utilisées et exécutées dans "pcap_files_to_df.py" pour un gain du temps au lancement du script----------------------------------------------------------------

    def tcp_messages_from_pcap_to_df(self,filename):
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


    def df_from_pcap_to_df_for_all_repository(self,repertoire_list):
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
                df_resultant = self.tcp_messages_from_pcap_to_df(fichier)
                
                #Ajout de la colonne pour connaitre le nom du repertoire
                df_resultant['Nom_du_repertoire'] = repertoire.split("\\")[1]
                df_resultant['Nom_du_packet'] = fichier.split("\\")[2]
                # Ajout du DataFrame résultant à la liste
                liste_dataframes.append(df_resultant)
    
        df = pd.concat(liste_dataframes, ignore_index=True)
    
        #return liste_dataframes, df
        return df
    
    
#---------Récupération du datadrame crée par les fonctions précédentes-----------------

    def data_open_source_to_df(self, filename_df_data_open_source):
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
    
    

#---------------Data from the paper ----------------------------------------------------------------------------

    def data_from_paper_txt_to_df(self, filename):
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

#------------------------------------------------------------------------
    def split_message(self,data_type):
        """
        Divise les messages hexadécimaux d'une colonne 'tcp_payload' en listes d'octets.
    
        Entrée:
        - self: L'instance de la classe.
        - data_type (str): Le type de données ('data_from_paper' ou 'data_open_source').
    
        Sortie:
        - Aucune (mise à jour des attributs de l'instance) :
            - self.messages_hex (list): Liste des messages hexadécimaux d'origine.
            - self.messages_hex_split (list): Liste des messages divisés en listes d'octets.
            - self.number_of_messages (int): Nombre total de messages.
        """        
        
        if data_type == 'data_from_paper':
            messages_df = list(self.df_data_from_paper['tcp_payload'])
        elif data_type == 'data_open_source':
            messages_df = list(self.df_data_open_source['tcp_payload'])
        else:
            raise ValueError("Merci de choisir entre data_type ='data_from_paper' ou data_type = 'data_open_source' ")
            
            
        messages = []
        for message in messages_df:
            split_message = message.split(' ')
            messages.append(split_message)
        
        
        self.messages_hex = messages_df
        self.messages_hex_split= messages
        self.number_of_messages = len(messages)

#------------------------------------------------------------------------
    
    def calculer_entropie_H_bx(self,position_byte):
        """
        Calcule l'entropie de la position spécifiée de l'octet bx dans les messages.
    
        Entrée:
        - self: L'instance de la classe.
        - position_byte (int): Position de l'octet bx.
    
        Sortie:
        - entropie_H_bx (float): L'entropie de la position spécifiée.
        - bytes_name (list): Liste des octets différents à la position spécifiée.
        - probabilites_bx (list): Distribution de probabilité des valeurs à la position spécifiée.
        """
        #position_byte: position de l'octet bx
        #messages: tout les messages du tableau Fig1
        messages = self.messages_hex_split
        
        
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
        
   
        # Calculer l'entropie en utilisant la formule
        entropie_H_bx = -sum(p * math.log2(p) for p in probabilites_bx)
        
        return entropie_H_bx, bytes_name,probabilites_bx
        
#------------------------------------------------------------------------
       
    def calculer_EP_bx(self, position_byte):
        """
        Calcule le pourcentage de messages qui contiennent la position spécifiée de l'octet bx.
    
        Entrée:
        - self: L'instance de la classe.
        - position_byte (int): Position de l'octet bx.
    
        Sortie:
        - EP_bx (float): Pourcentage de messages contenant la position spécifiée de l'octet bx.
        """
        #position_byte: position de l'octet bx
        #messages: tout les messages du tableau Fig1
        messages = self.messages_hex_split
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


    def calculer_entropie_modifiee_total_messages(self):
        """
        Calcule l'entropie modifiée des messages hexadécimaux.
    
        Entrée:
        - self: L'instance de la classe.
    
        Sortie:
        - Aucune (mise à jour des attributs de l'instance) :
            - self.length_longest_message (int): Nombre maximal d'octets enregistrés.
            - self.modified_entropy_messages (list): Liste des entropies modifiées pour chaque octet.
            - self.entropie_total_messages (list): Liste des entropies pour chaque octet.
            - self.ep_total_messages (list): Liste des pourcentages de messages pour chaque octet.
        """
        
        messages = self.messages_hex_split
        #nombre d'octet maximal enregistré
        length_longest_message = max([len(message) for message in messages ])
        
        entropie_total_messages,bytes_name_total_messages,ep_total_messages = [], [], []
        for octet in range(length_longest_message):    
            entropie,bytes_name,probabilites = self.calculer_entropie_H_bx(octet)
            entropie_total_messages.append(entropie)
            bytes_name_total_messages.append(bytes_name)
            
            ep = self.calculer_EP_bx(position_byte=octet)
            ep_total_messages.append(ep)
            
            
        paires = zip(entropie_total_messages,ep_total_messages)
        Modified_entropy_of_total_messages = []
        for x,y in paires:
            if y !=0:
                
                Modified_entropy_of_total_messages.append(x/y)
            else:
                Modified_entropy_of_total_messages.append(0)
        
        #Ajout d'attribut
        self.length_longest_message = length_longest_message
        self.modified_entropy_messages = Modified_entropy_of_total_messages
        self.entropie_total_messages = entropie_total_messages
        self.ep_total_messages = ep_total_messages
        
        
        
#---------------------------------------------------------------------------------------------------------
    

    def Plot_entropie_modifiee_total_messages(self):
        """
        Trace le graphe de l'entropie modifiée, de l'entropie et du pourcentage de messages pour chaque octet.
    
        Entrée:
        - self: L'instance de la classe.
    
        Sortie:
        - Aucune (affiche le graphe).
        """        

        length_longest_message = self.length_longest_message
        modified_entropy_messages = self.modified_entropy_messages 
        entropie_total_messages = self.entropie_total_messages 
        ep_total_messages = self.ep_total_messages
                
        plt.figure()
        plt.plot(list(range(length_longest_message)),modified_entropy_messages,'o-',label='Modified_entropy_of_total_messages')
        plt.plot(list(range(length_longest_message)),entropie_total_messages,label='H(bx)')
        plt.plot(list(range(length_longest_message)),ep_total_messages, label='EP(bx)')
        plt.ylabel('H(bx) / EP(bx)')
        plt.xlabel('bx')
        plt.title('Figure 3.(a) bis')
        plt.legend()
       
        
#---------------------------------------------------------------------------------------------------------        
        
    def calculer_position_moyenne_premier_sous_message(self):
        """
        Calcule la position moyenne du premier octet d'un sous-message pour tous les messages hexadécimaux.
    
        Entrée:
        - self: L'instance de la classe.
    
        Sortie:
        - Aucune (mise à jour de l'attribut de l'instance) :
            - self.position_moyenne_premier_sous_message (int): Position moyenne du premier octet d'un sous-message.
        """
        
        #tous les messages
        messages = self.messages_hex_split
        
        #On reprend le programme de la fonction Modified_entropy_of_total_messages(messages)
        length_longest_message = max([len(message) for message in messages ])
        
        entropie_total_messages,bytes_name_total_messages,ep_total_messages,probabilites_total_messages = [], [], [],[]
        for octet in range(length_longest_message):    
            entropie,bytes_name,probabilites = self.calculer_entropie_H_bx(position_byte=octet)
            entropie_total_messages.append(entropie)
            bytes_name_total_messages.append(bytes_name)
            probabilites_total_messages.append(probabilites)
            
            ep = self.calculer_EP_bx(position_byte=octet)
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
        
    
        
        #Ajout d'attribut
        self.position_moyenne_premier_sous_message = sub_message_starting_position_total_message
    


#-------------------------------------------------------------------------------------------



    def Plot_position_moyenne_premier_sous_message_et_entropie_modifiee_total_message(self):
        """
        Trace le graphe de l'entropie modifiée et marque la position moyenne du premier octet d'un sous-message.
    
        Entrée:
        - self: L'instance de la classe.
    
        Sortie:
        - Aucune (affiche le graphe).
        """
        length_longest_message = self.length_longest_message
        modified_entropy_messages = self.modified_entropy_messages 
        sub_message_starting_position_total_message = self.position_moyenne_premier_sous_message
        #plotting
        plt.figure()
        plt.plot(list(range(length_longest_message)),modified_entropy_messages ,'o-',label='Modified_entropy_of_total_messages')
        plt.axvline(x=sub_message_starting_position_total_message, color='red', linestyle='--', label='sub_message_starting_position_total_message')
        plt.ylabel('H(bx) / EP(bx)')
        plt.xlabel('bx')
        plt.title('Figure 3.(a)')
        plt.legend()
    
            
#---------------------------------------------------------------------------------------------------------
#---------------------------------------- Message_mi class
#---------------------------------------------------------------------------------------------------------


    
class Message_mi():
    

    def __init__(self, filename_data_from_paper_txt, filename_data_open_source_df_csv, data_type, number):
        """
        Initialisateur de la classe.
    
        Entrées:
        - filename_data_from_paper_txt (str): Le chemin du fichier texte avec les données du papier.
        - filename_data_open_source_df_csv (str): Le chemin du fichier CSV avec les données open source.
        - data_type (str): Le type de données ('data_from_paper' ou 'data_open_source').
        - number (int): Le numéro associé à l'instance.
    
        Sortie:
        - Aucune (initialise les attributs de la classe).
        """        
        #super().__init__(filename) # je préfère ne pas avoir les attributs de la classe précédente dans cette classe --> utilisation de l'instance directement
        Messages = All_messages( filename_data_from_paper_txt, filename_data_open_source_df_csv, data_type)
        self.Messages = Messages #Pour avoir les informations sur l'ensemble des messages
        
        self.No = number
        
        self.bx_taille_message = []
        self.n_gramms_and_pearson_correlation()
        
        
        self.entropie_mi = []
        self.calculer_entropie_H_mi()
       
        self.length_message_mi =[]
        self.entropie_modifiee_message_mi = []
        self.calculer_entropie_modifiee_message_mi() 
        #self.Plot_entropie_modifiee_message_mi()
        
        self.position_premier_sous_message_by_entropie = []
        self.calculer_position_premier_sous_message()
        #self.Plot_position_premier_sous_message_et_entropie_modifiee_total_message():
            
        self.critere_valide_acf_matrix = [] 
        self.acf_matrix =  []
        self.window_max_index = []
        self.position_premier_sous_message_by_ACF_matrix = []
        self.ACF_matrix()
        #self.Plot_ACF_matrix_heating_map()
        
        self.template = []
        self.acf_k_values = []
        #self.ACF(acf_seuil)  --> fonction à lancer en fonction de acf_seuil

        
        self.NW_matrix_list = [] 
        self.DP_matrix =[] 
        self.M = []
        self.S = [] 
        #self.Segmentation(pg,penalty_matrix)
        
        
        #MAJ de self.template
        #self.TemplateUpdate(self,g_seuil, penalty_matrix, pg,template_0)
        

        


#-------------------------------------------------------------------------------------------------------------------    
        


    def calculer_entropie_H_mi(self):
        """
        Calcule l'entropie d'un message spécifique.
    
        Entrées:
        - Aucune (utilise les attributs de l'instance).
    
        Sortie:
        - Aucune (met à jour l'attribut 'entropie_mi').
        """
        #No: numero message
        #messages: tout les messages du tableau Fig1
        No = self.No
        messages = self.Messages.messages_hex_split

        
        #print("\nAttention, le numéro du message correspond au numéro de message présent sur l'article")
        message_mi = messages[No-1]
        
        bytes_names = list(Counter(message_mi).keys())
        probabilites = [count / len(message_mi ) for count in Counter(message_mi ).values()]
        entropie_mi = -sum(p * math.log2(p) for p in probabilites)
             
        #ajout d'attribut
        self.entropie_mi = entropie_mi 
        
#-------------------------------------------------------------------------------------------------------------------    
        

    def calculer_entropie_H_mi_bx(self, position_byte):
        """
            Calcule l'entropie modifiée pour une position spécifique dans un message.
        
            Entrées:
            - position_byte (int): Position de l'octet bx.
        
            Sortie:
            - H_mi_bx_value (float): Valeur de l'entropie modifiée pour la position spécifiée.
        """        
        
        # Calcul de l'entropie modifiée pour une position spécifique
        messages = self.Messages.messages_hex_split
      
        # Calcul de l'entropie pour chaque message
        H_mi_value =  self.entropie_mi
        
        # Calcul de l'entropie modifiée pour chaque message
        
        H_bx = self.Messages.calculer_entropie_H_bx(position_byte)[0]
        EP_bx = self.Messages.calculer_EP_bx(position_byte)
        
        if (float(H_bx) == 0.0) | (float(EP_bx) == 0.0):
            H_mi_bx_value = 0
        else: 
            H_mi_bx_value = H_mi_value / (H_bx* EP_bx) 
        
        return H_mi_bx_value
    
#-------------------------------------------------------------------------------------------------------------------    


    def calculer_entropie_modifiee_message_mi(self):
        """
    Calcule l'entropie modifiée pour chaque position d'octet dans un message.

    Sorties:
    - None (les résultats sont stockés comme attributs de l'instance).
        """
        No = self.No
        messages = self.Messages.messages_hex_split
        
        #message sur lequel on calcule
        message_mi = messages[No-1]
        length_message_mi = len(message_mi)
        
        #boucle sur les bx
        H_mi_bx_values = []
        for octet in range(length_message_mi):
            H_mi_bx_values.append(self.calculer_entropie_H_mi_bx(octet))
    

        #ajout d'attrbut
        self.entropie_modifiee_message_mi = H_mi_bx_values
        self.length_message_mi = len(message_mi)

#-------------------------------------------------------------------------------------------------------------------    

    
    def Plot_entropie_modifiee_message_mi(self):
        """
            Trace le graphique de l'entropie modifiée pour chaque position d'octet dans un message.
        
            Sorties:
            - None (affiche le graphique).
            """
        No = self.No
        H_mi_bx_values = self.entropie_modifiee_message_mi
        length_message_mi = self.length_message_mi
        
        #plotting
        plt.figure()
        plt.plot(list(range(length_message_mi)),H_mi_bx_values,'o-',label=' H_mi_bx_values')
        plt.ylabel('Hmi(bx)')
        plt.xlabel('bx')
        plt.title('Figure 3.(b) pour le message m' + str(No))
        plt.legend()
    
#-------------------------------------------------------------------------------------------------------------------    

    def n_gramms_and_pearson_correlation(self):
        """
        Calcul des N-grams et de la corrélation de Pearson entre les octets du message et leur longueur.
    
        Sorties:
        - None (met à jour les attributs de l'instance).
        """        
        
        No = self.No
        messages_hex = self.Messages.messages_hex
        
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
            message_decimal.append([ (int(byte, 16)) for byte in n_grams])
            
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
        #print(f"L'octet donnant l'indication sur longueur du message est l'octet numéro: {Taille_probable_de_sous_message[0]}")
       
        
    
        #Attribut
        self.bx_taille_message =  Taille_probable_de_sous_message[0] 

#----------------------------------------------------------------------------------------------------------------

    def calculer_position_premier_sous_message(self):
        """
        Calcul de la position du premier sous-message en fonction des probabilités obtenues par la fonction 'calculer_entropie_H_bx'.
    
        Sorties:
        - None (met à jour les attributs de l'instance).
        """     
        messages_hex_split = self.Messages.messages_hex_split
        messages_hex = self.Messages.messages_hex
        bx_taille_message = self.bx_taille_message
        No = self.No

        
        #message sur lequel on calcule
        message_mi = messages_hex[No-1]
        message_mi = message_mi.split()
        
        #On récupère les proba comme dans la fonctions sub_message_starting_position_for_all_message
        length_message_mi = len(message_mi)
        length_longest_message = max([len(message) for message in messages_hex_split ])

        bytes_name_total_messages,probabilites_total_messages = [], []
        for octet in range(length_longest_message):    
            entropie,bytes_name,probabilites = self.Messages.calculer_entropie_H_bx(position_byte=octet)

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
        sub_message_starting_position_message = []
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

            
       
        #Si la position du premier sous message est inférieur strict à 4  [ Le 4eme octet correspond à la longueur du message Résultat trouvé grâce à la fonction n_gramms_and_pearson_correlation() ]
        elif int(res_first_sub_message_position) < bx_taille_message:
            print("\n !----Le message ne contient pas de sous messages----!")
            res_first_sub_message_position = 0
            
        #Si la position du premier sous message n'est pas trouvé, c'est qu'il y a sans doute pas de sous message
        elif res_first_sub_message_position == 0:
            print("\n !----Le message ne contient pas de sous messages----!")
            res_first_sub_message_position = 0                 
        
        
        #--------------Out
        if res_first_sub_message_position == 0:
            first_sub_message_position_b1 = res_first_sub_message_position + 1 
        else:    
            first_sub_message_position_b0 = str (int(res_first_sub_message_position))   #position si on considère que le premier bit est b0 
            first_sub_message_position_b1 = str (int(res_first_sub_message_position) + 1) #position si on considère que le premier bit est b1
            
        
        #Ajout d'attribut
        self.position_premier_sous_message_by_entropie = first_sub_message_position_b1 
        
        
#-----------------------------------------------------------------------------------------------------------------


    def Plot_position_premier_sous_message_et_entropie_modifiee_total_message(self): 
        """
        Plotting de la position du premier sous-message par rapport à l'entropie modifiée pour un message donné.
    
        Sorties:
        - None (affiche le graphique).
        """        
        No = self.No
        
        H_mi_bx_values = self.entropie_modifiee_message_mi
        
        position_premier_sous_message = self.position_premier_sous_message_by_entropie
            
        length_message_mi = self.length_message_mi
        
        # ---------------plotting
         # On récupère les valeurs de Hmi(bx)

        plt.figure()
        plt.plot(list(range(length_message_mi)),H_mi_bx_values,'o-',label=' H_mi_bx_values')
        if int(position_premier_sous_message) != 1:
            plt.axvline(x=int(position_premier_sous_message), color='red', linestyle='--', label='sub_message_position')
        plt.ylabel('Hmi(bx)')
        plt.xlabel('bx')
        plt.title('Figure 3.(b) pour le message m' + str(No))
        plt.legend()


           
#-----------------------------------------------------------------------------------------------------------------


    def ACF_matrix(self):
        
        """
        Calcul de l'ACF (AutoCorrelation Function) pour un message et création d'une matrice d'ACF.
    
        Sorties:
        - None (met à jour les attributs de l'instance).
        """
        
        No = self.No
        
        #Traitement du message
        messages_hex_split = self.Messages.messages_hex_split
        message_split =  self.Messages.messages_hex_split[No-1]
        
        #Filtrage de message, est ce que l'ACF peut être réalisé sur le message en question 
        #Cette méthode ne fonctionne que pour les long message généralement doté d'une structure de sous message:
           #Critère 1: les messages dont l longueur_message > moyenne 
           #Critère 2: (longueur_message - moyenne)**2 >  variance
        
        length_message = len(message_split)
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
        
        
        if critere_valide_acf_matrix == 1:
            
            #To illustrate that the sub-messages may be a part of the payload,
            # Ajoutez 10 nombres aléatoires à la liste
            for _ in range(10):
                random_number = random.randint(0, 255)
                message_split.append('{:02x}'.format(random_number))   
            
            
            message_main=[int(x, 16) for x in message_split]
            message_main_npa  = np.array(message_main)
            message_main_npa =  message_main_npa.astype(np.float64)  
            n = len(message_main_npa)
            #----------------------------------------------------------
            #On remplit la matrice message_moving avec les octets qui compose le message pour quelle devienne triangulaire supérieur 
            #Cette opération est nécessaire pour retrouver un graphique équivalent à celui de l'article
            message_window_bx = np.zeros((n , n))
            for j in range(n):
                message_window_bx[:, j] = message_main_npa
            message_window_bx = np.triu(message_window_bx)
            
            message_window_by = np.zeros((n , n))
            for i in range(n):
                message_window_by[i, :] = message_main_npa
            message_window_by = np.triu(message_window_by)
            
            
            ACF_matrix = np.zeros((n,n))#ACF matrix
            p = np.zeros((n,n)) #product matrix
            
                
            # Méthode 2 - Calculer l'ACF par ligne par ligne
            message_main_matrix = np.zeros((n,n))
            for i in range((n)):
                message_main_matrix[i,:] = message_main
            
           
        
            for i in range(n):
                for j in range(n):
                    if j >=i: 
                        value = min(np.correlate(message_window_bx[i,i:j+1], message_window_by[0:i+1,j], mode='valid'))
                        #normalization_factor = np.std(message_window_bx[i, i:j+1]) * np.std(message_window_by[0:i+1, j])
            
                        # Calcul de la normalisation
                        std_bx = np.std(message_window_bx[i, i:j+1])
                        std_by = np.std(message_window_by[0:i+1, j])
            
                        # Vérification de l'écart-type non nul
                        normalization_factor = std_bx * std_by if std_bx != 0 and std_by != 0 else 1
            
                        # Normalisation de ACF_matrix
                        ACF_matrix[i, j] = value / normalization_factor
                        
                        # produit avec la taille de la fenêtre
                        p[i, j] = ACF_matrix[i, j] * (j - i)
                
                
            # Trouver l'indice où l'ACF atteint sa valeur maximale
            max_value = np.max(ACF_matrix)
            #ACF_matrix: En pourcentage
            ACF_matrix_p = ACF_matrix/max_value
        
        
        
                
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
            bx = window_max_index[0]
            by = window_max_index[1]
            
            
            #Ajout attribut 
            self.critere_valide_acf_matrix = critere_valide_acf_matrix
            self.position_premier_sous_message_by_ACF_matrix = min(bx,by)
            self.acf_matrix = ACF_matrix_p
            self.window_max_index = window_max_index
        
        
#-----------------------------------------------------------------------------------------------------------------        
        
    def Plot_ACF_matrix_heating_map(self):
        """
        Affiche la carte de chaleur (heatmap) de la matrice d'ACF.
    
        Sorties:
        - None (affiche la heatmap).
        """
    
        ACF_matrix_p = self.acf_matrix
        # Créer la heatmap
        plt.figure()
        plt.imshow(ACF_matrix_p,cmap='viridis', interpolation='None')
        plt.colorbar()
        plt.ylabel('bx')
        plt.xlabel('by')
        plt.title("ACF heating map")
        plt.show()
        
    
#-------------------------------------------------------------------------------------------------

    def ACF(self,acf_seuil):
        """
        Calculates the Autocorrelation Function (ACF) and determines the optimal k for sub-message detection.
    
        Parameters:
        - acf_seuil (int): The threshold for ACF values to be considered significant.
    
        Returns:
        - None (updates instance attributes with ACF results).
        """
        
        No = self.No
        
        B = self.Messages.messages_hex_split[No-1]
        
        if self.critere_valide_acf_matrix == 1:
            position_premier_sous_message = self.position_premier_sous_message_by_ACF_matrix
        else:   
            position_premier_sous_message = self.position_premier_sous_message_by_entropie
            

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
        if int(position_premier_sous_message) + k_opt > n+1:
            k_opt = n+2 - int(position_premier_sous_message) 
        #Par observation si les valeurs de l'acf ne pique que de manière négative, c'est que k correspond à la taille du payload complet, il y a donc qu'un seul sous message
        if k_opt == 0:
            k_opt = n+1 - int(position_premier_sous_message) +1 
        
        
        #Création du template t = (b1,b2,...bk*)
        template = {}
        template['k'] = k_opt
        template['first_sub_message_index'] = int(position_premier_sous_message)
        
        template['template_hex_t'] = B[template['first_sub_message_index'] -1:template['first_sub_message_index']-1 + template['k']]
        
        template['template_dec_t'] = [int(x, 16) for x in template['template_hex_t']]
        
        
        #Attribut 
        self.template = template 
        self.acf_k_values = acf_values_for_all_k_with_threshold
    
    
#-------------------------------------------------------------------------------------------------


    def Plot_ACF_k(self):
        """
        Plots the Autocorrelation Function (ACF) for different k values and highlights the optimal k.
    
        Returns:
        - None (displays the plots).
        """

        No = self.No
        
        template = self.template 
        
        if template !=[]:
            
            B = self.Messages.messages_hex_split[No-1]
            acf_values_for_all_k_with_threshold = self.acf_k_values
            k_opt = self.template['k']
            
            message_dec = [int(x,16) for x in B]
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
        
            #plotting
            #Graphique complet 
            plt.figure()
            x_values = list(range(0,len(message_dec)-1))
            y_values = acf_values_for_all_k_with_threshold
            y_zero = [0]*len(y_values)
            # Créer le nuage de points
            plt.scatter(x_values, y_values,s=10)
            plt.plot(x_values,y_zero)
            plt.vlines(x_values, 0, y_values, linestyles='solid')
            plt.xlabel("k")
            plt.ylabel("ACF(k)")
            
#-------------------------------------------------------------------------------------------------------
    def calculate_penalty_linear(self,bi, bj):
        """
        Calculates the linear penalty between two values.
    
        Parameters:
        - bi (int): First value.
        - bj (int or None): Second value. If None, it is considered as 0.
    
        Returns:
        - float: Linear penalty between the two values.
        """
        if bj == None:
            bj = 0
        if bi== None:
            bi = 0
                
        res = -2 * abs(bi - bj) / 255 + 1
        return res
    
    
    def calculate_penalty_dirac(self,bi, bj):
        """
        Calculates the Dirac penalty between two values.
    
        Parameters:
        - bi (int): First value.
        - bj (int): Second value.
    
        Returns:
        - int: Dirac penalty (1 if values are equal, 0 otherwise).
        """
        res = 0
        if bi == bj:
            res = 1
        return res


#-------------------------------------------------------------------------------------------------------------------


    def nw_alignment(self,message1, message2, g_seuil, penalty_matrix, pg):
        """
        Effectue un alignement de séquence Needleman-Wunsch entre deux messages.
    
        Paramètres :
        - self : Instance de la classe contenant cette méthode.
        - message1 (list) : Premier message d'entrée.
        - message2 (list) : Deuxième message d'entrée.
        - g_seuil (int) : Seuil de gap, nombre maximal de gaps autorisés dans l'alignement.
        - penalty_matrix (str) : Type de matrice de pénalité à utiliser ('linear' ou 'dirac').
        - pg (int) : Pénalité pour un gap.
    
        Renvoie :
        - aligned_messages (list) : Liste contenant les messages alignés en formats décimal et hexadécimal.
    
        Remarque :
        - Suppose que les méthodes self.calculate_penalty_linear et self.calculate_penalty_dirac sont définies.
    
        Utilisation :
        aligned_messages = self.nw_alignment(message1, message2, g_seuil, penalty_matrix, pg)
        """
        
        n = len(message1)
        m = len(message2)
    
        # Initialize the NW matrix
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
                    match = nw_matrix[i - 1, j - 1] + self.calculate_penalty_linear(bi, bj)
                    delete = nw_matrix[i - 1, j] + pg
                    insert = nw_matrix[i, j - 1] + pg
                    nw_matrix[i, j] = max(match, delete, insert)
    
        if penalty_matrix == 'dirac':
            # Fill in the NW matrix
            for i in range(1, n + 1):
                for j in range(1, m + 1):
                    bi = message1[i - 1] if isinstance(message1[i - 1], int) else None
                    bj = message2[j - 1] if isinstance(message2[j - 1], int) else None
                    match = nw_matrix[i - 1, j - 1] + self.calculate_penalty_dirac(bi, bj)
                    delete = nw_matrix[i - 1, j] + pg
                    insert = nw_matrix[i, j - 1] + pg
                    nw_matrix[i, j] = max(match, delete, insert)
    
        # Ajout de gap
        aligned_message1 = []
        aligned_message2 = []
        i, j = n, m
        while i > 0 or j > 0:
            bi = message1[i - 1] if i > 0 and isinstance(message1[i - 1], int) else None
            bj = message2[j - 1] if j > 0 and isinstance(message2[j - 1], int) else None
            condition_1 = (nw_matrix[i, j] == nw_matrix[i - 1, j - 1] + self.calculate_penalty_linear(bi, bj)) & (
                        penalty_matrix == 'linear')
            condition_2 = (nw_matrix[i, j] == nw_matrix[i - 1, j - 1] + self.calculate_penalty_dirac(bi, bj)) & (
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
    
    
#-------------------------------------------------------------------------------------------------------------------

    def Segmentation(self,pg,penalty_matrix):
        """
        Réalise la segmentation d'un message en sous-messages en utilisant la méthode d'alignement global.
    
        Paramètres :
        - self : Instance de la classe contenant cette méthode.
        - pg (int) : Pénalité pour un gap dans l'alignement global.
        - penalty_matrix (str) : Type de matrice de pénalité à utiliser ('linear' ou 'dirac').
    
        Renvoie :
        - None : La fonction met à jour les attributs de l'instance pour stocker les résultats.
    
        Remarques :
        - La fonction utilise la méthode Needleman-Wunsch pour aligner les séquences.
        - Les matrices NW_matrix, DP_matrix, M et la segmentation S sont stockées comme attributs de l'instance.
        - Suppose que les méthodes self.calculate_penalty_linear et self.calculate_penalty_dirac sont définies.
    
        Utilisation :
        self.Segmentation(pg, penalty_matrix)
        """
        
        No = self.No
        
        if self.critere_valide_acf_matrix == 1:
            position_premier_sous_message = self.position_premier_sous_message_by_ACF_matrix
        else:   
            position_premier_sous_message = self.position_premier_sous_message_by_entropie
        
        if int(position_premier_sous_message) > 1: # rappel si position_premier_sous_message <= 1, le message n'a pas de sous message
            B = self.Messages.messages_hex_split[No-1]
            template = self.template
                
            
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
            #On récupère dans cette variable les lignes qui vont servir à crée la matrice triangulaire supérieure servant à determiner M
            #On récupère les lignes de la matrice - Figure 7 (b)
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
                            nw1 = NW_matrix[i-1, j-1] + self.calculate_penalty_dirac(bi, bj)
                            nw2 = NW_matrix[i-1, j] + pg
                            nw3 = NW_matrix[i, j-1] + pg
                
                            NW_matrix[i, j] = max(nw1, nw2, nw3)
             
                
                if penalty_matrix =='linear':
                    
                    # Filling
                    for i in range(1,n_dp):
                        for j in range(1,n_template+1):
                            bi = payload_dec[i+i_dp]
                            bj = template_dec[j]
                            nw1 = NW_matrix[i-1, j-1] + self.calculate_penalty_linear(bi, bj)
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
            if len(M1) != 0:
                
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
            
            
            
            #ajout d'attribut
            self.NW_matrix_list = NW_matrix_list
            self.DP_matrix = DP_matrix
            self.M = M
            self.S = S
        

    def merge_messages(self,aligned_messages):
        """
            Fusionne une séquence de messages alignés en une seule séquence fusionnée.
        
            Paramètres :
            - self : Instance de la classe contenant cette méthode.
            - aligned_messages (list) : Liste contenant les messages alignés. Chaque message est une liste d'éléments alignés.
        
            Renvoie :
            - list : Liste contenant la séquence fusionnée, à la fois en décimal et en hexadécimal.
        
            Remarques :
            - Les valeurs '-' représentent un espace (gap) dans l'alignement.
            - Pour chaque position, la valeur maximale non '-' parmi les messages alignés est conservée.
            - La séquence fusionnée est retournée sous forme de liste contenant les séquences fusionnées en décimal et en hexadécimal.
        
            Utilisation :
            merged_messages = self.merge_messages(aligned_messages)
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


    def Revert_messages(self,reverted_segments,g_seuil,penalty_matrix,pg):
        """
        Rétablit les segments alignés après une opération de "revert" en conservant le segment le plus long inchangé et ajoutant des gaps aux autres segments
    
        Paramètres :
        - self : Instance de la classe contenant cette méthode.
        - reverted_segments (list) : Liste des segments à rétablir après une opération de "revert".
        - g_seuil (int) : Seuil maximal autorisé pour le nombre de gaps dans l'alignement.
        - penalty_matrix (str) : Type de matrice de pénalité à utiliser ('linear' ou 'dirac').
        - pg (int) : Pénalité pour l'ouverture d'un gap dans l'alignement.
    
        Renvoie :
        - list : Liste contenant les segments rétablis, à la fois en décimal et en hexadécimal.
    
        Remarques :
        - La méthode utilise le segment le plus long qui ne subira pas d'ajout ou de retrait de gaps comme référence.
        - Chaque segment est aligné avec le segment de référence à l'aide de l'algorithme Needleman-Wunsch.
        - Les colonnes dépassant le seuil de gaps autorisé sont supprimées pour chaque segment rétabli.
        - Les segments rétablis sont renvoyés sous forme de liste contenant les segments en décimal et en hexadécimal.
    
        Utilisation :
        reverted_segments_aligned_dec_hex = self.Revert_messages(reverted_segments, g_seuil, penalty_matrix, pg)
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
            alignement =  self.nw_alignment(longuest_segment,reverted_segments[s], g_seuil, penalty_matrix, pg)
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


    def TemplateUpdate(self,g_seuil, penalty_matrix, pg,template_0):
        """
            Met à jour le template en itérant sur les segments alignés obtenus à partir de l'opération de "revert".
        
            Paramètres :
            - self : Instance de la classe contenant cette méthode.
            - g_seuil (int) : Seuil maximal autorisé pour le nombre de gaps dans l'alignement.
            - penalty_matrix (str) : Type de matrice de pénalité à utiliser ('linear' ou 'dirac').
            - pg (int) : Pénalité pour l'ouverture d'un gap dans l'alignement.
            - template_0 (dict) : Dictionnaire contenant les informations initiales sur le template.
        
            Remarques :
            - La méthode itère sur les segments alignés en utilisant l'algorithme Needleman-Wunsch pour aligner les paires de segments.
            - Les segments alignés sont "revert" et le template est mis à jour en fusionnant les segments alignés à l'aide de la fonction de merge_messages.
            - Le processus d'itération se poursuit jusqu'à ce que tous les segments soient pris en compte.
            - La taille du template itéré est déterminée par les conditions de taille et dépend de la variable k dans le dictionnaire du template_0.
        
            Utilisation :
            TemplateUpdate(g_seuil, penalty_matrix, pg, template_0)
            """
        
        if self.critere_valide_acf_matrix == 1:
            position_premier_sous_message = self.position_premier_sous_message_by_ACF_matrix
        else:   
            position_premier_sous_message = self.position_premier_sous_message_by_entropie
        
        
        if int(position_premier_sous_message) > 1: # rappel si position_premier_sous_message <= 1, le message n'a pas de sous message
            S = self.S
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
                     alignment = self.nw_alignment(template_in,S['Segmentation_dec'][segment_keys[i]], g_seuil, penalty_matrix, pg)
                     alignment_segments_history.append(alignment[0][0])
                     alignment_segments_history.append(alignment[0][1])
                     
                     #On supprime le message alignée correspondant au merge précédent qui est à présent inutile
                     if i>1 :
                         alignment_segments_history.pop(i)  
             
                     # Alignment_segments_history en hexadécimal 
                     alignment_segments_history_hex = [[f'0x{int(element):02x}' if isinstance(element, int) and element != '-' else element for element in sublist] for sublist in alignment_segments_history]
                     alignment_segments_history_dec_hex = [alignment_segments_history,alignment_segments_history_hex]
                     
                 
                     #Il faut prendre en compte l'historiques des messages
                     reverted_segments_aligned = self.Revert_messages(alignment_segments_history,g_seuil,penalty_matrix,pg)
                     # Récupération du template avec un merge
                     template = self.merge_messages(reverted_segments_aligned) 
                     
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
        
            
            
            #self.dict_template = dict_template
            #Ajout attribut
            #MAJ de la variable template
            self.template = dict_template
        
       
        
# =============================================================================
# =============================================================================
# # Exemple d'utilisation des classes
# =============================================================================
# =============================================================================

#--------------------------------------------------------------------
#---------------Class message - Exemple d'Utilisation-----------------------
#--------------------------------------------------------------------

# filename_data_paper = 'Data_found\\data_paper_PRE_image_reformed.txt'
# #filename_data_open_source = 'Data_found\\df_packets_2_repositories_300000_messages.csv' #300000 messages le calcul est très très long 4
# filename_data_open_source = 'Data_found\\df_packets_2_repositories_100_messages.csv'

# data_type = 'data_open_source'
# #data_type = 'data_from_paper'

# Messages = All_messages(filename_data_paper,filename_data_open_source,data_type)

# df_data_from_paper = Messages.df_data_from_paper
# df_data_open_source = Messages.df_data_open_source

# #dépendant du data_type
# messages_hex = Messages.messages_hex
# messages_hex_split = Messages.messages_hex_split



# length_longest_message = Messages.length_longest_message
# modified_entropy_messages = Messages.modified_entropy_messages 
# entropie_total_messages = Messages.entropie_total_messages 
# ep_total_messages = Messages.ep_total_messages
# #Messages.Plot_entropie_modifiee_total_messages()

# position_moyenne_premier_sous_message = Messages.position_moyenne_premier_sous_message
# #Messages.Plot_position_moyenne_premier_sous_message_et_entropie_modifiee_total_message()



#--------------------------------------------------------------------
#---------------Class message_mi - Exemple d'Utilisation -----------------------
#--------------------------------------------------------------------
# No = 9
# message_9 = Message_mi(filename_data_paper,filename_data_open_source,data_type, No)
# number = message_9.No 
# bx_taille_message = message_9.bx_taille_message

# entropie_mi = message_9.entropie_mi
# entropie_modifiee_message_mi  = message_9.entropie_modifiee_message_mi 
# length_message_mi = message_9.length_message_mi 
# H_mi_bx_values = message_9.entropie_modifiee_message_mi
# #message_9.Plot_entropie_modifiee_message_mi()

# position_premier_sous_message = message_9.position_premier_sous_message_by_entropie
# #message_9.Plot_position_premier_sous_message_et_entropie_modifiee_total_message()


# critere_valide_acf_matrix = message_9.critere_valide_acf_matrix
# ACF_matrix_p = message_9.acf_matrix 
# window_max_index = message_9.window_max_index
# position_premier_sous_message_by_ACF_matrix = message_9.position_premier_sous_message_by_ACF_matrix
#message_9.Plot_ACF_matrix_heating_map()



# acf_seuil = 2
# message_9.ACF(acf_seuil)
# template  = message_9.template 
# acf_values_for_all_k = message_9.acf_k_values 
# #message_9.Plot_ACF_k()


# pg = -0.1
# penalty_matrix = 'linear'
# message_9.Segmentation(pg,penalty_matrix)
# NW_matrix_list  = message_9.NW_matrix_list
# DP_matrix = message_9.DP_matrix 
# M = message_9.M
# S = message_9.S 


# g_seuil = 2
# template_0 = copy.deepcopy(template)
# message_9.TemplateUpdate(g_seuil, penalty_matrix, pg,template_0)
# dict_template  = message_9.dict_template


# =============================================================================
# =============================================================================
# # Début du code
# =============================================================================
# =============================================================================
print("\n----------------------------------------------------------")
print("-----------------------Début du code-----------------------------------")
print("----------------------------------------------------------")



# =============================================================================
# =============================================================================
# # Sub messages extraction algorithm
# =============================================================================
# =============================================================================

#------------------------Paramètres modifiables--------------------------------------
acf_seuil = 2  ##Un sous message à au minimum une longueur de deux octet
penalty_matrix = 'linear'
#penalty_matrix = 'dirac'
pg = -0.1 #gap penalty
g_seuil = 2 #Pas plus de 2 gaps alignés pour 3 segments
l_max = 5 #Nombre de loop maximal
t_seuil  = 1 #seuil de différence entre le dernier template et le précédant





#-------------------------- Initialisation: Sub messages extraction algorithm for all messages---------------------------------------------

#0.1-----Récupération de tous les messages

#filename_data_open_source = 'Data_found\\df_packets_2_repositories_300000_messages.csv' #300000 messages le calcul est très très long 4
filename_data_open_source = 'Data_found\\df_packets_2_repositories_50_messages.csv'
filename_data_paper = 'Data_found\\data_paper_PRE_image_reformed.txt'

#data_type = 'data_open_source'
data_type = 'data_from_paper'

Messages = All_messages(filename_data_paper,filename_data_open_source,data_type)
number_of_messages =  Messages.number_of_messages 

#0.2-----Récupération des Segmentations pour chaque message (Placement du 0 pour que les index coincïde avec No)
Segmentation_all_messages = ['Nan']

for No in range(1,number_of_messages+1): #number_of_messages+1
    #1-------Récupération d'un message
    
    B = Messages.messages_hex_split[No-1]
    message_mi = Message_mi(filename_data_paper,filename_data_open_source,data_type, No)
    
    
    #2-------Position du premier sous message s'il existe (Cut the protocol header operation)
    
    #----------------En utilisant seulement l'entropie----------------------
    position_premier_sous_message = message_mi.position_premier_sous_message_by_entropie
    
    
    # #----------------En utilisant seulement la condition comme définit dans l'article----------------------
    # #--------Deux méthodes existe pour trouver la position du premier sous message 
    # #2.1-----Méthode 1 si le message est "long" ( --> satisfaction de deux critères, si les critères sont vérifiés message_mi.critere_valide = 1)
    # if message_mi.critere_valide_acf_matrix == 1: 
    #     position_premier_sous_message = message_mi.position_premier_sous_message_by_ACF_matrix
    # #2.2-----Méthode 2 si le message est n'est pas "long", on utlise en l'entropie pour trouver la position du premier sous message ( -->  message_mi.critere_valide = 0)
    # else:       
    #     position_premier_sous_message = message_mi.position_premier_sous_message_by_entropie
    
    
    #3-------Template initialisation
    message_mi.ACF(acf_seuil)
    template  = message_mi.template 
    template_0 = copy.deepcopy(template) #copie profonde du template initial stockée
    
    #4-------Bouclage
    #-------------------------- Boucle: Sub messages extraction algorithm for all messages---------------------------------------------
    
    l = 0
    dt = t_seuil*100 #Valeur initial > tseuil random (100 correspond 0x64)
    
    
    #Stockage des segmentations et des templates au fur et à mesures des itérations
    S_list = []
    template_list = [template_0]
    
    
    while dt > t_seuil and l_max > l:
    
        #4.1-------Segmentation du payload (payload: message sans l'entête, protocol header) (NB: la MAJ de la segmentation se fait via l'attribut self.S dans la méthdode)
        message_mi.Segmentation(pg,penalty_matrix)
        S = message_mi.S
        S_list.append(S)
        
        
        
        # # #4.1-------Update du template pour l'itération suivante (NB: la MAJ du template se fait via l'attribut self.template dans la méthdode)
        message_mi.TemplateUpdate(g_seuil, penalty_matrix, pg,template_0)
        new_template = message_mi.template
        template_list.append(new_template)
    
        
        #difference entre le template actuelle et le précédant
        dt_list = [t1 - t2 for t1, t2 in zip(template_list[-1]['template_dec_t'] , template_list[-2]['template_dec_t'])]
        dt = sum(dt_list)
        
        l += 1 #itération
    
    Segmentation_all_messages.append(S_list)


 


# =============================================================================
# =============================================================================
# # Close figure
# =============================================================================
# =============================================================================#
plt.close('all')









