# -*- coding: utf-8 -*-
"""
Created on Fri Dec  8 12:52:41 2023

@author: bella
"""

# -*- coding: utf-8 -*-
"""
Created on Tue Nov 21 12:22:33 2023

@author: bella
"""
# =============================================================================
# Répertoire de travail
# =============================================================================
import os
os.chdir('C:\\Users\\bella\\Documents_C\\M2R\\POC\\Projet_POC_extraction_de_sous_messages\\Code')
print("\nLe répertoire de travail est:", os.getcwd())



# =============================================================================
# 
# =============================================================================
#-------------------------Blbiliothèque
import copy
#------------------------- Feremeture de figures 
from matplotlib import pyplot as plt
plt.close('all')

#-------------------------Mes fonctions
from Func.PRE_fonctions import data_from_paper_txt_to_df
from  Func.PRE_fonctions import split_message
# from Func.PRE_fonctions import calculer_entropie_H_bx
# from Func.PRE_fonctions import calculer_EP_bx
# from Func.PRE_fonctions import  calculer_entropie_modifiee_total_messages
from  Func.PRE_fonctions import calculer_position_moyenne_premier_sous_message
# from Func.PRE_fonctions import calculer_entropie_H_mi
# from Func.PRE_fonctions import H_entropie_mi_bx
# from Func.PRE_fonctions import calculer_entropie_modifiee_message_mi
from Func.PRE_fonctions import calculer_position_premier_sous_message
from Func.PRE_fonctions import ACF_matrix
from Func.PRE_fonctions import ACF_matrix_V0
from Func.PRE_fonctions import ACF
# from Func.PRE_fonctions import calculate_penalty_linear
# from Func.PRE_fonctions import calculate_penalty_dirac
# from Func.PRE_fonctions import nw_alignment
# from Func.PRE_fonctions import merge_messages
# from Func.PRE_fonctions import Revert_messages
from Func.PRE_fonctions import Segmentation
from Func.PRE_fonctions import Segmentation_show
from Func.PRE_fonctions import TemplateUpdate
from Func.PRE_fonctions import SAMS_criteria

# =============================================================================
# =============================================================================
# # Début du code
# =============================================================================
# =============================================================================
print("\n----------------------------------------------------------")
print("-----------------------Début du code-----------------------------------")
print("----------------------------------------------------------")




#----------------------------------------------------------------------------------------------------------------------------
#----------------------Code extrait du fichier Sub_messages_extraction_algorithm.py----------------------------------------
#----------------------------------------------------------------------------------------------------------------------------

# =============================================================================
# Blbiliothèques
# =============================================================================
import copy
from matplotlib import pyplot as plt

# =============================================================================
# Chargement des données de l'article depuis un fichier texte
# =============================================================================
filename = 'Data_found\\data_paper_PRE_image_reformed.txt'
df = data_from_paper_txt_to_df(filename)

# =============================================================================
# Extraction des messages des communications
# =============================================================================
messages_hex, messages_hex_split = split_message(df)

# =============================================================================
# Paramètres du programme
# =============================================================================
acf_seuil = 2  # Un sous-message a au minimum une longueur de deux octets
penalty_matrix = 'linear'
# penalty_matrix = 'dirac'
pg = -0.1  # Pénalité pour les gaps
g_seuil = 2  # Pas plus de 2 gaps alignés pour 3 segments
l_max = 100  # Nombre maximal d'itérations
t_seuil = 1  # Seuil de différence entre le dernier template et le précédent

# =============================================================================
# Boucle sur les messages No=1....17
# =============================================================================
Segmentation_all_messages =['Nan'] #On récupère les segmentations finales dans cette variable pour tous les messages

number_of_messages= len(messages_hex_split)
for No in range(1,number_of_messages+1):

    # -----------------------------------
    message_hex = messages_hex[No - 1]
    B = messages_hex_split[No - 1]
    #print("\nÉtude sur le message numéro:", No)

    # =============================================================================
    # Détermination de la position du premier sous-message en utilisant l'entropie uniquement
    # =============================================================================

    critere_valide, first_sub_message_position_by_ACF_Matrix = ACF_matrix(messages_hex,No)
    first_sub_message_position_by_entropie = calculer_position_premier_sous_message(No, messages_hex_split, messages_hex)
    first_sub_message_position = first_sub_message_position_by_entropie
    plt.close()
    plt.close()

#     print(
#         f"\nPosition du premier sous-message: {first_sub_message_position} - existe ssi il est supérieur à acf_seuil:{acf_seuil} "
#     )


    # =============================================================================
    # Détermination de la position du premier sous-message en utilisant l'entropie et l'ACF matrix pour les message long 
    # =============================================================================

    #2-------Position du premier sous message s'il existe (Cut the protocol header operation)
    #--------Deux méthodes existe pour trouver la position du premier sous message 

    # if critere_valide == 1 and int(first_sub_message_position_by_entropie)!=1:  #Rappel: first_sub_message_position_by_entropie = 1 est la valeur par défaut signifiant qu'il n'y a pas de sous message dans le message
    #2.1-----Méthode 1: ACF_matrix - si le message est "long" ( --> satisfaction de deux critères, si les critères sont vérifiés critere_valide = 1)
    #     first_sub_message_position = str(min(first_sub_message_position_by_ACF_Matrix))
    # #2.2-----Méthode 2: Entropie - si le message est n'est pas "long", on utlise en l'entropie pour trouver la position du premier sous message ( -->  message_mi.critere_valide = 0)
    # else:   
    #     first_sub_message_position = first_sub_message_position_by_entropie



    # =============================================================================
    # Initialisation du template
    # =============================================================================
    if int(first_sub_message_position) > 1:  # Rappel : si position_premier_sous_message <= 1, le message n'a pas de sous-message
        template = ACF(B, acf_seuil, first_sub_message_position)
        #print("\ntemplate", template)
        plt.close()
        plt.close()



        # =============================================================================
        # Boucle permettant de mettre à jour le template dans le but de trouver la meilleure segmentation S
        # =============================================================================
        l = 0
        dt = t_seuil * 100  # Valeur initiale > t_seuil random (100 correspond à 0x64)

        template_0 = copy.deepcopy(template)  # Copie profonde du template initial

        # Stockage des segmentations et des templates au fur et à mesure des itérations
        S_list = []
        template_list = [template_0]

        while dt > t_seuil and l_max > l:

            # =============================================================================
            # Segmentation du message en utilisant le template actuel
            # =============================================================================
            S = Segmentation(B, template, pg, penalty_matrix)
            S_list.append(S)

            # =============================================================================
            # Mise à jour du template en utilisant la segmentation actuelle
            # =============================================================================
            template = TemplateUpdate(S, g_seuil, penalty_matrix, pg, template_0)
            template_list.append(template)

            # =============================================================================
            # Calcul de la différence entre le template actuel et le précédent
            # =============================================================================
            dt_list = [
                t1 - t2 for t1, t2 in zip(template_list[-1]["template_dec_t"], template_list[-2]["template_dec_t"])
            ]
            dt = sum(dt_list)

            l += 1  # Itération

        #print("\nSegmentation finale:", S)
    else:
        template = {}
        S = {}
    
    
    #Récupération de la ségmentation pour le message No
    Segmentation_all_messages.append(S)




# =============================================================================
# Critère évaluation
# =============================================================================


Segmentation_real = [
    'Nan', 
    {'Segmentation_hex': {'s1': ['0xc1', '0x02', '0x02', '0x00'], 's2': ['0xc2', '0x02', '0x02', '0x02'], 's3': ['0xc0', '0x01', '0x0a']}, 'Segmentation_dec': {'s1': [193, 2, 2, 0], 's2': [194, 2, 2, 2], 's3': [192, 1, 10]}}, 
     'Nan',   'Nan', 'Nan',  'Nan',      'Nan',    
    #7
    {},  
    #8
    {'Segmentation_hex': {'s1': ['0x00', '0x01', '0x22', '0x03']}, 'Segmentation_dec': {'s1': [0, 1, 34, 3]}},  
     #9  
    {'Segmentation_hex': {'s1': ['0x00', '0x00', '0x22', '0x07'], 's2': ['0x00', '0x01','0x22', '0x07'],  's3': ['0x00','0x02', '0x22','0x11'],  's4': ['0x00', '0x03','0x22','0x07'], 's5': ['0x00','0x04','0x22','0x07'], 's6': ['0x00','0x07','0x22','0x07'], 's7': ['0x00','0xc8','0x22','0x10'], 's8': ['0x02','0xbd','0x22','0x10'], 's9': ['0x0b','0xb8','0x22','0x07'], 's10': ['0x03','0xe8','0x22','0x07'], 's11': ['0x03','0xea','0x22','0x07'], 's12': ['0x03','0xe9','0x22','0x07']}, 
     'Segmentation_dec': {'s1': [0, 0, 34, 7], 's2': [0, 1, 34, 7], 's3': [0, 2, 34, 17], 's4': [0, 3, 34, 7], 's5': [0, 4, 34, 7], 's6': [0, 7, 34, 7], 's7': [0, 200, 34, 16], 's8': [2, 189, 34, 16], 's9': [11, 184, 34, 7], 's10': [3, 232, 34, 7], 's11': [3, 234, 34, 7], 's12': [3, 233, 34, 7]}}, 
    'Nan', 
    #11
    {'Segmentation_hex': {'s1': ['0x01', '0x09', '0xc1', '0x02', '0x01', '0x00', '0xc2'], 's2': ['0x02', '0x01', '0x02']}, 'Segmentation_dec': {'s1': [1, 9, 193, 2, 1, 0, 194], 's2': [2, 1, 2]}}, 
    'Nan', 'Nan',    'Nan', 'Nan',   'Nan', 'Nan', 
    ]

No = 11
w=-2.5
res,w_borne,w_opt = SAMS_criteria(Segmentation_real,Segmentation_all_messages,messages_hex_split,No,w)



