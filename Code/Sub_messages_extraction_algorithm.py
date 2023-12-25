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

# =============================================================================
# =============================================================================
# # Début du code
# =============================================================================
# =============================================================================
print("\n----------------------------------------------------------")
print("-----------------------Début du code-----------------------------------")
print("----------------------------------------------------------")




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
No = 1 # Numéro du message Fig1 de l'article
acf_seuil = 2  # Un sous-message a au minimum une longueur de deux octets
penalty_matrix = 'linear'
# penalty_matrix = 'dirac'
pg = -0.1  # Pénalité pour les gaps
g_seuil = 2  # Pas plus de 2 gaps alignés pour 3 segments
l_max = 100  # Nombre maximal d'itérations
t_seuil = 1 # Seuil de différence entre le dernier template et le précédent

# -----------------------------------
message_hex = messages_hex[No - 1]
B = messages_hex_split[No - 1]
print("\nÉtude sur le message numéro:", No)

# =============================================================================
# Détermination de la position du premier sous-message en utilisant l'entropie uniquement
# =============================================================================

#critere_valide, first_sub_message_position_by_ACF_Matrix = ACF_matrix(messages_hex,No)
first_sub_message_position_by_entropie = calculer_position_premier_sous_message(No, messages_hex_split, messages_hex)
first_sub_message_position = first_sub_message_position_by_entropie

print(
    f"\nPosition du premier sous-message: {first_sub_message_position} - existe ssi il est supérieur à acf_seuil:{acf_seuil} "
)


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
    print("\ntemplate", template)



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

    print("\nSegmentation finale:", S)
else:
    template = {}
    S = {}




