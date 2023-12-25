# ReadMe: Présentation des documents/fichiers fournis 


Le dossier fourni comprend plusieurs dossiers et fichiers afin de réalisé la preuve de concept de l'article: **"Liu et al. - 2022 - Sub-messages extraction for industrial control protocol"**



## Dossier 'documents'

 - Contient l'article sur lequel est réalisé la preuve de concept Liu et al. - 2022 - Sub-messages extraction for industrial control pro.
 
 - Contient les articles utilisés afin d'implémenter les différents algorithmes évoqués dans l'article: "Liu et al. - 2022 - Sub-messages extraction for industrial control protocol".
 
 - Contient une présentation powerpoint de la preuve de concept réalisée.



## Dossier 'Data_found'
- **all_s7_data_from_ics_security_tools:**
  - Contiennent tous les messages du protocole de communication S7 disponibles de manière open source, référencés dans l'article.
- **all_s7_data_from_ics_security_tools et all_s7_data_from_s7_pcaps:**
  - Contiennent des messages du protocole de communication S7 disponibles de manière open source, référencés dans l'article.

- **df_packets_2_repositories_300000_messages et df_packets_2_repositories_50_messages:**
  - Représentent les DataFrames générés par le script "pcap_files_to_df.py", récupérant respectivement l'intégralité et une portion des messages extraits des paquets des dossiers "all_s7_data_from_ics_security_tools" et "all_s7_data_from_s7_pcaps".

- **s7comm_downloading_block_db1.pcap:**
  - Ce fichier, présent dans les données open source trouvées, correspond au paquet utilisé par les auteurs de l'article.

- **data_paper_PRE_image_reformed.txt:**
  - Fichier texte regroupant les données utilisées dans l'article.




## Fichiers Python (.py) et Jupyter (.ipynb) dans le dossier 'Code'

- **POC_extraction_sous_message_notebook.ipynb:**
    - Notebook

- **pcap_files_to_df.py:**
   - Permet de récupérer plus de 300 000 messages extraits de fichiers pcap/pcng présents dans différents répertoires.

- **Sub_messages_extraction_algorithm.py:**
   - Réalise l'extraction de sous-messages pour un message donné. Ce programme est organisé uniquement à l'aide de fonctions.
   
- **Sub_messages_extraction_algorithm_boucle.py:**
   - Réalise l'extraction de sous-messages pour tous les message présent dans l'article. Ce programme est organisé uniquement à l'aide de fonctions.


- **Script_PRE_class.py:**
   - Contient deux classes (All_messages et Message_mi) dont les méthodes correspondent aux fonctions utilisées dans "Sub_messages_extraction_algorithm.py". Ce script, déroulé en programmation orientée objet, permet de récupérer tous les sous-messages de manière plus organisé.



## Dossier 'Func'
 - Contient toutes les fonctions utilisées dans le script **'Sub_messages_extraction_algorithm.py'** et **'Sub_messages_extraction_algorithm_boucle.py'**


## Dossier 'images'
 - Contient les images du jupyter notebook



# 0. Sommaire

    ## I. Introduction et Problématique

    ## II. Aspects Essentiels de l'Ingénierie Inverse des Protocoles (PRE)

    ## III. Method SEIP: Inférence du Format de Protocole
        ### III.1 Collecte et Prétraitement des Données
        ### III.1.2 Inférence de l'En-tête du Protocole
        ### III.3 Séparation de la Charge Utile Longue
        ### III.4 Extraction des Sous-messages
        ### III.5 Inférence du Format des Sous-messages - Segmentation basé sur le template
        ### III.6  Algorithme complet - SEIP   

    ## IV. Résultats - Crtière d'évaluation

    ## V. Réecriture du code en POO
    
    ## VI. Conclusion
