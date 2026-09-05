pub mod utilitaires;
pub mod chaine_securisee;
pub mod salt;
pub mod chiffrement;
pub mod gestionnaire_cle;

use crate::utilitaires::*;
use crate::chaine_securisee::ChaineSecurisee;
use crate::salt::Salt;
use crate::chiffrement::*;
use crate::gestionnaire_cle::*;

use subtle::ConstantTimeEq;
use std::{fs::File, io::{Read, Write}, path::{PathBuf}, fs, env};
use zeroize::Zeroizing;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type Signature = [u8; 32];

pub const NOM_FICHIER_GESTIONNAIRE: &str = "MDP";
pub const NOM_DOSSIER_GESTIONNAIRE: &str = "gestionnaire";
pub const NOM_DOSSIER_SAUVEGARDES: &str = "sauvegardes";



pub fn verifier_mdp_principal_fichier(mdp_principal: &ChaineSecurisee, session: &mut Session) -> Result<Option<FichierMDP>, ErreurGestionnaire> {

    let fichier = charger_mdps(mdp_principal.clone());

    match fichier {
        
        Err(ErreurGestionnaire::ErreurIntegrite(_)) => return Ok(None), 
        Err(e) => return Err(e),
        Ok(fichier) => {

            let res = verifier_mdp_principal_2(&fichier, mdp_principal)?;

            if res {
                
                session.stocker_cles(mdp_principal, &fichier.salt_cle, &fichier.salt_cle_signature)?;
                Ok(Some(fichier))
            
            } else {
                Ok(None)
            }
        },
    }
}

pub fn verifier_mdp_principal(mdp_principal: &ChaineSecurisee) -> Result<bool, ErreurGestionnaire> {

    let fichier = charger_mdps(mdp_principal.clone());

    match fichier {
        
        Err(ErreurGestionnaire::ErreurIntegrite(_)) => return Ok(false),
        Err(e) => return Err(e),
        Ok(fichier) => {

            let res = verifier_mdp_principal_2(&fichier, mdp_principal)?;
            Ok(res)
        }
    }
}

fn verifier_mdp_principal_2(fichier: &FichierMDP, mdp_principal: &ChaineSecurisee) -> Result<bool, ErreurGestionnaire> {
   
   let hash = deriver_hash(&mdp_principal, &fichier.salt_hash)?;

   Ok(verifier_mdp(hash, fichier.hash_principal))
}

fn verifier_mdp(hash_derive: HashMDP, hash_fichier: HashMDP) -> bool {
    hash_derive.ct_eq(&hash_fichier).into()
}



// Fonctions de gestion du fichier de mots de passe


pub(crate) fn fichier_gestionnaire() -> Result<PathBuf, ErreurGestionnaire> {

    let fichier = dossier_gestionnaire()?.join(NOM_FICHIER_GESTIONNAIRE);
    Ok(fichier)
}

pub(crate) fn dossier_gestionnaire() -> Result<PathBuf, ErreurGestionnaire> {

    let dossier = env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    .join(NOM_DOSSIER_GESTIONNAIRE);

    Ok(dossier)
}



pub fn creer_sauvegarde() -> Result<(), ErreurGestionnaire> {

    let dossier_sauvegardes = dossier_gestionnaire()?.join(NOM_DOSSIER_SAUVEGARDES);
    let fichier_gestionnaire = fichier_gestionnaire()?;

    dupliquer_sauvegarde(fichier_gestionnaire, dossier_sauvegardes, false)
}

fn dupliquer_sauvegarde(chemin_fichier_gestionnaire: PathBuf, dossier_sauvegardes: PathBuf, automatique: bool) -> Result<(), ErreurGestionnaire> {

    if !chemin_fichier_gestionnaire.exists() {
        return Ok(());
    }

    let debut_nom_fichier = if automatique { "sauvegarde_automatique_" } else { "sauvegarde_manuelle_" };

    let mut max_index = 0;
    if let Ok(entries) = fs::read_dir(&dossier_sauvegardes) {

        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            
            if name_str.starts_with(debut_nom_fichier) && name_str.ends_with(".bak") {
                let part = name_str.trim_start_matches(debut_nom_fichier).trim_end_matches(".bak");
                
                if let Ok(index) = part.parse::<u32>() {
                    if index > max_index {
                        max_index = index;
                    }
                }
            }
        }
    }

    let nouveau_nom = format!("{}{}.bak", debut_nom_fichier, max_index + 1);
    let chemin_sauvegarde = dossier_sauvegardes.join(nouveau_nom);
    
    fs::copy(&chemin_fichier_gestionnaire, &chemin_sauvegarde)
        .map_err(|e| ErreurGestionnaire::ErreurLecture(e.to_string()))?;

    Ok(())
}

fn signer_fichier(data: Zeroizing<Vec<u8>>, cle_signature: &CleSignature) -> Result<(Zeroizing<Vec<u8>>, Signature), ErreurGestionnaire> {

    cle_signature.cle.expose(|cle_brute| {
        
        let mut mac = HmacSha256::new_from_slice(cle_brute)
            .map_err(|e| ErreurGestionnaire::ErreurIntegrite(e.to_string()))?;
    
        mac.update(&data);
        let signature: Signature = mac.finalize().into_bytes().into();
        
        Ok((data, signature))
    })
}

fn verifier_integrite(signature: &[u8], donnees: &[u8], cle_signature: &CleSignature) -> Result<bool, ErreurGestionnaire> {
    
    cle_signature.cle.expose(|cle_brute| {

        let mut mac = HmacSha256::new_from_slice(cle_brute)
            .map_err(|e| ErreurGestionnaire::ErreurIntegrite(e.to_string()))?;
        
        mac.update(donnees);
        
        Ok(mac.verify_slice(signature).is_ok())
    })
}

fn charger_mdps(mdp : ChaineSecurisee) -> Result<FichierMDP, ErreurGestionnaire> {

    let chemin = fichier_gestionnaire()?;

    charger_fichier_mdp(&chemin, mdp)
}

fn charger_fichier_mdp(chemin: &PathBuf, mdp : ChaineSecurisee) -> Result<FichierMDP, ErreurGestionnaire> {

    let mut fichier = File::open(chemin)
        .map_err(|e| ErreurGestionnaire::ErreurLecture(e.to_string()))?;
    
    let mut buffer = Vec::new();
    fichier.read_to_end(&mut buffer)
        .map_err(|e| ErreurGestionnaire::ErreurLecture(e.to_string()))?;

    if buffer.len() < 48 { // 32 (HMAC) + 16 (Salt minimum)
        return Err(ErreurGestionnaire::ErreurIntegrite("Fichier trop court".to_string()));
    }

    let (signature, corps) = buffer.split_at(32);
    let configuration = config_bincode();

    let (salt_cle_signature, _): (Salt, usize) = bincode::decode_from_slice(corps, configuration)
        .map_err(|e| ErreurGestionnaire::ErreurLecture(format!("Impossible de lire le sel d'intégrité : {}", e)))?;

    let cle_signature = deriver_cle_signature(&mdp, &salt_cle_signature)
        .map_err(|e| ErreurGestionnaire::ErreurIntegrite(e.to_string()))?;

    if !verifier_integrite(signature, corps, &cle_signature)? {
        return Err(ErreurGestionnaire::ErreurIntegrite("La signature du fichier est invalide.".to_string()));
    }

    let (fichier_decode, _): (FichierMDP, usize) = bincode::decode_from_slice(corps, configuration)
        .map_err(|e| ErreurGestionnaire::ErreurLecture(e.to_string()))?;

    Ok(fichier_decode)
}

pub fn sauvegarder_mdps(fichier: &FichierMDP, mdp: Option<&ChaineSecurisee>, session: &mut Session) -> Result<(), ErreurGestionnaire> {

    session.utiliser_cles(| cles| {

        let cle_signature = &cles.cle_signature;

        let chemin = fichier_gestionnaire()?;
        sauvegarder_fichier_mdp(chemin, fichier, &cle_signature)
    }, mdp)?
}

fn sauvegarder_fichier_mdp(chemin: PathBuf, fichier_mdp: &FichierMDP, cle_signature: &CleSignature) -> Result<(), ErreurGestionnaire> {
    
    let configuration = config_bincode();
    let mut buffer_securise = Zeroizing::new(Vec::with_capacity(4096));

    bincode::encode_into_std_write(
    &fichier_mdp, // Passer par référence évite de consommer ou copier la variable
    &mut *buffer_securise, 
    configuration
    ).map_err(|e| ErreurGestionnaire::ErreurChiffrement(e.to_string()))?;

    let buffer_pour_signature = buffer_securise.clone();

    let (buffer, signature) = signer_fichier(buffer_pour_signature, cle_signature)?;
    let buffer_signe = Zeroizing::new([signature.to_vec(), buffer.to_vec()].concat());

    let mut chemin_tmp = chemin.clone();
    chemin_tmp.set_extension("tmp");

    {
        let mut fichier = File::create(&chemin_tmp)
            .map_err(|e| ErreurGestionnaire::ErreurLecture(format!("Impossible de créer le fichier temp : {}", e)))?;
        
        fichier.write_all(&buffer_signe)
            .map_err(|e| ErreurGestionnaire::ErreurLecture(format!("Erreur d'écriture : {}", e)))?;
        
        fichier.sync_all()
            .map_err(|e| ErreurGestionnaire::ErreurLecture(format!("Erreur de synchronisation disque : {}", e)))?;
    }

    std::fs::rename(&chemin_tmp, &chemin)
        .map_err(|e| ErreurGestionnaire::ErreurLecture(format!("Erreur lors du remplacement du fichier : {}", e)))?;

    Ok(())
}

pub fn mdps_existent() -> bool {
    fichier_gestionnaire()
        .map(|c| c.exists())
        .unwrap_or(false)
}



pub fn modifier_mdp_principal(fichier: &mut FichierMDP, nouveau_mdp_principal: ChaineSecurisee, mdp: Option<&ChaineSecurisee>, session: &mut Session) -> Result<(), ErreurGestionnaire> {

    let chemin = fichier_gestionnaire()?;

    modifier_mot_de_passe_principal(fichier, nouveau_mdp_principal, chemin, mdp, session)
}

fn modifier_mot_de_passe_principal(fichier: &mut FichierMDP, nouveau_mdp_principal: ChaineSecurisee, chemin: PathBuf, mdp: Option<&ChaineSecurisee>, session: &mut Session) -> Result<(), ErreurGestionnaire> {

    let nouveau_salt_hash = Salt::new();
    let nouveau_salt_cle = Salt::new();
    let nouveau_salt_cle_signature = Salt::new();
    let nouveau_hash = deriver_hash(&nouveau_mdp_principal, &nouveau_salt_hash)?;
    let nouvelle_cle = deriver_cle(&nouveau_mdp_principal, &nouveau_salt_cle)?;
    let nouvelle_cle_signature = deriver_cle_signature(&nouveau_mdp_principal, &nouveau_salt_cle_signature)?;

    let (mdp_principal_chiffre, iv_principal) = nouveau_mdp_principal.chiffrer(&nouvelle_cle)?;

    let nb_mdp = fichier.donnees_chiffrees.len();

    let mut nouveau_fichier = FichierMDP {
        salt_cle: nouveau_salt_cle.clone(),
        salt_hash: nouveau_salt_hash.clone(),
        salt_cle_signature: nouveau_salt_cle_signature,
        hash_principal: nouveau_hash,
        iv_principal,
        mdp_principal_chiffre: OctetsSecurises::new(mdp_principal_chiffre),
        donnees_chiffrees: Vec::with_capacity(nb_mdp),
    };

    session.utiliser_cles(|cles| -> Result<(), ErreurGestionnaire> {

        for i in 0..nb_mdp {
            let entree = recuperer_entree(fichier, &cles.cle_principale, i)?;
            ajouter_entree(&mut nouveau_fichier, entree, &nouvelle_cle)?;
        }

        Ok(())
    }, mdp)??;

    *fichier = nouveau_fichier;

    sauvegarder_fichier_mdp(chemin, fichier, &nouvelle_cle_signature)?;

    session.stocker_cles(&nouveau_mdp_principal, &nouveau_salt_cle, &nouveau_salt_hash)?;
    
    Ok(())

}



pub fn nouveaux_mdps(mdp_principal : ChaineSecurisee, session: &mut Session) -> Result<FichierMDP, ErreurGestionnaire> {
    
    let (dossier_gestionnaire, dossier_sauvegardes) = creer_dossiers_gestionnaire()?;
    let chemin = dossier_gestionnaire.join(NOM_FICHIER_GESTIONNAIRE);

    let fichier = creer_nouveau_fichier_mdp(mdp_principal.clone(), chemin.clone())?;

    dupliquer_sauvegarde(chemin, dossier_sauvegardes, true)?;

    session.stocker_cles(&mdp_principal, &fichier.salt_cle, &fichier.salt_cle_signature)?;

    Ok(fichier)
}

fn creer_dossiers_gestionnaire() -> Result<(PathBuf, PathBuf), ErreurGestionnaire> {

    let dossier_gestionnaire = dossier_gestionnaire()?;
    let dossier_sauvegardes = dossier_gestionnaire.join(NOM_DOSSIER_SAUVEGARDES);
    std::fs::create_dir_all(&dossier_sauvegardes).map_err(|_| ErreurGestionnaire::ErreurFichiers("Échec de la création du dossier".to_string()))?;

    Ok((dossier_gestionnaire, dossier_sauvegardes))
}

fn creer_nouveau_fichier_mdp(mdp_principal : ChaineSecurisee, chemin: PathBuf) -> Result<FichierMDP, ErreurGestionnaire> {
    
    let salt_hash = Salt::new();
    let salt_cle = Salt::new();
    let nouveau_salt_cle_signature = Salt::new();

    let hash_principal = deriver_hash(&mdp_principal, &salt_hash)?;
    let cle = deriver_cle(&mdp_principal, &salt_cle)?;
    let cle_signature = deriver_cle_signature(&mdp_principal, &nouveau_salt_cle_signature)?;

    let (mdp_principal_chiffre, iv_principal) = mdp_principal.chiffrer(&cle)?;

    let fichier = FichierMDP {
        salt_cle: salt_cle,
        salt_hash: salt_hash,
        salt_cle_signature: nouveau_salt_cle_signature,
        hash_principal: hash_principal,
        iv_principal: iv_principal,
        mdp_principal_chiffre: OctetsSecurises::new(mdp_principal_chiffre),
        donnees_chiffrees: Vec::new(),
    };

    sauvegarder_fichier_mdp(chemin, &fichier, &cle_signature)?;

    Ok(fichier)
}



// Efface un fichier de manière sécurisée.
pub fn effacer_mdps() -> Result<(), ErreurGestionnaire> {
    
    let chemin = fichier_gestionnaire()?;

    effacer_fichier_securise(chemin)
}



pub fn noms_mdps(fichier: &FichierMDP, mdp: Option<&ChaineSecurisee>, session: &mut Session) -> Result<Vec<ChaineSecurisee>, ErreurGestionnaire> {

    session.utiliser_cles(|cles| {

        recuperer_noms(&fichier, &cles.cle_principale)
    }, mdp)?

}

fn recuperer_noms(fichier: &FichierMDP, cle: &Cle) -> Result<Vec<ChaineSecurisee>, ErreurGestionnaire> {
    
    let mut noms = Vec::new();

    for entree_chiffree in &fichier.donnees_chiffrees {

        let nom = ChampInformations::dechiffrer_nom(entree_chiffree, cle)?;
        noms.push(nom);
    }

    Ok(noms)
}



pub fn recuperer_champ_informations(fichier: &FichierMDP, index: usize, mdp: Option<&ChaineSecurisee>, session: &mut Session) -> Result<ChampInformations, ErreurGestionnaire> {

    session.utiliser_cles(|cles| {

        recuperer_entree(fichier, &cles.cle_principale, index)
    }, mdp)?
}

fn recuperer_entree(fichier: &FichierMDP, cle: &Cle, index: usize) -> Result<ChampInformations, ErreurGestionnaire> {
    
    let entree_chiffree = fichier.donnees_chiffrees.get(index)
        .ok_or_else(|| ErreurGestionnaire::ErreurIndex("Index hors limites".to_string()))?;
    
    ChampInformations::dechiffrer(entree_chiffree, cle)
}

pub fn recuperer_mdp_principal(fichier: &FichierMDP, mdp: Option<&ChaineSecurisee>, session: &mut Session) -> Result<ChaineSecurisee, ErreurGestionnaire> {
    
    session.utiliser_cles(|cles| {
       
        ChaineSecurisee::dechiffrer(fichier.mdp_principal_chiffre.octets.to_vec(), &fichier.iv_principal, &cles.cle_principale)
    }, mdp)?
}

// Ajoute une entrée en la chiffrent indépendamment.
pub fn ajouter_champ_informations(fichier: &mut FichierMDP, nouveau_champ_informations: ChampInformations, mdp: Option<&ChaineSecurisee>, session: &mut Session) -> Result<(), ErreurGestionnaire> {

    session.utiliser_cles(|cles| {

        ajouter_entree(fichier, nouveau_champ_informations, &cles.cle_principale)

    }, mdp)??;

    sauvegarder_mdps(fichier, mdp, session)
}

fn ajouter_entree(fichier: &mut FichierMDP, nouvelle_entree: ChampInformations, cle: &Cle) -> Result<(), ErreurGestionnaire> {
    
    let entree_chiffree = nouvelle_entree.chiffrer(cle)?;
    
    fichier.donnees_chiffrees.push(entree_chiffree);
    
    Ok(())
}

// Supprime une entrée par son index dans la liste des entrées déchiffrées. Retourne True si une entrée a été supprimée.
pub fn supprimer_entree(fichier: &mut FichierMDP, index: usize) -> Result<(), ErreurGestionnaire> {

    if index >= fichier.donnees_chiffrees.len() {
        return Err(ErreurGestionnaire::ErreurIndex("Index hors limites".to_string()));
    }

    fichier.donnees_chiffrees.remove(index);
    
    Ok(())
}

// Modifie une entrée existante en la remplaçant par une nouvelle version.
pub fn modifier_champ_informations(fichier: &mut FichierMDP, index: usize, nouveau_champ_informations: ChampInformations, mdp: Option<&ChaineSecurisee>, session: &mut Session) -> Result<(), ErreurGestionnaire> {

    session.utiliser_cles(|cles| {

        modifier_entree(fichier, &cles.cle_principale, index, nouveau_champ_informations)
    }, mdp)??;

    sauvegarder_mdps(fichier, mdp, session)
}

fn modifier_entree(fichier: &mut FichierMDP, cle: &Cle, index: usize, nouvelle_entree: ChampInformations) -> Result<(),ErreurGestionnaire> {

    if index >= fichier.donnees_chiffrees.len() {
        return Err(ErreurGestionnaire::ErreurIndex("Index hors limites".to_string()));
    }

    let entree_chiffree = nouvelle_entree.chiffrer(cle)?;

    fichier.donnees_chiffrees[index] = entree_chiffree;

    Ok(())
}



// Évalue la force du mot de passe

pub fn informations_formattees_securite_mdp(mdp: &ChaineSecurisee, essais_par_seconde: f64) -> (NiveauSecurite, f64, String, String) {

    let (score, entropie, tentatives, secondes) = informations_securite_mdp(&mdp, essais_par_seconde);
    
    // score 0-4, entropie, tentatives, estimation temps formatée
    (score, entropie, formatter_tentatives_fr(tentatives), formater_duree_fr(secondes))
}

fn formatter_tentatives_fr(tentatives: f64) -> String {

    if tentatives < 1_000. {
        format!("{}", tentatives as u64)
    } else {
        format!("{:.1e}", tentatives)
    }
}

fn formater_duree_fr(secondes: f64) -> String {

    let secondes_arrondies = secondes.round() as u64;
    if secondes < 60. {
        return format!("{} seconde{}", secondes_arrondies, if secondes_arrondies > 1 { "s" } else { "" });
    }

    let minutes = secondes_arrondies / 60;
    if minutes < 60 {
        return format!("{} minute{}", minutes, if minutes > 1 { "s" } else { "" });
    }

    let heures = minutes / 60;
    if heures < 24 {
        return format!("{} heure{}", heures, if heures > 1 { "s" } else { "" });
    }

    let jours = heures / 24;
    if jours < 30 {
        return format!("{} jour{}", jours, if jours > 1 { "s" } else { "" });
    }

    let mois = jours / 30;
    if mois < 12 {
        return format!("{} mois", mois);
    }

    let annees = jours / 365;
    if annees < 100 {
        return format!("{} année{}", annees, if annees > 1 { "s" } else { "" });
    }

    format!("{:.0e} années", annees) // Notation scientifique pour les durées astronomiques
}
