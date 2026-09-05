
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use zeroize::Zeroizing;
use crate::utilitaires::*;
use crate::chaine_securisee::ChaineSecurisee;



pub(crate) trait Chiffrable {
    fn chiffrer(&self, cle: &Cle) -> Result<(Vec<u8>, IV), ErreurGestionnaire>;
}

pub(crate) trait Dechiffrable: Sized {
    fn dechiffrer(data: Vec<u8>, iv: &IV, cle: &Cle) -> Result<Self, ErreurGestionnaire> where Self: Sized;
}



impl Chiffrable for Vec<u8> {

    fn chiffrer(&self, cle: &Cle) -> Result<(Vec<u8>, IV), ErreurGestionnaire> {
        
        let cle_aes = cle.cle.expose(|cle_brute| {

            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cle_brute))
        });

        let iv = generer_iv();
        
        cle_aes.encrypt(&iv.into(), self.as_slice())
            .map(|ctext| (ctext, iv))
            .map_err(|_| ErreurGestionnaire::ErreurChiffrement("Échec de l'opération cryptographique".to_string()))
    }
}

impl Dechiffrable for Vec<u8> {

    fn dechiffrer(data: Vec<u8>, iv: &IV, cle: &Cle) -> Result<Self, ErreurGestionnaire> {
        
        let cle_aes = cle.cle.expose(|cle_brute| {

            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cle_brute))
        });
        
        let nonce = Nonce::from_slice(iv);
        
        cle_aes.decrypt(nonce, data.as_slice())
        .map_err(|_| ErreurGestionnaire::ErreurDechiffrement("Échec de l'opération cryptographique".to_string()))
    }
}



impl Chiffrable for ChaineSecurisee {

    fn chiffrer(&self, cle: &Cle) -> Result<(Vec<u8>, IV), ErreurGestionnaire> {
        
        let configuration = config_bincode();
        let mut mdp_a_chiffrer = Zeroizing::new(Vec::with_capacity(128));

        self.expose(|string| {
            
            bincode::encode_into_std_write(
            string.as_bytes(), 
            &mut *mdp_a_chiffrer, 
            configuration
            ).map_err(|_| ErreurGestionnaire::ErreurChiffrement("Échec de la sérialisation".to_string()))
        })?;

        Ok(mdp_a_chiffrer.chiffrer(cle)?)
    }
}

impl Dechiffrable for ChaineSecurisee {

    fn dechiffrer(data: Vec<u8>, iv: &IV, cle: &Cle) -> Result<Self, ErreurGestionnaire> {

        let mdp_dechiffre = Zeroizing::new(<Vec<u8>>::dechiffrer(data, iv, cle)?);

        let configuration = config_bincode();
        let (mdp_decode, _): (ChaineSecurisee, usize) = bincode::decode_from_slice(&mdp_dechiffre, configuration)
            .map_err(|_| ErreurGestionnaire::ErreurDechiffrement("Échec de l'opération cryptographique".to_string()))?;
        
        Ok(mdp_decode)
    }
}



impl Chiffrable for (Vec<ChaineSecurisee>, Vec<ChaineSecurisee>, ChaineSecurisee) {

    fn chiffrer(&self, cle: &Cle) -> Result<(Vec<u8>, IV), ErreurGestionnaire> {

        let configuration = config_bincode();
        
        let mut autres_champs_a_chiffrer = Zeroizing::new(Vec::with_capacity(256));
    
        bincode::encode_into_std_write(
            (&self.0, &self.1, &self.2),
            &mut *autres_champs_a_chiffrer,
            configuration
        ).map_err(|_| ErreurGestionnaire::ErreurChiffrement("Échec de l'opération cryptographique".to_string()))?;
        
        <Vec<u8>>::chiffrer(&autres_champs_a_chiffrer, cle)
    }
}

impl Dechiffrable for (Vec<ChaineSecurisee>, Vec<ChaineSecurisee>, ChaineSecurisee) {

    fn dechiffrer(data: Vec<u8>, iv: &IV, cle: &Cle) -> Result<Self, ErreurGestionnaire> {

        let autres_champs_dechiffres = Zeroizing::new(<Vec<u8>>::dechiffrer(data, iv, cle)?);

        let configuration = config_bincode();
        let (autres_champs_decodes, _): ((Vec<ChaineSecurisee>, Vec<ChaineSecurisee>, ChaineSecurisee), usize) = bincode::decode_from_slice(&autres_champs_dechiffres, configuration)
            .map_err(|_| ErreurGestionnaire::ErreurDechiffrement("Échec de l'opération cryptographique".to_string()))?;
        
        Ok(autres_champs_decodes)
    }
}



impl ChampInformations {

    pub(crate) fn dechiffrer_nom(entree: &EntreeChiffree, cle: &Cle) -> Result<ChaineSecurisee, ErreurGestionnaire> {
        <ChaineSecurisee>::dechiffrer(entree.nom_chiffre.octets.to_vec(), &entree.iv_nom, cle)
    }

    pub(crate) fn dechiffrer(entree: &EntreeChiffree, cle: &Cle) -> Result<Self, ErreurGestionnaire> {
        let nom = Self::dechiffrer_nom(entree, cle)?;
        
        let (identifiants, mdps, commentaire) = 
            <(Vec<ChaineSecurisee>, Vec<ChaineSecurisee>, ChaineSecurisee)>::dechiffrer(
                entree.autres_champs_chiffres.octets.to_vec(), 
                &entree.iv_autres_champs, 
                cle
            )?;

        Ok(ChampInformations { nom, identifiants, mdps, commentaire })
    }

    pub(crate) fn chiffrer(&self, cle: &Cle) -> Result<EntreeChiffree, ErreurGestionnaire> {

        let (nom_chiffre, iv_nom) = self.nom.chiffrer(cle)?;
        let (autres_champs_chiffres, iv_autres_champs) = (self.identifiants.clone(), self.mdps.clone(), self.commentaire.clone()).chiffrer(cle)?;

        Ok(EntreeChiffree {
            nom_chiffre: OctetsSecurises::new(nom_chiffre),
            iv_nom: iv_nom,
            autres_champs_chiffres: OctetsSecurises::new(autres_champs_chiffres),
            iv_autres_champs: iv_autres_champs,
        })
    }
}