use argon2::{Argon2, Params, Algorithm, Version};
use rand_chacha::ChaCha20Rng;
use rand::{SeedableRng, seq::IndexedRandom};
use aes_gcm::{AeadCore, Aes256Gcm, aead::{OsRng as AesRng}};
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use memguard_rs::Secret;
use bincode::{Decode, Encode, config, de::Decoder, error::DecodeError};
use zxcvbn::zxcvbn;
use file_shred::shred_file;

use crate::chaine_securisee::ChaineSecurisee;
use crate::gestionnaire_cle::Cles;
use crate::salt::Salt;

const KO_DECHIFFREMENT: u32 = 32000;




pub(crate) type IV = [u8; 12];
pub(crate) type HashMDP = [u8; 32];


#[derive(PartialEq, Clone)]
pub enum NiveauSecurite {
    TresFaible,
    Faible,
    Modere,
    Fort,
    TresFort,
    ExtremementFort,
}

#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Clone)]
pub(crate) struct OctetsSecurises {
    pub(crate) octets: Zeroizing<Vec<u8>>
}

impl OctetsSecurises {
    
    pub(crate) fn new(octets: Vec<u8>) -> Self {
        Self { octets: Zeroizing::new(octets) }
    }
}

pub(crate) struct Cle {
    pub(crate) cle: Secret<[u8; 32]>
}


pub(crate) type CleSignature = Cle;



#[derive(Serialize, Deserialize, Decode, Encode, Zeroize, ZeroizeOnDrop)]
pub(crate) struct EntreeChiffree {
    pub(crate) iv_nom: IV,
    pub(crate) nom_chiffre: OctetsSecurises,
    pub(crate) iv_autres_champs: IV,
    pub(crate) autres_champs_chiffres: OctetsSecurises,
}

#[derive(Clone)]
pub struct ChampInformations {
    pub nom: ChaineSecurisee,
    pub identifiants: Vec<ChaineSecurisee>,
    pub mdps: Vec<ChaineSecurisee>,
    pub commentaire: ChaineSecurisee
}

#[derive(Serialize, Deserialize, Decode, Encode, Zeroize, ZeroizeOnDrop)]
pub struct FichierMDP {
    pub(crate) salt_cle_signature: Salt,
    pub(crate) salt_cle: Salt,
    pub(crate) salt_hash: Salt,
    pub(crate) hash_principal: HashMDP,
    pub(crate) iv_principal: IV,
    pub(crate) mdp_principal_chiffre: OctetsSecurises,
    pub(crate) donnees_chiffrees: Vec<EntreeChiffree>,
}

#[derive(Debug)]
pub enum ErreurGestionnaire {
    MotDePasseInvalide(String),
    ErreurGeneration(String),
    ErreurChiffrement(String),
    ErreurDechiffrement(String),
    ErreurLecture(String),
    ErreurSuppression(String),
    ErreurFichiers(String),
    ErreurIntegrite(String),
    ErreurIndex(String),
    ErreurCle(String),
    ErreurSaisie(String),
}

impl fmt::Display for ErreurGestionnaire {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        
        match self {
            ErreurGestionnaire::MotDePasseInvalide(m) => write!(f, "Mot de passe invalide : {}", m),
            ErreurGestionnaire::ErreurGeneration(m) => write!(f, "Erreur de génération : {}", m),
            ErreurGestionnaire::ErreurChiffrement(m) => write!(f, "Erreur de chiffrement : {}", m),
            ErreurGestionnaire::ErreurDechiffrement(m) => write!(f, "Erreur de déchiffrement (fichier corrompu ou mauvaise clé) : {}", m),
            ErreurGestionnaire::ErreurLecture(m) => write!(f, "Erreur de lecture : {}", m),
            ErreurGestionnaire::ErreurSuppression(m) => write!(f, "Erreur de suppression : {}", m),
            ErreurGestionnaire::ErreurFichiers(m) => write!(f, "Erreur de fichiers : {}", m),
            ErreurGestionnaire::ErreurIntegrite(m) => write!(f, "Erreur d'intégrité : {}", m),
            ErreurGestionnaire::ErreurIndex(m) => write!(f, "Erreur d'index : {}", m),
            ErreurGestionnaire::ErreurCle(m) => write!(f, "Erreur de clé : {}", m),
            ErreurGestionnaire::ErreurSaisie(m) => write!(f, "Erreur de saisie : {}", m),
        }
    }
}

impl std::error::Error for ErreurGestionnaire {}



pub(crate) fn config_bincode() -> impl config::Config {
    bincode::config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
}



// utilitaires de dérivation de clé et de hachage du mot de passe principal

pub(crate) fn deriver_cle(mdp: &ChaineSecurisee, salt: &Salt) -> Result<Cle, ErreurGestionnaire> {

    deriver(mdp, "KEY:", salt).map(|cle| Cle { cle:Secret::new(cle) })
}

pub(crate) fn deriver_cle_signature(mdp: &ChaineSecurisee, salt: &Salt) -> Result<CleSignature, ErreurGestionnaire> {
    deriver(mdp, "SIGN:", salt).map(|cle| Cle { cle:Secret::new(cle) })
}

pub(crate) fn deriver_hash(mdp: &ChaineSecurisee, salt: &Salt) -> Result<HashMDP, ErreurGestionnaire> {
    deriver(mdp, "HASH:", salt)
}

pub(crate) fn deriver_cles(mdp_principal: &ChaineSecurisee, salt_cle: &Salt, salt_cle_signature: &Salt) -> Result<Cles, ErreurGestionnaire> {
    
    let cle = deriver_cle(mdp_principal, salt_cle)?;
    let cle_signature = deriver_cle_signature(mdp_principal, salt_cle_signature)?;

    Ok(Cles { cle_principale: cle, cle_signature })
}

fn deriver(mdp: &ChaineSecurisee, chaine: &str, salt: &Salt) -> Result<[u8; 32], ErreurGestionnaire> {
    let mut cle = [0u8; 32];
    
    let params = Params::new(KO_DECHIFFREMENT, 3, 1, Some(32))
        .map_err(|_| ErreurGestionnaire::MotDePasseInvalide("Erreur lors de la dérivation".to_string()))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let mut mdp_complet = Zeroizing::new(Vec::new());
    mdp_complet.extend_from_slice(chaine.as_bytes());

    mdp.expose(| string | {
        mdp_complet.extend_from_slice(string.as_bytes());
    });

    argon2.hash_password_into(
        &mdp_complet,
        &salt.as_bytes(),
        &mut cle
    ).map_err(|_| ErreurGestionnaire::MotDePasseInvalide("Erreur lors de la dérivation".to_string()))?;
    
    Ok(cle)
}



pub(crate) fn generer_iv() -> IV {
    let nonce = Aes256Gcm::generate_nonce(&mut AesRng);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(nonce.as_slice());
    iv
}



pub(crate) fn effacer_fichier_securise(chemin: PathBuf) -> Result<(), ErreurGestionnaire> {
   
    shred_file(&chemin).map_err(|_| ErreurGestionnaire::ErreurSuppression("Échec de la suppression sécurisée".to_string()))
}



// Génère un mot de passe aléatoire selon les critères spécifiés.
pub fn generer_mdp_aleatoire(longueur: usize, minuscules: bool, majuscules: bool, chiffres: bool, speciaux: bool) -> Result<ChaineSecurisee, ErreurGestionnaire> {
    
    let mut alphabet = Zeroizing::new(Vec::new());
    if minuscules { alphabet.extend('a'..='z'); }
    if majuscules { alphabet.extend('A'..='Z'); }
    if chiffres { alphabet.extend('0'..='9'); }
    if speciaux { alphabet.extend("!@#$%^&*()-_=+[]{};:,.<>?/|~`".chars()); }
    
    let mut rng = ChaCha20Rng::from_rng(&mut rand::rng());

    let mdp: Zeroizing<String> = Zeroizing::new((0..longueur)
        .map(|_| *alphabet.choose(&mut rng).unwrap())
        .collect());
    
    Ok(ChaineSecurisee::from_zeroizing(mdp))
}



// Évalue la force du mot de passe
pub(crate) fn informations_securite_mdp(mdp: &ChaineSecurisee, essais_par_seconde: f64) -> (NiveauSecurite, f64, f64, f64) {
    
    mdp.expose(|string| {
        let mdp_chaine = string.as_str();

        let estimation = zxcvbn(mdp_chaine, &[]);
        let guesses = estimation.guesses() as f64;

        let mut taille_alphabet: f64 = 0.;
        if mdp_chaine.chars().any(|c| c.is_ascii_lowercase()) { taille_alphabet += 26.; }
        if mdp_chaine.chars().any(|c| c.is_ascii_uppercase()) { taille_alphabet += 26.; }
        if mdp_chaine.chars().any(|c| c.is_ascii_digit()) { taille_alphabet += 10.; }
        if mdp_chaine.chars().any(|c| !c.is_alphanumeric()) { taille_alphabet += 32.; }

        let tentatives = if mdp_chaine.len() < 100 && guesses < u64::MAX as f64 {
            guesses

        } else {
            taille_alphabet.powf(mdp_chaine.len() as f64)
        };

        let entropie = (mdp_chaine.len() as f64) * taille_alphabet.log2();

        let score = match entropie {
            e if e < 35.0 => NiveauSecurite::TresFaible,
            e if e < 55.0 => NiveauSecurite::Faible,
            e if e < 80.0 => NiveauSecurite::Modere,
            e if e < 100.0 => NiveauSecurite::Fort,
            e if e < 200.0 => NiveauSecurite::TresFort,
            _ => NiveauSecurite::ExtremementFort,
        };

        let secondes = tentatives / essais_par_seconde;

        (score, entropie, tentatives, secondes)
    })
}

impl Encode for OctetsSecurises {

    fn encode<E: bincode::enc::Encoder>(&self, encoder: &mut E) -> Result<(), bincode::error::EncodeError> {
        let s = self.octets.as_slice();
        s.encode(encoder)
    }
}

impl<C> bincode::Decode<C> for OctetsSecurises 
where 
    Vec<u8>: bincode::Decode<C> 
{
    fn decode<D: Decoder<Context = C>>(decoder: &mut D) -> Result<Self, DecodeError> {

        let vec = Vec::<u8>::decode(decoder)?;
        Ok(OctetsSecurises {
            octets: Zeroizing::new(vec),
        })
    }
}

impl<'de, C> bincode::BorrowDecode<'de, C> for OctetsSecurises 
where 
    Vec<u8>: bincode::Decode<C> 
{ 
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(decoder: &mut D) -> Result<Self, DecodeError> {
        
        let vec = Vec::<u8>::borrow_decode(decoder)?;

        Ok(OctetsSecurises {
            octets: Zeroizing::new(vec),
        })
    }
}