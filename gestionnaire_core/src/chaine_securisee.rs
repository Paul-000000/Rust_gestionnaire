use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;
use bincode::{Encode, de::Decoder, error::DecodeError};
use subtle::ConstantTimeEq;
use std::fmt;



#[derive(Clone)]    
pub struct ChaineSecurisee {
    chaine: SecretString        
}

pub struct ChaineAfficheable<'a>(&'a ChaineSecurisee);

impl<'a> fmt::Display for ChaineAfficheable<'a> {
    
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.expose(|s| write!(f, "{s}"))
    }
}

impl ChaineSecurisee {
    
    pub fn to_ui(&self) -> ChaineAfficheable<'_> {
        ChaineAfficheable(self)
    }
}


impl ChaineSecurisee {
    
    pub fn new(s: String) -> Self {
        Self {
            chaine: SecretString::from(s),
        }
    }

    pub fn from_str(s: &str) -> Self {
        Self {
            chaine: SecretString::from(s),
        }
    }

    pub fn from_zeroizing(s: Zeroizing<String>) -> Self {
        Self {
            chaine: SecretString::from(s.to_string()),
        }
    }

    pub fn est_vide(&self) -> bool {

        self.expose(|s| s.is_empty())
    }

    fn comparaison_securisee(chaine_1 : &ChaineSecurisee, chaine_2 : &ChaineSecurisee) -> bool {

        chaine_1.expose(| string_1 | {
            
            chaine_2.expose(| string_2 | {
                
                let a = string_1.as_bytes();
                let b = string_2.as_bytes();

                (a.len() == b.len()) && (a.ct_eq(b).into())
            })
        })
    }

    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&String) -> R,
    {
        let texte_temporaire = Zeroizing::new(self.chaine.expose_secret().to_string());
        f(&*texte_temporaire)
    }

    pub fn expose_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut String) -> R,
    {
        let mut texte_temporaire = Zeroizing::new(self.chaine.expose_secret().to_string());
        let resultat = f(&mut *texte_temporaire);

        *self = ChaineSecurisee::new(texte_temporaire.to_string());

        resultat
    }

}

impl PartialEq for ChaineSecurisee {
    fn eq(&self, other: &Self) -> bool {
        ChaineSecurisee::comparaison_securisee(self, other)
    }
}

impl Eq for ChaineSecurisee {}

impl Encode for ChaineSecurisee {
    fn encode<E: bincode::enc::Encoder>(&self, encoder: &mut E) -> Result<(), bincode::error::EncodeError> {

        self.expose(| string | string.as_str().encode(encoder))
    }
}

impl<C> bincode::Decode<C> for ChaineSecurisee 
where 
    String: bincode::Decode<C> 
{
    fn decode<D: Decoder<Context = C>>(decoder: &mut D) -> Result<Self, DecodeError> {
        // Ici, on appelle decode avec le bon contexte
        let s = String::decode(decoder)?;
        Ok(ChaineSecurisee {
            chaine: SecretString::from(s),
        })
    }
}

impl serde::Serialize for ChaineSecurisee {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.expose(| string | serializer.serialize_str(string.as_str()))
    }
}

impl<'de> serde::Deserialize<'de> for ChaineSecurisee {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(ChaineSecurisee {
            chaine: SecretString::from(s),
        })
    }
}
