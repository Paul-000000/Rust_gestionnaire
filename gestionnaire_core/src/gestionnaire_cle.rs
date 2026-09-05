use crate::chaine_securisee::ChaineSecurisee;
use crate::utilitaires::*;
use crate::salt::Salt;



pub(crate) struct Cles {
    pub(crate) cle_principale: Cle,
    pub(crate) cle_signature: CleSignature,
}

pub struct Session {
    fournisseur: Fournisseur,
}

impl Session {
    
    pub fn new(fournisseur: Fournisseur) -> Self {
        Self { fournisseur }
    }

    pub(crate) fn utiliser_cles<F, R>(&self, action: F, mdp: Option<&ChaineSecurisee>) -> Result<R, ErreurGestionnaire>
    where
        F: FnOnce(&Cles) -> R,
    {
        self.fournisseur.utiliser_cles(action, mdp)
    }

    pub(crate) fn stocker_cles(&mut self, mdp: &ChaineSecurisee, salt_cle: &Salt, salt_cle_signature: &Salt) -> Result<(), ErreurGestionnaire> {
        
        match &mut self.fournisseur {

            Fournisseur::Ram(ram) => {

                let cles = deriver_cles(mdp, salt_cle, salt_cle_signature)?;

                ram.modifier_cles(cles);
                Ok(())
            }

            Fournisseur::Ephemere(ephemere) => {
                
                ephemere.modifier_sels(salt_cle, salt_cle_signature);
                Ok(())
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.fournisseur.vider(); 
    }
}

pub enum Fournisseur {
    Ram(FournisseurRam),
    Ephemere(FournisseurEphemere),
}

impl Fournisseur {

    pub(crate) fn utiliser_cles<F, R>(&self, action: F, mdp: Option<&ChaineSecurisee>) -> Result<R, ErreurGestionnaire>
    where
        F: FnOnce(&Cles) -> R,
    {
        match self {
            Fournisseur::Ram(ram) => ram.utiliser_cles(action),
            Fournisseur::Ephemere(ephemere) => {
                let mdp = mdp.ok_or_else(|| ErreurGestionnaire::ErreurCle("Mot de passe requis en mode éphémère".to_string()))?;
                ephemere.utiliser_cles(action, mdp)
            }
        }
    }

    pub fn vider(&mut self) {
        match self {
            Fournisseur::Ram(ram) => ram.vider(),
            Fournisseur::Ephemere(ephemere) => ephemere.vider(),
        }
    }
}

pub(crate) trait FournisseurCles {
    fn utiliser_cles<F, R>(&self, action: F) -> Result<R, ErreurGestionnaire>
    where
        F: FnOnce(&Cles) -> R;
}

pub struct FournisseurRam {
    cles: Option<Cles>,
}

impl FournisseurRam {
    pub fn new() -> Self {
        Self { cles: None }
    }

    pub(crate) fn modifier_cles(&mut self, cles: Cles) {
        self.cles = Some(cles);
    }

    pub fn vider(&mut self) {
        self.cles = None;
    }
}

impl FournisseurCles for FournisseurRam {

    fn utiliser_cles<F, R>(&self, action: F) -> Result<R, ErreurGestionnaire>
    where
        F: FnOnce(&Cles) -> R,
    {
        match &self.cles {

            Some(cles) => Ok(action(cles)),
            None => Err(ErreurGestionnaire::ErreurCle("Aucune session active (coffre verrouillé)".to_string())),
        }
    }
}

pub struct FournisseurEphemere {
    sels: Option<(Salt, Salt)>,
}

impl FournisseurEphemere {
    pub fn new() -> Self {
        Self {
            sels: None,
        }
    }

    pub(crate) fn utiliser_cles<F, R>(&self, action: F, mdp: &ChaineSecurisee) -> Result<R, ErreurGestionnaire>
    where
        F: FnOnce(&Cles) -> R,
    {
        match &self.sels {
            Some((sel_p, sel_s)) => {
                let cles = deriver_cles(&mdp, sel_p, sel_s)?;
                Ok(action(&cles))
            }
            None => Err(ErreurGestionnaire::ErreurCle("Coffre verrouillé".to_string())),
        }
    }

    pub(crate) fn modifier_sels(&mut self, sel_principal: &Salt, sel_signature: &Salt) {
        self.sels = Some((sel_principal.clone(), sel_signature.clone()));
    }

    pub fn vider(&mut self) {
        self.sels = None;
    }
}