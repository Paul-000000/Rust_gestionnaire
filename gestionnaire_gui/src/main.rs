use eframe::egui::{self, Ui, Color32, FontId, TextFormat, text::LayoutJob, Galley, TextBuffer};
use std::time::{Duration, Instant};
use std::sync::Arc;

use arboard::Clipboard;

use gestionnaire_core::*;
use gestionnaire_core::gestionnaire_cle::*;
use gestionnaire_core::utilitaires::*;
use gestionnaire_core::chaine_securisee::*;
use gestionnaire_core::gestionnaire_cle::Session;


const TEMPS_ANIMATION : Duration = Duration::from_millis(300);
const LARGEUR_COLONNE : usize = 130;

const ROUGE : Color32 = Color32::RED;
const ROUGE_FONCE : Color32 = Color32::DARK_RED;
const GRIS_CLAIR : Color32 = Color32::from_gray(200);
const GRIS : Color32 = Color32::from_gray(125);
const GRIS_FONCE : Color32 = Color32::from_gray(35);



/*
FONCTIONNALITÉS À AJOUTER :

pouvoir paramétrer la suppression du presse papier après x secondes
pouvoir paramétrer le délai de verrouillage de l'application

ne pas afficher le mot de passe principal (utile pour savoir son niveau de sécurité mais inutile a connaitre)
fenêtre d'erreur

tâches lourdes dans des threads et animation de chargement spinner

fournisseur ephémère avec l'ui
pouvoir changer de fournisseur de clés
fournisseur avec tpm et l'os

sécurité des chaines sécurisées
*/



fn main() -> Result<(), eframe::Error> {

    let mdps_existent = mdps_existent();
    let fenetre = if mdps_existent {
        TypeFenetre::Authentification
    } else {
        TypeFenetre::NouveauMdpPrincipal
    };

    let dimensions = fenetre.dimensions();
    let options = eframe::NativeOptions {

        viewport: egui::ViewportBuilder::default()
            .with_inner_size(dimensions)
            .with_min_inner_size(dimensions)
            .with_max_inner_size(dimensions),
        ..Default::default()
    };

    let titre = if mdps_existent { "Authentification" } else { "Nouveau mot de passe principal" };

    eframe::run_native(
        titre,
        options,
        Box::new(move |cc:&eframe::CreationContext<'_> | {
        
            if let Some(monitor_size) = cc.egui_ctx.input(|i| i.viewport().monitor_size) {
                
                let x = (monitor_size.x - dimensions.x) / 2.0;
                let y = (monitor_size.y - dimensions.y) / 2.0;

                cc.egui_ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(x, y)));
            }

            Ok(Box::new(GestionnaireGui::new(
                fenetre,
                gestionnaire_cle::Fournisseur::Ephemere(gestionnaire_cle::FournisseurEphemere::new()),
                //gestionnaire_cle::Fournisseur::Ram(gestionnaire_cle::FournisseurRam::new()),
            )))
        }),
    )
}



enum TypeFenetre {
    Authentification,
    NouveauMdpPrincipal,
    Principal,
}

impl TypeFenetre {

    pub fn dimensions(&self) -> egui::Vec2 {

        match self {

            Self::Authentification => egui::vec2(300.0, 125.0),
            Self::NouveauMdpPrincipal => egui::vec2(330.0, 185.0),
            Self::Principal => egui::vec2(1000.0, 700.0),
        }
    }
}

#[derive(Clone)]
enum Fenetre {
    MotDePassePrincipal(SaisieChamp, SaisieChamp, SaisieChamp),
    NouveauMotDePasse(ChampMotDePasseGenere),
    ModifierMotDePasse(usize, ModeModificationMdp),
    Confirmation(Option<usize>),
    Parametres
}

impl PartialEq for Fenetre {

    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Fenetre::MotDePassePrincipal(..), Fenetre::MotDePassePrincipal(..)) => true,
            (Fenetre::NouveauMotDePasse(_), Fenetre::NouveauMotDePasse(_)) => true,
            (Fenetre::ModifierMotDePasse(a, _), Fenetre::ModifierMotDePasse(b, _)) => a == b,
            (Fenetre::Parametres, Fenetre::Parametres) => true,
            (Fenetre::Confirmation(a), Fenetre::Confirmation(b)) => a == b,
            _ => false
        }
    }
}

#[derive(Clone, PartialEq)]
enum ModeCreationMdp {
    Manuel(SaisieChamp),
    Genere(usize, bool, bool, bool, bool)
}

#[derive(Clone)]
enum ModeModificationMdp {
    Consultation(Option<ChampMotDePasse>),
    Modification(ChampMotDePasseGenere),
}

impl PartialEq for ModeModificationMdp {

    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ModeModificationMdp::Consultation(_), ModeModificationMdp::Consultation(_)) => true,
            (ModeModificationMdp::Modification(_), ModeModificationMdp::Modification(_)) => true,
            _ => false,
        }
    }
}

enum ActionGraphique {
    DebutAnimation(usize),
    CreerMotDePasse(usize),
    ModifierMotDePasse(usize, usize),
    Parametres(usize),
    Confirmation(Option<usize>, usize)
}

#[derive(Clone, PartialEq)]
struct SaisieChamp {
    champ: ChaineSecurisee,
    affiche: bool,
    mdp: bool,
    complexite: Option<(NiveauSecurite, f64, String, String)>
}

impl SaisieChamp {

    fn new(affiche: bool, mdp: bool) -> Self {

        Self {
            champ: ChaineSecurisee::new(String::new()),
            affiche: affiche,
            mdp: mdp,
            complexite: None
        }
    }
}

#[derive(Clone, PartialEq)]
struct ChampMotDePasse {
    nom: ChaineSecurisee,
    identifiants: Vec<SaisieChamp>,
    mots_de_passe: Vec<SaisieChamp>,
    informations_supplementaires: ChaineSecurisee,
}

#[derive(Clone, PartialEq)]
struct ChampMotDePasseGenere {
    nom: ChaineSecurisee,
    identifiants: Vec<SaisieChamp>,
    mots_de_passe_genere: Vec<ModeCreationMdp>,
    informations_supplementaires: ChaineSecurisee
}

impl Default for ChampMotDePasseGenere {

    fn default() -> Self {
        
        ChampMotDePasseGenere {
            nom: ChaineSecurisee::new(String::new()),
            identifiants: Vec::new(),
            mots_de_passe_genere: Vec::new(),
            informations_supplementaires: ChaineSecurisee::new(String::new())
        }
    }
}

impl ChampMotDePasse {

    fn from_champ_infos(champ_infos : &ChampInformations) -> ChampMotDePasse {
        
        ChampMotDePasse {
            nom: champ_infos.nom.clone(),
            identifiants: champ_infos.identifiants.iter().map(| identifiant | {
                SaisieChamp {champ: identifiant.clone(), affiche: true, mdp: false, complexite: None}
            }).collect(),

            mots_de_passe: champ_infos.mdps.clone().iter().map(| m | {
                SaisieChamp {champ: m.clone(), affiche: false, mdp: true, complexite: None}
            }).collect(),

            informations_supplementaires: champ_infos.commentaire.clone(),
        }
    }
}

impl ChampMotDePasseGenere {
    
    fn to_champ_informations(&self) -> ChampInformations {
        
        ChampInformations {
                                        
            nom: self.nom.clone(),
            identifiants: self.identifiants.iter().map(|i| i.champ.clone()).collect(),

            mdps: self.mots_de_passe_genere.iter().map(|m| match m {
                ModeCreationMdp::Manuel(mdp) => Ok(mdp.champ.clone()),
                ModeCreationMdp::Genere(longueur, inclure_minuscules, inclure_majuscules, inclure_chiffres, inclure_symboles) => generer_mdp_aleatoire(*longueur, *inclure_minuscules, *inclure_majuscules, *inclure_chiffres, *inclure_symboles),
            
            }).filter_map(| res_mdp| res_mdp.ok()).collect(),

            commentaire: self.informations_supplementaires.clone(),
        }
    }

    fn from_champ_infos(champ_infos : &ChampInformations) -> ChampMotDePasseGenere {

        ChampMotDePasseGenere {

            nom: champ_infos.nom.clone(),
            identifiants: champ_infos.identifiants.iter().map(| identifiant | {
                SaisieChamp {champ: identifiant.clone(), affiche: true, mdp: false, complexite: None}
            }).collect(),

            mots_de_passe_genere: champ_infos.mdps.clone().iter().map(| m | {
                ModeCreationMdp::Manuel(SaisieChamp {champ: m.clone(), affiche: false, mdp: true, complexite: None})
            }).collect(),
            informations_supplementaires: champ_infos.commentaire.clone(),
        }
    }
}

struct GestionnaireGui {

    session : Session,
    fichier : Option<FichierMDP>,
    type_fenetre: TypeFenetre,
    recherche: ChaineSecurisee,
    noms_mdp: Option<Vec<ChaineSecurisee>>,
    
    fenetres: Vec<Fenetre>,

    mdp_accepte: bool,
    debut_animation_mdp_accepte: Option<Instant>,
    mdp_nouveau_mdp: SaisieChamp,
    mdp_confirmation: SaisieChamp,
    saisie_mdp_authentification: SaisieChamp, 

    coloration_types_caracteres: bool,
    essais_par_seconde: f64,
}

impl GestionnaireGui {
    
    fn new(type_fenetre: TypeFenetre, fournisseur : Fournisseur) -> Self {
        
        Self {
            session: Session::new(fournisseur),
            fichier: None,
            type_fenetre: type_fenetre,
            mdp_accepte: true,
            debut_animation_mdp_accepte: None,
            mdp_nouveau_mdp: SaisieChamp::new(false, true),
            mdp_confirmation: SaisieChamp::new(false, true),

            saisie_mdp_authentification: SaisieChamp::new(false, true),

            recherche: ChaineSecurisee::new(String::new()),
            noms_mdp: None,
            fenetres: Vec::new(),
            
            coloration_types_caracteres: true,
            essais_par_seconde: 1e10,
        }
    }
}

impl eframe::App for GestionnaireGui {
    
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {

        egui::Frame::new()
        .fill(Color32::from_gray(30))
        .inner_margin(egui::Margin::symmetric(15, 15))
        .show(ui, |ui| {

            ui.set_min_size(ui.available_size());
            ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                
                ui.ctx().global_style_mut(|style| {
                    style.text_styles.insert(
                        egui::TextStyle::Body,
                        egui::FontId::proportional(15.),
                    );
                });

                self.verifier_fin_animation(ui);

                match self.type_fenetre {
                    
                    TypeFenetre::Authentification => self.afficher_ecran_authentification(ui, frame),
                    TypeFenetre::NouveauMdpPrincipal => self.afficher_ecran_nouveau_mdp_principal(ui, frame),
                    TypeFenetre::Principal => self.afficher_ecran_principal(ui, frame)
                }


                let mut fenetres_a_fermer = Vec::new();
                let mut actions_graphiques: Vec<ActionGraphique> = Vec::new();

                for (indice_fenetre, fenetre) in self.fenetres.iter_mut().enumerate() {
                    
                    match fenetre {

                        Fenetre::MotDePassePrincipal(mdp_authentification, mdp_nouveau_mdp, mdp_confirmation) => 
                            
                            GestionnaireGui::afficher_fenetre_mdp_principal(
                                ui,
                                indice_fenetre,
                                mdp_authentification,
                                mdp_nouveau_mdp,
                                mdp_confirmation,
                                self.mdp_accepte,
                                self.coloration_types_caracteres,
                                self.essais_par_seconde,
                                &mut fenetres_a_fermer,
                                &mut actions_graphiques
                            ),
                        
                        Fenetre::NouveauMotDePasse(champ_mdp) => 
                            
                            GestionnaireGui::afficher_fenetre_nouveau_mdp(ui, indice_fenetre, champ_mdp, &mut fenetres_a_fermer, &mut actions_graphiques, self.coloration_types_caracteres),

                        Fenetre::ModifierMotDePasse(indice_mdp, _) => 
                            
                            actions_graphiques.push(ActionGraphique::ModifierMotDePasse(indice_fenetre, *indice_mdp)),

                        Fenetre::Parametres => 

                            actions_graphiques.push(ActionGraphique::Parametres(indice_fenetre)),

                        Fenetre::Confirmation(indice_mdp) => 

                            actions_graphiques.push(ActionGraphique::Confirmation(*indice_mdp, indice_fenetre)),
                    }
                }


                for action in actions_graphiques {

                    match action {

                        ActionGraphique::DebutAnimation(indice_fenetre) => {

                            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                            // TODO : A MODIFIER

                            if let Some(Fenetre::MotDePassePrincipal(mdp_authentification, mdp_nouveau_mdp, mdp_confirmation)) = self.fenetres.get_mut(indice_fenetre) {

                                if !mdp_nouveau_mdp.champ.est_vide() && mdp_nouveau_mdp.champ == mdp_confirmation.champ {
                                    
                                    self.fichier = nouveaux_mdps(mdp_nouveau_mdp.champ.clone(), &mut self.session).ok();

                                    mdp_authentification.champ = mdp_nouveau_mdp.champ.clone();
                                    mdp_nouveau_mdp.champ = ChaineSecurisee::new(String::new());
                                    mdp_confirmation.champ = ChaineSecurisee::new(String::new());
                                    self.mdp_accepte = true;
                                
                                } else {
                                    
                                    self.debut_animation();
                                }
                            }

                            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                        }
                        ActionGraphique::CreerMotDePasse(indice_fenetre) => {
                            
                            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                            // TODO : A MODIFIER
                            
                            if let Some(Fenetre::NouveauMotDePasse(mdp_confirmation)) = self.fenetres.get_mut(indice_fenetre) {
                            
                                let nouvelle_entree = mdp_confirmation.to_champ_informations();

                                if let Some(fichier) = &mut self.fichier {
                                    
                                    let res = ajouter_champ_informations(fichier, nouvelle_entree, None, &mut self.session);

                                    if res.is_ok() {

                                        self.noms_mdp = noms_mdps(fichier, None, &mut self.session).ok();
                                        
                                        self.supprimer_fenetre_par_indice(indice_fenetre);

                                        let indice = self.noms_mdp
                                        .as_ref()
                                        .map_or(0, |v| if v.is_empty() { 0 } else { v.len() - 1 });

                                        self.fenetre_affichage_mdp(indice);
                                    }
                                }
                            }

                            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                        }
                        ActionGraphique::ModifierMotDePasse(indice_fenetre, indice_mdp) => {

                            let titre_fenetre = match self.noms_mdp.as_ref().and_then(|v| v.get(indice_mdp)) {
                                Some(m) => m.clone(),
                                None => continue,
                            };
                            
                            let mut fenetre_ouverte = true;

                            GestionnaireGui::ui_fenetre(ui, egui::vec2(335., 500.), &titre_fenetre, &mut fenetre_ouverte, |ui| {

                                if self.afficher_modification_mdp(ui, indice_fenetre) {
                                    fenetres_a_fermer.push(indice_fenetre);
                                }
                            });
                            
                            if !fenetre_ouverte { 
                                fenetres_a_fermer.push(indice_fenetre);
                            }
                        }
                        ActionGraphique::Parametres(indice_fenetre) => self.afficher_fenetre_parametres(ui, frame, indice_fenetre, &mut fenetres_a_fermer),
                        ActionGraphique::Confirmation(indice_mdp, indice_fenetre) => self.afficher_fenetre_confirmation(ui, frame, indice_mdp, indice_fenetre, &mut fenetres_a_fermer),
                    }
                }

                
                let mut i = 0;
                self.fenetres.retain(|_| {
                    let garder = !fenetres_a_fermer.contains(&i);
                    i += 1;
                    garder
                });
            });
        });
    }
}

impl GestionnaireGui {

    fn afficher_ecran_authentification(&mut self, ui: &mut Ui, frame: &mut eframe::Frame) {

        if let Some(fenetre) = frame.winit_window() {
            fenetre.set_title("Authentification");
        }

        ui.heading("Entrez votre mot de passe principal");
        ui.add_space(15.);

        
        ui.horizontal(|ui| {

            GestionnaireGui::entree_mot_de_passe(ui, true, true, false, Some(String::from("Mot de passe principal")), self.mdp_accepte, ui.available_width() - 75., &mut self.saisie_mdp_authentification);

            let bouton_entrer = egui::Button::new("➡").min_size(egui::vec2(30.0, 30.0));
            if ui.add(bouton_entrer).clicked() {
                self.traiter_saisie(ui, frame);
            }
        });

        if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            self.traiter_saisie(ui, frame);
        }

    }

    fn afficher_ecran_nouveau_mdp_principal(&mut self, ui: &mut Ui, frame: &mut eframe::Frame) {

        ui.heading("Choisissez un nouveau mot de passe principal");
        ui.add_space(15.);

        ui.horizontal(|ui| {
            GestionnaireGui::entree_mot_de_passe(ui, true, false, self.coloration_types_caracteres, Some("Nouveau mot de passe principal".to_string()), self.mdp_accepte, ui.available_width(), &mut self.mdp_nouveau_mdp);
        });

        ui.horizontal(|ui| {
            GestionnaireGui::entree_mot_de_passe(ui, true, false, self.coloration_types_caracteres, Some("Confirmation".to_string()), self.mdp_accepte, ui.available_width(), &mut self.mdp_confirmation);
        });

        ui.add_space(10.0); 

        let bouton_creer = egui::Button::new("Créer").right_text("📝").min_size(egui::vec2(ui.available_width(), 25.));

        if ui.add(bouton_creer).clicked() {

            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // TODO : A MODIFIER

            

            if !self.mdp_nouveau_mdp.champ.est_vide() && self.mdp_nouveau_mdp.champ == self.mdp_confirmation.champ {
            
                match nouveaux_mdps(self.mdp_nouveau_mdp.champ.clone(), &mut self.session) {
                    
                    Ok(fichier) => {
                        self.fichier = Some(fichier);
                        self.noms_mdp = self.fichier.as_ref().and_then(|f| noms_mdps(f, None, &mut self.session).ok());
                        self.mdp_accepte = true;
                        self.afficher_fenetre_principale(ui, frame);
                    }
                    
                    Err(_) => {
                        self.debut_animation();
                    }
                }

            } else {
                self.debut_animation();
            }
            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        }
    }

    fn afficher_ecran_principal(&mut self, ui: &mut Ui, frame: &mut eframe::Frame) {
            
        egui::Panel::left("menu_side").max_size(650.).show_inside(ui, |ui| {

            ui.heading("Gestionnaire de mots de passe");
            ui.add_space(7.);
            ui.separator();
            ui.add_space(7.);

            let bouton_nouveau_mdp = egui::Button::new("Nouveau mot de passe").right_text("➕").min_size(egui::vec2(ui.available_width(), 30.));

            if ui.add(bouton_nouveau_mdp).clicked() {
                self.afficher_fenetre(Fenetre::NouveauMotDePasse(ChampMotDePasseGenere::default()));
            }

            ui.add_space(7.);

            let bouton_mdp_principal = egui::Button::new("Mot de passe principal").right_text("🔑").min_size(egui::vec2(ui.available_width(), 30.));

            if ui.add(bouton_mdp_principal).clicked() {

                let fichier_option = &self.fichier;

                if let Some(fichier) = fichier_option {
                    
                    if let Ok(mdp_principal) = recuperer_mdp_principal(&fichier, None, &mut self.session) {
                        
                        self.afficher_fenetre(Fenetre::MotDePassePrincipal(
                            SaisieChamp {champ: mdp_principal , affiche: false, mdp: true, complexite: None},
                            SaisieChamp::new(false, true),
                            SaisieChamp::new(false, true)
                        )); 
                    }                    
                }
            }

            ui.add_space(7.);
            ui.separator();
            ui.add_space(7.);
            
            let bouton_parametres = egui::Button::new("Paramètres").right_text("⚙").min_size(egui::vec2(ui.available_width(), 30.));

            if ui.add(bouton_parametres).clicked() {
                
                self.afficher_fenetre(Fenetre::Parametres);
            }    
        });

        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {

            egui::Frame::new()
            .fill(Color32::from_gray(33))
            .inner_margin(egui::Margin::symmetric(15, 15))
            .show(ui, |ui| {

                // 1. Barre de recherche : On vérifie si la fenêtre est vide AVANT de modifier la recherche
                let fenetres_est_vide = self.fenetres.is_empty();

                ui.horizontal(|ui| {
                    ui.label("🔍");
                    
                    // On utilise expose_mut pour pouvoir TAPER du texte dans la recherche !
                    self.recherche.expose_mut(|string| {
                        let recherche = egui::TextEdit::singleline(string)
                            .text_color(Color32::from_gray(200))
                            .background_color(GRIS_FONCE)
                            .hint_text("Rechercher")
                            .desired_width(ui.available_width());

                        let res = ui.add(recherche);
                        
                        if fenetres_est_vide {
                            res.request_focus();
                        }
                    });
                });

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);

                
                // 2. Grille des mots de passe
                egui::ScrollArea::vertical().show(ui, |ui| {

                    let largeur_disponible = ui.available_width();
                    let mut nb_colonnes = (largeur_disponible / LARGEUR_COLONNE as f32) as usize;
                    
                    if nb_colonnes == 0 {
                        nb_colonnes = 1;
                    }
                    
                    let largeur_colonne = ((largeur_disponible / nb_colonnes as f32) - 8.0).max(0.);

                    ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {

                        if let Some(noms_mdp) = &self.noms_mdp {
                        
                            let recherche_min = self.recherche.expose(|s| s.to_lowercase());

                            let indices_filtres: Vec<usize> = noms_mdp
                                .iter()
                                .enumerate()
                                .filter(|(_, mdp)| {
                                    recherche_min.is_empty() || mdp.expose(|nom_string| {
                                        nom_string.to_lowercase().contains(&recherche_min)
                                    })
                                })
                                .map(|(i, _)| i)
                                .collect();

                            let mut index_a_ouvrir = None;

                            egui::Grid::new("grid_mots_de_passe")
                            .spacing([10.0, 10.0])
                            .max_col_width(largeur_colonne).min_col_width(largeur_colonne)
                            .show(ui, |ui| {
                                
                                for (j, &i) in indices_filtres.iter().enumerate() {
                                
                                    if let Some(mdp) = noms_mdp.get(i) {

                                        mdp.expose(|nom_string| {
                                            let nom_mdp = egui::Button::new(nom_string)
                                                .right_text("")
                                                .min_size(egui::vec2(largeur_colonne, 0.))
                                                .truncate();
                                            
                                            if ui.add(nom_mdp).clicked() {
                                                index_a_ouvrir = Some(i);
                                            }
                                        });

                                        if (j + 1) % nb_colonnes == 0 {
                                            ui.end_row();
                                        }
                                    }
                                }
                            });

                            // 4. On appelle afficher_fenetre EN DEHORS de tout bloc expose()
                            if let Some(i) = index_a_ouvrir {
                                self.afficher_fenetre(Fenetre::ModifierMotDePasse(
                                    i,
                                    ModeModificationMdp::Consultation(None),
                                ));
                            }

                            if let Some(fenetre) = frame.winit_window() {
                                fenetre.set_title(format!("{} résultat{}", indices_filtres.len(), if indices_filtres.len() > 1 { "s" } else { "" }).as_str());
                            }

                            if indices_filtres.is_empty() {
                                ui.label(egui::RichText::new("Aucun mot de passe.").color(Color32::from_gray(150)));
                            }
                        }
                    });
                });
            });
        });
    }


    fn afficher_fenetre_mdp_principal(
        ui: &mut Ui,
        indice_fenetre: usize,
        mdp_authentification: &mut SaisieChamp,
        mdp_nouveau_mdp:  &mut SaisieChamp,
        mdp_confirmation:  &mut SaisieChamp,
        mdp_accepte: bool,
        coloration : bool,
        nb_essais_par_seconde : f64,
        fenetres_a_fermer: &mut Vec<usize>,
        actions_graphiques: &mut Vec<ActionGraphique>
    ) {

        let mut fenetre_ouverte = true; 
                            
        GestionnaireGui::ui_fenetre(ui, egui::vec2(335., 305.), &ChaineSecurisee::from_str("Mot de passe principal"), &mut fenetre_ouverte, |ui| {

            ui.label("Mot de passe");
            ui.add_space(10.0);
            
            ui.horizontal(|ui| {
                GestionnaireGui::entree_mot_de_passe(ui, false, false, coloration,None, true, ui.available_width(), mdp_authentification);
            });

            ui.add_space(10.);

            mdp_authentification.complexite = Some(GestionnaireGui::afficher_complexite_mdp(ui, &mdp_authentification.champ, &mdp_authentification.complexite, nb_essais_par_seconde));

            ui.add_space(10.);
            ui.separator();
            ui.add_space(10.);
            ui.label("Modification");

            ui.horizontal(|ui| {
                GestionnaireGui::entree_mot_de_passe(ui, true, false, coloration,Some("Nouveau mot de passe principal".to_string()), mdp_accepte, ui.available_width(), mdp_nouveau_mdp);
            });

            ui.horizontal(|ui| {
                GestionnaireGui::entree_mot_de_passe(ui, true, false, coloration, Some("Confirmation".to_string()), mdp_accepte, ui.available_width(),mdp_confirmation);
            });

            ui.add_space(10.0);

            let bouton_modifier = egui::Button::new("Modifier").right_text("📝").min_size(egui::vec2(ui.available_width(), 25.));

            if ui.add(bouton_modifier).clicked() {

                actions_graphiques.push(ActionGraphique::DebutAnimation(indice_fenetre));
            }    
        });
                            
        if !fenetre_ouverte {
            fenetres_a_fermer.push(indice_fenetre);
        }
                
    }

    fn afficher_fenetre_nouveau_mdp(
        ui: &mut Ui,
        indice_fenetre: usize,
        champ_mdp: &mut ChampMotDePasseGenere,
        fenetres_a_fermer: &mut Vec<usize>,
        actions_graphiques: &mut Vec<ActionGraphique>,
        coloration : bool
    ) {
    
        let mut fenetre_ouverte = true; 
        
        GestionnaireGui::ui_fenetre(ui, egui::vec2(335., 395.), &ChaineSecurisee::from_str("Nouveau mot de passe"), &mut fenetre_ouverte, |ui| {

            ui.label("Nom du mot de passe");
            ui.add_space(10.0);
            

            champ_mdp.nom.expose_mut(|nom_string| {

                let nom_mdp = egui::TextEdit::singleline(nom_string)
                    .font(egui::TextStyle::Monospace)
                    .text_color(GRIS_CLAIR)
                    .background_color(GRIS_FONCE)
                    .desired_width(ui.available_width())
                    .margin(egui::vec2(4.0, 6.0))
                    .hint_text("Nom")
                    .interactive(true);

                ui.add(nom_mdp);
            });

            

            ui.add_space(10.);
            ui.separator();



            // Identifiants
            ui.add_space(7.);
            ui.label("Identifiants");
            ui.add_space(7.);

            let mut a_supprimer = None;

            for (i, identifiant) in champ_mdp.identifiants.iter_mut().enumerate() {
                
                ui.horizontal(|ui| {

                    let bouton_supprimer_identifiant = egui::Button::new("❌").min_size(egui::vec2(30., 30.));

                    if ui.add(bouton_supprimer_identifiant).clicked() {
                        a_supprimer = Some(i);
                    }

                    GestionnaireGui::entree_mot_de_passe(ui, true, false, coloration, Some(format!("Identifiant {}", i + 1)), true, ui.available_width(), identifiant);
                });
            }

            if let Some(indice) = a_supprimer {
                champ_mdp.identifiants.remove(indice);
            }

            ui.add_space(7.);

            let bouton_ajouter_identifiant = egui::Button::new("Ajouter").right_text("➕").min_size(egui::vec2(0., 25.));

            if ui.add(bouton_ajouter_identifiant).clicked() {

                let saisie_affichee = SaisieChamp::new(true, false);
                champ_mdp.identifiants.push(saisie_affichee);
            }

            ui.add_space(7.);
            ui.separator();
            


            // Mots de passe
            ui.add_space(7.);
            ui.label("Mots de passe");
            ui.add_space(7.);

            let mut a_supprimer = None;

            for (i, mdp) in champ_mdp.mots_de_passe_genere.iter_mut().enumerate() {
                
                GestionnaireGui::nouveau_mdp(ui, mdp, format!("Mot de passe {}", i + 1), &mut a_supprimer, i, coloration);
                ui.add_space(7.);
            }

            if let Some(indice) = a_supprimer {
                champ_mdp.mots_de_passe_genere.remove(indice);
            }

            let bouton_ajouter_mdp = egui::Button::new("Ajouter").right_text("➕").min_size(egui::vec2(0., 25.));

            if ui.add(bouton_ajouter_mdp).clicked() {

                let mode_mdp = ModeCreationMdp::Manuel(SaisieChamp::new(false, true));
                champ_mdp.mots_de_passe_genere.push(mode_mdp);
            }

            ui.add_space(7.);
            ui.separator();
            ui.add_space(7.);



            champ_mdp.informations_supplementaires.expose_mut(|informations_string| {
                
                let informations_supplementaires = egui::TextEdit::multiline(informations_string)
                    .font(egui::TextStyle::Monospace)
                    .text_color(GRIS_CLAIR)
                    .background_color(GRIS_FONCE)
                    .desired_width(ui.available_width())
                    .margin(egui::vec2(4.0, 6.0))
                    .hint_text("Informations supplémentaires")
                    .interactive(true);

                ui.add(informations_supplementaires);
            });

            ui.add_space(7.);
            


            let bouton_creer = egui::Button::new("Créer").right_text("➕").min_size(egui::vec2(ui.available_width(), 25.));

            if ui.add(bouton_creer).clicked() {

                if !champ_mdp.nom.est_vide() {
                    actions_graphiques.push(ActionGraphique::CreerMotDePasse(indice_fenetre));
                }
            }
        });

        if !fenetre_ouverte { 
            fenetres_a_fermer.push(indice_fenetre);
        }
    }

    fn afficher_fenetre_parametres(&mut self, ui: &mut Ui, frame: &mut eframe::Frame, indice_fenetre: usize, fenetres_a_fermer: &mut Vec<usize>) {
        
        let mut fenetre_ouverte = true; 
        
        GestionnaireGui::ui_fenetre(ui, egui::vec2(350., 400.), &ChaineSecurisee::from_str("Paramètres"), &mut fenetre_ouverte, |ui| {

            ui.style_mut().visuals.selection.bg_fill = GRIS;
            ui.style_mut().visuals.selection.stroke.color = Color32::WHITE;

            ui.toggle_value(&mut self.coloration_types_caracteres, "Coloriser les caractères des mots de passe par type")
                .on_hover_text("Si activé, les minuscules seront colorisées en bleu, les majuscules en rouge, les chiffres en vert et les symboles en orange.")
                .set_intrinsic_size(egui::vec2(ui.available_width(), 30.));
                
            ui.add_space(7.);
            ui.separator();
            ui.add_space(7.);

            ui.label("Essais par seconde utilisés dans le calcul de durée de protection des mots de passe");
            ui.add_space(7.);

            let slider = egui::Slider::new(&mut self.essais_par_seconde, 1.0..=1e15)
                .logarithmic(true)
                .fixed_decimals(0);

            if ui.add(slider).changed() {

                for f in self.fenetres.iter_mut() {

                    match f {
                        
                        Fenetre::MotDePassePrincipal(mdp_authentification, ..) => {
                            mdp_authentification.complexite = None;
                        },
                        Fenetre::ModifierMotDePasse(_, mode_modification) => {
                            
                            if let ModeModificationMdp::Consultation(Some(champ_mdp)) = mode_modification {
                                for mdp in champ_mdp.mots_de_passe.iter_mut() {
                                    mdp.complexite = None;
                                }
                            }
                        },
                        _ => continue,
                    }
                }
            };

            ui.add_space(7.);
            ui.separator();
            ui.add_space(7.);

            let bouton_sauvegarder = egui::Button::new("Sauvegarder les mots de passe").right_text("💾").min_size(egui::vec2(ui.available_width(), 30.));

            if ui.add(bouton_sauvegarder).clicked() {

                let _ = creer_sauvegarde();
            }

            ui.add_space(7.);

            let bouton_vider_presse_papier = egui::Button::new("Vider le presse-papier").right_text("📋").min_size(egui::vec2(ui.available_width(), 30.));

            if ui.add(bouton_vider_presse_papier).clicked() {

                let _ = GestionnaireGui::vider_presse_papier();
            }

            ui.add_space(7.);
            ui.separator();
            ui.add_space(7.);

            let bouton_supprimer_tous = egui::Button::new("Réinitialiser le gestionnaire")
            .right_text("❌")
            .min_size(egui::vec2(ui.available_width(), 30.))
            .fill(ROUGE_FONCE);

            if ui.add(bouton_supprimer_tous).clicked() {
                self.afficher_fenetre(Fenetre::Confirmation(None));            
            }
        });

        if !fenetre_ouverte { 
            fenetres_a_fermer.push(indice_fenetre);
        }
    }

    fn afficher_fenetre_confirmation(
        &mut self,
        ui: &mut Ui,
        frame: &mut eframe::Frame,
        indice_mdp: Option<usize>,
        indice_fenetre: usize,
        fenetres_a_fermer: &mut Vec<usize>,
    ) {
        let preparer_infos = || -> Option<(String, &'static str)> {

            match indice_mdp {
                Some(indice) => {
                    let nom = self.noms_mdp.as_ref()?.get(indice)?;
                    let mut texte = String::new();
                    nom.expose(|s| texte = format!("Êtes-vous sûr de vouloir supprimer définitivement {s} ?"));
                    Some((texte, "Supprimer"))
                }
                None => Some((
                    "Êtes-vous sûr de vouloir supprimer définitivement tous les mots de passe ?".into(),
                    "Réinitialiser",
                )),
            }
        };

        let Some((message, texte_bouton)) = preparer_infos() else { return };
        let mut fenetre_ouverte = true;

        GestionnaireGui::ui_fenetre(
            ui,
            egui::vec2(210., 115.),
            &ChaineSecurisee::from_str("Confirmation"),
            &mut fenetre_ouverte,
            |ui| {
                ui.label(&message);
                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    let btn_action = egui::Button::new(texte_bouton)
                        .right_text("❌")
                        .min_size(egui::vec2(30., 30.))
                        .fill(ROUGE_FONCE);

                    let btn_annuler = egui::Button::new("Annuler")
                        .right_text("➡")
                        .min_size(egui::vec2(30., 30.));

                    if ui.add(btn_action).clicked() {
                        match indice_mdp {
                            Some(indice) => self.supprimer_mdp(indice),
                            None => self.reinitialiser_gestionnaire(frame, ui),
                        }
                    }

                    if ui.add(btn_annuler).clicked() {
                        fenetres_a_fermer.push(indice_fenetre);
                    }
                });
            },
        );

        if !fenetre_ouverte {
            fenetres_a_fermer.push(indice_fenetre);
        }
    }

    fn centrer_fenetre(&self, fenetre: &std::sync::Arc<winit::window::Window>, nouvelle_taille: egui::Vec2) {
        
        if let Some(ecran) = fenetre.current_monitor() {

            let position_ecran = ecran.position();
            let taille_ecran = ecran.size();
            
            let facteur_echelle = fenetre.scale_factor();

            let largeur_pixels = (nouvelle_taille.x as f64 * facteur_echelle) as i32;
            let hauteur_pixels = (nouvelle_taille.y as f64 * facteur_echelle) as i32;

            let x = position_ecran.x + (taille_ecran.width as i32 - largeur_pixels) / 2;
            let y = position_ecran.y + (taille_ecran.height as i32 - hauteur_pixels) / 2;

            let _ = fenetre.set_outer_position(winit::dpi::PhysicalPosition::new(x, y));
        }
    }

    fn afficher_fenetre_principale(&mut self, ui: &mut Ui, frame: &mut eframe::Frame) {

        if let Some(fenetre) = frame.winit_window() {
                    
            fenetre.set_visible(false);

            let ctx = ui.ctx();
            ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(egui::vec2(550.0, 400.0)));
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(TypeFenetre::Principal.dimensions()));
            ctx.send_viewport_cmd(egui::ViewportCommand::Title("Gestionnaire".to_string()));

            fenetre.set_resizable(true);
            fenetre.set_min_inner_size::<winit::dpi::Size>(None);
            fenetre.set_max_inner_size::<winit::dpi::Size>(None);
            
            self.centrer_fenetre(fenetre, TypeFenetre::Principal.dimensions());
            ctx.request_repaint();

            fenetre.set_visible(true);
        }

        self.type_fenetre = TypeFenetre::Principal;
    }

    fn traiter_saisie(&mut self, ui: &mut Ui, frame: &mut eframe::Frame) {

        if !self.saisie_mdp_authentification.champ.est_vide() {
            
            if let Some(fenetre) = frame.winit_window() {
                fenetre.set_title("Vérification ...");
            }

            if let Ok(resultat_verification) = verifier_mdp_principal_fichier(&self.saisie_mdp_authentification.champ , &mut self.session) {
                
                match resultat_verification {
                    
                    Some(fichier) => {

                        self.noms_mdp = noms_mdps(&fichier, None, &mut self.session).ok();
                        self.fichier = Some(fichier);
                        self.afficher_fenetre_principale(ui, frame);
                    },
                    None => {
                        self.debut_animation();
                    }
                }
            }
        }
    }

    fn debut_animation(&mut self) {

        self.mdp_accepte = false;
        self.debut_animation_mdp_accepte = Some(Instant::now());
    }

    fn verifier_fin_animation(&mut self, ui: &mut Ui) {

        if let Some(moment) = self.debut_animation_mdp_accepte {
            if moment.elapsed() >= TEMPS_ANIMATION {
                self.mdp_accepte = true;
                self.debut_animation_mdp_accepte = None;

            } else {
                ui.ctx().request_repaint();
            }
        }
    }

    fn afficher_fenetre(&mut self, fenetre : Fenetre) {

        if self.fenetres.contains(&fenetre) {
            self.supprimer_fenetre(fenetre);

        } else {
            self.fenetres.push(fenetre);
        }
    }

    fn supprimer_fenetre(&mut self, fenetre : Fenetre) {
        
        self.fenetres.retain(|f| f != &fenetre);
    }

    fn supprimer_fenetre_par_indice(&mut self, indice: usize) {
    
        if indice < self.fenetres.len() {
            self.fenetres.remove(indice);
        }
    }

    fn fenetre_affichage_mdp(&mut self, indice_mdp: usize) {
        
        self.afficher_fenetre(Fenetre::ModifierMotDePasse(indice_mdp,ModeModificationMdp::Consultation(None)));
    }
    
    fn entree_mot_de_passe(ui: &mut Ui, actif : bool, focus : bool, coloration : bool, placeholder : Option<String>, accepte : bool, largeur : f32, saisie : &mut SaisieChamp) {

        let label = if saisie.affiche { "•" } else { "A" };
        let bouton_affichage = egui::Button::new(label).min_size(egui::vec2(30.0, 30.0));
        let mut layouter= GestionnaireGui::formattage_type_caracteres(13.0, !saisie.affiche);

        if ui.add(bouton_affichage).clicked() {
            saisie.affiche = !saisie.affiche;
        }

        let couleur_texte = if accepte { GRIS_CLAIR } else { ROUGE };
        let reponse = saisie.champ.expose_mut(|champ_string| {

            let mut entree = egui::TextEdit::singleline(champ_string)
            .font(egui::TextStyle::Monospace)
            .text_color(couleur_texte)
            .background_color(GRIS_FONCE)
            .desired_width(largeur)
            .margin(egui::vec2(4.0, 6.0))
            .password(!saisie.affiche)
            .interactive(actif);

            if let Some(texte_indicatif) = placeholder {
                entree = entree.hint_text(texte_indicatif);
            }

            if saisie.affiche && saisie.mdp && coloration {
                
                entree = entree.layouter(&mut layouter);
            }

            ui.add(entree)
        });
        
        if focus {
            reponse.request_focus()
        }

    }

    fn nouveau_mdp(ui: &mut Ui, mode : &mut ModeCreationMdp, label : String, a_supprimer : &mut Option<usize>, i : usize, coloration : bool) {

        ui.horizontal(|ui| {

            ui.style_mut().visuals.selection.bg_fill = GRIS;
            ui.style_mut().visuals.selection.stroke.color = Color32::WHITE;

            let bouton_supprimer_mdp = egui::Button::new("❌").min_size(egui::vec2(30., 30.));

            if ui.add(bouton_supprimer_mdp).clicked() {
                *a_supprimer = Some(i);
            }

            let est_manuel = matches!(mode, ModeCreationMdp::Manuel(_));

            let menu_manuel = egui::Button::new("Manuel").right_text("⌨")
                .selected(est_manuel)
                .min_size(egui::vec2(0., 30.));

            if ui.add(menu_manuel).clicked() {
                if !est_manuel {
                    *mode = ModeCreationMdp::Manuel(SaisieChamp::new(false, true));
                }
            }

            let est_genere = matches!(mode, ModeCreationMdp::Genere(_, _, _, _, _));
            let menu_genere = egui::Button::new("Généré").right_text("🎲")
                .selected(est_genere)
                .min_size(egui::vec2(0., 30.));

            if ui.add(menu_genere).clicked() {
                if !est_genere {
                    *mode = ModeCreationMdp::Genere(16, true, true, true, true);
                }
            }
            
            ui.label(label);
        });

        ui.add_space(10.);

        egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            
            ui.set_width(ui.available_width());
            

            match mode {

                ModeCreationMdp::Manuel(saisie) => {
                    
                    ui.horizontal(|ui| {

                        GestionnaireGui::entree_mot_de_passe(
                            ui, 
                            true, 
                            false,
                            coloration,
                            Some("Saisir le mot de passe".to_string()), 
                            true, 
                            ui.available_width(), 
                            saisie
                        );
                    });
                }
                ModeCreationMdp::Genere(longueur, inclure_minuscules, inclure_majuscules, inclure_chiffres, inclure_symboles) => {
                    
                    ui.horizontal(|ui| {
                        ui.label("Longueur :");
                        ui.add(egui::Slider::new(longueur, 1..=256).text("caractères"));
                    });

                    let nb_coches = [*inclure_minuscules, *inclure_majuscules, *inclure_chiffres, *inclure_symboles]
                    .iter()
                    .filter(|&&b| b)
                    .count();

                    ui.add_space(3.0);

                    ui.horizontal(|ui| {
                        
                        ui.style_mut().visuals.selection.bg_fill = GRIS;
                        ui.style_mut().visuals.selection.stroke.color = Color32::WHITE;

                        let autorise = nb_coches > 1 || !*inclure_minuscules;
                        
                        ui.add_enabled_ui(autorise, |ui| {
                            ui.toggle_value(inclure_minuscules, "a-z");
                        });

                        let autorise = nb_coches > 1 || !*inclure_majuscules;
                        
                        ui.add_enabled_ui(autorise, |ui| {
                            ui.toggle_value(inclure_majuscules, "A-Z");
                        });

                        let autorise = nb_coches > 1 || !*inclure_chiffres;

                        ui.add_enabled_ui(autorise, |ui| {
                            ui.toggle_value(inclure_chiffres, "0-9");
                        });

                        let autorise = nb_coches > 1 || !*inclure_symboles;

                        ui.add_enabled_ui(autorise, |ui| {
                            ui.toggle_value(inclure_symboles, "!@#$%^&*()-_=+[]{};:,.<>?/|~`");
                        });
                    });
                }
            }
        });
    }

    fn ui_fenetre<T>(
        ui: &mut Ui, 
        dimensions: egui::Vec2, 
        titre: &ChaineSecurisee, 
        ouverte: &mut bool, 
        contenu: impl FnOnce(&mut Ui) -> T
    ) {
        titre.expose(| titre_string | {

            egui::Window::new(titre_string)
            .open(ouverte)
            .collapsible(false)
            .resizable(false)
            .movable(true)
            .default_size(dimensions)
            .pivot(egui::Align2::CENTER_CENTER)
            .show(ui.ctx(), |ui| {
                egui::Frame::new()
                .inner_margin(egui::Margin::same(10)) 
                .show(ui, |ui| {
                    
                    egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        contenu(ui);
                    });
                });
            });
        });  
    }

    fn afficher_bouton_copier(ui: &mut Ui, chaine : ChaineSecurisee) {
        
        let copier_nom = egui::Button::new("📋")
            .min_size(egui::vec2(30., 30.));
        
        if ui.add(copier_nom).clicked() {
            
            GestionnaireGui::copier_presse_papier(&chaine);
        }
    }

    fn afficher_modification_mdp(&mut self, ui: &mut Ui, indice_fenetre: usize) -> bool {

        let mut fermer_fenetre = false;

        let (indice_mdp, mut mode_mutable) = match self.fenetres.get(indice_fenetre) {
            Some(Fenetre::ModifierMotDePasse(indice_mdp, mode)) => (*indice_mdp, mode.clone()),
            _ => return fermer_fenetre,
        };

        let fichier = match &self.fichier {
            Some(fichier) => fichier,
            None => return fermer_fenetre,
        };

        let mdp = match recuperer_champ_informations(&fichier, indice_mdp, None, &mut self.session).ok() {
            Some(mdp) => mdp,
            None => return fermer_fenetre,
        };

        ui.horizontal(|ui| {

            ui.style_mut().visuals.selection.bg_fill = GRIS;
            ui.style_mut().visuals.selection.stroke.color = Color32::WHITE;

            let est_consulte = matches!(mode_mutable, ModeModificationMdp::Consultation(_));
            let est_modifie = matches!(mode_mutable, ModeModificationMdp::Modification(..));

            let menu_consulter = egui::Button::new("Consulter").right_text("🔍")
                .selected(est_consulte)
                .min_size(egui::vec2(0., 30.));

            if ui.add(menu_consulter).clicked() {

                if !est_consulte {

                    mode_mutable = ModeModificationMdp::Consultation(None);
                }
            }

            let menu_modifier = egui::Button::new("Modifier").right_text("✏")
                .selected(est_modifie)
                .min_size(egui::vec2(0., 30.));

            if ui.add(menu_modifier).clicked() {

                if !est_modifie {

                    let champ_modification = ChampMotDePasseGenere::from_champ_infos(&mdp);

                    mode_mutable = ModeModificationMdp::Modification(champ_modification);
                }
            }

            let menu_supprimer = egui::Button::new("Supprimer").right_text("❌")
                .min_size(egui::vec2(0., 30.))
                .fill(ROUGE_FONCE);

            if ui.add(menu_supprimer).clicked() {
                self.afficher_fenetre(Fenetre::Confirmation(Some(indice_mdp)));
            }
        });
        ui.add_space(10.0);



        match mode_mutable {

            ModeModificationMdp::Consultation(ref mut champ_cache) => {

                let mdp_a_modifier = champ_cache.get_or_insert_with(|| ChampMotDePasse::from_champ_infos(&mdp));

                ui.label("Nom du mot de passe");
                ui.add_space(10.0);
                
                ui.horizontal(|ui| {

                    GestionnaireGui::afficher_bouton_copier(ui, mdp_a_modifier.nom.clone());

                    mdp_a_modifier.nom.expose_mut(|nom_string| {

                        let nom_mdp = egui::TextEdit::singleline(nom_string)
                        .font(egui::TextStyle::Monospace)
                        .text_color(GRIS_CLAIR)
                        .background_color(GRIS_FONCE)
                        .desired_width(ui.available_width())
                        .margin(egui::vec2(4.0, 6.0))
                        .hint_text("Nom")
                        .interactive(false);

                        ui.add(nom_mdp);
                    });
                });
                

                // Identifiants
                if !mdp_a_modifier.identifiants.is_empty() {

                    ui.add_space(10.);
                    ui.separator();
                    ui.add_space(7.);
                    ui.label("Identifiants");
                    ui.add_space(7.);
                

                    for (i, identifiant) in mdp_a_modifier.identifiants.iter_mut().enumerate() {
                        
                        ui.horizontal(|ui| {

                            GestionnaireGui::afficher_bouton_copier(ui, identifiant.champ.clone());

                            GestionnaireGui::entree_mot_de_passe(ui, false, false, self.coloration_types_caracteres, Some(format!("Identifiant {}", i + 1)), true, ui.available_width(), identifiant);
                        });
                    }
                }



                // Mots de passe
                if !mdp_a_modifier.mots_de_passe.is_empty() {

                    ui.add_space(7.);
                    ui.separator();
                    ui.add_space(7.);
                    ui.label(if mdp_a_modifier.mots_de_passe.is_empty() { "Aucun mot de passe" } else { "Mots de passe" });
                    ui.add_space(7.);

                    let nb_mdp = mdp_a_modifier.mots_de_passe.len();

                    for (i, mdp) in mdp_a_modifier.mots_de_passe.iter_mut().enumerate() {
                        
                        ui.horizontal(|ui| {

                            GestionnaireGui::afficher_bouton_copier(ui, mdp.champ.clone());

                            GestionnaireGui::entree_mot_de_passe(ui, false, false, self.coloration_types_caracteres, Some(format!("Mot de passe {}", i + 1)), true, ui.available_width(), mdp);
                        });

                        ui.add_space(5.);
                        mdp.complexite = Some(GestionnaireGui::afficher_complexite_mdp(ui, &mdp.champ, &mdp.complexite, self.essais_par_seconde));
                        ui.add_space(4.);

                        if i < nb_mdp - 1 {

                            ui.separator();
                            ui.add_space(4.);
                        }
                    }
                }

                if !mdp_a_modifier.informations_supplementaires.est_vide() {

                    ui.add_space(7.);
                    ui.separator();
                    ui.add_space(7.);

                    mdp_a_modifier.informations_supplementaires.expose_mut(|informations_string| {

                        let informations_supplementaires = egui::TextEdit::multiline(informations_string)
                            .font(egui::TextStyle::Monospace)
                            .text_color(GRIS_CLAIR)
                            .background_color(GRIS_FONCE)
                            .desired_width(ui.available_width())
                            .margin(egui::vec2(4.0, 6.0))
                            .hint_text("Aucunes Informations supplémentaires")
                            .interactive(false);

                        ui.add(informations_supplementaires);
                    });
                }
            }

            ModeModificationMdp::Modification(ref mut champ_mdp) => {

                ui.label("Nom du mot de passe");
                ui.add_space(10.0);
                
                
                champ_mdp.nom.expose_mut(|nom_string| {
                    
                    let nom_mdp = egui::TextEdit::singleline(nom_string)
                        .font(egui::TextStyle::Monospace)
                        .text_color(GRIS_CLAIR)
                        .background_color(GRIS_FONCE)
                        .desired_width(ui.available_width())
                        .margin(egui::vec2(4.0, 6.0))
                        .hint_text("Nom")
                        .interactive(true);

                    ui.add(nom_mdp);
                });

                ui.add_space(10.);
                ui.separator();



                // Identifiants
                ui.add_space(7.);
                ui.label("Identifiants");
                ui.add_space(7.);

                let mut a_supprimer = None;

                for (i, identifiant) in champ_mdp.identifiants.iter_mut().enumerate() {
                    
                    ui.horizontal(|ui| {

                        let bouton_supprimer_identifiant = egui::Button::new("❌").min_size(egui::vec2(30., 30.));

                        if ui.add(bouton_supprimer_identifiant).clicked() {
                            a_supprimer = Some(i);
                        }

                        GestionnaireGui::entree_mot_de_passe(ui, true, false, self.coloration_types_caracteres, Some(format!("Identifiant {}", i + 1)), true, ui.available_width(), identifiant);
                    });
                }

                if let Some(indice) = a_supprimer {
                    champ_mdp.identifiants.remove(indice);
                }

                ui.add_space(7.);

                let bouton_ajouter_identifiant = egui::Button::new("Ajouter").right_text("➕").min_size(egui::vec2(0., 25.));

                if ui.add(bouton_ajouter_identifiant).clicked() {

                    let saisie_affichee = SaisieChamp::new(true, false);
                    champ_mdp.identifiants.push(saisie_affichee);
                }

                ui.add_space(7.);
                ui.separator();
                


                // Mots de passe
                ui.add_space(7.);
                ui.label("Mots de passe");
                ui.add_space(7.);

                let mut a_supprimer = None;

                for (i, mdp) in champ_mdp.mots_de_passe_genere.iter_mut().enumerate() {
                    
                    GestionnaireGui::nouveau_mdp(ui, mdp, format!("Mot de passe {}", i + 1), &mut a_supprimer, i, self.coloration_types_caracteres);
                    ui.add_space(7.);
                }

                if let Some(indice) = a_supprimer {
                    champ_mdp.mots_de_passe_genere.remove(indice);
                }

                let bouton_ajouter_mdp = egui::Button::new("Ajouter").right_text("➕").min_size(egui::vec2(0., 25.));

                if ui.add(bouton_ajouter_mdp).clicked() {

                    let mode_mdp = ModeCreationMdp::Manuel(SaisieChamp::new(false, true));
                    champ_mdp.mots_de_passe_genere.push(mode_mdp);
                }

                ui.add_space(7.);
                ui.separator();
                ui.add_space(7.);


                champ_mdp.informations_supplementaires.expose_mut(|informations_string| {

                    let informations_supplementaires = egui::TextEdit::multiline(informations_string)
                        .font(egui::TextStyle::Monospace)
                        .text_color(GRIS_CLAIR)
                        .background_color(GRIS_FONCE)
                        .desired_width(ui.available_width())
                        .margin(egui::vec2(4.0, 6.0))
                        .hint_text("Informations supplémentaires")
                        .interactive(true);

                    ui.add(informations_supplementaires);
                });

                ui.add_space(7.);
                


                let bouton_creer = egui::Button::new("Appliquer les modifications").right_text("➕").min_size(egui::vec2(ui.available_width(), 25.));

                if ui.add(bouton_creer).clicked() {
                    
                    let nouveau_mdp = champ_mdp.to_champ_informations();

                    if let Some(fichier) = &mut self.fichier {
                        
                        let res = modifier_champ_informations(fichier, indice_mdp, nouveau_mdp, None, &mut self.session);

                        if res.is_ok() {
                            let _ = sauvegarder_mdps(fichier, None, &mut self.session);
                            self.noms_mdp = noms_mdps(fichier, None, &mut self.session).ok();
                        }
                    }

                    fermer_fenetre = true;
                }
            }
        }


        if let Some(Fenetre::ModifierMotDePasse(_, mode_modif)) = self.fenetres.get_mut(indice_fenetre) {
            *mode_modif = mode_mutable;
        }

        fermer_fenetre
    }

    fn supprimer_mdp(&mut self, indice_mdp: usize) {

        if let Some(fichier) = &mut self.fichier {
            let res = supprimer_entree(fichier, indice_mdp);

            if res.is_err() {
                return;
            }

            let _ = sauvegarder_mdps(fichier, None, &mut self.session);
            self.noms_mdp = noms_mdps(fichier, None, &mut self.session).ok();
        }

        self.fenetres.retain(|f| {
            !matches!(
                f,
                Fenetre::ModifierMotDePasse(indice, ..) | Fenetre::Confirmation(Some(indice))
                if *indice == indice_mdp
            )
        });

        for f in self.fenetres.iter_mut() {
            match f {
                Fenetre::ModifierMotDePasse(indice, ..) => {
                    if *indice > indice_mdp {
                        *indice -= 1;
                    }
                }
                Fenetre::Confirmation(Some(indice)) => {
                    if *indice > indice_mdp {
                        *indice -= 1;
                    }
                }
                _ => {}
            }
        }
    }

    fn afficher_complexite_mdp(ui: &mut Ui, mdp : &ChaineSecurisee, complexite: &Option<(NiveauSecurite, f64, String, String)> ,nb_essais_par_seconde : f64) -> (NiveauSecurite, f64, String, String) {

        let (niveau_securite, securite, tentatives_estimees, duree_protection) = match complexite {
            Some((niveau, securite, tentatives, duree)) => (niveau.clone(), *securite, tentatives.clone(), duree.clone()),
            None => informations_formattees_securite_mdp(mdp, nb_essais_par_seconde),
        };

        let (niveau_securite_str, couleur_niveau) = match niveau_securite {
            NiveauSecurite::TresFaible =>       ("très faible",         Color32::from_rgb(160, 0, 0)),
            NiveauSecurite::Faible =>           ("faible",              Color32::from_rgb(200, 25, 25)),
            NiveauSecurite::Modere =>           ("modérée",             Color32::from_rgb(205, 150, 0)),
            NiveauSecurite::Fort =>             ("fort",                Color32::from_rgb(15, 150, 45)),
            NiveauSecurite::TresFort =>         ("très fort",           Color32::from_rgb(0, 105, 5)),
            NiveauSecurite::ExtremementFort =>  ("extrêmement fort",    Color32::from_rgb(0, 80, 20)),
        };
        
        ui.add_space(5.);

        ui.horizontal(|ui| {

            let texte_colore = egui::RichText::new(format!("{} {niveau_securite_str}",securite.round() as usize))
                .strong()
                .color(Color32::LIGHT_GRAY);

            ui.style_mut().visuals.extreme_bg_color = GRIS_FONCE;

            ui.scope(|ui| {
                ui.spacing_mut().interact_size = egui::vec2(30.0, 30.0);

                ui.menu_button("  ···  ", |ui| {
                    ui.label(format!("Entropie : {:.2} bits", securite));
                    ui.label(format!("Durée de protection : {duree_protection} ({nb_essais_par_seconde:.0e} essais/seconde)"));
                    ui.label(format!("Tentatives estimées : {tentatives_estimees}"));
                });
            });

            const MAX_SECURITE: f32 = 1700.0;

            let ratio = (securite as f32 / MAX_SECURITE).clamp(0.0, 1.0);

            let progression = 1.0 - (1.0 - ratio).powf(18.0);


            let barre = egui::ProgressBar::new(progression)
                .fill(couleur_niveau)
                .text(texte_colore)
                .corner_radius(2)
                .desired_height(30.);

            ui.add(barre);
        });

        (niveau_securite, securite, tentatives_estimees, duree_protection)
    }

    fn vider_presse_papier() {

        if let Ok(mut cb) = Clipboard::new() {

            let _ = cb.clear();
        }
    }

    fn copier_presse_papier(mdp: &ChaineSecurisee) {

        if let Ok(mut cb) = Clipboard::new() {

            let _ = cb.set_text(mdp.expose(|mdp_string| mdp_string.clone()));
        }
    }

    pub fn formattage_type_caracteres(
        taille_police: f32,
        masquer: bool,

    ) -> impl Fn(&Ui, &dyn TextBuffer, f32) -> Arc<Galley> {
        
        move |ui, string, wrap_width| {
            let mut job = LayoutJob::default();
            job.wrap.max_width = wrap_width;

            for ch in string.as_str().chars() {
                
                let char_a_afficher = if masquer { '•' } else { ch };

                let couleur = if masquer {
                    Color32::LIGHT_GRAY 
                } else if ch.is_ascii_lowercase() {
                    Color32::from_rgb(100, 200, 255)
                } else if ch.is_ascii_uppercase() {
                    Color32::from_rgb(255, 120, 120)
                } else if ch.is_ascii_digit() {
                    Color32::from_rgb(120, 255, 120)
                } else {
                    Color32::from_rgb(255, 200, 100)
                };

                job.append(
                    &char_a_afficher.to_string(),
                    0.0,
                    TextFormat {
                        font_id: FontId::monospace(taille_police),
                        color: couleur,
                        ..Default::default()
                    },
                );
            }

            ui.painter().layout_job(job)
        }
    }

    fn reinitialiser_gestionnaire(&mut self, frame: &mut eframe::Frame, ui: &mut Ui) {

        let _ = effacer_mdps();
        self.fichier = None;
        self.noms_mdp = None;
        self.fenetres.clear();
        self.mdp_nouveau_mdp = SaisieChamp::new(false, true);
        self.mdp_confirmation = SaisieChamp::new(false, true);
        self.saisie_mdp_authentification = SaisieChamp::new(false, true);
        self.type_fenetre = TypeFenetre::NouveauMdpPrincipal;

        if let Some(fenetre) = frame.winit_window() {

            fenetre.set_visible(false);

            let dims: egui::Vec2 = TypeFenetre::NouveauMdpPrincipal.dimensions();
            let ctx = ui.ctx();

            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(dims));
            ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(dims));
            ctx.send_viewport_cmd(egui::ViewportCommand::MaxInnerSize(dims));
            ctx.send_viewport_cmd(egui::ViewportCommand::Title("Nouveau mot de passe principal".to_string()));

            fenetre.set_resizable(false);
            self.centrer_fenetre(fenetre, dims);
            ctx.request_repaint();

            fenetre.set_visible(true);   
        }
    }
    
    fn boucle_authentification(&mut self, ui: &mut Ui) -> Option<Result<ChaineSecurisee, ErreurGestionnaire>> {
        
        let mut open = true;
        let mut resultat_auth = None;
        let mdp_accepte = true;
        let mut saisie = SaisieChamp::new(false, true);

        GestionnaireGui::ui_fenetre(
            ui,
            egui::vec2(300., 300.),
            &ChaineSecurisee::from_str("Authentification"),
            &mut open,
            |ui| {
                let mut traiter_saisie = false;

                ui.heading("Mode éphémère : Entrez votre mot de passe principal");
                ui.add_space(15.);

                ui.horizontal(|ui| {
                    GestionnaireGui::entree_mot_de_passe(
                        ui,
                        true,
                        true,
                        false,
                        Some(String::from("Mot de passe principal")),
                        mdp_accepte,
                        ui.available_width() - 75.,
                        &mut saisie,
                    );

                    let bouton_entrer = egui::Button::new("➡").min_size(egui::vec2(30.0, 30.0));
                    if ui.add(bouton_entrer).clicked() {
                        traiter_saisie = true;
                    }
                });

                if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    traiter_saisie = true;
                }

                if traiter_saisie {
                    if let Ok(resultat_verification) = verifier_mdp_principal(&saisie.champ) {
                        
                        if resultat_verification {
                            resultat_auth = Some(Ok(self.saisie_mdp_authentification.champ.clone()));
                        } else {
                            self.debut_animation();
                        }
                    } else {
                        self.debut_animation();
                    }
                }
            },
        );

        if !open {
            return Some(Err(ErreurGestionnaire::ErreurSaisie("Arret de l'authentification".to_string())));
        }

        resultat_auth
    }
}
